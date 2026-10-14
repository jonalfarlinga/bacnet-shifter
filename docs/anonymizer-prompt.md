# Build a BACnet anonymizing proxy on the `bacnet` library

## What to build

A Go program that sits between two BACnet/IP networks and passes traffic between them, replacing every piece of site-identifying information with a pseudonym on the way out. Three names, used consistently throughout the spec, code and logs:

- **Site**: the real, live BACnet network. The program reaches it through the `client` package of `bacnet` (`github.com/jonalfarlinga/bacnet/client`), the way `cmd/explorer` does.
- **Shifter**: this program (the anonymizer).
- **Consumer**: any BACnet client software on the other side (YABE, the explorer, a BMS). It talks ordinary BACnet/IP to the shifter and cannot tell it is not talking to the site. It reads `AI-7c3e91ab0d42`, never `BAC_AHU01`.

"Client" means only the Go package. The shifter lives in `C:\Users\nxl16\code\bacnet-shifter` as its own module, with a `replace` directive to `..\bacnet` until the library is tagged. Changes the shifter needs in the library go into `bacnet` as their own commits. Confirm before writing to `bacnet`.

## Facts about the library to build on (read these first)

1. **`client` is a client only.** It has no device identity, sends no I-Am, and answers nothing except the SimpleACK for its own COV notifications (`client/client.go` package doc; `docs/library-upgrade-spec.md` §2 and §12). The shifter's consumer-facing side is a BACnet *server* and has to be written. The closest existing code is `client/sim` (`sim.go`, `devices.go`, `cov.go`): simulated devices on loopback that answer Who-Is, ReadProperty, ReadPropertyMultiple, ReadRange, Who-Is-Router-To-Network and SubscribeCOV, segment long replies, act as a router and a BBMD, and send COV notifications. Lift its station, dispatch and segmentation code into a reusable server package instead of writing a second one, and keep `sim` and its tests working on top of it.
2. **Everything `client` sends passes through one guard**, `allowed()` in `client/client.go`. It permits Who-Is, ReadProperty, ReadPropertyMultiple, ReadRange, Segment-ACK, client-side Abort, Who-Is-Router-To-Network and the BBMD functions. With `Config.ReadOnly` it also refuses SubscribeCOV and COV acks. It does not permit Who-Has or WriteProperty. There is **no WriteProperty method** (only the encoder in `services/wp.go`); the library spec plans the method in §11 and a per-device writable switch in §7.7. Full-service therefore needs library work.
3. **`client` already does the hard network parts**: routed addresses (`Address{Net, MAC}`), router learning, foreign-device registration with a BBMD, reading a device by address (`Knock`, `Probe`), in-flight and rate limits, a deny list, COV subscriptions that renew themselves (`SubscribeCOV`, `CancelCOV`), and `Config.OnPacket`, which sees every datagram sent and received. Use `OnPacket` on both sockets for the leak and guard tests below.
4. **The project writes a spec before code** (`docs/explorer-spec.md`, `docs/library-upgrade-spec.md`): plain prose, numbered sections, goals and non-goals, a testing section, open questions. Do the same.
5. **configuration variables contained in yaml** any variables that are created will be written to `config.yaml` set to default values. yaml comments will describe the options and context for each variable.

## Architecture: the shifter is a router to a virtual network

Do not give each site device its own IP on the consumer side, and do not put many devices at one IP:port (a ReadProperty to that address would be ambiguous). Instead:

- The shifter listens on one consumer-facing UDP socket and presents itself as a BACnet **router to virtual network V** (a network number from config, default 9000). Every site device, whether on the site's own subnet, behind a site router, or reached through a BBMD, appears to the consumer as a routed device at `(V, virtual MAC)`. The consumer learns this from the routed I-Ams the shifter sends (SNET=V, SADR=virtual MAC) and from I-Am-Router-To-Network. The `client` package handles routed devices already, so the explorer works unchanged as a consumer.
- The shifter keeps a bidirectional map: `(V, virtual MAC) <-> real Address` and `virtual device instance <-> real device instance`. Real IPs, network numbers, MACs and device instances never appear on the consumer socket.
- Two sockets on two adapters or addresses: the site side opened by `client` with the explorer's flags (`-interface`, `-bbmd`, `-bbmd-ttl`, `-add`), the consumer side by the server. They cannot share an IP:port.

## No identity on either side

The shifter has no device object, sends no I-Am of its own, and answers nothing about itself. This holds on both sides, and BACnet allows it: a request needs a source address, not a device, and COV notifications go to the subscriber's address. The library's client is already built this way (spec §12). What follows from it, and is to be designed in:

- **On the site, the shifter's footprint is its IP address.** It is the source of every request, and with `-bbmd` it is an entry in the BBMD's foreign device table, which anyone can read. Nothing else: it never answers a Who-Is, so site tools that list devices do not show it.
- **Every consumer reaches the site from that one address.** A device's per-source limits (requests in flight, COV subscribers) see the sum of all consumers. So the shifter coalesces: one upstream subscription per site object, fanned out to every consumer that subscribed to it, with the consumers' own process IDs kept on the consumer side.
- **On the consumer side it is a router, not a device.** Something must sit at the consumer-facing address, and a router to network V is the least the shifter can be: I-Am-Router-To-Network is a network-layer message, not a device, so there is no device object, no I-Am and nothing to read. A confirmed request addressed to the shifter's own address with no destination network is for a device that does not exist, and is answered with nothing.
- **It cannot be a notification recipient by device instance**, only by address, and receiving event notifications is a non-goal anyway.

## Pseudonyms

- **"Hashing" must be keyed.** A plain SHA-256 of `BAC_AHU01` is one dictionary lookup from the real name. Use HMAC-SHA256 under a per-site secret key, generated on first run and stored in the data directory with owner-only permissions. The forward mapping (real to pseudonym) is then a pure function of the key: the same site yields the same pseudonyms across restarts, so the consumer can store and chart them.
- **Object names**: `<type abbreviation>-<first 12 hex of HMAC(device instance, object type, object instance, real name)>`, e.g. `AI-7c3e91ab0d42`. Unique within a device by construction; detect and record collisions anyway. Descriptions and the other free-text identifying properties are replaced the same way (HMAC of the text) or with a fixed string, as the spec decides.
- **Device instances**: HMAC of the real instance reduced to 0..4194302, collisions resolved through the table. **Virtual MACs**: two bytes derived the same way, collisions likewise. Nothing is allocated sequentially, since discovery order says something about the site.
- **The table** (`table.json` in the data directory) is the reverse index and the audit record: every pseudonym ever issued, its real value, the real address, and when it was first seen. Together with the key it is the de-anonymization secret: it lives only on the shifter's machine and is never served on the consumer socket. A `-table` flag prints pseudonym and real side by side, filtered by either, and exits.

### What is replaced and what passes through

| Replaced | Passes through unchanged |
|---|---|
| Every object: object-name, description | Object type and instance of non-device objects (structural; rewriting them would mean rewriting every reference property) |
| Device object: object-identifier (instance), location, serial-number, model-name, description | vendor-name, vendor-identifier, firmware-revision, application-software-version (they name the product, not the site) |
| Every object identifier that names a **device** object, wherever it appears: I-Am, object-list, the initiating device of a COV notification, property references (trend-log log-device-object-property, member-of, and the like) | present-value, units, status-flags, reliability, out-of-service, priority-array, state-text, active-text, inactive-text, limits, COV increment, log records, everything else |
| device-address-binding: rewritten to virtual addresses, or answered empty | Error, Reject and Abort replies: same class, code or reason |

The list of replaced properties is a documented default in config, not hard-coded.

Requests from the consumer that carry a name: Who-Has by name is answered from the table (pseudonym to real, then I-Have with virtual identifiers), never forwarded, since the guard does not send Who-Has. A write to any replaced property is refused below `god` with Error class property, code write-access-denied: it would rename a site object and break the mapping. What `god` does with it is in the control section.

## The control setting

One setting, `-control`, read at start, default `no-write`. It bounds what the shifter sends to the site and is enforced twice: by the shifter's dispatch, which refuses the consumer's request with a BACnet Error (never a silent drop), and by the library's guard. Under `no-write` the site-side `client` is opened with `ReadOnly: true`, so a bug in the shifter still cannot write or subscribe. Each level includes the ones above it.

| Level | Adds, sent to the site | Still refused from the consumer (Error class services, code service-request-denied, unless noted) |
|---|---|---|
| `no-write` (default) | Exactly the library's read-only list: Who-Is, ReadProperty, ReadPropertyMultiple, ReadRange, Segment-ACK and Abort, Who-Is-Router-To-Network, BBMD registration and table reads | Everything else |
| `limited` | SubscribeCOV and CancelCOV, and the SimpleACK of confirmed notifications | Every write and every other service |
| `full-service` | WriteProperty (and WritePropertyMultiple if the encoder is cheap) at priority 13, to ordinary properties of ordinary objects | Priorities 1 to 12 (write-access-denied); the life-safety and alarm set below; every other service |
| `god` | Every confirmed service the shifter can translate, at any priority including 1 and 2, including the life-safety and alarm set | Only a payload the shifter cannot translate, see below |

**Full-service and priority.** A write that names no priority goes out at 13. One that asks for 13 to 16 keeps its priority. One that asks for 1 to 12 is refused with write-access-denied, so the consumer learns it rather than being silently demoted. A relinquish (Null) follows the same rule.

**The life-safety and alarm set, reserved for `god`.** Full-service refuses, with write-access-denied for writes and service-request-denied for services:

- the services LifeSafetyOperation, AcknowledgeAlarm, DeviceCommunicationControl, ReinitializeDevice, AddListElement, RemoveListElement, CreateObject, DeleteObject, AtomicReadFile and AtomicWriteFile;
- any write to a Life Safety Point, Life Safety Zone, Notification Class, Event Enrollment or Alert Enrollment object;
- any write, on any object, to out-of-service, event-detection-enable, event-enable, limit-enable, time-delay, time-delay-normal, notification-class, notify-type, recipient-list or ack-required: the properties that disable, delay or redirect alarms;
- any write to a replaced property (object-name, description, location and the rest of the table above).

**God.** All of the above is forwarded, after the same address and device-identifier translation as a read. A write to a replaced property is forwarded verbatim: the site object takes the consumer's string as its real name, the table records the rename, and the object's pseudonym changes with its name. What `god` still refuses, with an Error and a log line, is a payload the shifter cannot translate: a device identifier or an address in a place the shifter does not know how to rewrite, such as a consumer's own address in a recipient-list entry, is never forwarded broken. `god` is never the default: it prints a warning banner at start, and every god-only request it forwards is logged at Warn with the consumer's address, the device, the service, the object, the property and the priority.

SubscribeCOVProperty is refused at every level in v1, since the library does not send it. Every refusal is logged with the consumer's address, the service and the level.

**Library work, in `bacnet`, each as its own change, confirmed first, with the §7.7 test that everything else is still refused.** For full-service: `(*Client).WriteProperty(ctx, to, obj, prop, value, priority)` with Null to relinquish, no blind retransmission, and an error that separates "sent, no answer" from "never sent" (spec §11), plus the guard widened per §7.7 for devices switched to writable. For `god`: a way to send a confirmed request of any service, encoded by the caller, to a device switched to writable, behind a `Config` flag that is off by default and logs every such send at Warn. A client that sets neither stays exactly as read-only as today.

## Behavior per message, consumer side

- **Who-Is** (any form): one routed I-Am per matching known device, from V. Also forward a Who-Is to the site, rate-limited, so devices that appeared since the last discovery are found. **Who-Is-Router-To-Network**: I-Am-Router-To-Network for V.
- **ReadProperty, ReadPropertyMultiple, ReadRange**: translate the destination and any device identifiers, forward through `client`, translate the reply, answer with the same ComplexACK, Error, Reject or Abort the site gave. Segment on the consumer side when the reply exceeds the consumer's max APDU. An upstream timeout is answered with nothing, as the device itself would be silent; a consumer retry (same source, same invoke ID) while the upstream request is still in flight is not forwarded again.
- **SubscribeCOV** (limited and above): one upstream subscription per site object through `client.SubscribeCOV`, shared by every consumer that subscribed to it, confirmed upstream when any of them asked for confirmed. Each consumer's process ID and lifetime are kept on the consumer side. Notifications are re-issued to each consumer with the virtual device identifier and that consumer's process ID, confirmed when it asked, with its SimpleACK awaited. CancelCOV and expiry remove a consumer; the last one out cancels upstream; shutdown cancels every upstream subscription.
- **WriteProperty** (full-service and above): translate, apply the priority rule and the reserved set, forward, answer as the site did.
- **The god-only services** (`god`): translate, forward, answer as the site did; refuse what cannot be translated.
- **Anything else**: Reject with reason unrecognized-service, or the Error in the table above.

Site side: at start, Who-Is plus `-add` addresses and `-bbmd`; keep `OnIAm` running so a device that appears later gets its pseudonym and is announced. On each new device, one ReadProperty of object-name fills its table entry. Objects get their pseudonyms the first time they are read.

## Configuration and operation

Flags: `-interface` (site), `-bbmd`, `-bbmd-ttl`, `-add`, `-listen` (consumer address:port), `-vnet`, `-control` (`no-write`, `limited`, `full-service`, `god`), `-data` (directory for key, table and log), `-log`, `-frames`, `-table`, and `-sim`, which runs against `client/sim` on loopback with the consumer socket on loopback too. No web UI.

## Testing

Harness: `client/sim` as the site, the shifter, and a `client.Client` as the consumer, all in-process on loopback. Required:

1. **Leak test**: record every datagram on the consumer socket and assert no byte sequence equals any real name, description, model, serial, encoded real device instance, site IP or MAC of the sim devices.
2. **Fidelity**: through the shifter the consumer finds every sim device, reads its object list, and reads present-values equal to what a direct `client` reads. Sim's errors (unknown object, unknown property, the NoRPM device, the NoWildcard device) come through unchanged.
3. **Guard test, per level, all four**: record every datagram on the site socket and assert the set of (PDU type, service) sent is exactly the level's list, while the consumer sends one of every confirmed and unconfirmed service and gets the documented Error or Reject for each refused one. Mirror the library's §7.7 test.
4. **COV under limited**: the consumer subscribes; `sim.NotifyCOV` produces a notification at the consumer carrying only virtual identifiers; two consumers subscribed to one object share one upstream subscription and both get the notification; cancelling the last one empties sim's `COVSubscriptions`.
5. **Stability**: restarting with the same data directory leaves every pseudonym and virtual address unchanged; a different key changes them all.
6. **Collisions**: two objects whose pseudonyms collide get distinct ones and the table records both.
7. **Routed and BBMD-reached site devices** (`sim.RemoteSite`) appear on V like local ones.
8. **Priority and the reserved set under full-service**: a write with no priority reaches sim at 13; one at 16 reaches sim at 16; one at 8 is refused and nothing reaches sim; a write to out-of-service and a LifeSafetyOperation are refused and nothing reaches sim.
9. **God**: the same three writes and the LifeSafetyOperation all reach sim, the one at 8 at priority 8; a write to object-name reaches sim, after which the consumer reads a new pseudonym and the table shows the rename; the log has a Warn line for each.

For 8 and 9, `sim` must learn to accept WriteProperty with a priority array on its commandable objects, and to record and SimpleACK the god-only services it receives, so the tests can see what reached the site. That is a change to `bacnet`: confirm first, keep it its own commit.

Manual check: `go run ./cmd/explorer -interface <consumer-side address>` from the `bacnet` repo against the shifter shows only pseudonyms.

## Deliverables, in order

1. `docs/anonymizer-spec.md` in this repo, in the style of the library's specs: goals and non-goals, architecture, the pseudonym rules and the replaced/pass-through table, the control table, behavior per message, configuration, testing, delivery plan, open questions. **Stop for review before writing code.**
2. **M1, no-write**: server package lifted from `sim`, discovery, key and table, read passthrough, tests 1 to 3 (no-write), 5 to 7, the manual explorer check.
3. **M2, limited**: COV passthrough, test 4, the guard test for limited.
4. **M3, full-service**: WriteProperty, the guard change and the `sim` extension in `bacnet` first, then write passthrough with the priority rule and the reserved set, test 3 for full-service, and test 8.
5. **M4, god**: the caller-encoded request behind its flag in `bacnet` first, then god passthrough, test 3 for god, and test 9.

Each milestone: `go vet` and `go test ./...` clean in both modules, and a README section for the shifter.

## Non-goals for v1

MS/TP and BACnet/SC transports; receiving event notifications (the shifter is never a notification recipient); SubscribeCOVProperty; different views for different consumers (many consumers are fine, all see the same view); consumer authentication; a web UI; changing `-control` without a restart; hiding the type and instance of non-device objects; hiding timing and traffic patterns.

## Settled

1. vendor-name, vendor-identifier, firmware-revision and application-software-version pass through.
2. The shifter has no identity on either side (see that section); `limited` therefore needs no library change.
3. Four levels: `no-write`, `limited`, `full-service` at priority 13 and barred from the life-safety and alarm set, `god` with everything.
4. Instances of non-device objects pass through unchanged.
5. A separate `bacnet-shifter` module with a `replace` to `../bacnet`; confirm before any change to `bacnet`.
