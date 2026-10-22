# bacnet-shifter — Specification (v1 draft)

Companion to [anonymizer-prompt.md](anonymizer-prompt.md), which asked for this program, and [build-plan.md](build-plan.md), which fixed the order of work and the boundary with the `bacnet` library. This document says what the shifter is and how it behaves; the plan says in what order it is built. It is written against `../bacnet` at commit `837c927`, and the facts about the library it relies on were checked there (build-plan.md §2). Decisions the user took before this spec was written are carried in the text and listed in §15; §16 records what the review of the first draft resolved, and §17 what it deferred.

## 1. Goals

1. **Nothing identifying crosses to the consumer side.** Every name, description, device instance, address and network number of the site is replaced with a pseudonym before it leaves the shifter. The consumer reads `AI-7c3e91ab0d42`, never `AHU1.OAT`, and reaches it at a virtual address on a virtual network, never at the site's.
2. **Transparent to the consumer.** The consumer speaks ordinary BACnet/IP to the shifter and cannot tell it is not talking to the site: the same services, the same replies, the same errors. The library's own `client` works against it unchanged, and so does any other BACnet client. The site's shape survives too: each network behind a site router is a network of its own behind the shifter, so a consumer that groups devices by network, as the explorer does, sees the devices nested as they are on the site.
3. **Stable pseudonyms.** The pseudonyms are a pure function of a secret key and the real values, so the same site yields the same names across restarts and the consumer can store and chart them. Only the shifter's machine can turn them back.
4. **Bounded by one control level, enforced twice.** What the shifter will send to the site is one setting, `no-write` by default, applied by the shifter's dispatch and again by the library's guard. A bug in the shifter cannot write to a site whose shifter is set to `no-write`.
5. **No identity on either side.** The shifter has no device object, sends no I-Am of its own and answers nothing about itself. On the site it is an address; on the consumer side it is a router.
6. **A minimal footprint on the site.** All consumers reach the site from one address, so the shifter coalesces: one upstream subscription per site object, one Who-Is at most a second, the library's in-flight and rate limits in front of everything.
7. **Built on `client`, with the library changed as little and as late as possible.** Everything the shifter can do with the exported library it does itself; the five library changes (§13) are each confirmed first and land as their own commits.

## 2. Non-goals (v1)

- MS/TP and BACnet/SC transports. Both sides are BACnet/IP on UDP.
- Receiving event notifications. The shifter is never a notification recipient; it has no device instance to be one by, and it does not forward a consumer's recipient-list entry that names the consumer (§7.5).
- SubscribeCOVProperty, at every level: the library does not send it.
- Different views for different consumers. Many consumers are fine; all see the same view.
- Consumer authentication, and a BBMD function on the consumer side (a consumer on another IP subnet cannot register with the shifter as a foreign device; §16).
- A web UI.
- Changing the control level without a restart.
- Hiding the type and instance of non-device objects, or the shape of a device (how many objects, of which types).
- Hiding timing and traffic patterns.
- Showing which site router serves which network. Through any BACnet router, the shifter included, an end station learns only its first hop (§5.2); the roadmap (§17) has the one way round that and its cost.
- Replacing free text in properties outside the replaced list (§6.5): state-text, active-text, inactive-text, event-message-texts and the like pass through. The list is configuration, so a site that keeps names in them can add them.
- Segmented requests from a consumer. Requests that need segmentation are large writes; §8.1 says what the consumer is told.
- Forgetting a device. The table never drops an entry; a device that has gone from the site stays in the table and is announced no more, nothing else.

## 3. Vocabulary

| Term | Meaning |
|---|---|
| **site** | The real BACnet network. The shifter reaches it through the library's `client` package, as `cmd/explorer` does. |
| **shifter** | This program. |
| **consumer** | Any BACnet client on the other side: YABE, the explorer, a BMS. |
| **client** | Only the Go package `github.com/jonalfarlinga/bacnet/client`. |
| **V** | The virtual network number for the site's own IP subnet, from configuration, default 9000. |
| **virtual network** | V, or the number derived for one site network behind a router (§6.2); the shifter routes to all of them. |
| **real** | A value as it is on the site: a name, a device instance, an `Address`. |
| **virtual** | The pseudonym the consumer sees for it: a derived name, a device instance in 0..4194302, a network number, an address `(virtual network, virtual MAC)`. |
| **the key** | The per-site HMAC secret, generated on first run. |
| **the table** | `table.json`: every pseudonym issued, its real value, and when. With the key, the de-anonymization secret. |
| **level** | The control setting: `no-write`, `limited` or `full-service`. |

The site side and the consumer side are the two sockets. "Upstream" is toward the site, "downstream" toward the consumer.

## 4. What the library gives, and what the shifter adds

| In `bacnet` today | The shifter builds on it | The shifter has to add |
|---|---|---|
| `client`: one socket, confirmed transactions, segmented replies reassembled, routed addresses and router learning, foreign-device registration, `Knock` and `Probe`, in-flight and rate limits, deny list, `SubscribeCOV` that renews itself, `CancelCOV`, `OnIAm`, `OnPacket` | The whole site side | Nothing for `no-write` and `limited` |
| `allowed()`: one guard in front of everything sent; `ReadOnly` narrows it to reads | The second enforcement of the level | A write method and a per-device writable switch (L1) |
| `client.Value`: decoded property values that keep their kind, context tag, raw bytes and nesting | Replies are translated as values and re-encoded | The re-encoder (§9.4) |
| `client/sim`: simulated devices that answer reads, segment, route, act as a BBMD and notify COV | The site of every test | A server package copied out of it (§5.4), later lifted into the library (L4); writes recorded (L2) |
| `plumbing`: BVLC, NPDU, APDU and network-message codecs, `NetworksData` | The consumer-side parser and the I-Am-Router-To-Network | Nothing |
| `services`, `objects`: the encoders for Who-Is, I-Am, reads, tags | The few payloads the shifter builds itself: I-Am, I-Have, COV notifications, Error, Reject, Abort | Constants for LifeSafetyOperation (27), SubscribeCOVProperty (28) and GetEventInformation (29), and the error code write-access-denied (40), which `services` and `objects` lack; the shifter defines them |

Two things found in the library shape this spec and are decided rather than worked around: reads return decoded values, not the reply's tags, so replies are re-encoded (§9.4, decision 1); and `ReadSpec` has no per-property array index, so a ReadPropertyMultiple that indexes a property is refused (§8.3, decision 2).

## 5. Architecture

### 5.1 Two sockets, two adapters

The shifter owns two UDP sockets that cannot share an IP and port.

- **The site socket** is the library client's, opened by `client.Open` with the explorer's settings: an adapter named or addressed in configuration, a port (default 47808), optionally a BBMD to register with and a list of addresses to read at start. Under `no-write` it is opened with `ReadOnly: true`.
- **The consumer socket** is the server's. It is bound by the same rules as `client.Open`, through the exported `client.FindInterface` and `Interface.Config`: on Windows to the adapter's own address, which hears broadcasts there, so two adapters can both use port 47808; on Linux and macOS a socket that hears broadcasts binds every address, so the two sides need distinct ports, or a VM or network namespace per side. The README says so and gives both (decision 3). The socket drops datagrams from the subnets of the machine's other adapters, as the client does with `Exclude`.

Under `sim` (§10) both sockets are on loopback with distinct ports, the site being `client/sim`.

### 5.2 A router to the virtual networks

The consumer side does not give each site device an IP, and does not put many devices behind one IP and port, where a request would be ambiguous. The shifter is a BACnet router, and every site device is a routed device behind it, on a virtual network that mirrors where the device is on the site:

- A device on the site's own IP subnet, or reached through the BBMD on a remote IP subnet, is on **V**, the configured number, at `(V, virtual MAC)`.
- A device behind a site router, on real network N, is on the **virtual network derived from N** (§6.2), at `(V_N, virtual MAC)`. Two site networks are two virtual networks; the site's router is itself a device on V.

The shifter announces I-Am-Router-To-Network for V and every virtual network it knows, and answers Who-Is-Router-To-Network for them. A consumer learns the devices from routed I-Ams the shifter sends with SNET the virtual network and SADR the virtual MAC, and learns the router from the network messages. The `client` package handles both already (`routing_test.go`: a route learned from a routed I-Am, a router found on demand), so the explorer works as a consumer unchanged, and shows what it shows for any site reached through a router: the shifter's address as the router, each virtual network under it, each device under its network.

A consumer's request arrives with DNET a virtual network and DADR a virtual MAC. The shifter maps the pair to the real `client.Address` (an IP, or a router's IP with the real network and MAC) and the virtual device instance to the real one, forwards, and sends the reply back as a router would, from the same virtual pair. It keeps the maps in both directions: `(virtual network, virtual MAC) <-> real Address`, `virtual network <-> real network number`, `virtual device instance <-> real device instance`. Real IPs, network numbers, MACs and device instances never appear on the consumer socket.

**What an end station can see of nesting.** BACnet shows an end station only its first hop: a consumer asking who routes to a network hears the router on its own subnet, which is the shifter, whatever lies behind it. So the consumer sees every virtual network behind the shifter, and the site's router as a device on V, but cannot learn from the protocol that the one serves the other; it could not through a real router either. Preserving the networks is what the protocol allows, and it is what the explorer nests by. The roadmap (§17) notes the one way to show the site's routers as routers, and what it costs.

A virtual MAC is two bytes whatever the real one was. The consumer's own network may be routed too: a request that arrives with SNET and SADR is answered to that source through the router it came from, as any router does.

### 5.3 No identity on either side

The shifter has no device object, sends no I-Am of its own and answers nothing about itself. BACnet allows it: a request needs a source address, not a device, and a COV notification goes to the subscriber's address. The library's client is built this way already. What follows:

- **On the site, the shifter's footprint is its IP address.** It is the source of every request, and with a BBMD configured it is one entry in the BBMD's foreign device table, which anyone can read. It never answers a Who-Is, so site tools that list devices do not show it.
- **Every consumer reaches the site from that one address**, so a site device's per-source limits see the sum of all consumers. The shifter coalesces (§5.6, §8.5).
- **On the consumer side it is a router, not a device.** I-Am-Router-To-Network is a network-layer message; there is no device object, no I-Am for the shifter and nothing to read about it. A confirmed request addressed to the shifter's own address without a destination network is for a device that does not exist, and gets no answer (§8.1).
- **It cannot be a notification recipient** by device instance, only by address; receiving event notifications is a non-goal.

### 5.4 Packages

```
bacnet-shifter/
  go.mod                 module github.com/jonalfarlinga/bacnet-shifter; go 1.25
                         require github.com/jonalfarlinga/bacnet, gopkg.in/yaml.v3
                         replace github.com/jonalfarlinga/bacnet => ../bacnet
  config.yaml            every key at its default, with a comment each; generated by the
                         program from its defaults table, and this copy is that output
  cmd/shifter/           runs with no arguments; loads config.yaml from the working
                         directory; -table is the only switch
  internal/pseudonym/    the key file; HMAC derivation of names, text, instances and MACs
  internal/table/        table.json: forward and reverse maps, collisions, audit, the -table listing
  internal/server/       the consumer socket: parse, dispatch, reply, segment, the
                         confirmed-request sender for notifications; copied from client/sim
  internal/translate/    Value <-> tags; the rewriting of device identifiers, names and
                         addresses in requests, replies and notifications
  internal/control/      the three levels, the reserved set, the priority rule, the refusal table
  internal/shifter/      the proxy: site client, discovery, consumer dispatch, COV fan-out,
                         duplicate suppression, the daily survey's schedule
  internal/survey/       the bacnet-survey utility on the shifter's site client: the knocks, the
                         neighbor table, the pings, the summary
  internal/harness/      sim + shifter + consumer on loopback, packet recorders, the raw
                         sender; tests only
  docs/                  this spec, the build plan, the prompt
```

The module path and the split stand unless review changes them (decision 9). `internal/server` is copied out of `client/sim` (`serve`, `handle`, `confirmed`, `target`, `networkMessage`, `send`, the segmenting half of `read`, `sendSegments`, `continueReply`, `abortReply`, and from `cov.go` the confirmed-notification sender `notify` and `covAcked`: about three hundred lines against exported API) and moves into the library as `client/server`, with `sim` rebased on it, as the last step (L4, decision 8).

The server package knows nothing about pseudonyms or levels. It parses BVLC, NPDU and APDU generically with the `plumbing` unmarshalers, which is all it needs: PDU type, service, invoke ID, segmentation flags, max-APDU, the NPDU source, and the tags. It cannot use `bacnet.Parse`, which returns `ErrNotImplemented` for any confirmed service it has no type for, and the shifter must see every service to refuse it by name. It hands each request to a handler interface the shifter implements, and offers the handler: a reply with the consumer's invoke ID, segmented to the consumer's max APDU and window; an Error, Reject or Abort; a unicast or broadcast unconfirmed message from a virtual source `(virtual network, MAC)`; and a confirmed request to a consumer with its SimpleACK awaited, for confirmed notifications. It keeps a pending map keyed by consumer source and invoke ID for duplicate suppression (§8.3), and takes an `OnPacket` like the client's, for the leak test.

### 5.5 One read, end to end

A consumer reads present-value of `analog-input 3` on virtual device 1748213 at `(V, 0x2a7c)`.

1. The datagram arrives on the consumer socket: Original-Unicast-NPDU, DNET V, DADR `2a 7c`, ConfirmedReq ReadProperty, invoke ID 17, the consumer's max-APDU and segmentation flags.
2. The server parses it and calls the handler with the source, the NPDU and the APDU. The handler records `(source, 17)` as pending.
3. Dispatch checks the level: ReadProperty is allowed at every level. It looks up `(V, 0x2a7c)` in the table: real device 1001 at `10.22.60.3:47808`. For a device behind a site router the lookup gives the router's IP with the real network and MAC, which `client.Address` carries. The object identifier is not a device object, so it passes through; had it been `device 1748213`, it would become `device 1001`; had it been the wildcard `device 4194303`, it would pass through.
4. The shifter calls `client.ReadProperty(ctx, Address{IP: 10.22.60.3:47808}, {analog-input, 3}, present-value)`. The guard allows it. The reply comes back as `[]client.Value`.
5. The translator walks the values: any device object identifier becomes its virtual one; any character string of a replaced property is pseudonymized (not here); then re-encodes them into tags.
6. The handler answers with a ComplexACK, invoke ID 17, object `analog-input 3`, property present-value, the tags, from `(V, 0x2a7c)`, segmented if it does not fit the consumer's max APDU. The pending entry is removed.
7. Had the site answered with an Error, Reject or Abort, the consumer would have got the same class and code or reason. Had it timed out, the consumer would have got nothing.

### 5.6 Concurrency and limits

The server handles each request on its own goroutine; the client bounds what goes upstream by its in-flight limits per device and per routed network (`site.max_in_flight_net`, default the library's 1, decision 6) and its rate limit. A consumer that floods sees timeouts, as it would from a slow site. Shared state (the table, the COV fan-out, the pending map) is behind mutexes; the table is saved after each change (§6.4).

## 6. Pseudonyms

### 6.1 The key

A plain hash of `AHU1.OAT` is one dictionary lookup from the real name, so every derivation is keyed: HMAC-SHA256 under a per-site secret. The key is 32 bytes from `crypto/rand`, generated on first run, stored hex-encoded as `key` in the data directory with mode `0o600`. NTFS ignores the mode, so on Windows the setup instructions say the data directory must be one that only the shifter's account can read (decision 5). The key is never logged, never served, and never derived from anything.

### 6.2 Derivation

`H(label, fields...)` is HMAC-SHA256 over the key of the label and the fields joined with `|`, numbers in decimal, text as UTF-8. `hex12` is the first twelve hex characters of the digest (48 bits).

| Virtual value | Derivation | Form |
|---|---|---|
| Object name | `H("name", real device instance, object type, object instance, real name)` | `<abbrev>-<hex12>`, e.g. `AI-7c3e91ab0d42`, `DEV-1f0a93c7e5b2` |
| Any other replaced string property (§6.5) | `H("text", real device instance, object type, object instance, property id, text)` | `<prefix>-<hex12>`: `desc-`, `loc-`, `sn-`, `model-`, and `p<id>-` for a property added in configuration |
| Device instance | `H("instance", real instance)`, first four bytes big-endian, modulo 4194303 | 0..4194302 |
| Virtual MAC | `H("mac", real instance)`, first two bytes big-endian, modulo 65534, plus 1 | `0x0001`..`0xFFFE`, two bytes |
| Virtual network number | `H("network", real network number)`, first two bytes big-endian, modulo 65534, plus 1; the configured V counts as taken | 1..65534 |

`abbrev` comes from a table of the standard object types (AI, AO, AV, BI, BO, BV, CAL, CMD, DEV, EE, FILE, GRP, LOOP, MSI, MSO, MSV, NC, PROG, SCH, AVG, TL, LSP, LSZ, ACC, PC, EL, GG, TLM, LO, and so on through the types `objects` names); a type without one, proprietary types among them, uses `T<type number>`. An empty string stays empty.

The real name is part of the input, so renaming an object on the site changes its pseudonym. Nothing is allocated sequentially, since discovery order says something about the site.

### 6.3 Namespaces and collisions

Four virtual values are identifiers and must be unique; collisions are detected and resolved in these namespaces:

| Value | Unique within |
|---|---|
| Object name of a non-device object | its device |
| Object name of a device object | the site (BACnet requires it across the internetwork) |
| Device instance | the site |
| Virtual MAC | the site |
| Virtual network number | the site; V itself counts as taken |

The derivation gives candidate 0. If a candidate is already in the table for a different real value in the same namespace, candidate k (k = 1, 2, ...) is `H(label, fields..., "#k")`, until one is free. The table records the candidate index with the entry.

Stability (goal 3) follows from the table, not from the function alone: once an entry exists, it is never re-derived, so an earlier device that would have collided keeps its pseudonym whatever order the devices are seen in on a later run. Across sites with different keys, every pseudonym differs. Descriptions and the other replaced strings are not identifiers and need no collision handling.

A second real device with an instance already in the table at a different address is a site fault (BACnet forbids it). The shifter keeps the first, logs the second at Warn, and does not announce it.

### 6.4 The table

`table.json` in the data directory is the reverse index and the audit record. One record per pseudonym issued:

- what kind it is: device, network, object name, text, MAC;
- the real value: the device instance and real `Address` for a device; the real network number for a network; the device instance, object identifier and real name for an object name; the device instance, object identifier, property and text for a text;
- the pseudonym and its candidate index;
- when it was first seen, in UTC;
- for an object renamed on the site: the previous real name and when it changed, kept on the old record, which stays, since a consumer may still hold the old pseudonym.

A device's real address is updated in place when the site says it has moved (a later I-Am from another address, or a reply from one); the pseudonym does not change. A device object identifier referenced in a value before the device itself has been seen (a trend log's log-device-object-property, say) gets its pseudonym from the derivation and a record marked as referenced, not seen, so references are consistent before and after the device appears.

The file is loaded at start and written after every change, to a temporary file renamed into place. With the key it is the de-anonymization secret: it lives on the shifter's machine and is never served on the consumer socket.

`shifter -table` prints every record, pseudonym and real side by side, and exits; `shifter -table <text>` prints the records whose pseudonym or real side contains the text. It is the only command-line switch (decision 4), being a query rather than a setting.

### 6.5 What is replaced and what passes through

| Replaced | Passes through unchanged |
|---|---|
| On every object: object-name, description | The object type and instance of every non-device object. They are structural: rewriting them would mean rewriting every reference property on the site. |
| On the device object: the instance in object-identifier, location, serial-number, model-name, description (object-name as above) | vendor-name, vendor-identifier, firmware-revision, application-software-version: they name the product, not the site. max-apdu-length-accepted, segmentation-supported, protocol-version and the rest of the device object. |
| Every object identifier that names a **device** object, wherever it appears: I-Am; object-list; the initiating device of a COV notification; the device part of a property reference (trend-log log-device-object-property, member-of, zone-members, subordinate-list, a recipient-list destination, an event-enrollment object-property-reference, and so on) | present-value, units, status-flags, reliability, out-of-service, priority-array, state-text, active-text, inactive-text, limits, COV increment, log records, everything else |
| device-address-binding: every entry rewritten, the device instance to its virtual one and the address to its virtual network and MAC. Both derive from the instance and the network number, so an entry for a device the shifter has not seen is rewritten too. | Error, Reject and Abort replies: same class, code or reason |
| A BACnetAddress inside any other value (a recipient-list destination by address): its network number rewritten to the virtual one; its MAC to the virtual MAC when the table knows which device has that address, otherwise to an empty MAC, the broadcast on that virtual network, and logged | |

The list of replaced string properties is configuration (`pseudonym.replaced`, §10), with the five above as the documented default. A property on the list is replaced on every object it appears on, when its value is a character string or an array of them. The device identifiers and addresses are replaced by rule, not by list.

### 6.6 Where device identifiers are rewritten

The translator applies one rule to every request, reply and notification: any object identifier of type device (8), application- or context-tagged, at any depth in the tags, is mapped, real to virtual downstream and virtual to real upstream. The places it is known to appear are the ones in §6.5, but the rule does not depend on the list. Upstream, a virtual device instance the shifter never issued cannot be mapped; what then happens depends on the service (§7.5, §8.6). The wildcard instance 4194303 passes through in both directions.

The request's own object identifier, the one the reply echoes, follows the same rule: a consumer's `device <virtual>` becomes `device <real>` on the way up and back on the way down.

### 6.7 Requests that carry names

**Who-Has** is answered from the table and never forwarded: the guard does not send Who-Has. By name, the pseudonym is looked up and, when found, an I-Have carries the virtual device identifier, the object identifier and the pseudonym; by object identifier, every device in the table that is known to have that object answers. Only objects whose name has been read through the shifter are in the table, so Who-Has finds what has been looked at (§9.3). The device range of a Who-Has is matched against virtual instances, which are what the consumer knows.

**A write to a replaced property** is refused at every level with Error class property, code write-access-denied: it would rename a site object and break the mapping.

## 7. The control level

### 7.1 The three levels

One setting, `control`, read at start, default `no-write`. It bounds what the shifter sends to the site. Each level includes the ones above it. There is no fourth level (§7.5).

| Level | Adds, sent to the site | Refused from the consumer |
|---|---|---|
| `no-write` (default) | Exactly the library's read-only list: Who-Is, ReadProperty, ReadPropertyMultiple, ReadRange, Segment-ACK and the client's own Abort, Who-Is-Router-To-Network, Register-Foreign-Device, Read-FDT and Read-BDT | Everything else |
| `limited` | SubscribeCOV and CancelCOV, and the SimpleACK of a confirmed notification | Every write and every other service |
| `full-service` | WriteProperty at priority 13 to ordinary properties of ordinary objects | Priorities 1 to 12 and array-indexed writes; the reserved set (§7.4); WritePropertyMultiple; every other service |

The answers a refused request gets are in §7.6.

### 7.2 Enforced twice

The level is applied by the shifter's dispatch, which refuses a consumer's request with a BACnet Error or Reject, never a silent drop, and logs it with the consumer's address, the service and the level. It is applied again by the library's guard: under `no-write` the site client is opened with `ReadOnly: true`, so a SubscribeCOV or a write that a bug in dispatch let through fails in the library with `ErrServiceNotAllowed` and never reaches the site. Under `limited` the client is opened without `ReadOnly` and every device stays read-only in the per-device switch (L1), so the guard refuses writes. Under `full-service` the shifter switches each site device writable as it discovers it.

A refusal by the guard is a shifter bug and is logged at Error; the consumer gets Error class services, code service-request-denied.

### 7.3 full-service and priority

A write that names no priority goes out at 13. One that asks for 13 to 16 keeps its priority. One that asks for 1 to 12 is refused with Error class property, code write-access-denied, so the consumer learns it rather than being silently demoted. A relinquish (a Null value) follows the same rule: no priority becomes 13, 13 to 16 is kept, 1 to 12 is refused.

A write that names an array index is refused at `full-service` with Reject reason other, logged, since the library's write method (L1) takes none. A WritePropertyMultiple is refused at `full-service` (Error class services, code service-request-denied): applying the priority rule and the reserved set per element needs a decoder and encoder the shifter does not build in v1 (§16).

### 7.4 The reserved set

The life-safety and alarm set is refused at every level, `full-service` included, with write-access-denied for writes and service-request-denied for services. It is configuration (`reserved`, §10) with this documented default:

- the services LifeSafetyOperation, AcknowledgeAlarm, DeviceCommunicationControl, ReinitializeDevice, AddListElement, RemoveListElement, CreateObject, DeleteObject, AtomicReadFile and AtomicWriteFile;
- any write to a Life Safety Point, Life Safety Zone, Notification Class, Event Enrollment or Alert Enrollment object;
- any write, on any object, to out-of-service, event-detection-enable, event-enable, limit-enable, time-delay, time-delay-normal, notification-class, notify-type, recipient-list or ack-required: the properties that disable, delay or redirect alarms;
- any write to a replaced property (§6.5), which is a rule rather than a list entry.

### 7.5 No fourth level

A fourth level, `god`, stood here until 2026-10-20: every confirmed service the shifter could translate, at any priority, the reserved set included, with a banner at start, a Warn line per forwarded request, and a rename of a site object recorded in the table. It was dropped before it was built. A consumer that acknowledges alarms, reinitializes devices, creates objects or overrides at priority 1 is operating the site, and an operator does that from the site, not through an anonymizer; the threat model (threat-model.md §12.1) could not bound such a level, and nothing in the shifter's use needs it. The section number stays so that references hold. The library change it would have needed, L3, is cancelled (§13), and so are milestone M4 and test 9 (§12, §14).

What remains of it is one rule, applied at `full-service`: a write whose value names a device identifier or an address the shifter never issued is refused with Error class services, code other, and a log line. Nothing is forwarded broken.

### 7.6 What a refused request gets

Every confirmed service code from 0 to 255 has one documented answer per level, which test 3 (§12) asserts. The shifter's dispatch classes a service as *known* (it can parse and name it: 0 to 12, 14 to 17, 18, 19, 20, 26 to 29), or *unknown* (13, 21 to 25, 30 and above: removed from the standard, VT, or newer than the library). Of the known ones, ConfirmedCOVNotification (1), ConfirmedEventNotification (2), ConfirmedPrivateTransfer (18) and SubscribeCOVProperty (28) are forwarded at no level.

| The consumer sent | At | Answer |
|---|---|---|
| An unknown confirmed service | every level | Reject, reason unrecognized-service (9) |
| A known confirmed service the level does not forward, the four never-forwarded ones included | every level | Error, class services (5), code service-request-denied (29) |
| WriteProperty at priority 1 to 12, or Null at 1 to 12 | full-service | Error, class property (2), code write-access-denied (40) |
| WriteProperty to a reserved object, a reserved property or a replaced property | full-service | Error, class property, code write-access-denied |
| A reserved service | full-service | Error, class services, code service-request-denied |
| WriteProperty with an array index | full-service | Reject, reason other (0) |
| ReadPropertyMultiple with an array index on a property | every level | Reject, reason other (0) (decision 2) |
| WriteProperty whose value names a device or an address the shifter never issued | full-service | Error, class services, code other (0) |
| A request the guard refused (a shifter bug) | every level | Error, class services, code service-request-denied; logged at Error |
| An unconfirmed service other than Who-Is, Who-Has and the network messages of §8.2 | every level | Nothing: unconfirmed services get no reply. Logged at Debug, never forwarded. |

The `Error` constants the library has are `ErrorClassServices`, `ErrorClassProperty` and `ErrorCodeServiceRequestDenied`; write-access-denied (40) and other (0) the shifter defines. Every refusal is logged at Info with the consumer's address, the service, the object and property where there is one, and the level.

## 8. The consumer side, message by message

### 8.1 The envelope

The consumer socket takes Original-Unicast-NPDU and Original-Broadcast-NPDU. A Register-Foreign-Device gets the BVLC-Result NAK (0x0030): the shifter is not a BBMD. Every other BVLC function is dropped and logged at Debug.

The NPDU decides who the request is for:

- **DNET a virtual network, DADR a virtual MAC on it**: a request for that device. The rest of this section.
- **DNET a virtual network, DADR unknown there**: nothing. The device does not exist on that network.
- **DNET a virtual network, no DADR** (a broadcast on it): Who-Is and Who-Has are answered for the devices on that network; a confirmed request broadcast on a network gets nothing.
- **DNET 0xFFFF** (global broadcast): Who-Is and Who-Has are answered for every device on every virtual network.
- **No DNET** (addressed to the shifter itself): Who-Is and Who-Has are answered for every device, since a consumer may send them locally and the prompt asks that any form be answered; a confirmed request is for a device that does not exist and gets nothing.
- **Any other DNET**: Reject-Message-To-Network, reason 1 (not directly connected and no other router found), as `sim` does for a network it does not route to.

A request whose NPDU carries SNET and SADR came through a consumer-side router; the reply goes back with that as its destination, to the datagram's source, which is the router.

The I-Am the shifter sends for a virtual device carries the real device's max-APDU and vendor identifier, and its segmentation downgraded to what the shifter accepts: `both` becomes `transmit`, `receive` becomes `none`. The shifter does not accept segmented requests in v1; a request that arrives segmented is answered with Abort, reason segmentation-not-supported (4).

### 8.2 Who-Is, I-Am, and the network messages

**Who-Is**, in any form: one routed I-Am from `(virtual network, virtual MAC)` per device the envelope selects (§8.1) whose virtual instance is in the Who-Is range (the range names virtual instances, which are what the consumer knows), unicast to the asker as `sim` does. Also an upstream Who-Is, global and unranged, at most once per `site.whois_interval` (default 1 s, decision 7), so a device that appeared since the last discovery is found; a Who-Is inside the interval is answered from the table only. A device a forwarded Who-Is finds is announced when it appears (§9.2).

**Who-Is-Router-To-Network**, with no network: I-Am-Router-To-Network listing V and every virtual network in the table, unicast to the asker; with one of them: that one; with any other network: nothing, as a router that does not reach it stays silent. At start the shifter broadcasts one I-Am-Router-To-Network listing them all on the consumer subnet, as routers do, and when a site network is seen for the first time, one listing the new virtual network.

**Any other network-layer message** (I-Am-Router-To-Network from a consumer-side router, Initialize-Routing-Table, What-Is-Network-Number, and so on) is dropped and logged at Debug. The shifter learns nothing from the consumer side; it never sends to a consumer-side routed destination except in reply to a routed source.

**An I-Am from the consumer side** is dropped. Nothing from the consumer side is ever broadcast on the site except the shifter's own Who-Is.

### 8.3 ReadProperty, ReadPropertyMultiple, ReadRange

The request's object identifier is translated (§6.6), the destination mapped, and the request forwarded through `client.ReadProperty`, `ReadPropertyIndex`, `ReadPropertyMultiple` or `ReadRange`. The reply's values are translated and re-encoded (§9.4), and the consumer gets the same ComplexACK, Error, Reject or Abort the site gave, with its own invoke ID, from `(virtual network, virtual MAC)`, segmented when it exceeds the consumer's max APDU and window; when the consumer cannot take segments and the reply does not fit, Abort reason segmentation-not-supported, as a device would. The property identifier and array index are echoed.

A ReadPropertyMultiple with an array index on any property is refused with Reject reason other and logged, not split (decision 2): `client.ReadSpec` has no per-property index.

**What the site's outcome becomes:**

| From `client` | To the consumer |
|---|---|
| Values | ComplexACK |
| `BACnetError{Class, Code}` | Error, same class and code |
| `RejectError{Reason}` | Reject, same reason |
| `AbortError{Reason}` | Abort, same reason, server flag set |
| `ErrTimeout` | Nothing, as the device itself would be silent |
| `ErrNetworkUnreachable` (the site router rejected the network) | Nothing: the device is on a virtual network behind the shifter as far as the consumer knows, and a network reject for it would be false |
| `ErrResponseTooLarge` | Abort, reason buffer-overflow (1) |
| `ErrServiceNotAllowed`, `ErrSourceDenied` | Error, class services, code service-request-denied; logged at Error (§7.2) |

**Duplicates.** The pending map is keyed by the consumer's source (IP, or SNET and SADR when routed) and invoke ID. A retry that arrives while the upstream request is in flight is not forwarded again; the reply, when it comes, answers the one request. Once answered, the entry is dropped, and a later retry is a new request, as a device's TSM would treat it.

### 8.4 Who-Has

Answered from the table as §6.7 says, with an I-Have from `(virtual network, virtual MAC)` unicast to the asker; never forwarded.

### 8.5 SubscribeCOV and notifications (`limited` and above)

**One upstream subscription per site object.** The first consumer to subscribe to an object makes the shifter call `client.SubscribeCOV` on the real device and object with the shifter's own process ID, lifetime `site.cov_lifetime` (default 5 min; the library renews it at half), confirmed when that consumer asked for confirmed. Later consumers of the same object share it. If one of them asks for confirmed while the upstream subscription is unconfirmed, the shifter cancels its subscription and subscribes again confirmed, since the library refuses a second subscription to the same object under the same process ID (`ErrSubscribed`). The fan-out table is keyed by real device and object and holds, per consumer: its address, its process ID, whether it asked for confirmed, and when its subscription expires.

**Each consumer's subscription has its own lifetime**, kept on the consumer side. A lifetime of 0 or absent, which the standard reads as indefinite, is taken as `consumer.cov_max_lifetime` (default 24 h), and a longer one is clamped to it, so a consumer that vanishes does not hold an upstream subscription forever. A consumer renews by subscribing again with the same process ID. The SimpleACK to the consumer's SubscribeCOV is sent when the upstream subscription exists; an upstream Error, Reject, Abort or timeout is passed back as in §8.3 and the consumer's entry is not made.

**Notifications.** A `client.COVNotification` is re-issued to every consumer in the fan-out entry: the initiating device identifier is the virtual one, the process ID is that consumer's, the time-remaining is that consumer's remaining lifetime, the values are translated and re-encoded, the source is `(virtual network, virtual MAC)`. A consumer that asked for confirmed gets a ConfirmedCOVNotification through the server's confirmed-request sender with its SimpleACK awaited, resent up to `site.retries` times on silence; one that did not gets the unconfirmed form.

**CancelCOV** removes the consumer's entry and answers SimpleACK; so does expiry, silently. The last consumer out makes the shifter `CancelCOV` upstream. Shutdown cancels every upstream subscription before the site client closes (the library's `Close` does not).

### 8.6 WriteProperty (`full-service`)

The request is decoded from its tags directly (`services.ConfirmedWriteProperty.Decode` keeps only three value types): object identifier [0], property [1], optional index [2], the value tags inside [3], optional priority [4]. Dispatch applies, in order: the level; the array-index rule (§7.3); the reserved objects, properties and replaced properties (§7.4); the priority rule (§7.3). What passes is translated (the object identifier, and device identifiers inside the value; a value naming a device or an address the shifter never issued is refused, §7.5) and sent through `client.WriteProperty` (L1), with a single Null as the value to relinquish. The site's SimpleACK, Error, Reject, Abort or silence comes back as in §8.3. A write is never resent: the consumer's retry, if the site was silent, is a new request.

### 8.7 The other confirmed services

Refused as §7.6 says, at every level: no level forwards them (§7.5).

### 8.8 Everything else

Refused as §7.6 says.

### 8.9 Replies and acknowledgements arriving from a consumer

A SimpleACK, Error, Reject or Abort that matches a confirmed notification the shifter sent ends that notification's wait. A Segment-ACK or Abort that matches a segmented reply in progress continues or stops it. Anything else of those PDU types is dropped: the shifter sends consumers no other confirmed requests.

## 9. The site side

### 9.1 Opening the client

`client.Open` with `Interface.Config(port)` for the configured adapter and port; `ForeignDevice` when `site.bbmd` is set, with `site.bbmd_ttl`; `Timeout`, `Retries`, `MaxRequestsPerSec` and `MaxInFlightNet` from configuration; `ReadOnly` at `no-write`; `OnIAm` for discovery; `OnPacket` for `log.frames` and for the tests; `Logger` the shifter's. The code in `internal/source/bacnet/source.go:150` of the library repo is the model. Under `sim`, `Local` is `127.0.0.1:0` and `Broadcast` is `sim.Addr()`, as the explorer does.

### 9.2 Discovery

At start: a global Who-Is, then `Knock` and `Probe` for each address in `site.add`, as the explorer's `-add` does. `OnIAm` runs for the life of the shifter. For each device heard, new or known:

1. If its instance is in the table, its address is updated if it changed. If not, a virtual instance, a virtual MAC and a device record are issued (§6.2, §6.3). If it is behind a site router on a network the table has not seen, a virtual network number and a network record are issued first, and the new network is announced (§8.2).
2. One ReadProperty of the device object's object-name fills the name record, so Who-Has by the device's name works and the table is complete for the device.
3. The device is announced: one routed I-Am from `(virtual network, virtual MAC)`, broadcast on the consumer subnet and unicast to every consumer the shifter has heard from within `consumer.recent` (default 10 min). The unicast reaches consumers behind a consumer-side router, and on loopback, which has no broadcast address, the consumers of the tests.

A device in the table from an earlier run is reachable from the start at its last known address, before it has been heard this run; the table is the source of truth for addresses, and discovery corrects it. A device that stops answering stays in the table and is still announced; forgetting is a non-goal.

**The daily survey** (`survey` in configuration, off by default) finds the devices no Who-Is reaches without their being listed in `site.add`: the bacnet-survey utility, as `internal/survey`, run through the site client itself. Once a day at `survey.at`, and at start when `survey.on_start` is set, it sends one Who-Is and then one `Knock` to every address of the site adapter's subnet, or of `survey.ranges`, at `survey.rate` addresses a second; the knocks go through the client's guard and rate limit like every other request. A device that answers the knock, or declines it as one older than the wildcard instance does, or whose I-Am is heard, is read for its name, vendor and model; one that said which device it is and has not been heard this run is then probed and goes through steps 1 to 3 above. The addresses with nobody are sorted by the operating system's neighbor table on the subnet and by a ping beyond it, as the utility does. Results are kept in memory and logged; no survey history is saved. A survey the shifter is closed during stops and logs what it found. The I-Ams the client hears while a survey runs reach the survey as well as discovery.

### 9.3 Objects and their names

Non-device objects need no table entry to be reached: their type and instance pass through. They get a name record the first time their object-name is read through the shifter, whether by ReadProperty, ReadPropertyMultiple or as a COV notification's property, and a text record the first time a replaced property is read. The shifter does not walk the site on its own to fill the table: that would be a footprint the consumer did not ask for. The cost is that Who-Has finds only what has been looked at (§6.7).

### 9.4 Fidelity of re-encoded replies

Reads return `[]client.Value`, not the reply's tags, so the shifter re-encodes: a `Value` keeps its kind, its context tag number, the raw bytes of a context-tagged value and of a date or time, and the items of a constructed value, and the `objects.Enc*` functions and a raw `objects.Object` for a date or time put them back. What re-encoding loses, and v1 accepts (decision 1): the character set a string was sent in (UCS-2 and ISO 8859-1 come back as UTF-8, the same text), and the tag number of a reserved or malformed application tag (it becomes an octet string). The fidelity test (§12, test 2) is the check; if it finds a loss that matters, L5 (a read that returns the reply's tags) is the remedy, and it is the one library change that may be pulled forward.

Errors come back typed (`BACnetError`, `RejectError`, `AbortError`), so the consumer gets the same class, code or reason without the shifter interpreting them.

## 10. Configuration

The shifter runs without arguments and loads every setting from `config.yaml` in the directory it is started from (decision 4). A key left out takes its default. When the file is absent, the program writes it with every key at its default and a comment each, says where, and exits, since the site adapter has no default. The copy in the repository is that output. The prompt's flags (`-interface`, `-bbmd`, `-bbmd-ttl`, `-add`, `-listen`, `-vnet`, `-control`, `-data`, `-log`, `-frames`, `-sim`) are the keys below; `-table` is the only switch (§6.4).

```yaml
# bacnet-shifter configuration. Every key is shown at its default; a key left
# out takes it. The file is read from the directory the shifter starts in.
# Durations are Go durations: 3s, 5m, 1h.

# The site: the real BACnet network, reached through the bacnet library's client.
site:
  adapter: ""             # name or IPv4 address of the adapter on the site network; required unless sim is set
  port: 47808             # UDP port on that adapter
  bbmd: ""                # IP[:port] of a BBMD to register with as a foreign device, to reach a site on another subnet
  bbmd_ttl: 5m            # registration lifetime, renewed halfway through
  add: []                 # IP[:port] of devices no Who-Is reaches, read at start as the explorer's -add does
  timeout: 3s             # wait for each reply from the site
  retries: 2              # resends of a read or a notification that got no reply; a write is never resent
  max_rps: 50             # requests the shifter sends the site in a second, all consumers together
  max_in_flight_net: 1    # requests in flight at once to all the devices of one routed site network
  whois_interval: 1s      # a consumer's Who-Is is forwarded to the site at most this often
  cov_lifetime: 5m        # lifetime of the shifter's own subscriptions on the site, renewed by the client

# The consumer side: the socket the shifter serves consumers on, as a router to the virtual network.
consumer:
  adapter: ""             # name or IPv4 address of the adapter on the consumer network; required unless sim is set
  port: 47808             # on Windows the two sides may share a port on two adapters; on Linux and macOS they cannot
  network: 9000           # V: the virtual network the site's own IP subnet appears as; each site network behind a router gets a derived number of its own
  recent: 10m             # a new device or network is also announced by unicast to every consumer heard from within this long
  cov_max_lifetime: 24h   # ceiling on a consumer subscription's lifetime; 0 or absent in the request means this

# What the shifter will send to the site: no-write | limited | full-service.
# Each level includes the ones before it.
control: no-write

# Directory for the key and table.json. It must be readable by the shifter's account only.
data: data

log:
  level: info             # debug | info | warn | error
  frames: false           # log every datagram on both sockets, at debug

# Run against the library's simulated devices on loopback instead of the adapters:
# "" (off), default (sim.Start) or remote (sim.RemoteSite: a BBMD, a router and routed devices).
sim: ""

# A daily survey of the site's addresses, the bacnet-survey utility run through the site client: one read
# to each address, to find and announce the devices no Who-Is reaches. Results are logged, with no
# survey history saved. To the network it looks like a port scan
# of UDP 47808, and each vacant address on the subnet costs an ARP broadcast: tell whoever watches it.
survey:
  enabled: false
  at: "02:00"             # local time of day, HH:MM
  on_start: false         # also run one when the shifter starts
  ranges: []              # addresses to survey instead of the whole subnet of site.adapter: 192.168.1.20-192.168.1.60, or one address; those beyond the subnet are pinged too; required under sim
  rate: 10                # addresses tried in a second; a /24 takes half a minute at 10, a /16 two hours

pseudonym:
  replaced:               # properties whose character-string values are replaced with pseudonyms, on every object
    - object-name
    - description
    - location
    - model-name
    - serial-number

# The life-safety and alarm set: refused at every level, full-service included.
reserved:
  services:
    - life-safety-operation
    - acknowledge-alarm
    - device-communication-control
    - reinitialize-device
    - add-list-element
    - remove-list-element
    - create-object
    - delete-object
    - atomic-read-file
    - atomic-write-file
  objects:
    - life-safety-point
    - life-safety-zone
    - notification-class
    - event-enrollment
    - alert-enrollment
  properties:
    - out-of-service
    - event-detection-enable
    - event-enable
    - limit-enable
    - time-delay
    - time-delay-normal
    - notification-class
    - notify-type
    - recipient-list
    - ack-required
```

Property, object type and service names are the standard's hyphenated names. Property and object type names are resolved through the library's name tables (`objects/names.go`) reversed; service names through a short table of the shifter's own, since the library has none. A name the tables do not know is a configuration error reported at start. A number is accepted in place of a name for a proprietary property or object type.

## 11. Operation

**Start.** The shifter loads the configuration, the key (generating it on first run) and the table, opens the site client and the consumer socket, broadcasts I-Am-Router-To-Network for V and every virtual network in the table, sends the first Who-Is, and serves.

**Logging** is `slog` to stderr at `log.level`. At Info: start-up with both addresses and the level, each device and each site network discovered (virtual and real side), each refusal (§7.6), each upstream subscription made and cancelled, each write forwarded. At Warn: a collision resolved, a duplicate real instance, the key file created, a site device whose address changed. At Error: a refusal by the library's guard. At Debug: dropped datagrams and, with `log.frames`, every datagram on both sockets in hex. Real names appear in the log only at Info and below, with their pseudonym beside them; the log is on the shifter's machine, as the table is.

**Shutdown** on SIGINT or SIGTERM: every upstream subscription is cancelled, the table is saved, both sockets close.

**`shifter -table [text]`** reads the key and the table and prints, without starting the proxy (§6.4).

**Setup**, in the README: the two adapters and their ports by operating system (§5.1); the data directory's permissions (§6.1); the key and table as the de-anonymization secret, to back up together and never copy to the consumer side; the manual check `go run ./cmd/explorer -interface <consumer-side address>` from the `bacnet` repository, which must show only pseudonyms and virtual addresses, every device under its virtual network, and the devices behind the site's routers under networks of their own.

## 12. Testing

**Harness** (`internal/harness`, tests only): `sim.Start()` or `sim.StartDevices(sim.RemoteSite(false))` as the site; the shifter with both sockets on loopback, the site client's `Broadcast` set to the sim's address; a `client.Client` as the consumer, its `Broadcast` the shifter's consumer address; `OnPacket` recorders on the site client, on the server's socket and on the consumer client; and a raw sender that builds frames with `plumbing` and waits for the reply on its own socket, for the services the consumer client's guard will not send (tests 3, 8 and 9). The raw sender is a test helper in the shifter, not a library change.

| # | Test | Asserts | Step |
|---|---|---|---|
| 1 | **Leak** | Every datagram on the consumer socket, for the whole run of tests 2, 4 and 7, contains none of: each sim device's name, model and description and each object's name and description as UTF-8; each real device object identifier as its four encoded bytes; the network number and MAC of each routed sim device as encoded in an NPDU; the six-byte BACnet/IP address of each sim station. | M1 |
| 2 | **Fidelity** | Through the shifter the consumer finds every sim device on its virtual network; reads its object-list, which equals the direct read with the device entry translated; reads every property of every object, equal to a direct `client` read after translation, present-values the sim drifts within the sim's swing; the sim's errors (unknown object, unknown property, the NoRPM device's reject of ReadPropertyMultiple, the NoWildcard device's error on the wildcard instance) come through with the same class, code or reason. Trend logs read with ReadRange equal the direct read. | M1 |
| 3 | **Guard, per level, all three** | With the site recorder, the set of (PDU type, service) sent to the site is exactly the level's list of §7.1, while the raw sender sends every confirmed service code 0 to 255 and every unconfirmed service code, and gets the answer §7.6 documents for each, and the consumer client's reads still succeed. It mirrors `client/guard_test.go`. Each level's run is added in the milestone that adds the level. | M1 to M3 |
| 4 | **COV under `limited`** | The consumer subscribes to a sim object; `sim.NotifyCOV` produces a notification at the consumer carrying only virtual identifiers and the consumer's process ID; two consumers subscribed to one object share one upstream subscription (`sim.COVSubscriptions` has one entry) and both get the notification; a confirmed subscription gets a confirmed notification and the shifter sees its SimpleACK; cancelling the last consumer empties `sim.COVSubscriptions`; closing the shifter empties it too. | M2 |
| 5 | **Stability** | Restarting with the same data directory leaves every pseudonym and virtual address unchanged, in a different discovery order; a different key changes them all. At unit level: the derivation is a pure function of key and input. | M1 |
| 6 | **Collisions** | At unit level, with the derivation's width narrowed to force them: two objects whose names collide get distinct pseudonyms and the table records both with their candidate index; the same for two device instances, two MACs and two network numbers; a device seen second on a restart keeps its first-run pseudonym. | M1 |
| 7 | **Routed and BBMD-reached site devices** | With `sim.RemoteSite`, the site client registered with the sim BBMD as a foreign device: the BBMD's device and the air handler, reached across the BBMD, appear on V like local ones; the plant router appears on V; the terminal units behind it appear on one virtual network of their own, which the consumer finds through Who-Is-Router-To-Network, and the real network number 2001 appears in no NPDU on the consumer socket; reads to all of them succeed. | M1 |
| 8 | **Priority and the reserved set under `full-service`** | With the site recorder decoding every WriteProperty sent: a write with no priority reaches sim at 13; one at 16 reaches sim at 16; one at 8 is refused with write-access-denied and nothing reaches sim; a write to out-of-service, a write to a Notification Class object and a LifeSafetyOperation are refused and nothing reaches sim; a write to object-name is refused. The consumer gets sim's SimpleACK for the forwarded ones (needs L2). | M3 |
| 9 | **God** | Cancelled with the level (§7.5). | — |

**Unit tests**, beside the nine: `pseudonym` (derivation vectors, the key file), `table` (load, save, lookups, the listing), `server` (a `client.Client` on loopback against a canned handler: reads, a reply long enough to segment, a confirmed notification acknowledged, a routed consumer source answered through its router, duplicate suppression), `translate` (a round trip of every `Value` kind including nested constructed values, dates and times; device identifiers rewritten at every depth; the replaced properties), `control` (the refusal table for every service and level; the priority rule; the reserved set; the write path against a fake `siteWriter`).

**The manual check** is on a real adapter pair: the explorer from the `bacnet` repository pointed at the consumer-side adapter shows every site device under its virtual network with pseudonyms only, the devices behind the site's routers under networks of their own, and reads values through them.

**Gates.** Every milestone ends with `go vet ./...` and `go test ./...` clean in the shifter, the same in `../bacnet` when a library change landed in that milestone, a README section for what the milestone added, and in `../bacnet` no uncommitted change that this work made.

## 13. Library changes

Each is confirmed before it is written, lands as its own commit in `../bacnet`, and waits for a clean working tree there (the tree had uncommitted explorer-sources work on 2026-10-14). Everything else in this spec is built in the shifter against the exported library.

| | Change | Where | Test it carries | Earliest step |
|---|---|---|---|---|
| L1 | `(*Client).WriteProperty(ctx, to Address, obj ObjectID, prop uint16, value []*objects.Object, priority uint8) error`: `value` is the tags of the property value, a single Null relinquishes, `priority` 0 sends none. It is sent once, never retransmitted; `ErrTimeout` means sent and unanswered, and an error wrapping a new `ErrNotSent` means it never left (guard, deny list, context, rate limiter). A per-device writable switch, `Config.Writable []SourceRule` and `SetWritable(rule, bool)`, consulted by the guard for the destination of each send; every device starts read-only; `ReadOnly` overrides it. | `client/` | The §7.7 test of the library spec: every other service is still refused; one writable device changes nothing for any other; without a writable rule, WriteProperty fails with `ErrServiceNotAllowed` | M3, after the shifter's write path is built against a fake |
| L2 | `sim` takes WriteProperty on its commandable objects (AO, AV, BO, BV, MSV) with a sixteen-slot priority array and a relinquish-default, answers SimpleACK, and exposes what it received, so that test 8 can see what reached the site. | `client/sim/` | `sim`'s own tests, plus what test 8 reads back | M3, with L1 |
| L3 | Cancelled with `god` (§7.5): a confirmed request of any service, encoded by the caller, behind a flag off by default. Never written; the library stays as read-only as L1 left it. | — | — | — |
| L4 | `internal/server` moves into the library as `client/server`, beside `client/sim`, and `sim` is rebuilt on it. | `client/server/` new, `client/sim/` | `sim`'s tests unchanged and green | Last |
| L5 | A read that returns the reply's tags, only if test 2 shows re-encoding to be lossy in a way that matters. | `client/` | Test 2 | Last, or before M1's test 2 |

The signatures are proposals for the confirmation, not commitments: the user decides each when it comes up.

## 14. Delivery plan

The order is build-plan.md §4; this is the summary. Nothing in M1 or M2 touches the library.

| Milestone | Delivers | Library |
|---|---|---|
| **0** | This spec. Stop for review. | |
| **M1 `no-write`** | `pseudonym` and `table` with their unit tests; `server` copied from `sim`; `translate`; the site side; consumer dispatch for Who-Is, Who-Is-Router-To-Network, Who-Has, the three reads, and every refusal; the harness; tests 1, 2, 3 (`no-write`), 5, 6, 7; `cmd/shifter` with `config.yaml` generation and `-table`; the README's setup and the manual check. | none |
| **M2 `limited`** | The COV fan-out of §8.5; test 4; test 3 (`limited`). | none |
| **M3 `full-service`** | The write path of §8.6 against a fake, the priority rule, the reserved set, test 3 (`full-service`) and the refusal half of test 8; then L1 and L2, confirmed; then the real site writer and test 8 in full. | L1, L2 |
| **M4** | Cancelled with `god` (§7.5). | — |
| **Last** | L4, the lift of the server package into the library, once three milestones have stopped changing it; L5 if test 2 asked for it. | L4, (L5) |

## 15. Decisions carried from the build plan

Taken by the user on 2026-10-14 (build-plan.md §6) and carried here, where each lands:

1. Reply re-encoding: accept the losses, L5 a contingency. §9.4.
2. ReadPropertyMultiple with an array index: refused with Reject reason other. §8.3, §7.6.
3. The consumer socket: configured by adapter and port like the site side, bound like `client.Open`; shared port on Windows, distinct ports or namespaces elsewhere. §5.1.
4. Configuration in `config.yaml` in the working directory, nothing on the command line but `-table`; the file generated from defaults. §10, §6.4.
5. The key file on Windows: documented, since NTFS ignores the mode. §6.1.
6. Upstream in-flight limit per routed network: a key, default the library's 1. §5.6, §10.
7. Who-Is forwarding at most once a second, the interval a key. §8.2.
8. The server package's home for L4: `client/server`. §5.4, §13.
9. Module path `github.com/jonalfarlinga/bacnet-shifter` and the package split of §5.4.

Decided in this spec, for review: the derivation inputs and forms (§6.2), the namespaces and candidate scheme (§6.3), the table's record (§6.4), the text pseudonym rule and the empty-string rule (§6.2), the rewriting of device-address-binding and of addresses inside values (§6.5), the known and unknown service classes and the refusal table (§7.6), the I-Am's capabilities and the segmented-request refusal (§8.1), the envelope cases (§8.1), the COV lifetime ceiling and the confirmed resubscribe (§8.5), array-indexed writes and WritePropertyMultiple at `full-service` (§7.3), no walk of the site to fill the table (§9.3), and the proposed signatures of L1 and L3 (§13).

Decided after the review of 2026-10-14: one virtual network per site network (§5.2), in place of one network for everything, so that the nesting of the site survives; device-address-binding rewritten rather than emptied (§6.5); announcements by unicast to recent consumers as well as by broadcast (§9.2); the roadmap of §17.

## 16. Open questions

Resolved by the review of 2026-10-14:

1. **device-address-binding** is rewritten entry by entry, not emptied (§6.5). It is a device's cache of other devices' addresses, not the mechanism of nesting. Nesting lives in the network layer, and the one virtual network per site network of §5.2 carries it as far as the protocol lets an end station see.
2. **WritePropertyMultiple and array-indexed writes at `full-service`**: a follow-up, on the roadmap (§17).
3. **A BBMD on the consumer side**: on the roadmap.
4. **The COV lifetime ceiling** stays at 24 hours (§8.5).
5. **The explorer against a loopback shifter**: on the roadmap, as a library-side option.
6. **Announcing to recent consumers**: yes, by unicast as well as by broadcast (§9.2).
7. **L5** stays a contingency until test 2 runs (§9.4).

Nothing is open at this writing.

## 17. Roadmap (after v1)

Deferred by the review; not designed here, and the order is not fixed.

| Item | Notes |
|---|---|
| WritePropertyMultiple and array-indexed writes at `full-service` | Per-element enforcement of the priority rule and the reserved set, and either an array index on L1 or a WritePropertyMultiple method in the library. Neither is forwarded at any level in v1 (§7.3). |
| A BBMD on the consumer side | So that a consumer on another IP subnet can register with the shifter as a foreign device. In v1 a Register-Foreign-Device gets a NAK (§8.1). |
| A loopback adapter in `client.Interfaces` | A library option, so that the explorer can be pointed at a shifter running under `sim` and the manual check needs no network. |
| Site routers as routers on the consumer side | An end station nests networks by the address their routed I-Ams come from, and that is the shifter's for all of them (§5.2). The only way to show a site router as the parent of its networks is to give it an address of its own on the consumer side: an IP alias on the consumer adapter per site router, a socket bound to each, and the I-Ams and replies of that router's networks sent from it. The aliases are administered outside the shifter, and the server would hold one socket per router. Not needed to preserve the networks themselves, which v1 does. |
