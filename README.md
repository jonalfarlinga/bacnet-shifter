# bacnet-shifter

A BACnet anonymizing proxy. It sits between a site's BACnet/IP network and
a consumer's, passes traffic between them, and replaces every piece of
site-identifying information with a pseudonym on the way out: object names,
descriptions, locations, model names and serial numbers, device instances,
addresses and network numbers. The consumer, which may be YABE, the
`bacnet` repository's explorer or a BMS, speaks ordinary BACnet/IP to the
shifter and reads `AI-7c3e91ab0d42`, never `AHU1.OAT`.

This file says what the shifter does and how it is set up.
[docs/threat-model.md](docs/threat-model.md) says what it protects,
from whom, and which of those claims hold today;
[docs/security-plan.md](docs/security-plan.md) says what is built, in what
order, to make it a security boundary. Milestones M1 to M3 are built: the `no-write` level, in which the
shifter forwards Who-Is, ReadProperty, ReadPropertyMultiple and ReadRange
and nothing else; the `limited` level, which adds change-of-value
subscriptions; and the `full-service` level, which adds WriteProperty under
the rules in the permissions table below.

The shifter is built on the released `bacnet` library, v0.5.0 or later,
which `go.mod` requires like any other module. To develop against a
checkout of the library at `../bacnet` instead, add a workspace file,
which git ignores:

```bash
go work init . ../bacnet
```

## How it works

The shifter owns two UDP sockets. The **site socket** is the library's
`client`, opened read-only under `no-write`: it discovers the site's devices
with a Who-Is and reads from them. The **consumer socket** is a BACnet
server that presents the shifter as a router to a virtual network (9000 by
default). Every site device appears to the consumer as a routed device at a
virtual address `(network, MAC)` behind the shifter, with a virtual device
instance; devices behind a site router appear on a virtual network of their
own, so the site's nesting survives. The shifter has no device object of its
own on either side and never announces itself with an I-Am.

Pseudonyms are HMAC-SHA256 under a per-site key, so they are the same on
every run and the consumer can store and chart them. The key and
`table.json`, the record of every pseudonym issued and its real value, live
in the data directory and are, together, the de-anonymization secret.

## Setup

Build or run with Go 1.25 or later, from this directory:

```bash
go run ./cmd/shifter
```

The shifter takes no arguments and reads `config.yaml` from the directory
it is started in. When the file is absent it writes one with every key at
its default and a comment each, says where, and exits.
`config.yaml.example` in this repository is that output; `config.yaml`
itself is ignored by git, so the adapters you set stay out of the history.
Set at least:

- `site.adapter`: the name or IPv4 address of the adapter on the site
  network, as `ipconfig` or `ip addr` lists it.
- `consumer.adapter`: the adapter consumers reach the shifter on, or
  `127.0.0.1` for a consumer on the same machine.
- `control`: leave at `no-write` unless you know why not; the permissions
  table below says what each level accepts.

**The two sockets.** The site and consumer sides cannot share an IP address
and port. On Windows a socket bound to an adapter's own address hears the
broadcasts on that adapter, so the two sides can both use port 47808 on two
adapters, and that is the setup to use. On Linux and macOS a socket that
hears broadcasts binds every address, so the two sides cannot share a port:
give `consumer.port` another number, or run each side in its own VM or
network namespace. A consumer on the shifter's own machine can be served on
`127.0.0.1` instead of an adapter.

**The data directory** (`data` by default) holds the key file and
`table.json`. The key is written with mode 0600, which NTFS ignores: on
Windows make the directory one that only the shifter's account can read.
Back up the key and the table together, and never copy either to the
consumer side; losing the key means every consumer's stored names stop
matching.

To reach a site on another IP subnet, set `site.bbmd` to its BBMD and the
shifter registers there as a foreign device; `site.add` lists devices that
no Who-Is reaches, which are read at start. To find such devices without
listing them, enable the daily survey (below).

## Running

```bash
go run ./cmd/shifter
```

Log lines go to stderr at `log.level`; at `info` each device and site
network is logged as it is discovered, real and virtual side by side, and
every refused request with the consumer's address, the service and the
level. `log.frames: true` logs every datagram on both sockets at `debug`.

```bash
go run ./cmd/shifter -table
```

prints every record of the table, pseudonym and real side by side, and
exits; `-table <text>` keeps the records whose pseudonym or real side
contains the text. It is the only command-line switch.

To try the shifter without a network, set `sim: default` (the library's
simulated devices: an air handler, a plant router with terminal units
behind it, a meter gateway, a legacy panel) or `sim: remote` (a BBMD with
devices behind it). Both sockets are then on loopback, the consumer side at
`127.0.0.1:<consumer.port>`.

### The daily survey

A Who-Is finds only the devices that hear the broadcast and answer it. A
device on a subnet whose broadcasts are filtered, behind a BBMD the shifter
is not registered with, or too old to announce itself is never heard, and
the library client has no way to find a device by IP address on its own.
The `survey` block turns on a daily sweep that does: the
[bacnet-survey](https://github.com/jonalfarlinga/bacnet-survey) utility,
run inside the shifter through its own site client.

```yaml
survey:
  enabled: true
  at: "02:00"             # local time of day
  on_start: false         # also run one when the shifter starts
  ranges: []              # the whole subnet of site.adapter when empty
  rate: 10                # addresses a second
```

Each survey sends one Who-Is and then one ReadProperty of the Device
object's identifier, through the wildcard instance, to every address of the
site adapter's subnet (or of `ranges`: `192.168.1.20-192.168.1.60`, one
address, or several), at `rate` addresses a second. A device that answers,
or that declines as one older than the wildcard instance does, or whose
I-Am is heard, is a BACnet device; it is read for its name, vendor and
model, and one that no Who-Is reached this run is probed and discovered
like an address in `site.add`: it gets its pseudonyms, its table record and
its announcement to the consumers, and from then on it is proxied like any
other. The survey is read-only on the site and goes through the site
client's guard and rate limit like everything else the shifter sends, so
`site.max_rps` bounds it together with the consumers' reads.

The other addresses are sorted as the utility sorts them. On the adapter's
own subnet the operating system's neighbor table (`arp -a`, or
`/proc/net/arp`) says which have a host that is not a BACnet device and
which are vacant. Beyond the subnet, where `ranges` reach through a
router, each address is pinged as well (the ICMP API on Windows, which needs
no administrator; the `ping` command elsewhere): a reply is a host, a
router's host-unreachable is a vacant address, and an address that answers
nothing at all is only silent. Results are kept in memory; no survey history
is saved. The log gets the start of each survey with how
long it should take, the summary and each device found at `info`, and
progress every two seconds at `debug`.

A /24 takes half a minute at the default rate and a /16 two hours; a survey
that is still running when the shifter stops logs what it found. Under
`sim` the survey needs `ranges`, since the simulated devices are on
loopback: `127.0.0.1` on the first station's port is where they answer. To
the network a survey looks like a port scan of UDP 47808, and every vacant
address on the subnet costs an ARP broadcast: tell whoever watches the
network before enabling it, and keep `ranges` to where devices can be.

### The manual check

From the `bacnet` repository, point the explorer at the consumer-side
adapter:

```bash
go run ./cmd/explorer -interface <consumer-side address>
```

It shows the shifter as a router, every site device under its virtual
network with a pseudonym for a name, the devices behind the site's routers
under networks of their own, and reads values through them. No real name,
instance or address appears. The explorer needs port 47808 on an adapter of
its own, so it runs on another machine on the consumer network, or on a
second adapter of the shifter's machine.

## Permissions: what each `control` level accepts

The `control` key bounds what the shifter sends to the site. Each level
includes the ones before it. In the table, **forwarded** means the request
goes to the site and the consumer gets the site's own answer, translated;
**answered** means the shifter answers from its table and nothing goes to
the site; **refused** means the consumer gets Error, class services, code
service-request-denied, and nothing goes to the site, unless the cell
names another answer; **—** means the request is dropped without a reply.

| The consumer sends | `no-write` | `limited` | `full-service` |
|---|---|---|---|
| **Discovery** | | | |
| Who-Is, in any form | answered, and one Who-Is forwarded at most once a second | same | same |
| Who-Is-Router-To-Network | answered | answered | answered |
| Who-Has, by name or by identifier | answered | answered | answered |
| I-Am, any other unconfirmed service, any other network message | — | — | — |
| **Reads** | | | |
| ReadProperty, ReadPropertyMultiple, ReadRange | forwarded | forwarded | forwarded |
| ReadPropertyMultiple with an array index on a property | Reject, other | Reject, other | Reject, other |
| ReadRange by time | Reject, other | Reject, other | Reject, other |
| **Subscriptions** | | | |
| SubscribeCOV, to subscribe or to cancel | refused | forwarded | forwarded |
| SubscribeCOVProperty | refused | refused | refused |
| **Writes** | | | |
| WriteProperty with no priority, or priority 13 to 16, to an ordinary property of an ordinary object | refused | refused | forwarded, at 13 when none was given |
| WriteProperty at priority 1 to 12, a relinquish included | refused | refused | Error, write-access-denied |
| WriteProperty to a reserved object or property (`reserved` in the configuration), or to a replaced property (object-name, description, location, model-name, serial-number) | refused | refused | Error, write-access-denied |
| WriteProperty whose value names a device or an address the shifter never issued | refused | refused | Error, other |
| WriteProperty with an array index | refused | refused | Reject, other |
| WritePropertyMultiple | refused | refused | refused |
| **The life-safety and alarm services** (`reserved.services`): LifeSafetyOperation, AcknowledgeAlarm, DeviceCommunicationControl, ReinitializeDevice, AddListElement, RemoveListElement, CreateObject, DeleteObject, AtomicReadFile, AtomicWriteFile | refused | refused | refused |
| **Other confirmed services** | | | |
| GetAlarmSummary, GetEnrollmentSummary, GetEventInformation, ConfirmedTextMessage | refused | refused | refused |
| ConfirmedCOVNotification, ConfirmedEventNotification, ConfirmedPrivateTransfer | refused | refused | refused |
| A confirmed service the shifter cannot name (13, 21 to 25, 30 and up) | Reject, unrecognized-service | same | same |
| **At every level** | | | |
| A request naming a device instance the shifter never issued | Error, unknown-object, without asking the site | same | same |
| A segmented request | Abort, segmentation-not-supported | same | same |
| A request for a network the shifter does not route to | Reject-Message-To-Network | same | same |
| A request to the shifter's own address with no destination network, or to an address nobody is at | — | — | — |
| Register-Foreign-Device | BVLC-Result NAK: the shifter is not a BBMD | same | same |

What the site receives, as a result, is at `no-write` exactly the
library's read-only list (Who-Is, the three reads, the Segment-ACKs and
Aborts a segmented reply needs, Who-Is-Router-To-Network and the BBMD
registration); at `limited` also SubscribeCOV and the SimpleACK of a
confirmed notification; at `full-service` also WriteProperty. The level is
enforced twice: by the shifter's dispatch, which refuses with the answers in
the table, and by the library client's own guard, opened with `ReadOnly` at
`no-write`, so that a bug in the dispatch still cannot write to a site whose
shifter is set to `no-write`. Every refusal is logged at `info` with the
consumer's address, the service and the level.

`full-service` is the highest level. No level forwards the life-safety and
alarm set, a write at priority 1 to 12, or the other confirmed services: a
consumer that needs to acknowledge alarms, reinitialize devices or override
at priority 1 is operating the site, not reading it through a shifter. The
writes of `full-service` go through the library client's `WriteProperty`,
which sends only to a device the client has been told is writable: the
shifter switches each site device writable as it discovers it, at
`full-service` only, so that below it the client's own guard refuses every
write whatever the dispatch did.

## What `limited` adds

With `control: limited` the site client is opened without `ReadOnly`, and
the shifter takes SubscribeCOV from consumers. Its guard still refuses
every write.

- **One subscription per site object.** The first consumer to subscribe to
  an object makes the shifter subscribe to it on the site, under its own
  process ID, for `site.cov_lifetime`, renewed by the client at half of
  that. Every later consumer of the same object shares it. The site sees
  one subscriber however many consumers there are.
- **Confirmed when anyone asks.** The upstream subscription is unconfirmed
  until a consumer asks for confirmed notifications; the shifter then
  subscribes again confirmed, under its second process ID, and cancels the
  unconfirmed one. A consumer that asked for confirmed gets confirmed
  notifications, which the shifter resends until acknowledged; the others
  get unconfirmed ones.
- **Each consumer's own process ID and lifetime.** A notification is
  re-issued to each consumer with the virtual device identifier, that
  consumer's process ID and its own time remaining. A lifetime of 0, which
  the standard reads as indefinite, is taken as `consumer.cov_max_lifetime`
  (24 hours), and a longer one is clamped to it; a consumer renews by
  subscribing again. A consumer that joins an existing subscription is sent
  the latest notification, as a device tells a new subscriber the value as
  it is.
- **The last one out cancels upstream.** CancelCOV, or a lifetime running
  out, removes the consumer; when none is left the shifter cancels its own
  subscription on the site. Closing the shifter cancels them all.
- **An object that takes no subscription** answers as the site did: the
  consumer gets the same Error, Reject or Abort.

Test 4 of the spec covers this against the simulated site: the shared
upstream subscription, the confirmed upgrade and its acknowledgements, the
last cancellation and the shifter's close emptying the sim's subscriptions.

## What `full-service` adds

With `control: full-service` the shifter takes WriteProperty from
consumers and applies these rules, in this order, before anything is sent:

- **The array-index rule.** A write with an array index is refused with
  Reject, reason other: the library's write method takes none.
- **The reserved set.** A write to an object of a reserved type, to a
  reserved property on any object, or to a replaced property, whose
  pseudonyms must stay the shifter's, is refused with Error, class
  property, code write-access-denied. A reserved service is refused with
  service-request-denied, as the level refuses it anyway. The `reserved`
  keys are data, so a site can add to them.
- **The priority rule.** A write that names no priority goes out at 13; one
  at 13 to 16 keeps its priority; one at 1 to 12 is refused with
  write-access-denied, so that the consumer learns it rather than being
  silently demoted. A relinquish, a Null value, follows the same rule. A
  priority that is not 1 to 16 is refused with Reject,
  parameter-out-of-range.
- **Translation.** The object identifier is mapped to the real one, a
  device object by its virtual instance, and so are the device identifiers
  inside the value at any depth, by the rules reads use in the other
  direction. A value that names a virtual device the shifter never issued,
  or an address nobody is at, is refused with Error, class services, code
  other: nothing is forwarded broken.

What passes is sent once, never resent, and the consumer gets the site's
SimpleACK, Error, Reject or Abort, or silence when the site was silent; a
consumer's retry after silence is a new write. Every forwarded write is
logged at `info` with the consumer's address, the device, the object, the
property and the priority; one the library would not send, because the
device was never switched writable or is denied, is logged at `warn` and
answered service-request-denied.

Test 8 of the spec runs twice. Against a fake in the place of the library
client, each forwarded write reaches it at the right priority with the
right value, each refused one never does, the consumer gets the documented
answer, and the site's answers are injected one by one. Against the
simulated site through the real client, a write with no priority arrives
at 13 and one at 16 at 16, the consumer reads the value back, the refused
ones never arrive, a device behind the site's router takes a write too,
the site's own refusal comes back as it is, and a silent site gets exactly
one datagram.

## Implementation notes

Four points where the code is more specific than the spec:

- **Context-tagged device identifiers** in values are rewritten only when
  the instance is a device the table knows, or when the tag sits in the
  `[3]` slot of a device-object-property reference after an object `[0]`
  and a property `[1]`. The spec's blanket rule for any four-byte context
  tag of type device would also rewrite a context-tagged Time at two in the
  morning, which encodes as `02 mm ss hh` and reads as a device identifier.
  Application-tagged device identifiers are rewritten wherever they are.
- **The pending map** that drops a consumer's retransmission while the
  upstream request is in flight is keyed by the consumer, the virtual
  device addressed and the invoke ID, not by the consumer and invoke ID
  alone: a consumer reuses invoke IDs across the devices it talks to.
- **A virtual device instance the shifter never issued** in a read is
  answered locally with unknown-object rather than passed to the site,
  so that a consumer cannot use a site device as an oracle for real
  instances.
- **The site writer is an interface** of one method, `SiteWriter`, which
  the library client fills and the tests replace with a fake to inject the
  site's answers; the write path was built against the fake before the
  library could send a write. A write whose value names a virtual device
  the shifter never issued is refused rather than forwarded with the
  consumer's instance in it. A priority outside 1 to 16 is refused with
  Reject parameter-out-of-range before anything is sent.

The `internal/server` package is the station, dispatch and segmentation
code of the library's `client/sim`, reshaped into the shifter's own server.
It stays here: the library handles the plumbing, and its only server code
is the `sim` fixture and the examples. A fix to the segmentation and send
core the two copies share is checked against the other.

## Tests

```bash
go test ./...
```

runs the unit tests of every package and, in `internal/shifter`, the
end-to-end tests of the spec on loopback: the leak test, fidelity against a
direct read of the simulated site, the guard test at each level, stability
across restarts, collisions, a site reached through a BBMD with routed
devices behind a router, and the survey finding a simulated device that the
shifter's Who-Is cannot reach. The `internal/survey` tests are the
utility's, run against the simulated devices with the neighbor table and
the pings faked; one pings loopback for real, and `-short` skips it.

```bash
SHIFTER_SMOKE_ADAPTER="Ethernet 3" go test ./internal/shifter -run TestSmokeBench -v
```

runs the shifter against a real site on the adapter named, with the
consumer side on loopback: it reads the site directly first, then through
the shifter at `limited`, and checks every device comes through under a
pseudonym, that object lists and errors match, that a subscription to the
first object with a present value works when the device takes one, and
that nothing real crosses the consumer socket. It needs port 47808 free on
that adapter.
