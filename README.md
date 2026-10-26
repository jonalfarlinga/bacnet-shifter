# bacnet-shifter

A BACnet anonymizing proxy. It sits between a site's BACnet/IP network and
a consumer's, passes traffic between them, and replaces every piece of
site-identifying information with a pseudonym on the way out: every
character string, object names and descriptions first among them, device
instances, addresses and network numbers; and it hides the objects that
carry addresses. The consumer, which may be YABE, the `bacnet` repository's
explorer or a BMS, speaks ordinary BACnet/IP to the shifter and reads
`AI-7c3e91ab0d42`, never `AHU1.OAT`.

This file says what the shifter does and how it is set up.
[docs/threat-model.md](docs/threat-model.md) says what it protects,
from whom, and which of those claims hold today;
[docs/security-plan.md](docs/security-plan.md) says what is built, in what
order, to make it a security boundary. Milestones M1 to M3 are built: the `no-write` level, in which the
shifter forwards Who-Is, ReadProperty, ReadPropertyMultiple and ReadRange
and nothing else; the `limited` level, which adds change-of-value
subscriptions; and the `full-service` level, which adds WriteProperty under
the rules in the permissions table below.

The shifter is built on the released `bacnet` library, v0.6.0 or later. To develop against a
checkout of the library at `../bacnet` instead, add a workspace file,
which git ignores:

```bash
go work init . ../bacnet
```

Until the version go.mod requires is tagged on the remote, the workspace also needs the module
replaced at that version, or the go command looks for its go.mod on the module proxy:

```bash
go work edit -replace=github.com/jonalfarlinga/bacnet@v0.6.0=../bacnet
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

Who is served is decided below the protocol, since BACnet/IP cannot
authenticate a sender: the consumer socket is bound to one adapter, which
is meant to be an authenticated tunnel's, and `consumer.allow` lists the
source prefixes it answers. Each consumer is served at its own level,
from `consumer.peers`, never above the global `control`. The setup section
says how.

Pseudonyms are HMAC-SHA256 under a per-site key, so they are the same on
every run and the consumer can store and chart them. The key and
`table.json`, the record of every pseudonym issued and its real value, live
in the data directory and are, together, the de-anonymization secret.

## What crosses to the consumer

The rule is to deny what has not been allowed: a value crosses unchanged
only when it is enumerated as one that may.

- **Every character string is replaced.** Every character string in every
  reply and every notification, at any depth of the value, is replaced with
  a pseudonym through the table: an object's name with the type's
  abbreviation and twelve hex characters (`AI-7c3e91ab0d42`), any other
  string with a prefix for its property (`desc-`, `loc-`, `sn-`, `model-`,
  or `p<id>-` for a property with no abbreviation) and the same twelve
  characters. State texts, active and inactive texts, event message texts,
  profile names, tags, the present value of a CharacterString Value object
  and the text in a log record are replaced like a description. An empty
  string stays empty. The exception is `pseudonym.pass_through`, a list of
  properties whose strings cross as they are; its documented default is
  empty, and the version strings below are the only ones the code passes
  on its own.
- **The version strings pass, unless the profile is strict.** Vendor-name,
  firmware-revision and application-software-version name the product, not
  the site, and cross as they are, as the vendor identifier does in every
  I-Am and in the device object; so do protocol-version and
  protocol-revision, which are numbers. With `pseudonym.strict: true` the
  three strings are replaced like any other, and the vendor identifier is 0
  in every I-Am and in every read of the property. The strict profile hides
  what the equipment is; it cannot hide the shape of its object list.
- **Address-bearing objects are hidden.** An object whose type is on
  `pseudonym.hidden_objects` (default: `network-port`, whose properties are
  the device's IP address, subnet mask, gateway, MAC address, BBMD table and
  network number) does not exist on the consumer side: a read,
  subscription or write naming one is answered Error, class object, code
  unknown-object, without asking the site; it is left out of the device's
  object-list, whether read whole or element by element, and out of the
  structured-object-list, a Structured View's subordinate-list and a
  Group's list-of-group-members; a Who-Has for it finds nothing.

What knowingly crosses, and is not claimed as hidden: the equipment's
fingerprint outside the strict profile (vendor, versions, and in every
profile the services, object types and object list a device has); the
site's structure (non-device object instances, which sites often number by
floor or zone, the count and types of objects per device, the nesting of
networks); timing and traffic patterns, including the difference between a
locally answered and a forwarded request; and linkability, since every
consumer sees the same stable pseudonyms, so one consumer's stored data
joins another's and a leaked table de-anonymizes all of them at once.
[docs/threat-model.md](docs/threat-model.md) §10 keeps the list.

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

### The consumer side: who is served, and at what level

A BACnet/IP datagram carries no proof of who sent it: the source address
is whatever the sender wrote. The shifter therefore does not try to
authenticate consumers in BACnet. It takes its identities from below the
protocol, and makes two things of them.

**`consumer.allow`** is a list of IP prefixes (`10.8.0.0/24`,
`10.8.0.7/32`). A datagram from any other source is dropped before it is
parsed, counted, and logged at `debug` once per source per minute, so that
a flood from outside does not become a flood in the log. The default is
empty, which means *any source*, and the shifter says so with a line at
`warn` when it starts: the first run works, and the warning stays until
the list is set. A deployment sets it.

**`consumer.peers`** gives consumers a level each: a list of entries with
a `prefix` and a `control`. A consumer whose source matches an entry is
served at that entry's level; one that matches none is served at the
global `control`. No entry may name a level above `control`, which stays
the ceiling: the shifter refuses to start on one that does, and the site
client is opened for the global level, so the library guard under every
consumer is the global one. The first matching entry wins, so list the
narrower prefixes first.

```yaml
control: limited
consumer:
  adapter: wg0
  allow: [10.8.0.0/24]
  peers:
    - {prefix: 10.8.0.7/32, control: no-write}   # the dashboard reads only
    - {prefix: 10.8.0.0/24, control: limited}    # everyone else on the tunnel
```

**The tunnel.** An IP prefix identifies a consumer only on a network where
addresses cannot be forged, and the consumer LAN is not one. Run an
authenticated tunnel between each consumer and the shifter host, WireGuard
or IPsec as you prefer, give the shifter the tunnel adapter as
`consumer.adapter`, and write `consumer.allow` and `consumer.peers` in the
tunnel's inner addresses. The shifter needs nothing else: the socket is
bound to the tunnel adapter and hears nothing else, each inner address
belongs to the peer that holds its key, and the tunnel encrypts what
crosses the LAN, so a passive observer there learns nothing either.

With WireGuard, on the shifter host: install WireGuard, make a tunnel
`wg0` with an inner address such as `10.8.0.1/24`, add one `[Peer]` per
consumer with its public key and `AllowedIPs = 10.8.0.7/32` (that peer's
inner address, and only that), and activate it. On each consumer: a tunnel
with that inner address, the shifter host as its one peer, its endpoint
the host's LAN address and port, and `AllowedIPs = 10.8.0.1/32`. The
consumer's BACnet client then talks to `10.8.0.1:47808`. On Windows the
WireGuard adapter is named after the tunnel (`wg0`) and `consumer.adapter:
wg0` binds it alone. On Linux and macOS a socket that hears broadcasts
binds every address, so the consumer socket also answers on the LAN
adapter: confine `consumer.port` to the tunnel interface in the host
firewall (`iptables -A INPUT -p udp --dport 47808 ! -i wg0 -j DROP`, or
the nftables or pf equivalent), and keep `consumer.allow` set to the
tunnel's prefix as the second line.

Without a tunnel, on a plain LAN, `consumer.allow` is a filter against
mistakes, not an identity: anyone on the LAN can send as an allowed
address. Run that way only on a consumer network you trust as much as the
site, and never with `consumer.peers` raising anyone's level.

**The checklist** for the consumer side, before the shifter is described to
anyone as a boundary: the consumer socket is on the tunnel adapter;
`consumer.allow` is set to the tunnel's prefix; on Linux and macOS the host
firewall confines the port to the tunnel interface; `consumer.peers` names
every consumer that gets more than the default level, narrowest prefix
first; and the start-up log shows no warning about an empty allow list.

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
includes the ones before it. The level a request is judged at is its
consumer's own: the `consumer.peers` entry its source matches, or the
global `control` when it matches none; no entry is above `control`. In
the table, **forwarded** means the request
goes to the site and the consumer gets the site's own answer, translated;
**answered** means the shifter answers from its table and nothing goes to
the site; **refused** means the consumer gets Error, class services, code
service-request-denied, and nothing goes to the site, unless the cell
names another answer; **—** means the request is dropped without a reply.

| The consumer sends | `no-write` | `limited` | `full-service` |
|---|---|---|---|
| **Discovery** | | | |
| Who-Is, in any form | answered with one burst of I-Ams per source per `site.whois_interval`, and one Who-Is forwarded at most once per interval | same | same |
| Who-Is-Router-To-Network | answered | answered | answered |
| Who-Has, by name or by identifier | answered | answered | answered |
| I-Am, any other unconfirmed service, any other network message | — | — | — |
| **Reads** | | | |
| ReadProperty, ReadPropertyMultiple, ReadRange | forwarded | forwarded | forwarded |
| ReadPropertyMultiple with an array index on a property | Reject, other | Reject, other | Reject, other |
| ReadRange by time | Reject, other | Reject, other | Reject, other |
| **Subscriptions** | | | |
| SubscribeCOV, to subscribe or to cancel | refused | forwarded | forwarded |
| SubscribeCOV past a cap: the consumer's `consumer.max_subscriptions_per_source`, the device's `site.max_subscriptions_per_device` or the site's `site.max_subscriptions` | refused | Error, resources, no-space-to-add-list-element | same |
| SubscribeCOVProperty | refused | refused | refused |
| **Writes** | | | |
| WriteProperty with no priority, or priority 13 to 16, to an ordinary property of an ordinary object | refused | refused | forwarded, at 13 when none was given |
| WriteProperty at priority 1 to 12, a relinquish included | refused | refused | Error, write-access-denied |
| WriteProperty to a reserved object or property (`reserved` in the configuration) | refused | refused | Error, write-access-denied |
| WriteProperty whose value holds a character string, to a property not on `pseudonym.pass_through` (the strings the consumer sees are the shifter's, so it cannot write one back) | refused | refused | Error, write-access-denied |
| WriteProperty whose value names a device or an address the shifter never issued | refused | refused | Error, other |
| WriteProperty with an array index | refused | refused | Reject, other |
| WritePropertyMultiple | refused | refused | refused |
| **The life-safety and alarm services** (`reserved.services`): LifeSafetyOperation, AcknowledgeAlarm, DeviceCommunicationControl, ReinitializeDevice, AddListElement, RemoveListElement, CreateObject, DeleteObject, AtomicReadFile, AtomicWriteFile | refused | refused | refused |
| **Other confirmed services** | | | |
| GetAlarmSummary, GetEnrollmentSummary, GetEventInformation, ConfirmedTextMessage | refused | refused | refused |
| ConfirmedCOVNotification, ConfirmedEventNotification, ConfirmedPrivateTransfer | refused | refused | refused |
| A confirmed service the shifter cannot name (13, 21 to 25, 30 and up) | Reject, unrecognized-service | same | same |
| **At every level** | | | |
| A datagram from a source outside `consumer.allow`, when the list is set | — , dropped before parsing, counted, logged at debug once per source per minute | same | same |
| A request naming a device instance the shifter never issued | Error, unknown-object, without asking the site | same | same |
| A read, subscription, write or Who-Has naming an object of a hidden type (`pseudonym.hidden_objects`: network-port) | Error, unknown-object, without asking the site; nothing for the Who-Has | same | same |
| An object-list, structured-object-list, subordinate-list or list-of-group-members read | forwarded, with the hidden objects left out | same | same |
| A segmented request | Abort, segmentation-not-supported | same | same |
| A request for a network the shifter does not route to | Reject-Message-To-Network | same | same |
| A request to the shifter's own address with no destination network, or to an address nobody is at | — | — | — |
| A request beyond the source's `consumer.max_rps_per_source`, or a confirmed request beyond `consumer.max_in_flight` | — | — | — |
| A segmented reply whose next Segment-ACK is `consumer.segment_timeout` late | Abort, TSM timeout | same | same |
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

The level is enforced per consumer by the dispatch, which takes it from
the request's source; the library guard under all of them is opened for
the global `control`, which no consumer is above, so a consumer served at
`no-write` on a `limited` shifter is held to `no-write` by the dispatch and
to `limited` by the guard.

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

The end-to-end COV test covers this against the simulated site: the shared
upstream subscription, the confirmed upgrade and its acknowledgements, the
last cancellation and the shifter's close emptying the sim's subscriptions.

## What `full-service` adds

With `control: full-service` the shifter takes WriteProperty from
consumers and applies these rules, in this order, before anything is sent:

- **The array-index rule.** A write with an array index is refused with
  Reject, reason other: the library's write method takes none.
- **The reserved set and the strings.** A write to an object of a reserved
  type or to a reserved property on any object is refused with Error, class
  property, code write-access-denied; so is a write whose value holds a
  character string, at any depth, to a property not on
  `pseudonym.pass_through`: the strings the consumer sees are pseudonyms,
  and a string it writes would be replaced on the way back, so the shifter
  refuses the write rather than let the site hold a consumer's text under a
  pseudonym. A reserved service is refused with service-request-denied, as
  the level refuses it anyway. The `reserved` keys are data, so a site can
  add to them.
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

The write test runs twice. Against a fake in the place of the library
client, each forwarded write reaches it at the right priority with the
right value, each refused one never does, the consumer gets the documented
answer, and the site's answers are injected one by one. Against the
simulated site through the real client, a write with no priority arrives
at 13 and one at 16 at 16, the consumer reads the value back, the refused
ones never arrive, a device behind the site's router takes a write too,
the site's own refusal comes back as it is, and a silent site gets exactly
one datagram.

## Implementation notes

Four points where the code is more specific than the rules above:

- **Context-tagged device identifiers** in values are rewritten only when
  the instance is a device the table knows, or when the tag sits in the
  `[3]` slot of a device-object-property reference after an object `[0]`
  and a property `[1]`. A blanket rule for any four-byte context tag of
  type device would also rewrite a context-tagged Time at two in the
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
- **A device's object-list is answered from one read of it**, kept for
  thirty seconds: the hidden objects are left out, so the count and the
  elements must agree, and a consumer that reads the list element by
  element, as it must from a device that cannot segment, would otherwise
  cost the site one read of the whole list per element. The shifter reads
  the list as the library client does, whole or element by element, and
  answers the consumer's whole or indexed read from that; an index past
  the end is Error, class property, code invalid-array-index.
- **Each distinct string of a property gets a table record**, so that an
  array of state texts is reversible with `-table`; a property holds at
  most sixteen (`table.TextsPerProperty`), the oldest dropped, so that a
  string-valued present value that changes every second cannot grow the
  table without bound. Its pseudonyms stay derivable; only the reverse
  record of an old value is gone.
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

### What is bounded

Package P1 of the [security plan](docs/security-plan.md) put a bound on
everything a consumer, anyone who can reach the consumer socket, or a
site device could otherwise make the shifter do without limit. Each bound
has a key, shown at its default; none can be turned off, only set high.
A dropped request gets no reply, as from a device under load, and is
logged at `debug`; a refused one gets the answer in the permissions table.

| Key | Default | What it bounds |
|---|---|---|
| `consumer.max_in_flight` | 64 | confirmed requests being handled at once, all consumers together; beyond it a request is dropped |
| `consumer.max_rps_per_source` | 20 | confirmed requests, unconfirmed requests and network messages taken from one source address in a second, with a burst of the same; beyond it the datagram is dropped before it is parsed further. A reply to a request of the shifter's own (a Segment-ACK, the acknowledgement of a confirmed notification) is never rationed |
| `consumer.max_sources` | 1024 | source addresses tracked at once: for the rate limit, for the recent peers that are told of a new device by unicast, for the sources answered a Who-Is, and for the sources holding subscriptions. The one heard longest ago is forgotten for a new one |
| `consumer.max_subscriptions_per_source` | 256 | subscriptions one source address may hold; beyond it SubscribeCOV is refused |
| `consumer.segment_timeout` | 4s | how long a segmented reply waits for the next Segment-ACK; then it is aborted with TSM timeout and forgotten |
| `site.max_subscriptions_per_device` | 16 | the shifter's own subscriptions to one site device, whatever the consumers ask |
| `site.max_subscriptions` | 2048 | the shifter's own subscriptions on the whole site |
| `site.max_new_devices_per_minute` | 60 | devices admitted to the table from I-Ams, as a bucket of that many refilled at that rate; beyond it an I-Am for an unknown instance is dropped and logged at `warn`. A device the table knows is never dropped |
| `site.whois_interval` | 1s | one Who-Is forwarded to the site per interval, and one burst of I-Ams to each source per interval, however many Who-Is it sends; an empty burst does not count |
| `site.timeout` × (`site.retries` + 1) + 2s | 11s | the deadline of every request to the site a consumer causes, waiting in the client's rate limit included; past it the consumer gets silence |

And without a key:

- **Recent peers are earned.** A consumer is told of a new device by
  unicast when it has sent a confirmed request within `consumer.recent`;
  a Who-Is alone no longer makes a source recent, since its source address
  is whatever the sender wrote.
- **A moved device is confirmed.** When an I-Am claims an instance the
  table knows from a new address, and the device has not been heard this
  run, the shifter reads the old address first and takes the new one only
  when the old is silent; either way the change is logged at `warn`. A
  second address for a device heard this run is a duplicate, as before,
  and is not recorded.
- **The table is written at most once a second**, and once on close.
- **A handler that panics loses one message.** Every goroutine the server
  starts for a handler, and every one the shifter starts for a discovery,
  a notification or a probe, runs under a recover that logs the panic
  with the source and counts it; the read loops stay as they are, since a
  panic there is a bug to fix rather than input to survive.

The subscription caps count reservations, taken before the subscription
is made and given back when it goes, so that two subscriptions racing for
the last place cannot both have it. A subscription that joins an existing
upstream subscription costs the site nothing and counts for the source
only.

## Tests

```bash
go test ./...
```

runs the unit tests of every package and, in `internal/shifter`, the
end-to-end tests on loopback: the leak test, which collects every
character string, address and identifier the direct read of the simulated
site returned and asserts that none of them crosses the consumer socket
unless its property passes; fidelity against that direct read; a Network
Port object on a canned site device, refused and left out of the object
list; the guard test at each level; stability
across restarts, collisions, a site reached through a BBMD with routed
devices behind a router, and the survey finding a simulated device that the
shifter's Who-Is cannot reach. The `internal/survey` tests are the
utility's, run against the simulated devices with the neighbor table and
the pings faked; one pings loopback for real, and `-short` skips it.

The bounds have tests of their own in `internal/shifter`: a flood of
thousands of datagrams from forty source ports, during which the
goroutine count and the heap stay under a fixed bound and after which an
ordinary read succeeds; thirty Who-Is in a burst answered with one I-Am
per device; the three subscription caps and the place a cancellation
gives back; a thousand I-Ams for distinct devices, of which the table
admits the configured rate and writes its file once a second; and a device
claiming a known instance from a new address, refused while the old one
answers and taken once it is silent. `internal/server` tests the in-flight
cap, the per-source rate, the segment timeout and the recovery from a
panicking handler.

The parsers have fuzzers: the server's datagram and confirmed-request
parsers, the shifter's WriteProperty, ReadPropertyMultiple, ReadRange and
Who-Has parsers, and the value decoding and rewriting of `translate`.
`go test ./...` runs each on its seed corpus; to fuzz one for a minute,

```bash
go test ./internal/shifter -run='^$' -fuzz=FuzzParseWrite -fuzztime=60s
```

and likewise `FuzzParseRPM`, `FuzzParseReadRange` and `FuzzWhoHas` there,
`FuzzHandle` and `FuzzConfirmed` in `./internal/server`, and
`FuzzDecodeValues` in `./internal/translate`. Go runs one fuzz target per
invocation, so a plain `go test ./...` cannot fuzz for ten seconds as the
plan asked; the seeds run there, and the minute each is a step of the
release check.

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
