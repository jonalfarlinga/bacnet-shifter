# bacnet-shifter — Threat model

Companion to [anonymizer-spec.md](anonymizer-spec.md), which says what the shifter does, and to [security-plan.md](security-plan.md), which says what is built to make it a security layer and in what order. This document says what the shifter protects, from whom, through which openings, and how each threat stands against the code as it is. It was written on 2026-10-15 against v0.3.0 (`b4402f5`), with milestones M1 to M3 built and M4 (`god`) not yet started, and every finding in §7 was checked in the code; the file and line are given where it helps.

The one-sentence summary: the shifter is today a sound **disclosure control** with a well-built write guard, and it is **not yet a security boundary**, because nothing on the consumer side is authenticated and nothing bounds what a consumer, or anyone who can put a datagram on the consumer network, can make it do.

## 1. Purpose and scope

The threat model fixes the vocabulary and the claims against which the security plan is measured. It covers the shifter program, its two sockets, its data directory, its configuration and its log, on the host it runs on. It does not cover the BACnet devices themselves, the consumer applications, or the networks beyond what the shifter can see of them.

In scope: everything a consumer can send; everything a site device can send; what is on the shifter's disk; what the operator can get wrong. Out of scope, and stated as assumptions in §11: a compromise of the host itself, physical access, and the correctness of the Go runtime and the operating system.

## 2. The system in one page

```
   site network (Z1)                 shifter host (Z2)                 consumer network (Z3)
   ┌──────────────┐    BACnet/IP    ┌──────────────────────┐    BACnet/IP    ┌──────────────┐
   │ controllers, │ <────────────── │ site socket (client) │                │ YABE, BMS,   │
   │ routers,     │  Who-Is, reads, │   │   pseudonyms      │                │ explorer,    │
   │ BBMD         │  COV, writes    │   ▼   table, key      │                │ anything on  │
   │              │ ──────────────> │ consumer socket      │ <────────────── │ the LAN      │
   └──────────────┘  I-Am, replies, │ (server, a router to │  any request   └──────────────┘
                     notifications  │  the virtual nets)   │ ──────────────>
                                    │ config.yaml, log     │  replies, I-Am,
                                    └──────────────────────┘  notifications
```

- **The site socket** is the library client. It sends what the level allows and nothing else, enforced by the library's guard; it hears I-Ams, replies and notifications from any address on the site.
- **The consumer socket** is the server package. It takes any BACnet/IP datagram from any source, parses it, and hands confirmed and unconfirmed requests to the shifter's dispatch. It answers as a router to the virtual networks.
- **The data directory** holds the key and `table.json`, which together are the de-anonymization secret. **`config.yaml`** sets the level and the adapters. **The log** goes to stderr.

Data flows: a consumer's request is parsed, checked against the level, translated (virtual to real), sent to the site, and the reply translated back (real to virtual) and re-encoded. A site I-Am creates table records and is announced to consumers. A site COV notification is fanned out to the consumers of its object.

## 3. Assets

| ID | Asset | Where it is | What must not happen |
|---|---|---|---|
| A1 | **Site identity**: object names, descriptions, locations, model and serial numbers, device instances, IP addresses, MACs, network numbers, free text that names rooms, tenants, equipment | On the site; in the table; in the log | Any of it reaching a consumer or the consumer network |
| A2 | **Site state**: present values, setpoints, out-of-service flags, alarm configuration, life-safety objects, device operation | On the site | Changed by anyone the level does not allow, or beyond what the level allows |
| A3 | **Site availability**: the devices' subscription tables, their request capacity, the routers' capacity, the site's bandwidth | On the site | Exhausted through the shifter |
| A4 | **The de-anonymization secret**: the key and the table | Data directory | Read or copied by anyone but the shifter's account |
| A5 | **The shifter's availability** | The host | Crashed, hung or starved by anything either side sends |
| A6 | **The audit record**: who sent which write, and what was refused | The log | Missing, unattributable, or lost |
| A7 | **The configuration**: the level, the adapters, the reserved set | `config.yaml` | Changed by anyone but the operator; set to `god` without anyone noticing |

A1 is what the shifter exists to protect. A2 and A3 are what it must not become a path to. A4 to A7 are what makes the first three hold.

## 4. Trust zones and boundaries

| Zone | Trust | Note |
|---|---|---|
| **Z1, the site network** | Protected, and assumed well-behaved for integrity, not for availability | Devices are honest but fallible. A rogue or compromised device is considered (T4): it can send any I-Am, any reply, any notification, at any rate. |
| **Z2, the shifter host** | Trusted; the root of trust | Whoever controls the host controls the key, the table, the configuration and the level. The operator is trusted. A host compromise is out of scope but its consequences are listed as residual risk (§10). |
| **Z3, the consumer network** | Untrusted | Hosts there may be hostile, may spoof each other's addresses (UDP), and may read every datagram. A consumer that is authorized to talk is still untrusted in what it sends. |

Boundaries, which are the openings the threats come through:

| Boundary | Crosses from | Into | Enforced by |
|---|---|---|---|
| **B1, the consumer socket** | Z3 | the shifter | `internal/server` parsing, `internal/shifter` dispatch, the level |
| **B2, the site socket** | Z1 | the shifter | the library client's parsing, reply matching, and `OnIAm` |
| **B3, the site socket, outbound** | the shifter | Z1 | the dispatch, then the library guard (`ReadOnly`, the per-device writable switch) |
| **B4, the file system** | the host | the shifter | file permissions (0600 on the key, which NTFS ignores), nothing else |
| **B5, the command line and the log** | the shifter | the operator | `-table` prints the whole secret; the log at Info prints real values beside pseudonyms |

A note on B1 and B2 sharing a host. On Windows each socket binds its adapter's own address. On Linux and macOS a socket that hears broadcasts binds every address (`client/iface.go:84`, `BindAny`), so each socket hears every interface and the two sides are kept apart only by the other adapter's subnet being on the socket's `Exclude` list and by the two ports differing. A site host that is not on the site adapter's subnet (one reached through a BBMD, say) is not excluded, and would reach the consumer socket if the host's routing let it. The host firewall is part of the boundary there (§11, and plan P5).

## 5. Adversaries

| ID | Adversary | Can | Wants |
|---|---|---|---|
| **T1** | **A hostile consumer**: a host that is meant to talk to the shifter, or its operator | Send any BACnet request at any rate; read every reply; run for months | A1 (learn the site), A2 (change it, at a level above its own), A3 (exhaust it) |
| **T2** | **An unauthenticated host on the consumer network** | Everything T1 can, plus forge the source address of any datagram, including a legitimate consumer's | The same, and to make the shifter reflect traffic at a victim |
| **T3** | **A passive observer on the consumer network** | Read every datagram | A1 from what consumers see; the values consumers write |
| **T4** | **A rogue site device**, or one taken over | Send any I-Am, reply or notification from any site address, at any rate; claim any instance | A5 (take the shifter down), A2 (have writes meant for another device delivered to it), A1 (nothing: it is on the site already) |
| **T5** | **The operator, in error** | Set `control: god`; bind the wrong adapter; copy the data directory to the wrong place; ship the log | Nothing; the harm is the same |
| **T6** | **An attacker on the host** | Everything | Everything; out of scope, residual in §10 |

T1 and T2 are the adversaries the plan is built around. T2 is T1 without the courtesy of a stable address, and the UDP transport makes T2 cheap: nothing today distinguishes them.

## 6. Attack surface

| Entry point | Parsed by | What it can cause today |
|---|---|---|
| Any datagram on the consumer socket | `server.handle`: BVLC, NPDU, then APDU by type | A goroutine per confirmed request; a parse path per datagram; the source recorded as a recent peer |
| Who-Is, in any form | `shifter.whoIs` | One unicast I-Am per matching device to the datagram's source; one upstream Who-Is per interval |
| Who-Has | `shifter.whoHas` | A table lookup by pseudonym; I-Haves to the source |
| ReadProperty, ReadPropertyMultiple, ReadRange | `readHeader`, `parseRPM`, `readRange` | One upstream request each, through the library's limits |
| SubscribeCOV | `subscribeCOV` | A fan-out entry and, for a new object, one upstream subscription |
| WriteProperty | `parseWrite`, `control.Level.Write`, the upstream rules | One upstream write at full-service and above |
| Every other confirmed service | the level | A refusal, answered and logged |
| Network messages | `shifter.Network` | Who-Is-Router-To-Network answered; the rest dropped |
| Replies and acknowledgements | `server.reply` | Continue a segmented reply; end a confirmed notification's wait |
| Register-Foreign-Device | `server.handle` | A NAK |
| An I-Am on the site socket | the library, then `shifter.discovered` | A table record, a save of the whole file, one name read, one broadcast I-Am and one unicast per recent consumer |
| A reply on the site socket | the library | Matched to a pending request by source and invoke ID, or dropped |
| A COV notification on the site socket | the library, then `covDeliver` | A send to every consumer of the object |
| `config.yaml` | `cmd/shifter` | Everything, including the level |
| The data directory | `pseudonym.Load`, `table.Open` | The whole secret, in plaintext |
| `-table` | `cmd/shifter` | The whole secret, printed |

## 7. Threats and how they stand today

Each threat has an identifier by category (S spoofing, T tampering, R repudiation, I information disclosure, D denial of service, E elevation), what the code does about it today, and where the plan closes it. **Standing** is *held* (mitigated and tested), *partial*, *gap*, or *accepted* (a residual the design takes on knowingly, listed again in §10).

### 7.1 Spoofing

| ID | Threat | Today | Standing | Plan |
|---|---|---|---|---|
| S1 | A host on the consumer network sends with another consumer's source address, and is served as that consumer: at full-service it writes; at any level it is reflected at (D2). The shifter identifies a consumer by the datagram's source, or by SNET and SADR for a routed one (`server.Peer.Key`). | Nothing authenticates a source. | **gap** | P3 |
| S2 | A rogue site device claims an instance the table already holds. Within a run the second claimant at another address is logged and ignored (`table.EnsureDevice`, `Duplicate`); after a restart the first I-Am heard wins and the address is updated in place (`Moved`, logged at Warn). Reads and writes for that virtual device then go to the rogue. | Partial: the in-run case is caught; the restart case is logged only. | **partial** | P1 |
| S3 | A rogue site device answers for another. The library matches a reply to its request by source address and invoke ID (`client.deliver`), so the rogue must spoof the other device's IP address at the IP layer. | Held at the BACnet layer; the IP layer is Z1's. | **accepted** | — |
| S4 | A consumer-side router sends I-Am-Router-To-Network or Initialize-Routing-Table to steer the shifter's replies. The shifter learns no route from the consumer side and replies only to the datagram's source. | Dropped. | **held** | — |

### 7.2 Tampering

| ID | Threat | Today | Standing | Plan |
|---|---|---|---|---|
| T1 | A consumer below full-service changes site state. | Refused by the dispatch, and again by the library guard (`ReadOnly` at no-write; no device writable below full-service). Test 3 asserts the set of services that reach the site per level. | **held** | — |
| T2 | At full-service, a consumer writes to any object and property of any device, at 13 to 16, outside the reserved set. That is the level's definition, and the exposure is the whole site minus a deny list. | By design. | **gap** (for a boundary) | P4 |
| T3 | A write to a life-safety or alarm object, property or service. | Refused below god by the reserved set; the set is configuration. At god, forwarded. | **held** below god | decision 1, P4 |
| T4 | A write that renames a site object and breaks the mapping. | Refused below god; at god, recorded as a rename. | **held** below god | — |
| T5 | The table or the key is edited on the host: a device's address is redirected, a pseudonym forged. | Nothing checks the file's integrity. | **accepted** (Z2) | P5 |
| T6 | `config.yaml` is edited to `god`, or to the wrong adapter. | The banner is printed at start; nothing else. | **partial** | P4, P5 |

### 7.3 Repudiation

| ID | Threat | Today | Standing | Plan |
|---|---|---|---|---|
| R1 | A write cannot be attributed. Forwarded writes and refusals are logged at Info, to stderr, among every other line, with the consumer's source address, which S1 says can be forged. | Logged, not attributable, not separable, not durable. | **gap** | P3, P4 |
| R2 | The log is lost: stderr only, no file, no rotation, no append-only record. | Nothing. | **gap** | P4 |

### 7.4 Information disclosure

| ID | Threat | Today | Standing | Plan |
|---|---|---|---|---|
| I1 | Object names, descriptions, locations, model names, serial numbers, device instances, IP addresses, MACs and network numbers reach a consumer. | Replaced by rule and by the replaced list; test 1 scans every datagram on the consumer socket for each of them across tests 2, 4 and 7. | **held** | — |
| I2 | Free text in any other property reaches a consumer: state-text, active-text, inactive-text, event-message-texts, profile-name, tags, Structured View annotations, the present-value of a CharacterString Value object, file names. On real sites these name rooms, tenants and equipment. The replaced list is a deny list; the leak test whitelists every pass-through string (`e2e_test.go`, `addPassThrough`), so it cannot see this. | Passes through; configurable per property, off by default. | **gap** | P2 |
| I3 | Network Port objects (type 56) reach a consumer: ip-address, ip-subnet-mask, ip-default-gateway, mac-address, the BBMD tables, DNS servers, network-number. | Nothing handles the type; the sim has none, so no test sees it. | **gap** | P2 |
| I4 | The equipment is fingerprinted: vendor-identifier in every I-Am, vendor-name, firmware-revision, application-software-version, protocol-services-supported, the object-list's shape. | Pass through by design (spec §6.5: they name the product, not the site). | **accepted**, or a strict profile | decision 2 |
| I5 | The site's structure shows: non-device object instances, which sites often number by floor or zone; the nesting of networks; the count and types of objects per device. | Pass through by design (spec §2). | **accepted** | — |
| I6 | Timing and traffic: which objects are read how often, COV cadence, the difference between a locally answered and a forwarded request. | Not hidden (spec §2). | **accepted** | — |
| I7 | Pseudonyms are the same for every consumer and across time, so one consumer's stored data joins another's, and a table leaked from any context de-anonymizes all of them. | By design (goal 3: stable pseudonyms). | **accepted** | — |
| I8 | A consumer uses the shifter as an oracle: Who-Has by a guessed real name; a read of a guessed real device instance. | Who-Has matches pseudonyms only; an unissued virtual instance is answered unknown-object locally and never sent to the site. | **held** | — |
| I9 | The log discloses the site: at Info every device line carries the real name and address beside the pseudonym; `-table` prints everything. If the log is shipped off the host, it is the reverse table. | On the host, by design (spec §11). | **accepted** on the host; **gap** if shipped | P5 |
| I10 | A passive observer on the consumer network reads what consumers read and what they write. | BACnet/IP is plaintext. The observer learns no more than a consumer about A1, and learns every written value. | **gap** | P3, P6 |
| I11 | The key and table at rest are plaintext in a directory the program cannot lock on NTFS. | 0600 on the key; the README says to lock the directory. | **partial** | P5 |
| I12 | The shifter's own address is visible on the site, in a BBMD's foreign device table and as the source of every request. | By design (spec §5.3). | **accepted** | — |

### 7.5 Denial of service

| ID | Threat | Today | Standing | Plan |
|---|---|---|---|---|
| D1 | A flood of confirmed requests. Each gets a goroutine (`server.go:430`) with no cap; each handler then waits in the library's token bucket under the shifter's lifetime context, with no deadline of its own, so the goroutines queue without bound. | Nothing bounds it. | **gap** | P1 |
| D2 | Reflection. One Who-Is of about twenty bytes yields one unicast I-Am per matching device to the datagram's source (`shifter.go:541`), which T2 can forge; with a hundred devices that is a hundredfold amplification at a victim. Any datagram also makes its source a recent peer (`noteConsumer`) that is sent every announcement for ten minutes. | Nothing bounds it. | **gap** | P1 |
| D3 | Subscription exhaustion. No cap on consumers per object, on subscriptions per consumer, or on upstream subscriptions; a consumer can subscribe to every object of every device. Site controllers hold a handful of subscriptions each, so the site's own subscribers are pushed out, while the site sees one subscriber. | Nothing bounds it. | **gap** | P1 |
| D4 | A segmented reply whose consumer stops acknowledging stays in the server's `sending` map forever. | No timer. | **gap** | P1 |
| D5 | A site I-Am flood (T4). Every distinct instance adds a table record and rewrites the whole file (`table.save`), reads the device's name, and broadcasts an I-Am on the consumer side; the local table is already over half a megabyte. Identification is bounded to four at once (`slots`), not in rate. | Partial. | **partial** | P1 |
| D6 | A malformed datagram panics a parser. No `recover` anywhere; a panic on a handler goroutine ends the process. The library fuzzes its top-level parser and APDU codec; the shifter's own parsers (`server.confirmed`, `parseWrite`, `parseRPM`, `readRange`, `whoHas`, `translate.Decode`) are not fuzzed. | Nothing catches it. | **gap** | P1 |
| D7 | Consumers overload the site. | The library's `max_rps` and in-flight limits bound what reaches the site, all consumers together; Who-Is is forwarded at most once a second. | **held** for the site; one consumer can starve the others | P1 |
| D8 | The disk fills: the table grows without bound; the log is stderr with no rotation. | Nothing. | **gap** | P1, P4 |

### 7.6 Elevation of privilege

| ID | Threat | Today | Standing | Plan |
|---|---|---|---|---|
| E1 | A bug in the dispatch lets a service through at a lower level. | The library guard refuses it independently; a guard refusal is logged at Error. Test 3 per level. | **held** | — |
| E2 | `god` is in effect without anyone meaning it to be. | A banner at start; every forwarded god-only request logged at Warn. No time limit, no second condition. | **partial** | decision 1, P4 |
| E3 | A consumer registers as a foreign device, or sends a segmented request, or a BVLC function the server does not take. | NAK; Abort segmentation-not-supported; dropped. | **held** | — |
| E4 | The site pushes state into the shifter: I-Ams create records and announcements (D5), notifications are fanned out, replies are parsed. A hostile site device can make the shifter broadcast on the consumer side. | Bounded only by `slots`. | **partial** | P1 |
| E5 | A consumer's request names a device or an address the shifter never issued, inside a value, and it is forwarded broken. | Refused with Error class services, code other, at full-service and god. | **held** | — |

## 8. What holds today

The claims the shifter can make at v0.3.0, each backed by a test:

1. **No site name, description, location, model name, serial number, device instance, address or network number crosses the consumer socket** (I1; test 1).
2. **Below `full-service` nothing a consumer sends changes site state, and below `limited` nothing leaves state on a device**, enforced by the dispatch and again by the library guard (T1, E1; test 3 per level, the guard test in the library).
3. **At `full-service` no write reaches a life-safety or alarm object, property or service, or any priority above 13**, with the reserved set as configured (T3; test 8).
4. **A consumer cannot learn a real name or instance by asking** (I8; the Who-Has and unknown-object paths).
5. **The site sees one address, one subscriber per object, at most one Who-Is a second and at most `max_rps` requests a second** (D7; test 4, the library's limits).

## 9. Security objectives

The claims the shifter is to make once the plan is done. Each is testable, and the plan names the test. They are the acceptance criteria of [security-plan.md](security-plan.md).

| ID | Objective | Closes |
|---|---|---|
| **O1 Disclosure** | No site name, free text, device instance, address, network number, or address-bearing object reaches a consumer. What passes is an enumerated allow list, and the leak test scans for everything the site returned, not for a list. | I1, I2, I3 |
| **O2 Integrity** | Below `full-service` no consumer changes site state. At `full-service` only the writes on a configured allow list, at priority 13 to 16, reach the site; the reserved set is never written below `god`; `god` is either absent from the security profile or time-boxed and audited. | T1, T2, T3, E2 |
| **O3 Identity** | Only consumers the operator has admitted are served, over a path that authenticates them, and the level is per consumer, never above the global one. | S1, I10, R1 |
| **O4 Attribution** | Every forwarded write, every refusal and every change of level is recorded, append-only, with the consumer's authenticated identity, the real and virtual object, the property, the priority and the outcome. | R1, R2 |
| **O5 Site availability** | The load the shifter puts on the site is bounded whatever consumers do: requests a second, requests in flight, subscriptions per device and in total, Who-Is per interval, and the rate at which new devices are admitted. | D3, D7, E4 |
| **O6 Shifter availability** | No datagram, and no sequence of datagrams from either side, takes the shifter down or grows its memory, its goroutines or its disk without bound. Reflection is bounded per source. | D1, D2, D4, D5, D6, D8 |
| **O7 Secrets** | The key and the table are readable by the shifter's account only, and the shifter refuses to start otherwise. The log can be run without real values. | I9, I11 |
| **O8 Fail closed** | Any error in parsing, translation or policy refuses the request; nothing is forwarded on a partial translation; a panic drops one request, never the process. | D6, E5 |

## 10. Residual risks and accepted exposures

Taken on knowingly, and to be stated in the README once the plan is done:

- **I4, fingerprinting.** Vendor, firmware and the object-list's shape say what the equipment is. A strict profile (decision 2) can blank the vendor identifier and replace the version strings; it cannot hide the shape.
- **I5, structure.** Non-device instances and the nesting of networks pass through; rewriting instances would mean rewriting every reference on the site.
- **I6, timing.** Traffic patterns are not hidden.
- **I7, linkability.** One stable view for every consumer is the product's point; the price is that the table de-anonymizes every consumer's data at once.
- **I12, the shifter's footprint on the site.** One address, one BBMD entry.
- **S3, IP-layer spoofing on the site.** Z1's problem.
- **T5, T6 and everything under T6 (host compromise).** The host is the root of trust; the plan makes misconfiguration harder to miss (P5), not impossible.
- **A consumer that is admitted and hostile (T1 after P3)** still learns everything O1 lets through, can still send the writes its allow list permits, and can still use its share of the site's capacity. Identity makes it attributable and bounded, not harmless.

## 11. Assumptions

1. The host is administered by the operator, runs nothing else that speaks BACnet, and is not reachable from the consumer network except on the consumer socket's port.
2. The site network and the consumer network are separate, and the shifter is the only path between them. The host does not forward IP between its adapters (on Windows `IPEnableRouter` is 0, the default; on Linux `ip_forward` is 0).
3. Both sides are BACnet/IP over UDP; MS/TP and BACnet/SC are not in v1 (spec §2). P6 changes this for the consumer side.
4. Consumers are BACnet clients that tolerate Error, Reject, Abort and silence, as the standard requires of them.
5. The operator reads the log, or ships it somewhere that is as trusted as the host.
6. The host's clock is right: subscription lifetimes, the audit record and a time-boxed `god` depend on it.
7. The library's parsers are correct on well-formed input and do not panic on malformed input where they are fuzzed; where they are not, the shifter's recovery (P1) catches it.

## 12. Decisions for review

Taken by the user before the plan's packages start; the plan carries them.

1. **The fate of `god`.** (a) Drop it from the security profile: the level does not exist in a build meant as a boundary. (b) Keep it, time-boxed: `control: god` needs a `god_until` timestamp in the near future, after which the shifter falls back to `full-service`, with the banner and an audit line at both ends. (c) Keep it as it is, outside the security claims. The plan assumes (b) until told otherwise.
2. **A strict profile for fingerprinting (I4).** Whether to add a profile that sends a fixed vendor identifier in I-Ams and replaces vendor-name, firmware-revision and application-software-version like other text. The plan includes it as an optional key in P2.
3. **How a consumer gets an identity (O3).** The plan proposes an authenticated tunnel with the consumer socket bound to the tunnel adapter and the tunnel's inner addresses as the allow list, with BACnet/SC as the standard's route later (P6). The choice of tunnel is the operator's; the shifter needs only an adapter name.
4. **The default of the consumer allow list.** Empty meaning *any source, with a warning at start* keeps the first run working; empty meaning *no source* is the safer default and breaks the first run until the key is set. The plan proposes the first with a Warn line, and the README's checklist says to set it.
5. **The write allow list's default (O2).** Empty meaning *nothing is writable at full-service until the operator lists it* is the boundary's answer; it makes `full-service` a no-op until configured. The plan proposes that.
