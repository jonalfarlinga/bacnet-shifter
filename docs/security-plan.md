# bacnet-shifter — Security plan

Companion to [threat-model.md](threat-model.md), which says what the shifter protects: the library at `../bacnet` is changed as little and as late as possible, each library change is confirmed first and lands as its own commit, the README's rules are revised before code where behaviour changes, and each package starts on the user's word. This document says what is built to turn the shifter from a disclosure control into a security boundary, in what order, and how each piece is shown to work. Written 2026-10-15 against v0.3.0.

The principle, in one line: **deny what has not been allowed**, on the strings that pass, on the writes that pass, and on who may talk to the shifter at all. Today the shifter replaces what it knows is identifying and refuses what it knows is dangerous; a boundary passes only what has been enumerated.

## 1. The packages

Six packages, P1 to P6. The first two touch only the shifter. P3 to P5 add configuration and a small amount of code. P6 is a library milestone. The objectives (O1 to O8) and threats (S, T, R, I, D, E) are the threat model's.

| | Package | Closes | Touches | Library | Rules revised |
|---|---|---|---|---|---|
| **P1** | Robustness: bounds, reflection, recovery, fuzzing | O5, O6, O8; D1 to D8, S2, E4 | `internal/server`, `internal/shifter`, `internal/table`, config | none | none; the implementation notes gain the limits |
| **P2** | Disclosure: the string allow list, hidden objects, the strict profile | O1; I2, I3, I4 | `internal/shifter`, `internal/control`, config, the leak test | none | the non-goals, the string rule, the refusals |
| **P3** | Consumer identity: the tunnel, the allow list, per-consumer level | O3; S1, I10 (with the tunnel), R1 (the identity half) | `internal/server`, `internal/shifter`, config, README | none | the non-goals, the consumer side, the levels |
| **P4** | Policy and audit: the write allow list, the audit log | O2, O4; T2, T6, R1, R2 | `internal/control`, `internal/shifter`, `cmd/shifter`, config | none | the write rules, the host |
| **P5** | Host and secrets: start-up checks, key store, log mode, the deployment checklist | O7; I9, I11, T5, T6 | `cmd/shifter`, `internal/pseudonym`, README | none | the key, the host |
| **P6** | BACnet/SC on the consumer side | O3 the standard's way; I10 | the library, then `internal/server` | **L6** | the non-goals, the consumer side |

Order: P1, then P2, then P3, then P4; P5 at any point after P1, since it is independent; P6 as the next library milestone, L4 having been cancelled on 2026-10-22. §8 says why this order.

## 2. P1 — Robustness

Everything in P1 is shifter-side and changes nothing a well-behaved consumer sees. It is the cheapest way to stop the proxy being one packet from down, and it comes first because every later package adds parsing and state that need the same bounds.

**Built 2026-10-26.** The README's implementation notes ("What is bounded") are the record of the keys and defaults. Where the build departs from the table below: the per-source rate limit (c) rations unconfirmed requests and network messages too, not only confirmed requests and the Who-Is and Who-Has answers, since any of them costs the shifter work; the sources holding subscriptions (e) are bounded by `consumer.max_sources` as well, so that the consumer subscriptions in all are bounded; the probe of a moved device (h) is one ReadProperty of the old address, and any answer keeps it; the fuzzers (j) run their seed corpus under `go test ./...`, since Go fuzzes one target per invocation, and the minute each is a documented step of the release check rather than ten seconds under the ordinary test run; and the table test flushes before it reloads the file, which the coalesced writes made necessary.

### 2.1 What is built

| | Item | Where | Threat |
|---|---|---|---|
| a | **A deadline per consumer request.** The handlers call the site client with the shifter's lifetime context; each gets a context with a deadline of `site.timeout × (site.retries + 1)` plus a margin, so a request waiting in the library's token bucket gives up rather than queues forever. The consumer gets silence, as from a device under load. | `internal/shifter`, every call of `s.site.*` from a handler | D1 |
| b | **A cap on consumer requests in flight**, a semaphore around the handler; beyond it the request is dropped and logged at Debug. Key `consumer.max_in_flight`, default 64. | `internal/server.confirmed` or the shifter's `Confirmed` | D1 |
| c | **A rate limit per source** on confirmed requests and on Who-Is and Who-Has answers: one token bucket per peer key, in a bounded map that evicts the oldest. Keys `consumer.max_rps_per_source` (default 20) and `consumer.max_sources` (default 1024). The Who-Is answer is further bounded to one I-Am burst per source per `site.whois_interval`. | `internal/server`, `internal/shifter.whoIs` | D1, D2, D7 |
| d | **Recent peers bounded and earned.** The recent-peer map takes a peer only from a confirmed request, not from any datagram, holds at most `consumer.max_sources` entries, and evicts the oldest. | `shifter.noteConsumer` | D2 |
| e | **Subscription caps.** Keys `consumer.max_subscriptions_per_source` (default 256), `site.max_subscriptions_per_device` (default 16) and `site.max_subscriptions` (default 2048). Beyond a cap the SubscribeCOV is refused with Error class resources, code no-space-to-add-list-element, and logged. | `internal/shifter/cov.go` | D3 |
| f | **A segment timeout.** A segmented reply whose next Segment-ACK does not arrive within `consumer.segment_timeout` (default 4 s, the standard's T-seg) is aborted and dropped from the server's `sending` map. | `internal/server` | D4 |
| g | **New devices admitted at a bounded rate.** Key `site.max_new_devices_per_minute` (default 60): beyond it an I-Am for an unknown instance is logged and dropped until the window passes. Table saves are coalesced: at most one write a second, and one on Close, without changing the table's semantics or its tests. The device-identification `slots` stays at four. | `shifter.discovered`, `internal/table` | D5, D8, E4 |
| h | **A moved address is confirmed before it is taken.** When an I-Am claims a known instance from a new address and the device was not heard this run, the shifter probes the old address first; the new one is taken only when the old is silent, and the change is logged at Warn either way. | `shifter.discovered`, `table.EnsureDevice` | S2 |
| i | **Panic recovery.** Every goroutine the server starts for the handler, and every goroutine the shifter starts for a notification or a discovery, runs under a `recover` that logs the panic with the datagram's source and drops that one request. The read loops stay as they are: a panic there is a bug to fix, and the recovery on the handler goroutines is where malformed input lands. | `internal/server`, `internal/shifter` | D6, O8 |
| j | **Fuzz tests** (Go native, `func Fuzz…` in `_test.go`) for `server.handle` on raw datagrams, the confirmed-request tag parser, `parseWrite`, `parseRPM`, the ReadRange parsing in `readRange`, Who-Has decoding, `translate.Decode` and `translate.Rules.Values`, each seeded with valid frames from the harness. Each runs for at least a minute in development and for ten seconds under `go test ./...`. | beside each parser | D6 |

### 2.2 Tests and gate

- **A flood test** in `internal/shifter`: from a raw socket, a burst of several thousand Who-Is and ReadProperty datagrams with varied source ports, during which goroutine count and heap stay under a fixed bound, and after which an ordinary consumer read succeeds within the usual timeout.
- **A reflection test**: the bytes the shifter sends to one source in answer to a Who-Is burst are bounded by one I-Am per device per interval.
- **A subscription test**: the caps refuse the subscription past the limit with the documented Error, and the site's subscription count never exceeds `site.max_subscriptions_per_device`.
- **A site flood test**: the sim sends I-Ams for a thousand distinct instances in a burst; the table admits at most the configured rate, the file is written at most once a second, and the consumer side sees at most that many announcements.
- The nine end-to-end tests, the smoke test and the fuzzers green; `go vet` clean; `GOWORK=off go test ./...` against the released library.
- README: a section under the implementation notes listing what is bounded and by which key; `config.yaml.example` regenerated.

## 3. P2 — Disclosure

Rules first, then code. The revised rules below are reviewed before any code, and land in the README's permissions table and the package comments.

**Built 2026-10-26**, the rules as commit d46f91b and the code after it. The README's section "What crosses to the consumer" is the record of the rules. Where the build departs from the text below: the non-goals live in that README section, since the spec that held them is gone; the version strings pass outside the strict profile by code rather than by a listed default, so that `pseudonym.pass_through` can stay empty; protocol-version and protocol-revision are numbers and pass in every profile; the write rule that replaced "a write to a replaced property" refuses any write whose value holds a character string to a property whose strings the shifter replaces; an indexed read of the object-list is answered from one read of the whole list, cached for thirty seconds, so that the count and the elements agree; each distinct string of a property gets a table record, capped at sixteen per property; and the Network Port test uses a canned site device on a raw socket in the harness, since the sim has none.

### 3.1 The rules

- **The non-goals**: remove the one about free text outside the replaced list. Add the accepted residuals from threat model §10 (fingerprint, structure, timing, linkability) in their place, so the non-goals say what is knowingly left rather than what is unhandled.
- **The string rule**: replace the deny list with an allow list. Every character string in every reply and notification is pseudonymized through the table, as names and the four text properties are today, with a per-property prefix (`p<id>-` for any property the table has no abbreviation for), **unless** its property is on `pseudonym.pass_through`, whose documented default is empty. The replaced list is retired; the threat model's I2 to I4 record why.
- **Hidden objects**: a read, subscription or write that names an object of a type on `pseudonym.hidden_objects` (default: `network-port`) is answered Error class object, code unknown-object, without asking the site; the type is left out of a device's object-list on the way down and out of every object-list-like property (structured-view subordinate-list, group member lists) by the same rule.
- **The strict profile**, `pseudonym.strict: false`. When true, I-Ams carry a fixed vendor identifier (0), and vendor-name, firmware-revision, application-software-version and protocol-revision strings go through the text rule like any other. Decision 1 of the threat model.

### 3.2 The code

- `internal/control`: parsers for the three keys beside `ParseReplaced`; `ParseReplaced` goes once nothing calls it.
- `internal/shifter.downstream`: strings are replaced by default and pass only when allowed; object-list reads drop hidden types; `readProperty`, `readPropertyMultiple`, `readRange`, `subscribeCOV` and `writeProperty` refuse hidden types locally. `cov.go` already goes through `downstream`. `iAm` applies the strict profile.
- `cmd/shifter/config.go`: the keys, their comments, `config.yaml.example` regenerated.
- **The leak test rewritten**: instead of whitelisting pass-through strings, it collects every character string the direct read of the sim returned, and asserts that none of them, and none of the sim's addresses and identifiers, appears on the consumer socket unless its property is on the allow list. The fidelity test's comparisons adjust for the strings now replaced. A new unit test reads a Network Port object through a canned handler and asserts the refusal and its absence from the object-list.
- The sim has no Network Port object; if `../bacnet` adds one later it joins the test, but the shifter's test does not wait for it.

### 3.3 Gate

Test 1 in its new form, test 2 adjusted, the new unit test; README's permissions table gains the hidden-object row and the implementation notes say what the allow list means; `go vet`, `GOWORK=off go test ./...` clean.

## 4. P3 — Consumer identity

**Rules landed 2026-10-26** in the README (the setup section on the consumer side, the per-consumer sentence over the permissions table and its allow-list row) and in the threat model (S1, I10 and R1, assumption 8, claim 6 of §8, decisions 2 and 3 taken); the code follows.

BACnet/IP cannot authenticate a sender, and the shifter should not try to add a scheme of its own to it. The identity comes from below the protocol, now, and from BACnet/SC, later (P6).

### 4.1 The tunnel

The operator runs an authenticated tunnel between each consumer and the shifter host: WireGuard or IPsec, the choice is theirs. The shifter needs nothing new for it: `consumer.adapter` names the tunnel adapter, so the consumer socket is bound to it and hears nothing else, and the tunnel's inner addresses identify the peers. The README gets a section on the setup, with the WireGuard case worked through on Windows and Linux, and a note that on Linux the socket binds every address and the firewall must confine the port to the tunnel interface.

### 4.2 The allow list and per-consumer level

- `consumer.allow`: a list of IP prefixes. A datagram from any other source is dropped before parsing, counted, and logged at Debug (once per source per minute, so the log does not become the flood). Default empty, meaning any source, with a Warn line at start saying so (decision 3 of the threat model); the README's checklist says to set it.
- `consumer.peers`: a list of `{prefix, control}` entries. A consumer matching an entry gets that level, **never above the global `control`**, which stays the ceiling; a consumer matching none gets the global level. The library guard stays as it is, the floor under all of them: the site client is opened for the global level.
- The dispatch takes the level from the request's peer instead of from the configuration; `control.Level` is unchanged.

### 4.3 Tests and gate

- The allow list: a source outside it gets nothing, inside it is served; the drop is counted.
- Per-consumer level: two raw senders from two prefixes, one at `no-write` and one at `full-service` under a global `full-service`, get the documented answers for a write; a peer entry above the global level is a configuration error at start.
- Test 3 runs per peer level.
- The threat model drops the non-goal of consumer authentication; the README's permissions table gains the per-consumer rule and its setup section covers the tunnel and the checklist.

## 5. P4 — Policy and audit

### 5.1 The write allow list

`writes.allow`: a list of entries, each with an object type, a property or `*`, and optionally a device (virtual instance or prefix of them) and a consumer prefix. At `full-service` a WriteProperty is forwarded only when an entry matches, after the reserved set and the priority rule, which stay as the floor. Default empty: nothing is writable until the operator lists it (decision 4). `control.Level.Write` takes the list as it takes the reserved set, and the order of the write rules gains one step. Test 8 gains the allow-list cases.

### 5.2 The audit log

`audit.file`: a path; when set, every forwarded write, every refusal, every subscription made and cancelled, the level in effect at start and every allow-list drop summary is appended as one JSON line: time in UTC, the peer's address and the prefix it matched, the level, the service, the virtual and the real device and object, the property, the index, the priority, the outcome (forwarded, the site's answer, or the refusal and its reason). The file is opened append-only (`O_APPEND`), written through a single goroutine, synced on each write, and never truncated by the shifter; rotation is the operator's, and the README says how. The audit line is in addition to the Info log, not instead of it. A test reads the file back after test 8 and checks each write has its line.

### 5.3 Gate

Test 8 with the allow list; the audit test; the README's write rules and operating notes revised, and its permissions table gains the allow-list row.

## 6. P5 — Host and secrets

- **Start-up checks.** The shifter refuses to start when the data directory is readable by anyone but its own account: on Unix, mode bits for group and other; on Windows, the directory's ACL through `golang.org/x/sys/windows` (a new dependency, to be confirmed), with the README giving the `icacls` command to fix it. The check can be turned off with `data.unchecked: true` for development, which logs at Warn.
- **The key in the OS key store**, optional: `data.key_store: file | dpapi | keyring`. With `dpapi` on Windows the key file is encrypted to the shifter's account, so a copied data directory is useless without the account; with `keyring` on Linux and macOS the OS keyring holds it. Default `file`, as today.
- **A log without real values**: `log.real_values: true` by default; `false` prints pseudonyms only, for a log that is shipped. `-table` is unaffected: it is the operator's tool on the host.
- **The deployment checklist** in the README: a dedicated non-admin account; no other BACnet software on the host; IP forwarding off between adapters; firewall rules per adapter (site adapter: UDP 47808 to and from the site subnet and the BBMD only; consumer adapter or tunnel: UDP 47808 from `consumer.allow` only); the data directory's permissions; backups of the key and table encrypted and off the consumer side; log shipping only with `log.real_values: false` or to a host as trusted as this one.
- **Incident guidance**: a key or table disclosure cannot be undone for data already stored by consumers; the response is a new key and an empty table, after which every consumer's stored names change, and the README says so plainly.

Gate: a test for the permission check on each platform the CI runs; README sections on the key store and the host checklist.

## 7. P6 — BACnet/SC on the consumer side (L6)

The standard's answer to O3 and I10: BACnet Secure Connect (ASHRAE 135-2020, Clause AB) carries BACnet over WebSockets with TLS 1.3, mutual authentication by device certificates, and a hub that connects the nodes. With it the consumer side needs no tunnel: each consumer holds a certificate the operator issued, the shifter is a node (or the hub), and the allow list of P3 becomes the certificates' identities.

It is a library project, **L6**, proposed here only in outline and designed when its turn comes:

1. In `../bacnet`, a `sc` transport package: the BVLC-SC codec, the WebSocket connection with TLS, the hub connection and the direct-connect option, VMAC addressing, the node's certificate handling, and the transport boundary the library's own roadmap needs for the client once a second transport exists.
2. The shifter's `internal/server`, which stays in the shifter (L4 was cancelled on 2026-10-22), takes a transport through that boundary, so that the consumer side can be BACnet/IP or BACnet/SC.
3. The shifter gains `consumer.transport: ip | sc` and the certificate paths; the per-consumer level of P3 keys on the certificate's subject instead of a prefix.
4. The library's `sim` gains an SC hub for the tests.

The site side stays BACnet/IP: the site is what it is. The sizing is weeks, not days, and it waits for a user who needs it.

## 8. Order, gates and the milestones already planned

1. **P1** first. No change to the rules, no library change, and it closes the threats that need the least discussion.
2. **P2** second. Its revision of the rules reopens two non-goals and must be reviewed; the code is small once the rules say what passes.
4. **P3** third. It is mostly operator setup and configuration; the code is the allow list and the per-peer level.
5. **P4** fourth, since the audit log needs P3's identity to be worth anything, and the write allow list is the first thing a reviewer will ask for after identity.
6. **P5** at any point after P1, in its own session: it touches `cmd/shifter` and the README and nothing the other packages change.
7. **L4** (the server package into the library) was cancelled on 2026-10-22: the library handles the plumbing, and `internal/server` stays in the shifter, where P1's server changes land.
8. **P6** as its own milestone, the next library one.

Versions are the user's: the v0.5.0 once reserved for the server move is free again. The packages above can be tagged as patch versions on the way, or P1 and P2 together as the first "hardened" minor; the plan does not decide it.

Every package ends as every milestone does: `go vet ./...` and `GOWORK=off go test ./...` clean, a README section, the README's rules revised where the package changed behaviour, and nothing uncommitted in `../bacnet` that the package made.

## 9. Configuration added, in one place

| Key | Package | Default | Meaning |
|---|---|---|---|
| `consumer.max_in_flight` | P1 | 64 | consumer requests being handled at once |
| `consumer.max_rps_per_source` | P1 | 20 | confirmed requests a second from one source |
| `consumer.max_sources` | P1 | 1024 | sources tracked for rate limits and recent peers |
| `consumer.max_subscriptions_per_source` | P1 | 256 | COV subscriptions one source may hold |
| `consumer.segment_timeout` | P1 | 4s | wait for the next Segment-ACK of a segmented reply |
| `site.max_subscriptions_per_device` | P1 | 16 | upstream subscriptions to one site device |
| `site.max_subscriptions` | P1 | 2048 | upstream subscriptions in total |
| `site.max_new_devices_per_minute` | P1 | 60 | new table records admitted from I-Ams |
| `pseudonym.pass_through` | P2 | `[]` | properties whose strings are not replaced |
| `pseudonym.hidden_objects` | P2 | `[network-port]` | object types refused and left out of object lists |
| `pseudonym.strict` | P2 | false | fixed vendor identifier; version strings replaced |
| `consumer.allow` | P3 | `[]` (any, with a Warn) | source prefixes served |
| `consumer.peers` | P3 | `[]` | `{prefix, control}`; a level per consumer, never above `control` |
| `writes.allow` | P4 | `[]` (nothing) | what `full-service` may write |
| `audit.file` | P4 | `""` | append-only JSON lines of writes, refusals and level changes |
| `data.unchecked` | P5 | false | skip the data directory permission check |
| `data.key_store` | P5 | `file` | `file`, `dpapi`, `keyring` |
| `log.real_values` | P5 | true | `false` logs pseudonyms only |

`pseudonym.replaced` is retired in P2.

## 10. Verification, as a whole

| Objective | Shown by | Package |
|---|---|---|
| O1 Disclosure | test 1 rewritten to scan for everything the site returned; the Network Port unit test; the fidelity test | P2 |
| O2 Integrity | test 3 per level and per peer; test 8 with the allow list; the library guard test | P3, P4 |
| O3 Identity | the allow-list and per-peer tests; the tunnel setup verified by the manual check from a tunnel peer | P3 |
| O4 Attribution | the audit test; a review of the audit file after the smoke test | P4 |
| O5 Site availability | the subscription and site-flood tests; the library's limit tests | P1 |
| O6 Shifter availability | the flood and reflection tests; the fuzzers; a soak run of the smoke test under a flood | P1 |
| O7 Secrets | the permission-check test; the key-store round trip | P5 |
| O8 Fail closed | the fuzzers under the recovery wrapper; test 3's refusal table; the untranslatable-value tests | P1 |

Beyond the tests: **an external review** of the threat model and the code before the shifter is described to anyone as a security layer, and a re-run of this plan's §10 table on every release that touches `internal/server`, `internal/shifter` or `internal/control`.

## 11. Decisions carried from the threat model

1. The strict profile (§12.1): included in P2 as `pseudonym.strict`, off by default.
2. Identity by tunnel now, BACnet/SC later (§12.2): taken with P3 on 2026-10-26.
3. `consumer.allow` empty means any source, with a Warn (§12.3): taken with P3.
4. `writes.allow` empty means nothing is writable at `full-service` (§12.4).

None is taken here; each is the user's, before the package that depends on it starts.
