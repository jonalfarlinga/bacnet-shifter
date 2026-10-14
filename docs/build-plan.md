# bacnet-shifter — Build plan

Companion to [anonymizer-prompt.md](./anonymizer-prompt.md), which says *what* to build. This document says in what order, where the boundary with the `bacnet` library falls, and what each step delivers. It is a plan, not the spec: deliverable 1 of the prompt, `docs/anonymizer-spec.md`, is step 0 below and is written after this plan is agreed.

The one rule that shapes the order: **writes to `../bacnet` are deferred as long as possible, and each one is confirmed first.** Everything in milestones M1 and M2 is built without touching the library. The first library commit comes at the end of M3, and the lift of the server package into the library, which the prompt lists as part of M1, is moved to the end, when the package has stopped changing.

## 1. What the prompt asks of the library, and what this plan does instead

| The prompt asks for, in `bacnet` | Done instead, in the shifter | Library change, when |
|---|---|---|
| A server package lifted from `client/sim` (station, dispatch, segmentation), with `sim` rebuilt on it | The same code copied out of `sim` into the shifter's own `internal/server` package and adapted there. `sim` is left as it is. | **L4**, last. The package moves into the library as `client/server` and `sim` is rebased on it, once M1 to M4 have stopped changing it. |
| `(*Client).WriteProperty` with priority and relinquish, and the §7.7 guard widened for writable devices | The shifter's write path is coded against a one-method interface and tested with a fake, so the priority rule, the reserved set and the translation are done before the library can send a write. | **L1**, at the end of M3. |
| `sim` accepts WriteProperty with a priority array and records the god-only services | A recorder on the site socket (`Config.OnPacket`) decodes every datagram sent and asserts what reached `sim` and at what priority. Only the SimpleACK back to the consumer needs `sim` to understand the write. | **L2**, at the end of M3, with L1. |
| A caller-encoded confirmed request behind a `Config` flag, for `god` | The translatable-payload check, the Warn logging and the banner are built and unit-tested first. | **L3**, in M4. |
| (not asked, but found) The reads return decoded values, not the reply's tags | The shifter re-encodes decoded values into tags. §2 says why this is expected to be faithful enough. | **L5**, only if the fidelity test disagrees. This is the one change that could be pulled forward. |

## 2. Facts checked in the library

Checked on 2026-10-14 against `../bacnet` at commit `837c927`. The working tree there has uncommitted explorer-sources work (README, `internal/`, `web/`): every library commit in this plan waits for that tree to be clean, on top of waiting for the user's go-ahead.

**What the shifter can build on, as exported today.**

- The guard is one function, `allowed()` in `client/client.go:427`. With `ReadOnly` the client sends exactly the no-write list. `Config.OnPacket` (`client.go:135`) sees every datagram sent and received, which is what the leak test, the guard test and the write recorder need. `Config.OnIAm` is the discovery hook. `Knock` and `Probe` read a device by address for `-add`. `SubscribeCOV` renews itself and `CancelCOV` exists.
- Routed devices work on the consumer side without library changes: the client learns a route from a routed I-Am (`client/routing_test.go`, `TestRouteLearnedFromIAm`) and asks Who-Is-Router-To-Network on demand (`TestRouterFoundOnDemand`). The shifter has to answer that message, and `plumbing` has the constant and `NetworksData` to encode I-Am-Router-To-Network.
- `ReadProperty`, `ReadPropertyMultiple` and `ReadRange` return decoded `client.Value`s (`client/value.go:37`), not the reply's tags. A `Value` keeps its kind, context tag number, raw bytes for context-tagged and date/time data, and nested items for constructed values, so it can be re-encoded with the `objects.Enc*` functions. What re-encoding loses: the character set a string was sent in (it comes back as UTF-8, the same text) and the tag number of a reserved or malformed tag (it becomes an octet string). Both are acceptable for v1 and are checked by the fidelity test. Errors come back typed (`BACnetError`, `RejectError`, `AbortError`), so the consumer gets the same class, code or reason.
- `client.ReadSpec` has property IDs but no per-property array index, so a consumer's ReadPropertyMultiple that indexes a property cannot be forwarded as one request. It is refused with a Reject (§6, decision 2).
- `bacnet.Parse` returns `ErrNotImplemented` for any confirmed service it has no type for (`parsing.go:302`), so the server cannot use it to see a LifeSafetyOperation it must refuse by name. The server parses BVLC, NPDU and APDU generically with the exported `plumbing` unmarshalers, which is all it needs: PDU type, service, invoke ID, segmentation flags, max-APDU, and the tags.
- `services` has a Who-Has decoder but no I-Have encoder, a COV notification type whose payload is built by hand, and a WriteProperty builder that hard-codes priority 16 and three value types (`services/wp.go:27`). The shifter builds these few payloads itself from `objects` primitives; none of them needs a library change.
- `sim` exports `Start`, `StartDevices`, `Default`, `RemoteSite`, `Addr`, `Addrs`, `Close`, `Silence`, `NotifyCOV` and `COVSubscriptions`, which is everything tests 1 to 7 need. It drops a WriteProperty silently today (`sim/sim.go:258`, no case for it), which is why tests 8 and 9 need L2 for their consumer-side half.
- The code to copy for the server package is in `sim/sim.go`: `serve`, `handle`, `confirmed`, `target`, `networkMessage`, `send`, the segmenting half of `read`, `sendSegments`, `continueReply`, `abortReply`, and in `sim/cov.go` the confirmed-notification sender `notify` and `covAcked`. About three hundred lines, all of it against exported `plumbing` and `objects` API.
- Nothing in the library uses YAML. The shifter adds `gopkg.in/yaml.v3` to its own module. The toolchain is Go 1.27; `bacnet` declares `go 1.25`, and the shifter does the same. There is no `go.work`; the `replace` directive is enough.

**What follows for the test harness.** The consumer in tests 2, 4, 5, 6 and 7 is a `client.Client`, as the prompt says. The consumer in test 3 cannot be: the client's own guard refuses the services the test must send. Tests 3, 8 and 9 use a small raw sender in the harness that builds frames with `plumbing` and waits for the reply on its socket. That is a test helper in the shifter, not a library change.

## 3. Module layout

```
bacnet-shifter/
  go.mod                 module github.com/jonalfarlinga/bacnet-shifter; go 1.25
                         require github.com/jonalfarlinga/bacnet, gopkg.in/yaml.v3
                         replace github.com/jonalfarlinga/bacnet => ../bacnet
  config.yaml            every option at its default, with a comment each; generated by
                         the program from its defaults table, and this copy is that output
  cmd/shifter/           runs with no arguments; loads config.yaml from the working
                         directory; -table is the only switch; the god banner
  internal/pseudonym/    the key file, HMAC derivation of names, instances and MACs
  internal/table/        table.json: forward and reverse maps, collisions, audit, -table listing
  internal/server/       consumer-facing socket: parse, dispatch, reply, segment,
                         confirmed-notification sender; copied from client/sim
  internal/translate/    Value <-> tags, and the rewriting of device identifiers,
                         names and addresses in requests, replies and notifications
  internal/control/      the four levels, the reserved set, the priority rule
  internal/shifter/      the proxy: site client, discovery, consumer dispatch,
                         COV fan-out, duplicate suppression
  internal/harness/      sim + shifter + consumer on loopback, packet recorders,
                         the raw sender; used by the tests only
  docs/                  anonymizer-spec.md, build-plan.md
```

The module path, the package split and the names are the one point still open (§6, point 9); they stand unless the spec changes them.

## 4. Steps, in order

### Step 0 — the spec. Stop for review.

`docs/anonymizer-spec.md`, in the style of `docs/library-upgrade-spec.md`: numbered sections, goals and non-goals, architecture, the pseudonym rules and the replaced/pass-through table, the control table, behaviour per message, configuration, testing, delivery plan, open questions. §6 of this plan records the decisions already taken, which the spec carries; its own open-questions section starts from what is left open there. No code before the spec is reviewed.

### Step 1 — M1, `no-write`. No library writes.

Ordered so that each piece is testable on its own before the network is involved.

1. **`pseudonym` and `table`.** Key generation and storage, HMAC-SHA256 derivation of object names, device instances and virtual MACs, collision detection and resolution, `table.json` load and save, the `-table` listing. Pure code with unit tests that are tests 5 (stability) and 6 (collisions) at unit level: same key, same pseudonyms; different key, all different; two forced collisions resolved and both recorded.
2. **`server`.** Copy the station code out of `sim` (§2 lists the functions) and reshape it: one socket, bound the way `client.Open` binds (so that it hears broadcasts, with the same `BindAny` and exclusion logic); generic BVLC/NPDU/APDU parsing; a handler interface the shifter implements; replies that carry the consumer's invoke ID and are segmented to the consumer's max APDU; the confirmed-request sender with its SimpleACK wait, for notifications; a pending map keyed by source and invoke ID for duplicate suppression; `OnPacket` on this socket too. The identity is a router to network V: replies to routed requests carry SNET V and the virtual MAC, and it answers Who-Is-Router-To-Network. Tested with a `client.Client` on loopback against a canned handler, including a reply long enough to segment.
3. **`translate`.** `Value` to tags and back, with a round-trip test over every kind including nested constructed values. Then the rewriting: device identifiers wherever they appear (I-Am, object-list, property references, the initiating device of a notification), the replaced string properties, device-address-binding, and the request side (the consumer's object identifiers back to real ones). The list of replaced properties is data, read from config.
4. **Site side.** Open the `client` with `ReadOnly: true`, the explorer's settings for the interface, BBMD and added addresses as `config.yaml` keys (the code in `internal/source/bacnet/source.go:150` is the model), `OnIAm` for discovery, one ReadProperty of object-name per new device, table entries for devices as they appear and for objects as they are first read.
5. **Consumer dispatch** in `shifter`: Who-Is to routed I-Ams from V plus an upstream Who-Is at most once a second, the interval a `config.yaml` key (§6, decision 7); Who-Is-Router-To-Network; ReadProperty, ReadPropertyMultiple and ReadRange translated, forwarded, translated back, answered with the same ComplexACK, Error, Reject or Abort; an upstream timeout answered with silence; Who-Has answered from the table with an I-Have; everything else refused with the documented Reject or Error. Every refusal logged with the consumer's address, the service and the level.
6. **Harness and tests.** `sim.Start()` or `sim.StartDevices(sim.RemoteSite(false))` as the site, the shifter on two loopback ports, a `client.Client` consumer whose `Broadcast` is the shifter's consumer address. Tests 1 (leak), 2 (fidelity, against a direct `client` read of the same sim), 3 for `no-write` (mirroring `client/guard_test.go`, with the raw sender), 5 and 6 end to end, 7 (`RemoteSite`, both routed and BBMD-reached devices appear on V).
7. **`cmd/shifter`** runs with no arguments and takes everything from `config.yaml` in the working directory: the prompt's flags, `sim`, `log` and `frames` among them, become keys there. When the file is absent the program writes it with every key at its default and a comment each, says where, and exits, since the site adapter has no default. `-table` is the only command-line switch, being a query rather than a setting. The README's setup instructions cover the two sockets (§6, decision 3) and the key file (§6, decision 5). The manual check: `go run ./cmd/explorer -interface <consumer-side address>` from `../bacnet` shows pseudonyms only.

Gate: `go vet` and `go test ./...` clean in the shifter; `git status` in `../bacnet` unchanged by this work.

### Step 2 — M2, `limited`. No library writes.

The site client opened without `ReadOnly`. One upstream `client.SubscribeCOV` per site object, confirmed if any consumer asked for confirmed, held in a fan-out table keyed by real device and object; each consumer's process ID and lifetime kept on the consumer side with its own expiry; notifications re-issued through `server` with the virtual device identifier and the consumer's process ID, confirmed when it asked; CancelCOV and expiry remove a consumer, the last one out cancels upstream, shutdown cancels all. Test 4 in full, including `sim.COVSubscriptions` empty after the last cancel, and test 3 for `limited`.

Settled point 2 of the prompt holds: nothing here needs the library.

### Step 3 — M3, `full-service`. The first library writes, at the end.

1. **Shifter first.** Decode the consumer's WriteProperty (the tags directly, since `services.ConfirmedWriteProperty.Decode` keeps only three value types); the priority rule (none to 13, 13 to 16 kept, 1 to 12 refused with write-access-denied, Null the same); the reserved set from `control`, as data in config; refusal of writes to replaced properties. The forward path calls a one-method interface, `siteWriter`, which a fake implements in the unit tests. Test 3 for `full-service` runs now for every refused service, since refusals never reach the site. The recorder half of test 8 runs now too: a write at 8, to out-of-service, and a LifeSafetyOperation put nothing on the site socket.
2. **L1, confirmed first:** `(*Client).WriteProperty(ctx, to, obj, prop, value, priority)` in `bacnet`, Null to relinquish, no blind retransmission, an error that separates "sent, no answer" from "never sent", the per-device writable switch of spec §7.7 and the guard widened for it, with the §7.7 test that every other service is still refused and that one writable device changes nothing for any other.
3. **L2, confirmed first, its own commit:** `sim` accepts WriteProperty on its commandable objects with a priority array and answers SimpleACK; it records and SimpleACKs the god-only confirmed services so tests can see what reached the site.
4. **Wire it.** `siteWriter` is the library client. Test 8 in full: a write with no priority reaches `sim` at 13, one at 16 at 16, the consumer gets the SimpleACK back.

Why the library work cannot be deferred past here: the site-side send is the only piece of M3 the shifter cannot do itself, because `client` has no write method and its guard refuses the service. Everything before 3.2 is done and tested without it.

### Step 4 — M4, `god`. One library write.

1. **Shifter first.** The translatable-payload check: for each god-only service, where in its payload device identifiers and addresses sit and whether the shifter can rewrite them; a payload it cannot translate is refused with an Error and a log line. The Warn line per forwarded request with address, device, service, object, property and priority; the start-up banner. A write to a replaced property forwarded verbatim, the table recording the rename, the pseudonym changing with it. All unit-tested against the fake.
2. **L3, confirmed first:** in `bacnet`, a way to send a confirmed request of any service, encoded by the caller, to a device switched to writable, behind a `Config` flag that is off by default and logs every such send at Warn; the §7.7 test extended so that a client without the flag is exactly as read-only as today.
3. **Wire it.** Test 3 for `god` and test 9, with L2's recording in `sim`.

### Step 5 — L4, the lift. Last.

Move `internal/server` into `bacnet` as `client/server`, beside `client/sim`, and rebase `sim` on it, keeping `sim`'s tests green. By now the package has been through four milestones and will not change under `sim`. This is what the prompt asked for in M1; doing it last means the library takes one commit instead of one per iteration. If the fidelity test in step 1.6 showed the re-encoding of replies to be lossy in a way that matters, **L5** (a client method that returns a reply's tags) joins this step, or moves ahead of step 1.6 if M1 cannot pass without it.

## 5. The library changes, as they will be proposed

Each is confirmed before it is written, lands as its own commit in `../bacnet`, and waits for a clean working tree there.

| | Change | Where | Test it carries | Earliest step |
|---|---|---|---|---|
| L1 | `WriteProperty` with priority and relinquish; per-device writable switch; guard widened for it | `client/` | §7.7 test: every other service still refused; one writable device changes nothing for the others | 3.2 |
| L2 | `sim` takes WriteProperty on commandable objects with a priority array; records and acks the god-only services | `client/sim/` | `sim`'s own tests, plus what shifter test 8 reads back | 3.3 |
| L3 | Caller-encoded confirmed request of any service, behind a `Config` flag, off by default, Warn per send | `client/` | §7.7 test: without the flag, read-only as today | 4.2 |
| L4 | The server package, with `sim` rebuilt on it | `client/server/`, new; `client/sim/` | `sim`'s tests unchanged and green | 5 |
| L5 | A read that returns the reply's tags (only if needed) | `client/` | fidelity test 2 | 5, or before 1.6 |

## 6. Decisions

Points found while checking the library, decided by the user on 2026-10-14. The spec carries them as decisions; only the last is still open.

1. **Reply re-encoding: accept the losses.** Replies are re-encoded from decoded values. A string comes back as UTF-8 and a reserved or malformed tag as an octet string; the fidelity test is the check. L5 stays a contingency.
2. **ReadPropertyMultiple with an array index on a property: refused.** The shifter answers a Reject and logs why; it does not split the request. The reason proposed is `other`, since the request is well-formed; the spec names it.
3. **The consumer-side socket: configured like the site side, by adapter and port.** `config.yaml` names an adapter and a port (default 47808) for each side, and the consumer socket is bound by the same rules as `client.Open` (`client/iface.go:81`): on Windows to the adapter's own address, which hears broadcasts there, so two adapters can both use 47808, and that is the setup the instructions describe. On Linux and macOS a socket that hears broadcasts binds every address, so the two sides cannot share a port; the instructions say so and give the alternatives, another port for the consumer side or a VM or network namespace per side. Under sim both sides are on loopback with distinct ports.
4. **Configuration: `config.yaml` in the working directory, nothing on the command line.** The shifter runs without arguments and loads every setting from `config.yaml` in the directory it is started from. The file lists every variable with its default value and a comment; the program generates it from its defaults table when it is absent, and the copy in the repo is that output. A key missing from the file takes its default. `-table` is the only switch, being a query rather than a setting.
5. **The key file on Windows: documented.** The file is written with mode `0o600`, which NTFS ignores. The setup instructions say the data directory must be one that only the shifter's account can read.
6. **Upstream in-flight limit per routed network: a `config.yaml` key.** Default the library's 1 (`DefaultMaxInFlightNet`), to raise for sites whose routers take more at once.
7. **Who-Is forwarding: at most one upstream Who-Is a second.** The interval is a `config.yaml` key with default 1000 ms.
8. **The server package's home for L4: `client/server`**, beside `client/sim`.
9. **module path and package split.** `github.com/jonalfarlinga/bacnet-shifter` and the layout in §3 stand unless the spec changes them.

## 7. Milestone gates

Every milestone ends with `go vet ./...` and `go test ./...` clean in the shifter, the same in `../bacnet` when a library change landed in that milestone, a README section for what the milestone added, and in `../bacnet` no uncommitted change that this work made.
