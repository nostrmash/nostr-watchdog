# Integration

Branch `feat/rust-integration` starts at the shared rewrite baseline `8283bdba641543eca6c13e116cbed48e7951a7d1`. The three reviewed snapshots were merged with `--no-ff`, in this order, without changing their branches:

| Step | Reviewed commit | Merge commit | Result |
| --- | --- | --- | --- |
| Production hardening | `9103d7ffce027f1be805a0b1698b3a18dae20fdb` | `62439ed` | Clean. Main workspace tests passed: core 35, engine 3, native 2, notify 9, store 15. |
| Native Marmot | `1d2e349cab3480639576c52403eba0150e0acd4f` | `267b501` | Clean tree merge. One behavioural mismatch, recorded below. |
| Cloudflare Marmot | `5da50d71d29ad11de1e3735eafeea39e3521a384` | `6d40646` | Clean. The Durable Object worker typechecks for `wasm32-unknown-unknown`. |

Later reviewed corrections were merged after that table:

| Step | Reviewed commit | Merge commit | Result |
| --- | --- | --- | --- |
| Native admission failure | `70d3a63008cc1c09dccb8ea29aaf84f43a5b8544` | `e939b27` | Clean. `marmot_recovery.rs` auto-merged. |
| Native checkpoint ordering | `61dbbda279d7c6649836951f5f63d64e41044f05` | `648a42a` | Clean. A checkpoint must not restore a previous operation state. |
| Cloudflare relay correlation | `0331239089875b6758d2e4037b311baf2853b1d9` | `b0a81f4` | Clean. |
| Cloudflare token identity | `2c45627e4bacd273757aeff82f9f53d9463021d3` | `b9cdbab` | Clean. Wake records use the full identity, and the historical index commits by id. |

No newer commit was on either agent branch at the last fetch. Those four merges were clean. The claim-test edit from the first integration was preserved.

The files touched by the three snapshots do not overlap. Git reported no conflicts.

## Qualification

Implementation tested by the runs below is `be486a8ea6fa20e1d5dc40e1ae78d1062989235a`. Later commits containing only documentation record the results.

The reviewed integration baseline was `3ef57fac5c3ae6f7525705e5595d1c2982337b24`. The fetched integration branch contained all three handoff tips and matched GitHub before changes. The TypeScript behavioral reference is `a236b35a9dda14aa6f1a96dc37fc2daccc838ed8`. Further handoff details and prior experiments remain in [native Marmot](agent-a-integration.md), [Cloudflare Marmot](agent-b-integration.md), and [production hardening](agent-c-integration.md).

| Development change | Evidence |
| --- | --- |
| Native relay lifetime | Separate handshake, DNS, and TCP connection deadlines. The proxy caps active clients and outstanding DNS work. Tests exercised established forwarding past the handshake deadline, saturation, timeout, and shutdown. |
| Cloudflare history | `transactionSync` covers operation retirement, index writes, and the sealed account revision CAS. Per-bucket commitments are inside the sealed snapshot. Workerd exercised exceptions before and after index insertion, a losing CAS, a later unrelated revision, retired-operation recovery after restart, and refusal of new encryption after an indexed row was removed. |
| Historical authentication | Versioned HMAC-SHA256 over the full canonical record. HKDF derives the history authentication key separately from snapshot encryption. Authenticated fields include the project, account, recipient, group, payload digest, terminal message and push evidence, event IDs, revision, and writer. |
| Transport identity and evidence | The Worker normalized an `nsec`/`npub` pair for SmartFlowSocial and hex keys for NostrMash. Onboarding requires matching project, operation, and sender evidence. The shared engine merges persisted acceptance before deciding lifecycle. Both operational stores fence completion and keep the original message event ID. |
| Partial trigger recovery | The authority tracks each trigger independently. Accepted events remain accepted when another trigger fails. Temporary failures get bounded per-trigger retries. The operational store follows the authority's disposition and keeps aggregate acceptance data and counters. |
| D1 fallback | A durable fallback insert precedes fenced completion. Local workerd exercised both interruption directions, including a persisted fallback followed by a failed completion and convergence on retry. SQLite completes both records in one transaction. |
| Scheduling and readiness | Separate bounded operational and synchronization work, effective project routing and emergency stops, interval leases, and bounded Marmot response reads. Authenticated Worker diagnostics expose actual account, membership, Welcome, recipient and token observations. |

### History and retention

An operation is absent only when the sealed snapshot's commitment and the bounded SQL bucket agree, and there is no corresponding historical row. An indexed entry requires an exact record digest and a valid record MAC. A missing or modified required record latches an integrity failure on detection. An ordinary request reads one bucket and uses the operation ID primary key. Full-history scans are reserved for operator diagnostics or offline recovery. [Cloudflare synchronous SQLite transactions](https://developers.cloudflare.com/durable-objects/api/sqlite-storage-api/#transactionsync)

The active journal retains unresolved operations. Compaction excludes the current mutation and the Welcome needed for onboarding evidence. Accepted operations with unresolved push work expire at the authority age limit, including when the caller stops polling. Version 2 snapshots use bounded compression before authenticated encryption, which allowed the runtime test to reach the journal retirement threshold. The history retains operation identities for as long as a replay can arrive. The per-bucket and snapshot limits are fail-closed capacity limits. Monitor long-lived account size before rollout.

A legacy snapshot without authenticated history metadata requires recovery or deliberate re-onboarding. Preserve the full state and its history together. A complete point-in-time rollback can restore mutually consistent old records and snapshots. Treat a known restore as an operator recovery event and follow the fencing procedure in [deployment.md](deployment.md). The service has no independent witness for a complete rollback.

### Cloudflare account capacity

The authenticated Marmot readiness response reports `authority.storageCapacity` with live used and limit counters. It lists a warning once a counter reaches 80% of its limit. The sealed account supplies the committed plaintext byte count after authenticated decompression. The sealed row length includes a 34-byte envelope and authentication tag for format 2. The response reports the largest history bucket and total retired operations from SQLite. These counts describe capacity. Operation lookups still verify the bucket commitment and record MAC. The capacity query leaves state unchanged.

| Limit | Current bound |
| --- | ---: |
| Accounts per Durable Object | 1 |
| Groups per account | 64 |
| Message records per group | 4,096 |
| OpenMLS provider entries per account | 20,000 |
| Snapshots and checkpoints per group | 32 each |
| Serialized plaintext account document | 8,388,608 bytes |
| Sealed account row, application cap | 1,500,000 bytes |
| Active publication journal | 64 target, 128 hard cap |
| Authenticated historical index | 256 buckets, 256 records per bucket |
| Rolling ingress markers | 4,096 |

The platform documents an 8 MB maximum row or BLOB and a 10 GB limit per paid SQLite Durable Object. The Watchdog applies the smaller account cap above. A full bucket can stop retirement before the total historical index reaches 65,536 entries. [Cloudflare Durable Object limits](https://developers.cloudflare.com/durable-objects/platform/limits/)

The controlled local workerd scenarios used generated identities and loopback relays. The operations used actual MDK encryption, SQLite persistence and relay acknowledgement. The autonomous test filled the journal with 62 settled alerts, changed and revoked recipient tokens, interrupted and retried retirement, restarted workerd and recovered the original accepted event ID. A separate conversation verified three consecutive MLS epoch transitions, subsequent alert decryption, and incoming recipient messages. The scheduled incident scenario also went through both Worker bundles and actual D1.

| Sample | Plain / sealed bytes | Message records | MLS entries | Snapshots / checkpoints | Journal / retired / peak history bucket |
| --- | ---: | ---: | ---: | ---: | ---: |
| Before the 62 sends | 181,703 / 52,073 | 5 | 13 | 1 / 0 | 2 / 0 / 0 |
| Journal target reached | 3,118,049 / 997,747 | 129 | 13 | 1 / 0 | 64 / 0 / 0 |
| After retirement, token changes and restart | 3,126,332 / 997,205 | 139 | 13 | 1 / 0 | 64 / 1 / 1 |
| Before epoch changes in second conversation | 214,329 / 55,443 | 12 | 14 | 1 / 0 | 7 / 0 / 0 |
| After three epoch changes and incoming traffic | 597,897 / 116,785 | 24 | 14 | 4 / 3 | 11 / 0 / 0 |

The 62 sends took 21.6 seconds total, with a 355 ms median and a 569 ms p95. Readiness probes took 14–40 ms. The highest sampled local workerd process RSS was 374 MiB. This process includes the local runtime and its isolates. Remote isolate memory, CPU and network latency require staging measurements.

At the journal target, the sealed account had 502,253 bytes of room and the plaintext account had 5,270,559 bytes of room. The sealed account was the closest hard limit at roughly 66% used. The journal is designed to hold steady at its target when publications settle. Larger messages, multiple push destinations and retained epoch snapshots can exhaust sealed bytes sooner. A stalled journal or a busy epoch history can change which bound is reached first. The 4,096 message-record bound counts storage records, including protocol activity. A mixed workload's safe lifetime depends on the traffic and state composition.

The storage-only regression exercised 4,100 historical identities and prevented re-encryption when the associated index was missing. Separately, hashing sequential synthetic IDs `alt_capacity_fixture_00001` and onward into the real 256 SHA-256 partitions produced a largest bucket of 29 at 4,100 entries, the first 80% warning at 43,127 entries, and a first rejected insertion at 55,314. This sample only measures partition distribution. It uses no cryptographic messages or SQLite transactions and gives no guaranteed count before a bucket fills.

MDK already prunes old replay anchors and state checkpoints within its canonical convergence policy. Its group message retention features do not authorize clearing raw transport replay state or retired application identities. The Worker retains its existing maintenance policy and authenticated history. Capacity warnings and the documented rotation procedure preserve original operation IDs and avoid re-encrypting old outbox rows. [Operator procedure](deployment.md#capacity-and-staging-measurements)

### Current dependency review

All three lockfiles passed `cargo audit` and `cargo deny` (advisories, dependency bans, licenses and sources). The repository remains Unlicensed. Existing upstream licenses and attribution remain in place.

| Warning | Path and disposition |
| --- | --- |
| `chrono` 0.4.45 | Unmaintained runtime dependency in the three workspaces. No patched version is listed. The existing advisory-specific policy remains in place. |
| `heapless` 0.8.0 | Nine unsoundness warnings. The locked graph reaches it through `nostr → faster-hex` on Linux and WASM. All production builds enable `faster-hex/alloc`, which compiles out its heapless code. The affected APIs have no production caller in this graph. `faster-hex` 0.10 requires heapless 0.8 for its non-alloc implementation. |
| `instant` 0.1.13 | Unmaintained WASM-only dependency of a second upstream Nostr crate in the helper lockfile. It is absent from the Linux native graph and both deployed WASM workspaces. |
| `proc-macro-error2` 2.0.1 | Unmaintained build-time macro support through the upstream libcrux/Hax path. It has no request-time call site. |
| `zbus_names`, `zvariant`, `zvariant_derive` | Unmaintained. The first two are Linux helper native dependencies through MDK's Secret Service keyring and also support host macros. The derive crate only runs at build time. The Workers have no D-Bus dependency. |

The compatibility crate re-exports the upstream FFI and forwards the selected bundled SQLCipher and OpenSSL features. It declares no separate `links` value and runs no build script. The locked native graphs have one SQLite link provider, upstream `libsqlite3-sys` 0.40.0. The optimized helper fixture verifies the linked SQLCipher 4.20.0 and SQLite 3.54.1. The Cloudflare release has no SQLCipher linkage. The Cloudflare workspace uses the adapter for native MDK interoperability tests. No new suppression or dependency upgrade was required for the warnings above.

### Executed tests

- Native controlled test used the actual watchdog and helper, a real HTTP monitor, an independent official MarmotApp recipient, and isolated relays and state. The recipient decrypted the outage and the recovery alert in the same conversation. The original outbox kept its event ID and `relay_accepted` message state. Native push evidence remained `unobservable`. The configured critical fallback reached an isolated Telegram-compatible endpoint. Representative helper crash boundaries were exercised. The final optimized native suite passed in 175.20 seconds, including a direct check of SQLCipher 4.20.0 and SQLite 3.54.1.
- Workerd controlled test ran the actual operational and cryptographic Worker bundles together through `MARMOT_SENDER`. Independent official recipients retrieved their Welcomes and joined separate SmartFlowSocial and NostrMash groups. Both projects reached authenticated participation and token readiness. An unknown project and a mismatched internal token were rejected. Retrying the same onboarding operation with matching credentials succeeded. A scheduled SmartFlowSocial outage generated a D1 outbox row and a relay-accepted message, which the official SQLite MDK recipient decrypted. An independent test key opened the notification gift wrap and verified kind 446. One target failed temporarily, the local fallback accepted the critical alert, and restart recovery published the remaining trigger while retaining one application encryption. A subsequent scheduled recovery alert decrypted in the same conversation.
- The opt-in public Workerd test completed in 32.68 seconds using disposable identities and the WhiteNoise EU and US relays. The official recipient independently retrieved and joined the Welcome and decrypted both alerts, including the alert after restart. The fixture server key opened the relay-retrieved notification gift wrap using a synthetic token. The disposable IDs were `91a9b9102fef6233e751584b4f409fc8dd19b54050be0b03274b473a89fba0c6` for the first alert, `78c3fcc1e09701e14c7d9f3ba51dad15da08848d80fd1a74af74622d544f813d` for the trigger, and `802b392fd17bcc36fbc40913c920d78bbd18f3344604dad4789dd33cf20867bf` for the alert after restart.
- A separate local fault fixture tested the operational Worker across its actual Durable Object binding. A malformed successful response yielded `marmot_response_invalid`. A response that sent its headers and stalled its body yielded `marmot_timeout` in 2.03 seconds against a two-second request budget. The paired Worker test continues to use the actual cryptographic authority.
- The operational workerd suite applied all D1 migrations, exercised fallback deduplication and interrupted completion, checked scheduler bounds and the signed `watchdog-status-v1` response, and passed. Two concurrent requests sharing the same signed heartbeat nonce yielded one success and one replay rejection. Equal timestamps could not replace progress. A scheduled reminder loaded the open incident, paused on its HTTP probe, and produced no reminder after the real operator acknowledgement. An authenticated onboarding request reported the missing cryptographic binding as unavailable. Remote D1 behavior remains a staging measurement.

```bash
cargo fmt --all -- --check
cargo test --locked --workspace --exclude watchdog-worker
cargo test --locked -p watchdog-store --features sqlite --lib
cargo build --locked --release -p watchdog-native
cargo build --locked --release --manifest-path crates/watchdog-marmot/Cargo.toml
cargo test --locked --manifest-path crates/watchdog-marmot/Cargo.toml --lib
cargo test --release --locked --manifest-path crates/watchdog-marmot/Cargo.toml --test fixture_exchange -- --test-threads=1
npm ci --prefix crates/watchdog-marmot-worker/worker
worker-build --release crates/watchdog-worker -- --locked
sh crates/watchdog-marmot-worker/worker/build-release.sh
cargo test --locked --manifest-path crates/watchdog-marmot-worker/Cargo.toml --workspace --lib
cargo test --locked --manifest-path crates/watchdog-marmot-worker/Cargo.toml -p marmot-worker-interop --test two_member
cargo test --locked --manifest-path crates/watchdog-marmot-worker/Cargo.toml -p marmot-worker-interop --test workerd_conversation -- --ignored --test-threads=1 --skip public
sh tests/runtime/worker-scheduled.sh
```

The public run was a single explicit invocation of `public_network_marmot_exchange_survives_restart` from the same test target with `--ignored --exact --nocapture`.

Local Cargo runs used Rust 1.100.0 and locked dependencies. Native helper builds used Odin `dev-2026-10-nightly:84bc3fc`. Local Wrangler came from the npm lock at 4.166.0.

- The owner acceptance script also ran against an eligible independent MarmotApp recipient on a local relay. It established the conversation, observed the test token, sent two explicit alerts across process restart, and the recipient decrypted both in the original group. The final optimized script run completed in 76.24 seconds.

### Deployment artifacts

Both staging manifests passed Wrangler dry-run bundling.

| Artifact | Total upload | Gzipped upload |
| --- | ---: | ---: |
| Operational Worker | 3,986.43 KiB | 2,054.47 KiB |
| Marmot Durable Object Worker | 10,757.03 KiB | 4,129.41 KiB |

The sizes above are local bundle measurements. Staging resource setup, secret installation, deployment order, onboarding, activation, and rollback are in [deployment.md](deployment.md). Native and staging phone procedures are in [acceptance.md](acceptance.md).

### Migration manifest

| State | Manifest |
| --- | --- |
| Operational SQLite and D1 | Apply the ordered `migrations/0001_init.sql` through `migrations/0012_transport_evidence.sql`. No new operational SQL migration was needed. |
| Marmot Durable Object | The `v1` Wrangler class migration creates the SQLite class. The class initializes its account, operation, and history-bucket tables. Snapshot version 2 records the sealed index commitments. |
| Native helper | Keep SQLCipher state and the operation journal together. The helper uses its upstream migrations. |

### CI and Docker

The six baseline jobs passed on `3ef57fa`, including the original Docker startup smoke test. [Baseline run](https://github.com/nostrmash/nostr-watchdog/actions/runs/45967372076)

The first expanded run on `7922c52` passed Rust tests, dependency and license audits, the WASM checks, the D1 runtime suite, and the image startup and volume smoke steps. The autonomous Worker fixture had not yet observed the replacement token when it attempted publication. The image job built its Rust qualification binary and failed while looking for it in the old Cargo artifact directory. The test now waits for authenticated token-directory evidence, and the image build selects the executable from Cargo's machine-readable output. [Expanded run](https://github.com/nostrmash/nostr-watchdog/actions/runs/45975386938)

The run at `d3193b6` found a Linux stack overflow in the native official-recipient test and a recipient decryption failure in the Docker fixture after the outage reached a relay-accepted row. The native suite now sizes the thread polling the MDK future and checks independent relay evidence before decryption. The earlier image fixture also tried the recipient's history-repair operation after incremental synchronization missed the event. The image driver stage exports only that test executable. [Linux and Docker failure logs](https://github.com/nostrmash/nostr-watchdog/actions/runs/45977380393)

The expanded dependency checks caught both a command-line option placement error and a real vulnerable SQLCipher build in the pinned MDK lockfiles. Both native dependency graphs now select upstream `libsqlite3-sys` 0.40.0 and SQLCipher 4.20.0 through a local compatibility crate. The MDK revision is unchanged. The vulnerability gate remains enabled, and both RustSec and license scans passed against the patched lockfiles. The existing policy still reports transitive unmaintained and unsoundness warnings. [RustSec binding advisory](https://rustsec.org/advisories/RUSTSEC-2026-0459.html) · [RustSec SQLCipher advisory](https://rustsec.org/advisories/RUSTSEC-2026-0502.html)

The recipient history-repair run confirmed the image published an independently matched group event and trigger, then hit `full_history_coverage_unproven` before it could decrypt. The native test relay now applies history limits separately to each filter and the test account uses explicitly isolated relay routes. The native crash check waits for the recovered message to decrypt before asserting that the recipient has exactly one copy. [Earlier image job](https://github.com/nostrmash/nostr-watchdog/actions/runs/45979994297/job/140441167928)

The image job now runs the packaged watchdog and helper against a dedicated official SQLite MDK recipient. It publishes a key package with the native profile's required proposals, retrieves the signed relay Welcome, and decrypts the exact group events from the scheduled outage and recovery. The test checks the watchdog's stored receipt and the helper's journal before and after removing and replacing the container on the same mount. The recipient checks for a duplicate outage by comparing decrypted content among newly published group messages. The full native `MarmotApp` fixture covers token readiness, trigger evidence, and crash boundaries separately. The same direct-recipient test passed in 124.91 seconds against the local optimized process pair and persistent directory. The image job is the evidence for container replacement.

The latest implementation run uses the exact commit above. It covers Rust, audits, WASM compilation, operational workerd, container replacement, and the native and paired Worker fixtures. [Implementation run](https://github.com/nostrmash/nostr-watchdog/actions/runs/45986345284)

| Job | Conclusion | Evidence |
| --- | --- | --- |
| `rust` | Passed | Workspace tests, SQLite tests, optimized build, Clippy, and license and vulnerability checks for all three lockfiles. [Job log](https://github.com/nostrmash/nostr-watchdog/actions/runs/45986345284/job/140462843474) |
| `wasm-worker` | Passed | Operational Worker and pinned MDK engine compile to WASM. [Job log](https://github.com/nostrmash/nostr-watchdog/actions/runs/45986345284/job/140462843337) |
| `workerd` | Passed | Local D1 migrations, scheduler, concurrency, and both interrupted fallback directions. [Job log](https://github.com/nostrmash/nostr-watchdog/actions/runs/45986345284/job/140462843384) |
| `cloudflare-marmot` | Passed | Both optimized Worker bundles, independent MDK recipient, and actual workerd interop and history recovery. [Job log](https://github.com/nostrmash/nostr-watchdog/actions/runs/45986345284/job/140462843063) |
| `native-marmot` | Failed | The 24 helper library tests and linked SQLite/SQLCipher check passed. The standalone official app recipient did not decrypt the first alert, and the packaged fixture recipient did not join its Welcome. The shell stopped before the operator-script fixture. [Job log](https://github.com/nostrmash/nostr-watchdog/actions/runs/45986345284/job/140462843442) |
| `image` | Passed | Linux amd64 startup, UID 10001, directory mode 0700, runtime libraries, and direct-recipient exchange across container replacement in 129.88 seconds. [Job log](https://github.com/nostrmash/nostr-watchdog/actions/runs/45986345284/job/140462843368) |


### Release gates

| Gate | Status | Evidence or remaining condition |
| --- | --- | --- |
| G1 Integration and handoffs | Passed | All three reviewed tips are ancestors and the integration branch was fetched and preserved. |
| G2 Historical atomicity | Passed | Workerd transaction rollback, losing CAS, interrupted retirement, later unrelated revision, and restart. |
| G3 Historical identity and retention | Partial | Canonical MAC, per-bucket completeness proof, and missing-row halt passed. Full rollback requires the operator recovery procedure. Long-lived account capacity is still unmeasured. |
| G4 Standard Nostr key formats | Passed | Both project configurations ran through the private Worker binding with the two formats. Invalid key unit coverage passed. |
| G5 Monotonic message evidence | Passed | Actual SQLite and workerd D1 store tests and integrated restart evidence. |
| G6 Multi-trigger reconciliation | Passed | First target accepted, second temporarily interrupted, third publication recovered, and the first trigger stayed at one send. |
| G7 Native egress | Passed | Actual loopback fixture, stalled handshakes, capacity limits, shutdown, and long-lived forwarding checks. |
| G8 Onboarding and readiness | Passed | Both isolated Cloudflare projects reached account, Welcome, participation, canonical group and token readiness. The native SmartFlowSocial conversation and the acceptance script also reached token readiness. |
| G9 Scheduling and fallback | Partial | Configured local critical fallback and bounded workerd scheduling passed. The pinned native helper still synchronizes its hosted accounts through a shared upstream catch-up call. |
| G10 Native incident delivery | Passed | Actual executables, monitor outage and recovery, independent recipient, persisted evidence and fallback. |
| G11 Paired Cloudflare incident | Passed | Actual workerd and cross-script binding, scheduled incident and subsequent recovery alert. |
| G12 Independent recipient and trigger | Passed | Local paired Worker and opt-in public recipient decryption and trigger validation. |
| G13 Restart and duplicate prevention | Passed | Both runtimes recovered persisted conversations and kept the original application event. |
| G14 D1 and parity | Partial | Local migrations, both interrupted fallback completion directions, stale claim and generation fences, simultaneous replay, equal timestamps, the acknowledgement/reminder race, and signed status passed. Remote D1 remains a staging measurement. |
| G15 Integrated CI | Partial | Five of six jobs passed on the exact implementation commit. The optimized Ubuntu `MarmotApp` fixtures failed at recipient synchronization, while the same suite and the operator script passed on the local optimized build. |
| G16 Docker conversation persistence | Passed | Both packaged executables ran against the same mounted operational and cryptographic state. The independent recipient decrypted the outage and recovery, and the prior application ID remained stable after container replacement. |
| G17 Isolated staging procedure | Passed | Both build and dry-run bundle paths verified. Authorization is required for provisioning and deployment. |
| G18 Native physical WhiteNoise | Untested | Requires an observed test iPhone notification. |
| G19 Cloudflare physical WhiteNoise | Blocked | Requires authorized isolated staging and an observed test iPhone notification. |

### Release assessment

The decisive incident path is working locally in both deployment shapes. The native MDK API can acknowledge the group message without exposing alert-specific push acknowledgement. The native helper also checks canonical membership before calling the upstream kind-9 send. A membership change between those operations remains possible because the pinned native API has no atomic guarded send. These upstream limitations remain visible in deployment and acceptance decisions.

Release qualification remains open. The Linux `MarmotApp` fixtures failed during recipient catch-up despite the local native pass and the separate Linux Docker pass with a direct official MDK recipient. The exact cause of the Linux recipient failures remains unresolved. The optimized image is built and tested on Linux amd64, and both isolated Worker manifests are ready for authorized staging. Remote D1 and Durable Object measurements, notification-server processing, and observed iPhone notifications remain pending.
