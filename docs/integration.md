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

## Final release qualification

All six expanded GitHub Actions jobs passed on implementation `5a8175536d0e1c6f249f66e92ec72c1e070e0b8c`. The run used Ubuntu amd64, Rust 1.100.0, Node 22, Odin `dev-2026-10` revision `84bc3fc`, the locked Marmot MDK revision `ca52a04718628f08ed76b777df9c444594074182`, and patched SQLCipher. [Expanded CI run](https://github.com/nostrmash/nostr-watchdog/actions/runs/46008823008)

### Native synchronization

The reviewed Ubuntu run failed in the standalone official MarmotApp decryption test and the packaged official MarmotApp Welcome test. The optimized diagnostic run reproduced the decryption failure. Its loopback relay delivered the recipient token event and the alert event with the same timestamp. It returned both events in finite `#h` queries, then left two `NEG-OPEN` comparisons unanswered for the shared timestamp. The pinned transport treats the unanswered boundary as inconclusive and can hold the group while that boundary remains unproven. This accounts for the alert being relay-accepted while its recipient message projection was still empty. The separate official SQLite MDK recipient does not need the app runtime's history coverage decision. [Reviewed native failure](https://github.com/nostrmash/nostr-watchdog/actions/runs/45986345284/job/140462843442) · [Instrumented Ubuntu failure](https://github.com/nostrmash/nostr-watchdog/actions/runs/46000741408/job/140511430147)

The fixture relay now publishes its NIP-11 capabilities, enforces the advertised 500-event replay limit for each NIP-01 filter, and returns a protocol refusal for unsupported NIP-77 comparisons. This gives the app runtime the relay's actual coverage capabilities. Its normal relay retrieval and official decryption assertions remain in place. Both native scenarios now independently verify the accepted signed Welcome and its intended sender and recipient before asserting that the MarmotApp recipient joined. The signed-event verification never feeds the recipient's runtime. Failure traces report event sequence, kind, timestamp and filter shape without keys, tokens or message bodies.

The next Ubuntu run reproduced the packaged Welcome failure with the relay capability correction in place. Its trace shows one live delivery of the Welcome and 20 replays on renewed account inbox subscriptions, each ending in EOSE. The recipient had been configured with `CursorPersistence::Frozen`, the pinned MDK's short-lived notification-wake mode. Each catch-up in that mode reactivates the inbox, replacing the current subscription attempt and resetting replay coverage. The packaged test models a recipient that stays open throughout the incident and sender restarts. It now uses the normal advancing cursor and checks network readiness before onboarding. The signed Welcome still travels through the real relay and the independent official recipient still supplies the canonical group admission and decryption evidence. The corrected local fixture passed and issued two inbox requests across the complete incident, helper restart and crash exercise. The private MDK disposition of the earlier Welcome remains unobserved. [Reproduced packaged failure](https://github.com/nostrmash/nostr-watchdog/actions/runs/46003594793/job/140521102254) · [Pinned activation and catch-up policy](https://github.com/marmot-protocol/mdk/blob/ca52a04718628f08ed76b777df9c444594074182/crates/marmot-app/src/client/sync.rs#L1352)

Two Ubuntu runs joined the conversation and decrypted both the outage and recovery. The helper reached the accepted-send crash marker in one run and the submitted-send marker in the other. In both cases it then logged an OpenSSL HMAC provider failure and ended by signal. The old fault hook used normal process exit, which invokes native teardown while MDK workers can still be using SQLCipher. The fault hooks now use POSIX `_exit(75)` to model abrupt loss at the same durable boundary. The tests still require that status, recover exactly one accepted operation, and verify independent decryption. The SQLCipher and SQLite versions remain 4.20.0 and 3.54.1. [Accepted-send log](https://github.com/nostrmash/nostr-watchdog/actions/runs/46005053707/job/140526012788) · [Submitted-send log](https://github.com/nostrmash/nostr-watchdog/actions/runs/46007339979/job/140533728940)

```bash
export ODIN="$HOME/.local/odin-dev-2026-10/odin"
cargo build --release --locked -p watchdog-native
cargo build --release --locked --manifest-path crates/watchdog-marmot/Cargo.toml
cargo test --release --locked --manifest-path crates/watchdog-marmot/Cargo.toml --lib
export WATCHDOG_TEST_BINARY="$PWD/target/release/nostr-watchdog"
for run in 1 2 3; do
  cargo test --release --locked --manifest-path crates/watchdog-marmot/Cargo.toml \
    --test fixture_exchange -- --test-threads=1 || exit 1
done
cargo test --release --locked --manifest-path crates/watchdog-marmot/Cargo.toml \
  --test fixture_exchange whitenoise_script_onboards_and_reuses_the_conversation \
  -- --ignored --exact
```

### Staging artifacts

Both actual deployment configurations passed Wrangler 4.166.0 dry runs using the optimized bundles.

| Worker | Total upload | Gzipped upload |
| --- | ---: | ---: |
| Operational Worker | 3,986.58 KiB | 2,054.53 KiB |
| Private Marmot Worker | 10,754.13 KiB | 4,126.85 KiB |

The private binding, dedicated resources, authorization, migration order, rollback, and remote measurement steps are in [the staging runbook](deployment.md#isolated-cloudflare-staging). Native and Cloudflare locked-iPhone procedures are in [WhiteNoise acceptance](acceptance.md).

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

The controlled local workerd scenarios used generated identities and loopback relays. The operations used actual MDK encryption, SQLite persistence and relay acknowledgement. The autonomous test filled the journal with 62 settled alerts, changed and revoked recipient tokens, interrupted and retried retirement, restarted workerd and recovered the original accepted event ID. The wider sequence recorded 11 committed retirements after restart. A separate conversation verified three consecutive MLS epoch transitions, subsequent alert decryption, and incoming recipient messages. The scheduled incident scenario also went through both Worker bundles and actual D1.

| Sample | Plain / compressed / sealed bytes | Message records | MLS entries | Snapshots / checkpoints | Journal / retired / peak history bucket |
| --- | ---: | ---: | ---: | ---: | ---: |
| Before the 62 sends | 181,585 / 50,533 / 50,567 | 5 | 13 | 1 / 0 | 2 / 0 / 0 |
| Journal target reached | 3,117,368 / 995,634 / 995,668 | 129 | 13 | 1 / 0 | 64 / 0 / 0 |
| After eight actual retirements | 3,172,524 / 1,007,623 / 1,007,657 | 145 | 13 | 1 / 0 | 64 / 8 / 1 |
| After token changes and restart | 3,173,189 / 1,005,207 / 1,005,241 | 153 | 13 | 1 / 0 | 64 / 11 / 1 |
| Before epoch changes in second conversation | 214,923 / 55,651 / 55,685 | 12 | 14 | 1 / 0 | 7 / 0 / 0 |
| After three epoch changes and incoming traffic | 600,593 / 117,185 / 117,219 | 24 | 14 | 4 / 3 | 11 / 0 / 0 |

The 62 sends took 18.6 seconds total, with a 298 ms median and 517 ms p95. Readiness took 14–38 ms. Workerd RSS peaked at 438 MiB for one local process and 518 MiB across simultaneous local workerd processes. These process figures include the local runtime and its isolates. Cloudflare gives each isolate a 128 MB memory limit. Measure remote resource use and network latency during isolated staging. [Cloudflare Workers limits](https://developers.cloudflare.com/workers/platform/limits/#memory)

At the journal target, the sealed account had 504,332 bytes of room and the plaintext account had 5,271,240 bytes of room. The sealed account was the closest hard limit at roughly 66% used. The journal is designed to hold steady at its target when publications settle. Larger messages, multiple push destinations and retained epoch snapshots can exhaust sealed bytes sooner. A stalled journal or a busy epoch history can change which bound is reached first. The 4,096 message-record bound counts storage records, including protocol activity. A mixed workload's safe lifetime depends on the traffic and state composition.

The storage-only regression exercised 4,100 historical identities and prevented re-encryption when the associated index was missing. Separately, hashing sequential synthetic IDs `alt_capacity_fixture_00001` and onward into the real 256 SHA-256 partitions produced a largest bucket of 29 at 4,100 entries, the first 80% warning at 43,127 entries, and a first rejected insertion at 55,314. In an in-memory SQLite model with the same bucket JSON shape, the readiness query's median was 0.17 ms at 4,100 identities and 2.18 ms at 55,313 identities. At the latter point the bucket JSON totaled 5.31 MB. The model uses synthetic IDs and digests and excludes authenticated operation rows, MLS processing, persistence and remote I/O. Actual bucket capacity depends on the ID distribution.

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

### Expanded CI

| Job | Result | Evidence |
| --- | --- | --- |
| `rust` | Passed | Locked workspace and SQLite tests, Clippy, release build, and dependency, license and advisory checks for all three lockfiles. [Job](https://github.com/nostrmash/nostr-watchdog/actions/runs/46008823008/job/140538754918) |
| `wasm-worker` | Passed | Operational Worker and pinned MDK engine WASM compilation. [Job](https://github.com/nostrmash/nostr-watchdog/actions/runs/46008823008/job/140538754914) |
| `workerd` | Passed | Actual D1 migrations, scheduled operation, interrupted fallback, claim fences, and incident acknowledgement during a probe. [Job](https://github.com/nostrmash/nostr-watchdog/actions/runs/46008823008/job/140538755007) |
| `cloudflare-marmot` | Passed | 29 runtime tests, 8 storage tests, 4 native MDK interoperability tests and 3 actual workerd scenarios. The paired Worker incident reached and decrypted at the independent recipient. The capacity run independently retained 11 retired operations after restart. [Job](https://github.com/nostrmash/nostr-watchdog/actions/runs/46008823008/job/140538755367) |
| `native-marmot` | Passed | All 24 helper library tests, three consecutive complete optimized suites, linked SQLCipher and SQLite version checks, and the owner acceptance-script fixture. [Job](https://github.com/nostrmash/nostr-watchdog/actions/runs/46008823008/job/140538754460) |
| `image` | Passed | Linux amd64 startup, UID 10001, directory mode 0700, linked libraries, and actual container replacement with an independent official SQLite MDK recipient in 129.91 seconds. [Job](https://github.com/nostrmash/nostr-watchdog/actions/runs/46008823008/job/140538755215) |

Ubuntu completed the three optimized exchanges in 153.82, 154.44 and 154.69 seconds. Each run verified both official recipients, linked SQLCipher, and the accepted, intent and submitted crash boundaries. The separate owner acceptance-script fixture finished in 75.87 seconds. [Native test log](https://github.com/nostrmash/nostr-watchdog/actions/runs/46008823008/job/140538754460)

### Release gates

| Gate | Status | Evidence or remaining condition |
| --- | --- | --- |
| Q1 Native Ubuntu diagnosis | Diagnosed | The relay trace identified incomplete same-second coverage in the standalone scenario and repeated wake-mode inbox activation in the packaged scenario. The internal disposition of the individual Welcome remains unobserved. |
| Q2 Both official MarmotApp scenarios | Passed | Final Ubuntu CI verified standalone decryption and packaged signed Welcome admission, outage and recovery. |
| Q3 Repeated optimized Ubuntu qualification | Passed | Three consecutive runs of the complete optimized native fixture suite passed in the same Ubuntu job. |
| Q4 Owner acceptance script in CI | Passed | The final Ubuntu job verified onboarding, token readiness and two independently decrypted alerts in the original conversation across a restart. |
| Q5 Integrated two-Worker incident | Passed | The final paired workerd job verified actual D1, independent recipient decryption, push, fallback and subsequent recovery. |
| Q6 Historical-operation integrity and restart | Passed | Workerd CI verified transactional retirement, restart, original operation identity and rejection after history corruption. |
| Q7 Capacity and operational limits | Passed | Actual sends, token updates, retirements, epochs and local resource measurements are above. Remote capacity is a staging measurement. |
| Q8 Native security limitations | Constrained | Use a dedicated two-account conversation with stable membership while dispatch is enabled. Native push acceptance remains `unobservable`. [Operating constraints](deployment.md#native-process) |
| Q9 Dependency and license checks | Passed | RustSec and dependency policy checks passed for all three exact lockfiles. Remaining warnings are classified above. |
| Q10 Docker conversation persistence | Passed | Final image CI recovered both runtimes on the same volume, kept the original application event, and independently decrypted the outage and recovery. |
| Q11 Six expanded jobs on one SHA | Passed | [Implementation workflow](https://github.com/nostrmash/nostr-watchdog/actions/runs/46008823008) |
| Q12 Optimized staging artifacts | Passed | Both deployment manifests passed Wrangler dry-run bundling on the implementation. |
| Q13 Native phone procedure | Ready | [Native acceptance](acceptance.md#native) |
| Q14 Cloudflare phone procedure | Ready | [Cloudflare acceptance](acceptance.md#cloudflare) |
| Q15 Observed iPhone notification | Pending | Requires the owner's dedicated account and physical test iPhone. |

### Staging assessment

The qualification used private fixtures and GitHub Actions. Use the [production runbook](deployment.md#cloudflare-production) for actual deployed resource measurements and the [acceptance procedure](acceptance.md#cloudflare) for phone delivery. Native operation requires a dedicated two-account group with stable membership and reports alert-specific push acknowledgement as `unobservable`.

## Previous integration qualification

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

The reviewed baseline run uses the implementation SHA in this section. It covers Rust, audits, WASM compilation, operational workerd, container replacement, and the native and paired Worker fixtures. [Implementation run](https://github.com/nostrmash/nostr-watchdog/actions/runs/45986345284)

| Job | Conclusion | Evidence |
| --- | --- | --- |
| `rust` | Passed | Workspace tests, SQLite tests, optimized build, Clippy, and license and vulnerability checks for all three lockfiles. [Job log](https://github.com/nostrmash/nostr-watchdog/actions/runs/45986345284/job/140462843474) |
| `wasm-worker` | Passed | Operational Worker and pinned MDK engine compile to WASM. [Job log](https://github.com/nostrmash/nostr-watchdog/actions/runs/45986345284/job/140462843337) |
| `workerd` | Passed | Local D1 migrations, scheduler, concurrency, and both interrupted fallback directions. [Job log](https://github.com/nostrmash/nostr-watchdog/actions/runs/45986345284/job/140462843384) |
| `cloudflare-marmot` | Passed | Both optimized Worker bundles, independent MDK recipient, and actual workerd interop and history recovery. [Job log](https://github.com/nostrmash/nostr-watchdog/actions/runs/45986345284/job/140462843063) |
| `native-marmot` | Failed | The 24 helper library tests and linked SQLite/SQLCipher check passed. The standalone official app recipient did not decrypt the first alert, and the packaged fixture recipient did not join its Welcome. The shell stopped before the operator-script fixture. [Job log](https://github.com/nostrmash/nostr-watchdog/actions/runs/45986345284/job/140462843442) |
| `image` | Passed | Linux amd64 startup, UID 10001, directory mode 0700, runtime libraries, and direct-recipient exchange across container replacement in 129.88 seconds. [Job log](https://github.com/nostrmash/nostr-watchdog/actions/runs/45986345284/job/140462843368) |


### Previous release gates

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

### Previous release assessment

The decisive incident path is working locally in both deployment shapes. The native MDK API can acknowledge the group message without exposing alert-specific push acknowledgement. The native helper also checks canonical membership before calling the upstream kind-9 send. A membership change between those operations remains possible because the pinned native API has no atomic guarded send. These upstream limitations remain visible in deployment and acceptance decisions.

Release qualification remains open. The Linux `MarmotApp` fixtures failed during recipient catch-up despite the local native pass and the separate Linux Docker pass with a direct official MDK recipient. The exact cause of the Linux recipient failures remains unresolved. The optimized image is built and tested on Linux amd64, and both isolated Worker manifests are ready for authorized staging. Remote D1 and Durable Object measurements, notification-server processing, and observed iPhone notifications remain pending.
