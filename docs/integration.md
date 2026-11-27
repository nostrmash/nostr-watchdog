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

Implementation under qualification: `7c038ff7f1ba2d998ff2ed1a9b28cac5e131e569`.

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

The active journal retains unresolved operations. Compaction excludes the current mutation and the Welcome needed for onboarding evidence. Version 2 snapshots use bounded compression before authenticated encryption, which allowed the runtime test to reach the journal retirement threshold. The history retains operation identities for as long as a replay can arrive. The per-bucket and snapshot limits are fail-closed capacity limits. Monitor long-lived account size before rollout.

A legacy snapshot without authenticated history metadata requires recovery or deliberate re-onboarding. Preserve the full state and its history together. A complete point-in-time rollback can restore mutually consistent old records and snapshots. Treat a known restore as an operator recovery event and follow the fencing procedure in [deployment.md](deployment.md). The service has no independent witness for a complete rollback.

### Executed tests

- Native controlled test used the actual watchdog and helper, a real HTTP monitor, an independent official MarmotApp recipient, and isolated relays and state. The recipient decrypted the outage and the recovery alert in the same conversation. The original outbox kept its event ID and `relay_accepted` message state. Native push evidence remained `unobservable`. The configured critical fallback reached an isolated Telegram-compatible endpoint. Representative helper crash boundaries were exercised.
- Workerd controlled test ran the actual operational and cryptographic Worker bundles together through `MARMOT_SENDER`. An independently retrieved Welcome established the group. A scheduled SmartFlowSocial outage generated a D1 outbox row and a relay-accepted message, which the official SQLite MDK recipient decrypted. An independent test key opened the notification gift wrap and verified kind 446. One target failed temporarily, the local fallback accepted the critical alert, and restart recovery published the remaining trigger while retaining one application encryption. A subsequent scheduled recovery alert decrypted in the same conversation.
- The opt-in public Workerd test completed in 32.68 seconds using disposable identities and the WhiteNoise EU and US relays. The official recipient independently retrieved and joined the Welcome and decrypted both alerts, including the alert after restart. The fixture server key opened the relay-retrieved notification gift wrap. It used a synthetic token and public relay traffic was limited to this qualification.
- The operational workerd suite applied all D1 migrations, exercised fallback deduplication and interrupted completion, checked scheduler bounds and the signed `watchdog-status-v1` response, and passed. Remote D1 behavior remains a staging measurement.

```bash
cargo fmt --all -- --check
cargo test --locked --workspace --exclude watchdog-worker
cargo test --locked -p watchdog-store --features sqlite --lib
cargo test --locked --manifest-path crates/watchdog-marmot/Cargo.toml --lib
cargo test --locked --manifest-path crates/watchdog-marmot/Cargo.toml --test fixture_exchange -- --test-threads=1
npm ci --prefix crates/watchdog-marmot-worker/worker
worker-build --release crates/watchdog-worker -- --locked
sh crates/watchdog-marmot-worker/worker/build-release.sh
cargo test --locked --manifest-path crates/watchdog-marmot-worker/Cargo.toml --workspace --lib
cargo test --locked --manifest-path crates/watchdog-marmot-worker/Cargo.toml -p marmot-worker-interop --test workerd_conversation -- --ignored --test-threads=1 --skip public
sh tests/runtime/worker-scheduled.sh
```

Local Cargo runs used Rust 1.100.0 and locked dependencies. Native helper builds used Odin `dev-2026-10-nightly:84bc3fc`. Local Wrangler came from the npm lock at 4.166.0.

- The owner acceptance script also ran against an eligible independent MarmotApp recipient on a local relay. It established the conversation, observed the test token, sent two explicit alerts across process restart, and the recipient decrypted both in the original group. The test completed in 80.74 seconds.

### Deployment artifacts

Both staging manifests passed Wrangler dry-run bundling.

| Artifact | Total upload | Gzipped upload |
| --- | ---: | ---: |
| Operational Worker | 3,986.16 KiB | 2,054.23 KiB |
| Marmot Durable Object Worker | 10,752.50 KiB | 4,126.50 KiB |

The sizes above are local bundle measurements. Staging resource setup, secret installation, deployment order, onboarding, activation, and rollback are in [deployment.md](deployment.md). Native and staging phone procedures are in [acceptance.md](acceptance.md).

### Migration manifest

| State | Manifest |
| --- | --- |
| Operational SQLite and D1 | Apply the ordered `migrations/0001_init.sql` through `migrations/0012_transport_evidence.sql`. No new operational SQL migration was needed. |
| Marmot Durable Object | The `v1` Wrangler class migration creates the SQLite class. The class initializes its account, operation, and history-bucket tables. Snapshot version 2 records the sealed index commitments. |
| Native helper | Keep SQLCipher state and the operation journal together. The helper uses its upstream migrations. |

### CI and Docker

The expanded workflow was enabled at implementation commit `7922c5243aa67519a3e0fe84ec9d00cf2d0915f3`. Later corrections validate native onboarding identity and persistence, bound delivery calls, and exercise the owner acceptance script on the controlled relay.

The six baseline jobs passed on `3ef57fa`, including the original Docker startup smoke test. The expanded workflow runs local-only conversation and restart tests, operational D1 runtime tests, dependency checks for the shipped Rust workspaces, and an image fixture that creates a real conversation and replaces the container against the same mounted data. [Baseline run](https://github.com/nostrmash/nostr-watchdog/actions/runs/45967372076) · [Expanded workflow](https://github.com/nostrmash/nostr-watchdog/actions/runs/45975386938)

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
| G8 Onboarding and readiness | Partial | Both project identities initialized, and a full working SmartFlowSocial conversation reached observed participation and token readiness. Equivalent live NostrMash participation and token readiness remain untested. |
| G9 Scheduling and fallback | Partial | Configured local critical fallback and bounded workerd scheduling passed. The pinned native helper still synchronizes its hosted accounts through a shared upstream catch-up call. |
| G10 Native incident delivery | Passed | Actual executables, monitor outage and recovery, independent recipient, persisted evidence and fallback. |
| G11 Paired Cloudflare incident | Passed | Actual workerd and cross-script binding, scheduled incident and subsequent recovery alert. |
| G12 Independent recipient and trigger | Passed | Local paired Worker and opt-in public recipient decryption and trigger validation. |
| G13 Restart and duplicate prevention | Passed | Both runtimes recovered persisted conversations and kept the original application event. |
| G14 D1 and parity | Partial | Local migrations, fences, interrupted fallback completion, heartbeat and signed status passed. Remote D1 and the broader concurrency rehearsal remain open. |
| G15 Integrated CI | Partial | Expanded run submitted. See the CI results below. |
| G16 Docker conversation persistence | Partial | Functional container replacement fixture is wired to CI. See the image job conclusion below. |
| G17 Isolated staging procedure | Passed | Both build and dry-run bundle paths verified. Authorization is required for provisioning and deployment. |
| G18 Native physical WhiteNoise | Untested | Requires an observed test iPhone notification. |
| G19 Cloudflare physical WhiteNoise | Blocked | Requires authorized isolated staging and an observed test iPhone notification. |

### Release assessment

The decisive incident path is working locally in both deployment shapes. The native MDK API can acknowledge the group message without exposing alert-specific push acknowledgement. The native helper also checks canonical membership before calling the upstream kind-9 send. A membership change between those operations remains possible because the pinned native API has no atomic guarded send. These upstream limitations remain visible in deployment and acceptance decisions.

Release qualification remains open until the expanded CI, container persistence, remote staging measurements, and physical notification gates are resolved.
