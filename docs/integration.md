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

## Behavioural resolution

Agent A's claim test called `extend_claim` with a deadline in the past and expected that write to expire the claim. Production hardening refuses a deadline that is not strictly in the future and inside five minutes, so a rejected write leaves the live claim in place. `crates/watchdog-native/src/marmot.rs` now asserts that refusal. Expiry of an already elapsed claim remains covered by the store test `an_expired_claim_cannot_be_renewed`.

## Shared transport result

`watchdog_core::delivery::OperationResult` is the projection both adapters copy into `DeliveryOutcome.operation`. `operation_from_transport` is the only parser.

- Native counters come from the nested `operation` object: `messageSubmissions`, `messagePublications`, `messageReconciles`, `ambiguousReconciles`, `tokenWaits`, `pushPublications`, `pushReconciles`. Flat `message_attempts` is not a submission count and is not copied.
- Cloudflare counters: `messageAttempts` is a new ciphertext, `messagePublicationAttempts` and `pushPublicationAttempts` are network publications, and `unobservableAttempts` is push reconciliation. `pushAttempts` counts recorded outcomes and is not a publication count.
- A negative or overflowing counter is rejected and stays null. An explicit zero is kept. A missing key stays null.
- `retryAtMs`, `retryAfterMs`, and `reconcileAfterMs` are relative delays. A value outside 1–300000 ms is ignored, so a Unix timestamp is not added to the clock.
- Unknown message or push names stay unknown. They are not stored as `rejected`.
- A settled native `unobservable` push, with `relay_accepted`, stops polling. A Cloudflare `unobservable` push with disposition `reconcile` stays open and keeps the accepted message.
- NIP-17 and Telegram failures use `LifecycleDecision::Retry` and the TypeScript budget: eight attempts, backoff `min(1h, 30s * 2^(attempt-1))`. Marmot `Reconcile` does not consume that counter.

The engine reads the typed result when the adapter supplies one. Ordinary transports still use `accepted` and `terminal`.

## Worker boundary

`WorkerNotifier::deliver_marmot` calls Durable Object namespace `MARMOT_SENDER`. The object name is the project id. The request is `POST https://marmot-sender.internal/marmot?sender=<projectId>` with `Authorization: Bearer <MARMOT_OPERATOR_TOKEN>`. A new alert sends `op: deliver`. An admitted operation sends `op: reconcile` and does not include text. The project character set is `[A-Za-z0-9_:-]`, length 1–128. A response whose `operationId` or `projectId` does not match the request is discarded. A timeout or malformed body does not replace an accepted message with `not_submitted`. The fetch is bounded by the configured check timeout. No MLS state, token, ciphertext, or storage key is written to D1. `MARMOT_OPERATOR_TOKEN` is loaded. `MARMOT_STORAGE_KEY` is not a key of the operational Worker.

`wrangler.staging.toml` binds `MARMOT_SENDER` to script `nostr-watchdog-marmot-staging`. `wrangler.marmot-staging.toml` exports class `MarmotSender`. Local counterparts are `wrangler.rust-local.toml` and `wrangler.marmot-local.toml`. `ENABLE_MARMOT` stays false. A missing binding or a missing operator token finishes the row as terminal `marmot_engine_unavailable` or `marmot_unauthorized`. The scheduled tick calls `establish`, then `sync`, and `maintain` on the six-hour boundary, only when Marmot is enabled, the binding exists, and the operator token is set.

The operator onboard route records the operation id, then asks the helper or the Durable Object. The shared handler still describes the transport as unconnected until that call returns. A configured `nsec1` secret is not sent to the Durable Object, because that object accepts 32-byte hex and must not be given a freshly generated identity in place of the configured sender. An empty sender secret is the isolated generated-identity path.

## D1 completion

Local D1 does not undo an earlier statement when a later statement errors. A required Telegram row is inserted first, and only while the claim or the settlement predicate still matches. The completion update then requires that Telegram `logical_id` and writes a fresh `completion_token`.

- If the insert fails, the completion matches nothing and the claim stays.
- If the insert lands and the completion matches nothing, the Telegram row remains and the original claim stays. The next attempt sees the existing logical row, inserts nothing, and completes when the claim still matches.
- A second logical notification does not insert another Telegram row.
- SQLite does the insert after the winning update inside one transaction and rolls that update back when the insert changes nothing.

That is recoverability on D1, and a real transaction on SQLite. The workerd suite that demonstrated the first failure direction ran on Agent C's branch, run https://github.com/nostrmash/nostr-watchdog/actions/runs/45889582901. It has not been re-executed on this combined tree.

Migration `0012_transport_evidence.sql` adds `push_event_id`, `evidence`, `transport_disposition`, and `transport_updated_at`. Existing migrations are unchanged. A later incomplete response does not clear `relay_accepted`, the message event id, or a stored push event id. `operation_started_at` is written once from `startedAtMs` and is not moved by a later response. Critical `nostr_fallback` creates the Telegram row on the first unsuccessful Marmot or NIP-17 attempt, including while the Marmot operation stays reconcilable. The logical id still prevents a second Telegram row. An aggregate push label of `relay_accepted` does not settle the operation while the disposition is `reconcile`.

## What was executed on this tree

- `cargo test -p watchdog-core --lib`: 51 passed. The fixture parser, the forbidden `message_attempts` mapping, the `pushAttempts` distinction, and the reconcile-versus-aggregate-push decision are in that run.
- `cargo test -p watchdog-engine --lib`: 3 passed.
- `cargo test -p watchdog-store --features sqlite --lib`: 16 passed, including monotonic evidence and the interrupted `0012` rollback.
- `cargo test -p watchdog-native --bin nostr-watchdog`: 5 passed.
- `cargo check -p watchdog-worker --target wasm32-unknown-unknown`.
- `cargo fmt --all -- --check` and clippy on the edited crates.
- `cargo test --manifest-path crates/watchdog-marmot/Cargo.toml --offline --lib` with Odin `dev-2026-10` revision `84bc3fc`: 23 passed, including the checkpoint tests that keep an updated operation when a checkpoint is interrupted.
- `cargo build --manifest-path crates/watchdog-marmot/Cargo.toml --offline --release` produced `crates/watchdog-marmot/target/release/watchdog-marmot`.

## Not executed

- Integrated native incident through both executables to an independent recipient, including restart and a second alert in the same conversation.
- Integrated workerd incident through `WorkerNotifier::deliver_marmot`, including partial triggers, restart, and a second alert. A standalone Durable Object test is not that path.
- The operational workerd suite on this combined commit.
- Docker image build and container replacement with a recovered conversation. A marker file is not that proof.
- Staging deploy, remote D1, bundle size on the combined tree, or a physical WhiteNoise notification.
- Bulk public-relay sends.

## Physical acceptance

Native procedure, from Agent A, not run in this integration:

```bash
scripts/whitenoise-acceptance.sh prepare <test-recipient>
scripts/whitenoise-acceptance.sh start
scripts/whitenoise-acceptance.sh init
scripts/whitenoise-acceptance.sh conversation
scripts/whitenoise-acceptance.sh alert-foreground
```

`alert-locked` asks before sending. `restart` stops both processes and starts them again without sending. The script uses an isolated database and ignores inherited production secrets. A notification counts only after the phone owner sees it.

Cloudflare physical acceptance waits for an authorized deploy of `nostr-watchdog-rust-staging` with a dedicated D1 database, a dedicated `MARMOT_SENDER` namespace, a dedicated sender, a dedicated recipient, and `MARMOT_OPERATOR_TOKEN` plus `MARMOT_STORAGE_KEY` stored as secrets. `ENABLE_MARMOT` and `ALERTS_ENABLED` stay false until that rehearsal. Do not reuse production ids or keys.

After the first observed notification, the qualification targets remain 100 controlled sends, 99 percent observed under normal connectivity, median latency under 5 seconds, 95th percentile under 15 seconds, no unexplained duplicates, and no cryptographic state corruption. Those are targets, not a service level.

## Acceptance gates

| Gate | Result |
| --- | --- |
| I1 Latest A and B handoffs | Incorporated through `61dbbda` and `2c45627`. No newer commit was on either branch at the last fetch. |
| I2 Checkpoint regression | `61dbbda` is in the branch. The helper journal tests passed, including `process_stop_during_checkpoint_keeps_the_updated_operation`. |
| I3 Private cross-Worker binding | Declared in the local and staging configs. Not exercised by a running workerd pair. |
| I4 Autonomous deliver and reconcile | Implemented and covered by parser and command tests. Not exercised against a live Durable Object. |
| I5 Onboarding and readiness | The operator route calls the helper or the Durable Object after the operation id is stored. Readiness treats a missing binding or operator token as unavailable, and an unobserved conversation as unknown. A live conversation was not established. |
| I6 Counters, evidence, and retry timing | Store test keeps acceptance, the push event id, and the original start time across a later timeout. |
| I7 Partial push | A reconcile disposition does not settle only because the aggregate push label is `relay_accepted`. |
| I8 Critical fallback and ordinary retries | Fallback is created while Marmot is still reconcilable. Ordinary NIP-17 and Telegram stay on eight attempts. |
| I9 Native incident | Not run. |
| I10 Cloudflare incident | Not run. |
| I11 D1 and scheduling | The fence implementation is on this tree. The workerd suite was not re-run here. |
| I12 Integrated CI | Jobs `native-marmot` and `cloudflare-marmot` are in the workflow. No run of this commit exists yet. |
| I13 Docker conversation persistence | Not run. |
| I14 Staging configuration | Both Worker configs are prepared. Nothing was deployed. |
| I15 Native security limitations | Still deployment-blocking. The pinned MDK build does not correlate push, and membership and network-policy limits remain. |
| I16 Physical native notification | Pending observation. |
| I17 Physical Cloudflare notification | Pending an authorized staging deploy and observation. |

## Release readiness

The branch is not a release candidate. The operational adapter, the counter contract, and the staging binding are in the tree. No monitoring incident has been delivered through the combined Cloudflare watchdog to an independent recipient, and no phone notification has been observed.
