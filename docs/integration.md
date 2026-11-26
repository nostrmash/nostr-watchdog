# Integration

Branch `feat/rust-integration` starts at the shared rewrite baseline `8283bdba641543eca6c13e116cbed48e7951a7d1`. The three reviewed snapshots were merged with `--no-ff`, in this order, without changing their branches:

| Step | Reviewed commit | Merge commit | Result |
| --- | --- | --- | --- |
| Production hardening | `9103d7ffce027f1be805a0b1698b3a18dae20fdb` | `62439ed` | Clean. Main workspace tests passed: core 35, engine 3, native 2, notify 9, store 15. |
| Native Marmot | `1d2e349cab3480639576c52403eba0150e0acd4f` | `267b501` | Clean tree merge. One behavioural mismatch, recorded below. |
| Cloudflare Marmot | `5da50d71d29ad11de1e3735eafeea39e3521a384` | `6d40646` | Clean. The Durable Object worker typechecks for `wasm32-unknown-unknown`. |

No commits exist on the agent branches after those reviewed hashes. There is no later handoff to integrate.

The files touched by the three snapshots do not overlap. Git reported no conflicts.

## Behavioural resolution

Agent A's claim test called `extend_claim` with a deadline in the past and expected that write to expire the claim. Production hardening refuses a deadline that is not strictly in the future and inside five minutes, so a rejected write leaves the live claim in place. `crates/watchdog-native/src/marmot.rs` now asserts that refusal. Expiry of an already elapsed claim remains covered by the store test `an_expired_claim_cannot_be_renewed`.

## Shared transport result

`watchdog_core::delivery::OperationResult` is the projection both adapters copy into `DeliveryOutcome.operation`. `operation_from_transport` is the only parser.

- Native helper counters: `message_attempts`, `unknown_attempts`, `token_wait_attempts`, `unobservable_attempts`. `push_attempts` stays absent when the helper sends null. It is not invented.
- Cloudflare counters: `messageAttempts` and `pushAttempts` when those keys are present. Other counters stay absent.
- `retryAtMs`, `retryAfterMs`, and `reconcileAfterMs` are relative delays. A value outside 1–300000 ms is ignored, so a Unix timestamp is not added to the clock.
- Unknown message or push names stay unknown. They are not stored as `rejected`.
- A settled native `unobservable` push, with `relay_accepted`, stops polling. A Cloudflare `unobservable` push with disposition `reconcile` stays open and keeps the accepted message.
- NIP-17 and Telegram failures use `LifecycleDecision::Retry` and the TypeScript budget: eight attempts, backoff `min(1h, 30s * 2^(attempt-1))`. Marmot `Reconcile` does not consume that counter.

The engine reads the typed result when the adapter supplies one. Ordinary transports still use `accepted` and `terminal`.

## Worker boundary

`WorkerNotifier::deliver_marmot` calls Durable Object namespace `MARMOT_SENDER`, one object name per project id, `POST https://marmot-sender.internal/marmot`. The body is the `send` command. The response is parsed with `TransportOrigin::CloudflareObject`. No MLS state, token, or ciphertext is written to D1.

The binding is absent unless wrangler declares it. A missing binding finishes the row as `marmot_engine_unavailable` instead of pretending the recipient token is missing. `wrangler.staging.toml` does not declare the binding and leaves `ENABLE_MARMOT` false. The class compiles in `crates/watchdog-marmot-worker` and is not yet exported by the operational Worker script. Linking those crates is the remaining deployment step. It was not done here because the operational Worker and the MDK graph are separate workspaces.

## D1 completion

Local D1 does not undo an earlier statement when a later statement errors. A required Telegram row is inserted first, and only while the claim or the settlement predicate still matches. The completion update then requires that Telegram `logical_id` and writes a fresh `completion_token`.

- If the insert fails, the completion matches nothing and the claim stays.
- If the insert lands and the completion matches nothing, the Telegram row remains and the original claim stays. The next attempt sees the existing logical row, inserts nothing, and completes when the claim still matches.
- A second logical notification does not insert another Telegram row.
- SQLite does the insert after the winning update inside one transaction and rolls that update back when the insert changes nothing.

That is recoverability on D1, and a real transaction on SQLite. The workerd suite that demonstrated the first failure direction ran on Agent C's branch, run https://github.com/nostrmash/nostr-watchdog/actions/runs/45889582901. It has not been re-executed on this combined tree.

## What was executed on this tree

- `cargo test --workspace --exclude watchdog-worker` after the hardening merge.
- `cargo test -p watchdog-core --lib`: 45 passed, including the native-versus-Cloudflare disposition test, the eight-attempt ordinary budget, and the delay parser.
- `cargo test -p watchdog-engine --lib`: 3 passed.
- `cargo test -p watchdog-native --bin nostr-watchdog`: 5 passed after the claim-test correction.
- `cargo check -p watchdog-worker --target wasm32-unknown-unknown`.
- `cargo check --manifest-path crates/watchdog-marmot-worker/worker/Cargo.toml --target wasm32-unknown-unknown`.
- The native helper check stops because Odin `dev-2026-10` is not installed in this environment (`ODIN` is unset and `odin` is not on `PATH`).

## Not executed

- Native helper build, journal crash test, or MDK interoperability.
- Integrated native incident through the helper to an independent recipient.
- Integrated workerd incident through `MarmotSender`, including restart and a second alert.
- The operational workerd suite on this combined commit.
- Docker image build and container replacement.
- Staging deploy, remote D1, or a physical WhiteNoise notification.
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

## Release readiness

The branch combines the three reviewed snapshots and connects the typed lifecycle. It is not a release candidate. The helper is not built here, the Durable Object is not linked into the operational Worker, and no end-to-end Marmot delivery was run through the combined application.
