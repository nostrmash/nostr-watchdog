# Production hardening

Branch `feat/rust-production-hardening` from `8283bdba641543eca6c13e116cbed48e7951a7d1`. The TypeScript reference remains `a236b35a9dda14aa6f1a96dc37fc2daccc838ed8`. This document records what changed, how to rehearse it, and what is still blocked on the other agents.

## Remediation

| Finding | Change |
| --- | --- |
| Probe result applied after a newer generation won | The check cycle loads memory before the probe and commits that generation. `committed: false` is discarded and does not open an incident or an alert. |
| Stale scheduler metadata | `scheduler_runs` updates only for a newer start, or the same owner completing that start. The finish time is the clock at completion. Leases renew while the owner still holds them and are released on every exit path. |
| Heartbeat reorder | A row is replaced only when `reported_at` is strictly greater. Equal timestamps keep the first committed row. The nonce is still consumed. Replay is `401 replay`. A stale observation is `409 stale_observation`. A database error stays 500. |
| Coupled dispatch | Health, vendor, Telegram, NIP-17, Marmot messages, and push reconciliation are separate bounded passes. The Worker minute cron runs health, then message dispatch, then push reconciliation. The hourly cron runs vendor checks and prune. A pass does not start with less than 1.5 seconds left. |
| Claim renewal after expiry | Extension requires an unexpired token and a deadline inside five minutes. Ownership is checked before NIP-17 publication. |
| One attempt counter for message and push | Message, push, token-wait, and ambiguous-outcome counters are independent nullable columns. They are copied from the transport. Phase strings do not increment them. `attempt_count` stays the scheduler counter. |
| Global flags stranding alerts | `queued_transport` is the only route decision. Emergency flags override projects. Disabled transports are finalized or fall back. Test alerts do not fall back. |
| Fallback split from the failure | `finish_with_fallback` and settlement write the completion and the Telegram row together. On D1 the fallback insert runs first and the completion requires that Telegram `logical_id`, because a later statement error does not undo an earlier one. SQLite inserts after the winning update and rolls the transaction back when the insert does not land. Equal timestamps are not ownership. Dedupe uses `logical_id`. |
| NIP-42 stopped after the first challenge | Publication signs at most two challenges, waits for the AUTH OK, and resends the original event once. Discovery never signs. |
| Request bodies read before a limit | The Worker streams the body and stops at the limit even when `Content-Length` is missing or small. Operator routes do not read a body when the bearer header is absent. Native HTTP uses a 16 KiB body limit and a 10 second request deadline. |
| Vendor fingerprint stored before its alert | Version state, vendor state, and the alerts commit in one fenced operation. |
| Readiness was a database ping | `/readyz` reports schema, configuration, scheduler freshness, and transport availability. Unknown Marmot state is not a failure. Enabled Worker Marmot is unavailable. |
| No per-alert diagnostic | `GET /v1/outbox/<id>` returns operational state without the alert text, keys, or push material. |
| Shutdown left claims held | SIGINT and SIGTERM stop new ticks, drain for 25 seconds, release claims, and then signal the helper. |

## Heartbeat ordering

The HMAC string is unchanged: `timestamp\nnonce\nMETHOD\npath\nsha256(body)`. Clock skew is still rejected before the store. Among observations that pass skew, the greatest `reported_at` wins. Two valid observations with the same `reported_at` keep the first committed progress token, idle flag, and loop time. `progress_changed_at` changes only when the progress token changes.

## Networking

Native HTTP and relay sockets share one deadline across DNS, connect, TLS, and the response body. DNS pinning and the public-destination check are unchanged. Private addresses are allowed only for an explicitly authorized monitor target. Discovered relay URLs use the public profile. Telegram uses `no_proxy`, pins `api.telegram.org`, caps the response at 64 KiB, and returns `telegram_failed` without the bot token.

The Worker cannot pin DNS. Its URL policy rejects literal private hosts, credentials, and non-default ports before `fetch`. That is not the same protection as the native pin. WebSocket close ends the session immediately. Frame, message, session-byte, and event caps are unchanged.

## Migrations and rollback

Bundled SQLite is `libsqlite3-sys` 0.39.1 through `rusqlite` 0.41, which includes the fix for RUSTSEC-2026-0459. `chrono` remains because the Worker SDK links it and RustSec records no fixed release (`RUSTSEC-2026-0543` is ignored in `deny.toml` for that reason).

`0001` through `0008` are unchanged. `0009_operations.sql`, `0010_lifecycle.sql`, and `0011_delivery_fencing.sql` are additive. `0010` adds phase columns, settlement, operation id, and claim owner. `0011` adds `completion_token`, immutable operation and phase timestamps, nullable authoritative counters, and `marmot_onboard_history`. Neither rewrites historical message or push state, and `0011` does not turn a historical NULL into an observed zero. Native migrations stay transactional, one file at a time. The Worker does not run DDL on a request. Schema validation checks required tables, columns, indexes, and the migration ledger. An unknown ledger id is `schema_unsupported`.

Rollback of the operational database is restoring a snapshot taken before the migration being removed, then running the binary that matches that ledger. Do not point an older binary at a database whose ledger contains a newer id. There is no down migration. Rollback does not restore MLS state, because this database does not store it. The image is linux/amd64 only.

Do not apply these migrations to the production D1 database from this branch.

## Runtime command

From the repository root:

```bash
sh tests/runtime/worker-scheduled.sh
```

That script builds the Worker, applies the migrations to an isolated local D1 database, and starts `wrangler dev --test-scheduled` on an ephemeral port. It is the command to use. `wrangler.rust-local.toml` is a development config and is not the integration fixture.

`tests/runtime/worker-scheduled.sh` is the isolated sequence. It uses a generated copy of `wrangler.runtime-test.toml`, its own persist directory, and an ephemeral fixture port. It does not use the production database id and it does not kill an unrelated process that happens to hold a port.

Native store tests, including heartbeat order and expired-claim rejection:

```bash
cargo test -p watchdog-store --features sqlite --lib
cargo test -p watchdog-core -p watchdog-engine -p watchdog-notify -p watchdog-native
```

## Gates

These are the results of this working tree. A GitHub Actions URL is recorded only after the workflow for the pushed commit has been created. The previous green run, https://github.com/nostrmash/nostr-watchdog/actions/runs/45881010284, is commit `4a3eadc` and does not include this change.

| Gate | Result on this branch |
| --- | --- |
| C1 D1 completion fencing | `sh tests/runtime/worker-scheduled.sh` drove `finish_with_fallback` through the D1 adapter. The winning claim inserted one Telegram row. The equal-timestamp loser did not. A required insert that conflicts on `dedupe_key` left the claim in place. `commit_check` with the same generation succeeded once and failed the second time. |
| C2 Typed delivery decisions | `watchdog_core::delivery::interpret` chooses reconcile, accept, or fail. The engine stores canonical phase names. An unknown phase stays unset and is not written as `rejected`. Counters on `DeliveryOutcome` stay unknown until Agent A or Agent B copies them. |
| C3 Counters and age | Nullable `auth_*` columns are monotonic when a transport supplies them and stay NULL otherwise. Settlement uses `COALESCE(operation_started_at, created_at)`, not `updated_at`. SQLite tests cover a repeated phase, a young row with an old `updated_at`, and an aged row. |
| C4 Settlement fallback | SQLite `settle_one` rolls back when the fallback does not land. The workerd probe settled one aged D1 row, created one Telegram row, rejected the second settlement, and left a conflicting row retrying. |
| C5 Reconciliation interval | The Worker minute cron runs message dispatch and push reconciliation. The hourly cron runs vendor checks and prune. A pass does not start with less than 1.5 seconds left. The suite's slow fixture returned inside the probe budget. |
| C6 Claims and retries | SQLite tests cover a stale token, an expired claim, transport-specific dead-letter retry, and shutdown that releases only `native-<pid>`. NIP-17 envelope reuse is covered by the engine tests. A live helper timeout was not executed on this branch. |
| C7 D1 adapter concurrency | The workerd probe calls the store. It does not apply the fence by executing SQL against the D1 file from the test script. Reminder and acknowledgement races on two overlapping Worker isolates were not executed. |
| C8 Isolated workerd suite | `sh tests/runtime/worker-scheduled.sh` passed: incident open and recovery, Telegram fallback, status HMAC, heartbeat replay and stale rejection, the D1 fence above, and the probe deadline. The fixture binds port 0. It does not kill an unrelated listener. |
| C9 Docker | The Dockerfile pins Odin `dev-2026-10` revision `84bc3fc` and SHA-256 `c3c8b095621fd0c75f7f73e3a0829f1b4d45324225f20ba11ed8dc4da310a8ab`, builds linux/amd64 only, and leaves Odin out of the runtime image. The image was not built on this machine. The CI `image` job is the build. A marker file is not Marmot conversation recovery. |
| C10 CI | `.github/workflows/ci.yml` runs fmt, Clippy, tests, cargo-deny, cargo-audit, the Worker and MDK wasm checks, the image job, and the workerd suite. Native helper tests, the OpenMLS Durable Object, Agent B's workspace, and a workerd MDK conversation are not jobs on this branch. The SQLCipher WASM probe is not a required success. Public relay tests stay opt-in. |
| C11 Migrations | `0011_delivery_fencing.sql` is additive. Existing files `0001`–`0010` are unchanged. SQLite tests upgrade a TypeScript-shaped database and an interrupted `0011` without inventing acceptance or an observed zero. No production database was migrated. |
| C12 Integration contract | `docs/agent-c-integration.md` is the shared contract. `POST /v1/diagnostics/marmot/onboard` returns `unavailable` until `MarmotControl` is replaced. It does not claim a conversation exists. |

## Behaviour that changed on purpose

- A valid older heartbeat no longer overwrites newer progress.
- Equal heartbeat timestamps keep the first writer.
- A project can enable a transport that the global default disables, and dispatch follows that route.
- A transport that is turned off is no longer retried forever. Critical rows can fall back to Telegram once.
- Test alerts do not create a second transport.
- Telegram text is the short notice, not the full incident message.
- Retrying a stored envelope does not mint a new submission.
- Vendor alerts and the fingerprints that suppress them commit together.
