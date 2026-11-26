# Production hardening

Branch `feat/rust-production-hardening` from `8283bdba641543eca6c13e116cbed48e7951a7d1`. The TypeScript reference remains `a236b35a9dda14aa6f1a96dc37fc2daccc838ed8`. This document records what changed, how to rehearse it, and what is still blocked on the other agents.

## Remediation

| Finding | Change |
| --- | --- |
| Probe result applied after a newer generation won | The check cycle loads memory before the probe and commits that generation. `committed: false` is discarded and does not open an incident or an alert. |
| Stale scheduler metadata | `scheduler_runs` updates only for a newer start, or the same owner completing that start. The finish time is the clock at completion. Leases renew while the owner still holds them and are released on every exit path. |
| Heartbeat reorder | A row is replaced only when `reported_at` is strictly greater. Equal timestamps keep the first committed row. The nonce is still consumed. Replay is `401 replay`. A stale observation is `409 stale_observation`. A database error stays 500. |
| Coupled dispatch | Health, vendor, Telegram, NIP-17, Marmot messages, push reconciliation, and sync are separate loops. The Worker runs health before vendor and stops dispatch at a 20 second budget. Claims match the number of rows that will start. |
| Claim renewal after expiry | Extension requires an unexpired token and a deadline inside five minutes. Ownership is checked before NIP-17 publication. |
| One attempt counter for message and push | Migration `0009_operations.sql` adds independent message and push columns. Push reconciliation is a separate claim kind. |
| Global flags stranding alerts | `queued_transport` is the only route decision. Emergency flags override projects. Disabled transports are finalized or fall back. Test alerts do not fall back. |
| Fallback split from the failure | `finish_with_fallback` writes the failure and the Telegram row together. Dedupe uses `logical_id`. |
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

`0001` through `0008` are unchanged. `0009_operations.sql` is additive. Native migrations stay transactional. The Worker does not run DDL on a request. Schema validation checks required tables, columns, indexes, and the migration ledger. An unknown ledger id is `schema_unsupported`.

Rollback of the operational database is restoring a snapshot taken before `0009`, then running the older binary. Do not point an older binary at a database whose ledger contains `0009_operations`. There is no down migration, and rollback does not recreate cryptographic state because this database does not store it.

Do not apply these migrations to the production D1 database from this branch.

## Runtime command

From the repository root, after the Worker bundle exists:

```bash
worker-build --dev --no-opt --out-dir build crates/watchdog-worker
npx wrangler d1 migrations apply nostr-watchdog-rust-local --local --config wrangler.rust-local.toml
npx wrangler dev --test-scheduled --config wrangler.rust-local.toml --port 8788
curl -fsS "http://127.0.0.1:8788/__scheduled?cron=*+*+*+*+*"
```

`tests/runtime/worker-scheduled.sh` is that sequence. It uses `wrangler.rust-local.toml` only. It does not use the production database id.

Native store tests, including heartbeat order and expired-claim rejection:

```bash
cargo test -p watchdog-store --features sqlite --lib
cargo test -p watchdog-core -p watchdog-engine -p watchdog-notify -p watchdog-native
```

## Gates

| Gate | Result on this branch |
| --- | --- |
| C1 Scheduled Worker monitoring | The scheduled handler runs health, then vendor only on the hourly cron, then bounded dispatch. `cargo check -p watchdog-worker --target wasm32-unknown-unknown` succeeded. A live workerd `__scheduled` run was not completed in this session. |
| C2 D1 generation fencing | SQLite tests cover a lost generation and a fenced loser statement. D1 uses the same SQL. Two overlapping workerd isolates were not executed here. |
| C3 Heartbeat order and replay | SQLite test covers older, equal, and replayed observations. D1 uses the same predicate. |
| C4 NIP-17 and Telegram fixtures | Engine NIP-17 tests still publish the stored event. Telegram is pinned and size-capped. A live fixture relay was not started in this session. |
| C5 Independent budgets | Native loops and the Worker budget are separate. Stall tests are the claim limits and the deadline checks, not a timed fault injection process. |
| C6 Claim renewal | An expired token cannot be extended. Ownership is checked before publication. |
| C7 Message and push contract | Documented in `docs/agent-c-integration.md` and stored by migration 0009. |
| C8 Diagnostics and readiness | `/readyz`, `GET /v1/outbox/<id>`, and onboarding are implemented. Marmot fields the helper does not supply stay `unknown`. |
| C9 Migration rehearsal | Schema validation and the additive migration are in the store. A D1 export rehearsal was not executed here. |
| C10 Packaging and CI | The workflow includes this branch, the SQLite feature tests, and the image. The image build was not run locally. No GitHub Actions URL exists until the branch is pushed and the workflow runs. |

## Behaviour that changed on purpose

- A valid older heartbeat no longer overwrites newer progress.
- Equal heartbeat timestamps keep the first writer.
- A project can enable a transport that the global default disables, and dispatch follows that route.
- A transport that is turned off is no longer retried forever. Critical rows can fall back to Telegram once.
- Test alerts do not create a second transport.
- Telegram text is the short notice, not the full incident message.
- Retrying a stored envelope does not mint a new submission.
- Vendor alerts and the fingerprints that suppress them commit together.
