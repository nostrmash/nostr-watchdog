# Agent C integration contract

The shared operational store is a sanitized projection. Native MDK and the Cloudflare Durable Object remain authoritative for cryptographic operation state. This database does not store MLS secrets, private keys, raw device tokens, or encrypted wake capabilities.

Agent A's helper and Agent B's Durable Object are not modified on this branch. The types in `watchdog_core::delivery` are the contract both transports implement. Existing adapters keep compiling. Unknown transport state names stay unknown. They are not stored as `rejected`.

## Application-message states

`not_submitted`, `prepared`, `accepted_pending`, `relay_accepted`, `rejected`, `completion_unknown`.

Legacy aliases, accepted only at the boundary:

| Incoming | Canonical |
| --- | --- |
| `message_prepared` | `prepared` |
| `message_accepted`, `accepted`, `published` | `relay_accepted` |
| `failed` | `rejected` |

`relay_accepted` stays `relay_accepted` when push fails, expires, or is unobservable. Human acknowledgement is `operator_ack_at` and incident `acked_at`. Neither is inferred from relay acceptance, and relay acceptance is not phone delivery.

## Push states

`unknown`, `not_required`, `not_attempted`, `token_unavailable`, `prepared`, `pending`, `publication_attempted`, `relay_accepted`, `rejected`, `expired`, `unobservable`, `terminal_failure`.

Legacy aliases: `push_token_unavailable`, `push_trigger_prepared`, `push_trigger_accepted`, `push_expired`, `push_unobservable`.

Agent A's current helper emits `not_attempted`, `token_unavailable`, and `unobservable`. It does not emit push `relay_accepted`, `pending`, `expired`, or `terminal_failure`. A null `push_event_id` stays null. `push_envelope_json` stays null.

## Operation result

`watchdog_core::delivery::operation_view` is the JSON shape:

- `projectId`, `operationId`
- `messageState`, `messageEventId`
- `pushState`, `pushEventId` (null until a transport actually observes one)
- `evidence`
- `error` (sanitized token only)
- `disposition`: `settled` or `reconcile`
- `retryAtMs`
- `phoneDelivery`: always false

Counters are copied from the transport for one operation id. They are not derived by counting phase strings. A repeated observation of the same phase does not invent a submission. A push reconciliation that restates an accepted message does not increment the message-submission counter. A missing counter stays NULL. NULL is not zero.

The columns added by migration `0010` (`message_attempts`, `message_reconcile_attempts`, `unknown_attempts`, `token_wait_attempts`, `push_publication_attempts`, `unobservable_attempts`) stay at their historical values. New writes do not increment them. The authoritative columns are nullable:

| Column | Meaning |
| --- | --- |
| `auth_message_submissions` | Application-message submissions reported by the transport |
| `auth_message_publications` | External message publication attempts |
| `auth_message_reconciles` | Application-message reconciliation observations |
| `auth_ambiguous_reconciles` | Ambiguous-outcome reconciliation observations |
| `auth_token_waits` | Token waits |
| `auth_push_publications` | Push publication attempts |
| `auth_push_reconciles` | Push reconciliation observations |
| `attempt_count` | Scheduler attempts. It does not increase on a reconciliation |

When the transport sends a count, the store keeps the greater value for that operation. A smaller later value does not move the counter backward. `watchdog_core::delivery::interpret` is the only state parser the engine uses. SQLite and D1 store a canonical name or leave the previous state. An unknown name is `unknown_transport_state` and stays in reconciliation. It is not stored as `rejected`.

`operation_id` is the stable transport operation id. For Marmot it defaults to the alert id. `submission_generation` increments only for a NIP-17 dead letter that has no signed gift wrap. It is not a new Marmot operation id.

## Reconciliation budgets

Settlement uses `COALESCE(operation_started_at, created_at)`. `updated_at` changes on claim and retry, so it is not an age. `operation_started_at` is frozen to `created_at` on the first completion and is not moved. `message_phase_started_at` and `push_phase_started_at` record when that phase last changed.

A free claim leaves the active queues when either the attempt budget or the age limit is reached:

- Original age at least 24 hours. An accepted message stays `relay_accepted`. Anything else becomes delivery `failed`.
- `completion_unknown`: `auth_ambiguous_reconciles >= 4`, or age at least 15 minutes when the counter is still unknown.
- `accepted_pending` or `prepared`: `auth_message_reconciles >= 8`, or age at least 15 minutes.
- Accepted message with push still open: `auth_push_publications` or `auth_push_reconciles >= 2`, token waits `>= 2`, or age at least 15 minutes.
- Push `rejected`, `terminal_failure`, or `expired` settles immediately and keeps `relay_accepted`.

The old shared eight-attempt cap is not a Marmot decision. `attempt_count` stays the scheduler counter. Recommended retry delays are clamped to 15 seconds through 5 minutes. A permanently unobservable push is settled by the age limit rather than polled forever.

`settle_due` is the terminal path. It uses the same fallback rule as delivery completion and the same completion token, so the settlement and the Telegram row commit together or not at all. A test alert does not fall back. Explicitly disabled Telegram stays disabled. A second fallback with the same logical id is not inserted.

Message reconciliation (`delivery` claim of a not-yet-accepted Marmot row) and push reconciliation (`push` claim) are separate scheduler passes.

## Dead-letter retry

`retry_dead_letter` is transport-aware:

- NIP-17 with `envelope_json`: `SameOperation`. The event id and bytes stay.
- NIP-17 without an envelope: `NewSubmission`. `submission_generation` increments and `attempt_count` resets. This is the only path that mints a new submission generation.
- Marmot, with or without a local envelope: `Reconcile`. The journal in the helper or Durable Object is authoritative. Accepted message evidence is not erased.
- Telegram: `SameOperation`. Delivery is at-least-once. An ambiguous HTTP acknowledgement is not proof the chat received it, and it is not permission to mint a new logical notification.
- Missing row: `Missing`.

A new logical notification requires a new alert id. A missing NIP-17 envelope is not permission to submit a new Marmot operation.

## Claims and shutdown

`claim_outbox(..., runtime_id)` records `claim_owner`. `extend_claim` requires the same unexpired token, `until > now`, and `until <= now + 300000`. `claim_ownership` returns `Active`, `Expired`, `Lost`, or `Missing`. Call it before an irreversible publish. `save_envelope` requires a live claim and does not replace an existing envelope.

`release_open_claims(runtime_id, now)` clears claims whose `claim_owner` is that runtime. An empty runtime id releases nothing. Native shutdown aborts tasks, then releases only `native-<pid>`. Another process's claims stay. If the helper is still inside `submit_text` after the caller stops, the next owner reconciles `operation_id` and does not encrypt again.

## D1 atomicity

D1 `batch` is the atomic boundary. Local D1 does not undo an earlier statement when a later statement errors, so a required fallback is inserted first. The completion update then requires that Telegram `logical_id` to exist, and it sets a fresh `completion_token`. Equal `state` and `updated_at` are not ownership. A losing claimant's token matches neither statement. If the insert does not land, the completion's `EXISTS` check matches nothing, so the claim stays. Settlement uses the same order: the insert matches only a row that still satisfies the settlement predicate, and the settlement update requires the Telegram row. A second settlement does not insert another Telegram row. SQLite does the insert after the winning update inside one transaction and rolls that update back when the insert changes nothing and no Telegram row exists. Replaying a finished operation is idempotent: the claim is gone, neither statement matches, and no second fallback is created.

Reminder updates require the observed `decision_generation`, `reminder_count`, `acked_at IS NULL`, and silence not in the future, plus the winning monitor generation and commit token. The reminder alert insert requires that the reminder update already landed. Vendor version, vendor fence, and vendor alerts are one batch. A version write without the matching vendor token aborts the batch.

## Onboarding

`POST /v1/diagnostics/marmot/onboard` requires the operator token. The body is:

```json
{
  "projectId": "smartflowsocial",
  "operationId": "onboarding-operation-id",
  "replace": false
}
```

`idempotencyKey` is an alias of `operationId`. The same project and operation id replays. A different id with `replace: false` returns 409 `operation_in_progress` and the stored id. `replace: true` moves the current pointer and appends `marmot_onboard_history`. It does not delete the previous operation and it does not rewrite alert rows. The response is `202` with `status: unavailable`, `connected: false`, and dependency `marmot transport is not connected on this build`. This route does not invent a group id. `MarmotControl::onboard` in `crates/watchdog-engine/src/http_api.rs` is the hook a later integration replaces. `UnconnectedMarmot` is the implementation on this branch.

The Worker compares the bearer token before it reads an operator body.

## Scheduling

Native loops stay separate. The check loop stops at about 55 seconds. The vendor loop stops at about 180 seconds. Dispatch passes a deadline and does not start work after it.

The Worker minute cron runs health for 12 seconds, then Telegram, NIP-17, and Marmot message dispatch until 17 seconds, then Marmot push reconciliation until 20 seconds. A transport is not started when less than 1.5 seconds remain. The hourly cron (`0 ...`) runs vendor checks and prune. It does not run health or push reconciliation. CPU time (`cpu_ms` 30000) is not the wall-clock deadline. Telegram and other Worker HTTP calls use the configured check timeout, capped at 15 seconds. An admitted helper or Durable Object mutation is not cancelled by the caller. The owner reconciles it later.

Cloudflare Workers are not treated as Marmot-capable. `marmot_supported` is false. An enabled Marmot route, including a project override, makes `/readyz` unavailable. A scheduler with no successful run is `uninitialized` after the native 180 second startup grace. The Worker has no startup grace. Unknown historical push state does not, by itself, fail readiness.

## What Agent A implements

- Map helper journal states onto the canonical enums above. Do not send a state this contract does not list.
- Keep `operation_id` equal to the alert id. Reconcile on `RetryMode::Reconcile`. Do not call `submit_text` again while a journal or MDK record exists.
- Renew the claim with `extend_claim` during the helper call. After `Lost` or `Expired`, do not start another mutation. Let the in-flight call finish.
- Onboarding uses `operationId` and `replace`. `MARMOT_REONBOARD=<project>` remains `reonboard:<project>` with `replace: true`.
- `readiness` should return account, canonical convergence, key-package, and recipient-token readiness without token bytes. Until that projection is stored, native readiness reports `unknown` or `unconfigured`.

## What Agent B implements

- The Durable Object is the cryptographic authority on Cloudflare. D1 stores only the projection columns in migrations `0009` and `0010`.
- Use the same canonical states and the same rule that a push failure does not clear `relay_accepted`.
- Complete an admitted operation even if the Worker invocation that started it has returned. The next scheduled owner reconciles `operation_id`.
- Do not put MLS state, private keys, or push capabilities in D1.
- Expose the same diagnostic fields Agent A's `readiness` exposes. Missing fields stay `unknown`.

## Runtime notes

Worker probes measure latency with `Date.now`. `std::time::Instant` panics on `wasm32-unknown-unknown` and aborts the scheduled invocation before the request is sent.

`PRIVATE_NETWORK_PROFILE` is the only switch that allows a non-default port. Public probe URLs still reject one. The isolated workerd config sets the switch so a local fixture can bind an unprivileged port. Production wrangler files do not set it.

Public status is `misconfigured` for a missing NIP-17 sender or recipient only when NIP-17 is enabled. Disabled NIP-17 does not by itself fail `/v1/status`. Dead letters still make that status `degraded`. Readiness does not treat historical dead letters as a failed scheduler.

`sh tests/runtime/worker-scheduled.sh` builds the Worker, applies migrations `0001`–`0011` to an isolated local D1 database, and runs the fixture against `wrangler dev --test-scheduled`. The fixture binds port 0 and writes that port down. The script does not kill a process merely because a port is in use. `POST /v1/diagnostics/runtime-fence` exists only when `ENVIRONMENT=test`. It drives `finish_with_fallback`, `settle_one`, and `commit_check` through the D1 adapter. Production wrangler files do not set `ENVIRONMENT=test`.

## Build and rollback

Migrations `0010_lifecycle` and `0011_delivery_fencing` are additive. Neither rewrites historical `message_state` or `push_state`, and `0011` leaves the new counters NULL. A null historical state stays unknown. Native migrations run one file per transaction, so an interrupted file rolls back with its ledger row. Operational rollback is a snapshot from before the migration being removed. It is not MLS recovery. An unknown ledger id is `schema_unsupported`.

Apply `0001` through `0011` in order on a fresh database and on an upgrade. Do not apply them to production from this branch. The Durable Object's own storage migration stays on Agent B's branch and is not part of this ledger.

## Adapter changes still required

This branch stays buildable against the current `DeliveryOutcome`. `interpret` reads `message_phase`, `push_phase`, `accepted`, `terminal`, and `hold_attempt`. Counters stay unknown until the adapter copies them. Do not add a required field to `DeliveryOutcome` in a way that breaks `crates/watchdog-native/src/marmot.rs`; that file belongs to Agent A.

Agent A, in the helper client that builds `DeliveryOutcome` (the native Marmot adapter, not this branch's store):

- Map `message_state` / `message_phase` and `push_state` / `push` through `MessageState::parse` and `PushState::parse`.
- Copy `message_attempts`, `unknown_attempts`, `token_wait_attempts`, and `unobservable_attempts` into `AuthoritativeCounters`. Leave `push_publications` unset: the helper's `push_attempts` is null.
- Pass `retry_after_ms` through `bounded_retry_ms`. The engine currently clamps its own fallback when the outcome has no delay field.
- `onboard` and `readiness` replace `UnconnectedMarmot` and the readiness `unknown` fields. `MARMOT_REONBOARD=<project>` remains `reonboard:<project>` with `replace: true`.
- Renew the claim during `submit_text`. A caller timeout must not kill the helper or start a second encryption.

Agent B, in the Worker client that calls `POST /marmot` (not present on this branch):

- Map `messagePhase`, `pushPhase`, `messageEventId`, `pushEventId`, `evidence`, `error`, `settled`, `reconcileAfterMs`, `messageAttempts`, and `pushAttempts` onto the same enums and `AuthoritativeCounters`. Omitted counters stay omitted.
- `pushPhase: relay_accepted` is relay acceptance of the kind-446 gift wrap, not phone delivery.
- One Durable Object per project sender. `replace: true` does not change the recipient after a group exists.
- An admitted cryptographic mutation continues if the Worker invocation returns. The next scheduled owner reconciles `operationId`.

The operational store still must not contain MLS secrets, private keys, raw device tokens, or encrypted wake capabilities. `stage_push` material stays in the Durable Object.
