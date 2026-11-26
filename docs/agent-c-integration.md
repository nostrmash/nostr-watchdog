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

Counters are cumulative and phase-specific. A repeated phase adds nothing. A push reconciliation that restates `relay_accepted` does not increment `message_attempts`. Unknown counters stay zero only when that phase was never observed. They are not invented from a missing field.

| Column | Increments when |
| --- | --- |
| `message_attempts` | A new submission leaves `not_submitted` or `prepared` |
| `message_reconcile_attempts` | An already-open message phase changes |
| `unknown_attempts` | The phase becomes `completion_unknown` or push `unknown` |
| `token_wait_attempts` | Push becomes `token_unavailable` |
| `push_publication_attempts` | Push becomes `prepared` or `publication_attempted` |
| `unobservable_attempts` | Push becomes `unobservable` |
| `attempt_count` | Scheduler attempts. Independent of the counters above |

`operation_id` is the stable transport operation id. For Marmot it defaults to the alert id. `submission_generation` increments only for a NIP-17 dead letter that has no signed gift wrap. It is not a new Marmot operation id.

## Reconciliation budgets

`settle_expired` runs before a claim. A row leaves the active queues when any of these is true and the claim is free:

- Older than 24 hours.
- `completion_unknown` with 4 message reconciliations.
- `accepted_pending` or `prepared` with 8 message attempts and age over 15 minutes.
- `token_unavailable` with 2 token waits.
- `publication_attempted` or `unobservable` with 2 unobservable observations.
- Push `rejected`, `terminal_failure`, or `expired`.

A settled `relay_accepted` message stays `relay_accepted`. Push `publication_attempted`, `prepared`, or `pending` becomes `unobservable`. The historical phase is kept in `message_phase` and `push_phase`. Recommended retry delays are clamped to 15 seconds through 5 minutes. An unobservable evidence API is not polled forever.

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

D1 `batch` is the atomic boundary. `finish_with_fallback` updates the winning claim and inserts the Telegram fallback in one batch. The insert reads the updated row (`claim_token IS NULL`, matching state and `updated_at`) and refuses a second Telegram row with the same `logical_id`. A stale token changes zero rows, so the insert selects nothing. A statement error rolls the batch back, so a failed insert does not leave the original finalized.

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

`idempotencyKey` is an alias of `operationId`. The same project and operation id replays. A different id with `replace: false` returns 409 `operation_in_progress` and the stored id. `replace: true` stores the new id and does not rewrite alert rows. The response is `202` with `status: unavailable` and dependency `watchdog-marmot helper onboard operation`. This route does not invent a group id.

The Worker compares the bearer token before it reads an operator body.

## Scheduling

Native loops stay separate. The check loop stops at about 55 seconds. The vendor loop stops at about 180 seconds. Dispatch passes a deadline and does not start work after it.

The Worker minute cron runs health for 12 seconds, then Telegram, NIP-17, and Marmot message dispatch until 20 seconds. The hourly cron (`0 ...`) runs vendor checks, then push reconciliation and prune. It does not run health. CPU time (`cpu_ms` 30000) is not the wall-clock deadline. An admitted helper or Durable Object mutation is not cancelled by the caller. The owner reconciles it later.

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

`sh tests/runtime/worker-scheduled.sh` builds the Worker, applies migrations `0001`–`0010` to an isolated local D1 database, and runs the fixture against `wrangler dev --test-scheduled`.

## Build and rollback

Migration `0010_lifecycle` is additive. It does not rewrite historical `message_state` or `push_state`. A null historical state stays unknown. Operational rollback is a database snapshot from before `0010`. It is not MLS recovery. An unknown ledger id is `schema_unsupported`.
