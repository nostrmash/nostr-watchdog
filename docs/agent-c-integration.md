# Agent C integration contract

This branch does not modify the native Marmot helper, `crates/watchdog-native/src/marmot.rs`, `crates/watchdog-core/src/marmot_recovery.rs`, or the Cloudflare Durable Object Marmot work. The shared store and engine now expose the operations those implementations need.

## Claim ownership

Long native Marmot operations must keep the outbox claim they were given.

- `extend_claim(id, token, until, now)` succeeds only while the same token is unexpired, the row is `retrying`, and the new deadline is within five minutes of `now`. An expired token cannot be renewed. Take a new claim instead.
- `claim_ownership(id, token, now)` returns `Active { until }`, `Expired`, `Lost`, or `Missing`. Call it immediately before an irreversible publish or push. Do not submit a new cryptographic message when the result is not `Active`.
- `release_open_claims(now)` clears claim tokens on shutdown without deleting a stored envelope.
- `save_envelope` still refuses to replace an envelope that already exists, and it requires a live claim.

## Message state and push state

`alert_outbox` now stores these independently. They are sanitized projections. They are not MLS secrets, push tokens, or private keys.

| Column | Meaning |
| --- | --- |
| `message_state` | `prepared`, `accepted`, `accepted_pending`, `failed`, or null |
| `push_state` | `pending`, `accepted`, `unobservable`, `expired`, `rejected`, or null |
| `message_attempts` | Application-message submissions |
| `push_attempts` | Push reconciliation attempts |
| `message_updated_at`, `push_updated_at` | Completion time of that dimension |
| `terminal_reason` | Sanitized error code |
| `operator_ack_at` | Operator acknowledgement of the alert row |
| `logical_id` | Transport-independent notification id used for fallback dedupe |
| `submission_generation` | Increments only when a dead letter is retried as a new submission |

`accepted_pending` means the message was handed to a relay or helper and completion was not observed. It is not device delivery. `push_state` of null or `unobservable` is not device delivery either. Push reconciliation is claimed separately (`kind = "push"`) and is limited so it cannot consume the message budget.

`retry_dead_letter` returns:

- `SameOperation` when an envelope already exists. The envelope and attempt count stay. This retries the same NIP-17 event.
- `NewSubmission` when there is no envelope. `submission_generation` increments and attempts reset.
- `Missing` when the row is not a dead letter.

## Fallback

One policy, `queued_transport`, decides delivery for incidents, recoveries, reminders, version notices, security advisories, integrity alerts, and test alerts.

- Global `ENABLE_*` flags are defaults. A project route can turn a transport on.
- `EMERGENCY_DISABLE_NIP17`, `EMERGENCY_DISABLE_MARMOT`, and `EMERGENCY_DISABLE_TELEGRAM` are master switches. They override project routes.
- A disabled or unconfigured transport is finalized. Critical NIP-17 or Marmot rows can create one Telegram fallback when `TELEGRAM_MODE=nostr_fallback`. The fallback is inserted in the same store operation as the failure.
- Test alerts never create a fallback.
- `accepted_pending`, and a critical Marmot message whose push is missing or unobservable, still require the configured fallback.
- Fallback dedupe uses `logical_id`, not the transport-specific dedupe key.

## NIP-42 privacy

Discovery connections never sign an AUTH event, even if the caller has the project nsec. An optional challenge is ignored. `auth-required` on OK or CLOSED fails closed with `relay_auth_required`.

Publication connections sign only after a required challenge, at most twice. They wait for OK of the AUTH event id. On acceptance they resend the original event once. The application event id does not change. A rejected AUTH is `relay_auth_rejected`.

Bootstrap relays are discovery infrastructure. A gift wrap is published only to relays in the recipient's validated inbox list.

## Onboarding

`POST /v1/diagnostics/marmot/onboard` with operator auth and JSON `{ "projectId", "idempotencyKey" }` stores the key once. The same key reads the same row. A different key returns 409. The response status is `unavailable` until the helper performs onboarding. This API does not create a group and does not invent a conversation id.

Agent A: stop treating `MARMOT_REONBOARD=<project id>` inside `deliver()` as a per-alert re-onboard. Re-onboarding belongs on this idempotent route, then one helper operation. The current helper `shutdown_helper()` (SIGTERM, then kill after five seconds) is what native shutdown calls. Please also expose a bounded health result the readiness endpoint can store: account initialized, last successful sync, key-package readiness, and recipient-token readiness. Until that exists, readiness reports Marmot as `unknown` on the native process and `unavailable` on the Worker when Marmot is enabled.

Agent B: the Worker does not report Cloudflare Marmot as ready. `marmot_supported` is false. Supply the same diagnostic fields through the store projection when the Durable Object exists. Do not put MLS secrets or push capabilities in D1.

## Readiness

`GET /readyz` checks the database, schema, configuration, scheduler freshness, and required transports. A disabled optional transport stays healthy. Unknown Marmot or push-token state does not fail readiness. An enabled transport this runtime cannot provide does. Historical dead letters do not. Pending recovery counts are reported and do not, by themselves, fail readiness.

## Scheduling

Native loops are separate: health every 60 seconds, vendor hourly, Telegram and NIP-17 every 15 seconds, Marmot messages every 15 seconds, push reconciliation every 30 seconds with a limit of one, and Marmot sync on its own loop. Missed ticks are skipped. Each dispatch claims only the rows it will start.

The Worker scheduled event always runs health first. Vendor checks run only on the hourly cron and only when time remains. Dispatch order is Telegram, NIP-17, Marmot messages, then one push reconciliation. The budget is 20 seconds inside the 30 second CPU limit.

## CI after your branches merge

If either branch adds a crate, lockfile, or system package:

- Audit that lockfile with `cargo deny` and `cargo audit`.
- Add the crate to the image only when it is a runtime binary. Keep Odin, Node, and other build tools out of the final image.
- The native SQLCipher WASM probe is an expected-failure experiment. Do not make it a required CI job.
- Do not add opt-in public relay tests to the routine workflow.
