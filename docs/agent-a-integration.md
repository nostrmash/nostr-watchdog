# Agent A integration contract

This is the helper contract for Agent C's operational store and API, and the push-protocol boundary for Agent B. The native helper observes official MDK at `ca52a04718628f08ed76b777df9c444594074182`. It does not publish kind 446 itself and it does not fork MDK.

## IPC

Newline-delimited JSON on the Unix socket. Requests that carry `nsec` must not be logged. Responses never contain token bytes, secrets, or gift-wrap ciphertext.

Stable operation id for an alert is the alert id (`alt_...`). It is stable across every retry. Onboarding uses its own operation id.

`send` response fields:

| Field | Meaning |
| --- | --- |
| `ok` | The helper produced a record. A published message can still have `hold: true`. |
| `operation_id` | The alert id. |
| `disposition` | `submitting`, `accepted_pending`, `published`, `rejected`, or `completion_unknown`. |
| `message_phase` | `accepted_pending`, `relay_accepted`, `rejected`, or `completion_unknown`. |
| `message_event_id` | First MDK message id, or null. |
| `message_ids` | MDK message ids. Empty when nothing was admitted. |
| `push` | One of the states below. |
| `push_event_id` | Always null. MDK discards the gift-wrap id. |
| `push_evidence` | Why `push` has that value. See below. |
| `push_error` | Sanitized MDK `error_kind`, or null. |
| `published` | MDK `SendSummary.published`. |
| `preserve_message` | The application message must not be described as unpublished. |
| `hold` | Retry later without encrypting again. |
| `terminal` | Stop automatic retries for this phase. |
| `retry_after_ms` | Helper backoff. Advisory until the engine uses it. |
| `message_attempts`, `unknown_attempts`, `token_wait_attempts`, `unobservable_attempts` | Independent counters. |
| `started_at_ms` | First observation of this operation. |
| `status_detail` | `refused_new_members` or null. |
| `account`, `group`, `payload_sha256` | Binding checked on every retry. |

Message phases the helper can evidence:

- `accepted_pending` — MDK has the operation and has not reported publication.
- `relay_accepted` — MDK `SendAcceptDisposition::Published`.
- `rejected` — MDK rejected the attempt, including `RefusedNewMembers` when that status is actually returned.
- `completion_unknown` — a journal exists and MDK has no record. Do not encrypt again.

Push states the helper can evidence:

- `not_attempted` — the application message is not published, so no trigger was due.
- `prepared` — submission intent is recorded and `submit_text` has not returned.
- `token_unavailable` — the published message has no active token for the configured recipient.
- `publication_attempted` — recipient tokens existed and MDK did not log a publish failure. The relay acknowledgement was discarded.
- `rejected` — during that `submit_text`, MDK logged `notification trigger publish failed`.
- `unobservable` — bounded refreshes still have no acknowledgement. This is not a relay acceptance and not a phone delivery.
- `terminal_failure` — reserved for a future MDK error that names the trigger as terminally failed. This build does not emit it from `submit_text`.

`push_evidence` is `not_attempted`, `token_availability_only`, `publish_error_observed`, or `mdk_discards_publish_result`.

These push states are not emitted because this MDK revision does not support them: `relay_accepted`, `pending`, and `expired`. Kind 446 at this revision has a single `["v","marmot-push-v1"]` tag and no expiration tag.

Sanitized errors are short tokens: `crash_injected:<point>`, `alert_identity_mismatch`, `operation_already_recorded`, `recipient_absent`, `sender_absent`, `conversation_mismatch`, `conversation_not_reusable`, `conversation_index_not_ready`, `conversation_unavailable`, `mdk_storage_missing`, `mdk_storage_replaced`, `device_identity_invalid`, `sender_identity_mismatch`, `recipient_identity_mismatch`, `operation_identity_mismatch`, `operation_id_invalid`, `helper_busy`, `helper_already_running`. Hex runs of 32 or more characters, and any error text containing `nsec`, `token`, or `bearer`, become `marmot_app_error` or `[redacted]`.

Other operations: `ping`, `import`, `create_group`, `reonboard`, `members`, `sync`, `onboard`, `onboard_status`, `identity`, `readiness`.

`onboard` is idempotent. The same `operation_id` with the same recipient and `replace` flag returns the recorded account and group, including `reused: true` on a repeat. A different recipient or flag returns `operation_identity_mismatch`. It does not mint a second conversation when a group is already saved. `MARMOT_REONBOARD=<project>` maps to operation id `reonboard:<project>` with `replace: true`. A new rotation needs a new `MARMOT_ONBOARD_OPERATION`. The first uncached project uses `initial:<project>`.

`readiness` returns `recipient_devices`, `active_recipient_tokens`, and the identity step. It does not return token bytes or fingerprints.

## What Agent C should persist

Keep the helper journal as the authority for whether an alert was encrypted. `consumed.json` is never pruned. Per-alert files may be pruned only after the consumed disposition is `published` or `rejected`, keeping the newest 64. Do not delete a consumed entry to force a new encryption.

Suggested outbox columns, separate from the existing single `attempt_count`:

- `message_attempts` integer default 0
- `unknown_attempts` integer default 0
- `token_wait_attempts` integer default 0
- `unobservable_attempts` integer default 0
- `started_at_ms` integer
- `preserve_message` integer default 0
- `push_event_id` text null

Existing `message_phase`, `push_phase`, and `message_event_id` stay. `push_envelope_json` must stay null. Do not store gift-wrap content.

Budgets implemented in `watchdog_core::marmot_recovery::advance_phase`:

- Pending publication and accepted-pending: 8 message attempts or 15 minutes.
- Completion unknown: 4 attempts or 15 minutes, then terminal, and the message phase stays `completion_unknown`.
- Missing recipient tokens: 2 waits, then `token_unavailable` is settled. The message stays published.
- Push publication attempted: one hold, then `unobservable` after 2 attempts. The message stays published.
- Push `rejected` settles immediately and preserves the message.
- Any operation older than 24 hours settles.
- Backoff is 15 seconds shifted by the phase attempt, capped at 5 minutes, returned as `retry_after_ms`.

When `message_phase` is `relay_accepted`, `preserve_message` is true, and `hold` is false, the adapter sets `accepted: true` and does not put the row in the dead-letter queue because push is unverified. A push failure must not clear `message_event_id` or schedule another encryption.

`retry_dead_letter` may reset the engine attempt counter. The helper still refuses `SendStep::Submit` when a journal or MDK record exists. A manual retry of a completed cryptographic operation returns the stored record.

The engine's single `attempt_count` and `RECONCILE_BUDGET` of 8 remain until Agent C switches to the four counters and `retry_after_ms`. The adapter settles a published message before that shared cap can mark it unpublished.

## Claim renewal

`deliver` extends the outbox claim before onboarding, before group creation, and again immediately before `send`. If the claim is already lost, the result is `claim_lost` and no MDK call is made. If the claim expires after `submit_text` returns, the helper still returns the journal outcome. `finish_delivery` can drop the SQLite update when the claim token no longer matches. The next owner must reconcile from the helper journal instead of submitting a new encryption. Agent C's claim renewal should cover the helper call, whose timeout is 90 seconds. The default claim is 120 seconds.

The adapter removes a stale socket only when `helper.lock` can be taken and the socket is not accepting connections. Startup is serialized. The parent must not hold that lock while the helper starts.

## Operator API still required from Agent C

`POST /v1/diagnostics/marmot/onboard` with `Authorization: Bearer OPERATOR_TOKEN` and body:

```json
{"projectId":"smartflowsocial","operationId":"reonboard:smartflowsocial","replace":false}
```

The handler reads the project sender secret from the server environment, calls helper `onboard`, and returns `operationId`, `phase`, `account` prefix, `group`, and `reused`. It does not return the secret or any token.

`GET /v1/diagnostics/marmot?project=` should call helper `readiness` and return `identityStep`, `group`, `recipientDevices`, and `activeRecipientTokens`. The current handler's `pushTokenAvailable: "unknown"` does not read MDK.

Until those routes exist, `scripts/whitenoise-acceptance.sh` starts the helper itself and talks to its socket for init, conversation, and status. The watchdog process adopts a helper that already answers `health.sock`. It otherwise spawns the helper only inside delivery, so a freshly started watchdog has no socket yet. Alert commands use the existing `POST /v1/diagnostics/test-alert`. The native app reads `DATABASE_PATH`, not `WATCHDOG_DB`.

## Agent B

Do not add a second push publisher. If a shared encoder is extracted, it has to match this MDK revision: kinds 446, 447, 448, 449, owner proof 451, legacy proof 450, server inbox 10050, version `marmot-push-v1`, 1084-byte records, and the HKDF labels in `marmot-app` `notifications.rs`. The native helper only reports the states above.

## Upstream limits

`MarmotAppRuntime::submit_text` persists the application message and then calls `publish_notification_trigger_best_effort`. That function discards the event id and the relay acknowledgement. Success is not logged. Failure is a tracing warning on target `marmot_app::notifications`. There is no push operation id, no durable pending push record, and no retry of the trigger. A message id that was already notified is not triggered again after restart. `decrypt_push_token_for_test` is `pub(crate)` and test-only, so this crate cannot decrypt the token. The fixture test unwraps the kind-1059 gift with the temporary server key, checks the kind-446 rumor shape, and compares `push_token_fingerprint` with `group_push_debug_info`. That is not APNs or FCM delivery. The fixture uses one recipient device and covers replacement, revocation, an unregistered notification server, and a non-member recipient. Two active leaves of the authorized recipient are counted by `active_recipient_tokens`. This fixture does not pair a second device.

`submit_text` does not return `RefusedNewMembers`. Membership is checked with fresh `group_members` immediately before submit. A published local-send status stays the publication record if membership changes afterwards.

Configured relays are checked, including one DNS lookup, before MDK opens. MDK resolves names again and accepts domains without a lookup, including discovered group relays and notification-server hints. This helper does not pin those later connections and does not claim rebinding protection for them. `--allow-loopback` is only for the fixture. The watchdog does not pass it.

A physical locked-screen notification on the WhiteNoise relays has not been run.
