# Agent A integration contract

This is the helper contract for Agent C's operational store and API, and the push-protocol boundary for Agent B. The native helper observes official MDK at `ca52a04718628f08ed76b777df9c444594074182`. It does not publish kind 446 itself and it does not fork MDK.

The branch stays buildable against its own baseline. Agent C's files are not edited here. The adapter in `crates/watchdog-native/src/marmot.rs` already speaks this contract. Where Agent C's scheduler still has one attempt counter, the helper reports the counters below and does not ask the store to infer them from phase strings.

## Stable identity

Every alert operation is bound to:

- project id
- stable operation id, normally the alert id (`alt_...`)
- operation type `application_message`
- sender public key
- authorized recipient public key
- group id
- payload hash

An existing operation id cannot be reused for a different project, sender, recipient, group, payload, or operation type. The helper returns `alert_identity_mismatch`. A released attempt keeps the same binding. A retry with another recipient fails even when the group and payload match. A legacy journal row that has no `recipient` is not attached to the recipient configured now. Historical alerts do not move to a replacement conversation after re-onboarding. A new rotation needs a new onboarding operation id. It does not rewrite old alert journals.

Onboarding is a separate operation, idempotent within the project and bound to the recipient and the `replace` flag.

## IPC

Newline-delimited JSON on the Unix socket. Requests that carry `nsec` must not be logged. Responses never contain token bytes, secrets, or gift-wrap ciphertext.

`send` accepts an optional `project`. The adapter sends `row.project_id`. An empty project does not mismatch a record that also has an empty project. A non-empty stored project must match.

`send` response fields:

| Field | Meaning |
| --- | --- |
| `ok` | The helper produced a record. A published message can still need reconciliation. |
| `operation_id` | The alert id. |
| `project` | Project id when one was supplied. |
| `message_state` and `message_phase` | Canonical application-message state below. |
| `message_event_id` | First MDK message id, or null. |
| `message_ids` | MDK message ids. Empty when nothing was admitted. |
| `push_state` and `push` | Canonical push state below. |
| `push_event_id` | Always null. This MDK revision discards the gift-wrap id. |
| `push_evidence` | Why `push` has that value. |
| `push_error` | Null. A tracing warning is not attributed to this operation. |
| `push_attempts` | Null. This revision has no push-attempt counter. Do not infer one. |
| `published` | MDK `SendSummary.published`. |
| `preserve_message` | The application message must not be described as unpublished. |
| `settled` | This phase does not need another helper poll. |
| `reconcile` | Same as `hold`. Poll again without encrypting again. |
| `hold` | Retry later without encrypting again. |
| `terminal` | Stop automatic retries for this phase. |
| `retry_after_ms` | Relative delay in milliseconds. It is not an absolute timestamp. |
| `operation_age_ms` | Age since the first observation of this operation. |
| `message_attempts`, `unknown_attempts`, `token_wait_attempts`, `unobservable_attempts` | Authoritative cumulative counters for those phases. Unknown counters stay absent or null. |
| `started_at_ms` | First observation of this operation. |
| `status_detail` | `refused_new_members` or null. |
| `account`, `group`, `payload_sha256` | Binding checked on every retry. |
| `operation` | Nested view for Agent C. Its `disposition` is `settled` or `reconcile`. It does not replace the journal `disposition`. |

`operation` is the object Agent C should copy. `retryAtMs` and `retryAfterMs` are the same relative delay. Convert it with `now + retryAfterMs`. Do not treat either name as an absolute clock time. `startedAtMs` is frozen on the first observation. `updatedAtMs` is the time of this response.

| `operation` field | Authoritative meaning |
| --- | --- |
| `messageSubmissions` | `1` after MDK has a local-send record (`relay_accepted`, `accepted_pending`, or `rejected`). Null while admission is still unknown. This is not `message_attempts`. |
| `messagePublications` | Null. This revision does not count external publication attempts. |
| `messageReconciles` | Cumulative `accepted_pending` observations, and only then. Null on other message states. |
| `ambiguousReconciles` | Cumulative `completion_unknown` or `prepared` observations. Null on other message states. |
| `tokenWaits` | Cumulative missing-token observations while push is `token_unavailable`. Null otherwise. |
| `pushPublications` | Null. No correlated push attempt is visible. |
| `pushReconciles` | Cumulative observations that settled push as `unobservable`. Null otherwise. |
| `retryAfterMs` | Relative delay while `disposition` is `reconcile`. Null when `settled`. |

The older flat fields `message_attempts`, `unknown_attempts`, `token_wait_attempts`, and `unobservable_attempts` are the same raw counters `advance_phase` keeps. `message_attempts` counts pending-publication reconciliations. It is not a submission count. Leave a null nested field null in `auth_*`. Do not substitute zero.

`disposition: settled` with push `unobservable` means this MDK revision will not produce a correlated push result. That is not a temporary network failure and it should not be polled like one. `token_unavailable` stays `reconcile` until two waits or the 24 hour age limit, and the application message stays `relay_accepted`.

Copy `retryAfterMs` and the nested counters. Do not invent push publication attempts from token availability, from a missing warning, or by restating `unobservable`. Scheduler attempts stay Agent C's `attempt_count`. A later timeout or push failure does not downgrade a `relay_accepted` application message or clear its message ids.

A push-reconciliation response is not a new application-message submission. `message_attempts` stays unchanged when only push state is settled. Agent C may keep a separate scheduler-attempt counter.

### Application-message states

Only states with evidence are emitted.

- `not_submitted` — no helper record and no MDK record. The adapter has not admitted the operation.
- `prepared` — the helper has recorded intent and `submit_text` has not returned.
- `accepted_pending` — MDK has the operation and has not reported publication.
- `relay_accepted` — MDK `SendAcceptDisposition::Published`. This remains when push fails, expires, or is unobservable.
- `rejected` — MDK rejected the application message.
- `completion_unknown` — a journal exists and MDK has no record. Do not encrypt again.

Human acknowledgement is a separate operational dimension. The helper does not report it.

### Push states

- `unknown` — intent is recorded and no token evidence has been read.
- `not_required` — not emitted. This path always uses a waking chat message.
- `not_attempted` — the application message is not published, so no trigger was due.
- `token_unavailable` — the published message has no active token for the configured recipient.
- `prepared` — not emitted as a result. A stored legacy `prepared` value settles to `unobservable` without being reported as an attempt.
- `pending` — not emitted. There is no durable pending-push record.
- `publication_attempted` — not emitted. A missing warning is not an attempt.
- `relay_accepted` — not emitted. Application-message acceptance is not push acceptance.
- `rejected` — not emitted from a tracing warning. A stored legacy value still settles as rejected and preserves the message.
- `expired` — not emitted. Kind 446 at this revision has no expiration tag.
- `unobservable` — tokens exist, or a legacy attempt value was stored, and this revision cannot correlate a publication attempt or a relay answer to the alert.
- `terminal_failure` — reserved. `submit_text` does not emit it.

`push_evidence` for a new result is `intent_recorded`, `message_not_published`, `token_lookup_failed`, `token_availability_only`, or `no_correlated_push_evidence`.

Kind 446 at this revision has a single `["v","marmot-push-v1"]` tag and no expiration tag.

Sanitized errors are short tokens: `crash_injected:<point>`, `alert_identity_mismatch`, `operation_already_recorded`, `recipient_absent`, `sender_absent`, `conversation_mismatch`, `conversation_not_reusable`, `conversation_index_not_ready`, `conversation_unavailable`, `mdk_storage_missing`, `mdk_storage_replaced`, `device_identity_invalid`, `sender_identity_mismatch`, `recipient_identity_mismatch`, `operation_identity_mismatch`, `operation_id_invalid`, `helper_busy`, `helper_already_running`. Hex runs of 32 or more characters, and any error text containing `nsec`, `token`, or `bearer`, become `marmot_app_error` or `[redacted]`.

Other operations: `ping`, `import`, `create_group`, `reonboard`, `members`, `sync`, `onboard`, `onboard_status`, `identity`, `readiness`.

## Onboarding

Canonical operator body, once Agent C exposes the route:

```json
{
  "projectId": "smartflowsocial",
  "operationId": "onboarding-operation-id",
  "replace": false
}
```

`idempotencyKey` may be accepted as an alias of `operationId`. The operation is idempotent within the project. The same id, recipient, and `replace` flag return the recorded account and group, including `reused: true`. A different recipient or flag returns `operation_identity_mismatch`. It does not forget a saved group or mint a second conversation.

`MARMOT_REONBOARD=<project>` maps to operation id `reonboard:<project>` with `replace: true`. A new rotation needs a new `MARMOT_ONBOARD_OPERATION`. The first uncached project uses `initial:<project>` with `replace: false`. Once a group is saved, later alerts do not send `nsec` again.

Safe re-onboarding for Agent C:

- Use a new operation id only for a deliberate sender or recipient change.
- `replace: true` adopts the group id MDK already considers reusable. It is not permission to create a second conversation after an ambiguous outcome.
- An unready conversation index stays `RetryIndex`. Creation waits until two empty lookups and at least 15 seconds.
- Missing or replaced MDK storage, a signed-out device, or a missing saved group fails closed. Do not import over a cached account whose storage is gone.
- Already submitted alert ids stay bound to their original account, recipient, group, and payload.

`readiness` returns `recipient_devices`, `active_recipient_tokens`, and the identity step. It does not return token bytes or fingerprints.

## Journal

`outbox-boundary/<operation-id>.json` is the durable identity, including a released attempt. Those files are not deleted when ciphertext is retired or when the log is checkpointed. `consumed.json` is read once for ids that have no file and is not deleted.

`outbox-boundary/operations.log` is a write-ahead log of updates since the last checkpoint. Each line is fsynced with its directory before the per-id file is replaced. On open, a torn final line — incomplete JSON or incomplete UTF-8 after the last newline — is truncated to that newline, and the file and directory are synced, before another append is allowed. A complete line that is not valid UTF-8 or JSON is `boundary_corrupt` and is not discarded. A symlink at the journal directory or the log is `boundary_symlink`.

Checkpoint runs when the log exceeds 64 KiB, or when superseded lines are at least eight and more than twice the number of operation ids. It writes any missing per-id file, then atomically replaces the log with an empty file. It does not copy historical ids back into the log, so the next operation is one append. A crash after the empty temporary file is synced and before the rename leaves the previous log in place.

`released` means MDK returned a pre-admission validation error and `local_send_status` was empty. The id stays, with its project, sender, recipient, group, operation type, and payload hash. The same identity may be submitted again only in that case. Any other `submit_text` error, including a timeout, a storage error, a panicked admission task, or an empty status after a successful return, stays `completion_unknown` and is not encrypted again. When a later `local_send_status` appears, the same operation id is projected. A different recipient, sender, group, or payload returns `alert_identity_mismatch`.

A journal write updates memory only after the log line and the per-id file are synced. If that write fails, the helper reloads the directory before it returns. If the reload fails, the journal is poisoned and later sends return `boundary_durable_failure` instead of calling `submit_text`. A symlink is `boundary_symlink`. A directory owned by another user is `boundary_owner`.

Checkpoint still reads the per-id files. That is acceptable at the current volume. A local run of 1,500 operations took about 21 seconds, almost all of it `fsync`, left `operations.log` at 42,120 bytes, and reopened in 95 milliseconds. An ordinary write does not copy those historical records back into the log.

Manual retry of a completed cryptographic operation returns the stored record. A dead-letter reset of the scheduler counter does not authorize `SendStep::Submit` while a journal or MDK record exists.

## Claim renewal

The adapter checks the claim before onboarding, group creation, and a new submission. While a helper call is in flight it renews the same claim token about every one third of the claim interval, clamped to 5–60 seconds. `extend_claim` succeeds only while the current claim is unexpired and the token matches. An expired claim is not given a new expiry. After that renewal fails, the adapter does not start another MDK operation. The call already in flight is allowed to finish. The next claimant reconciles that stable operation id from the helper journal.

A caller timeout must not kill a healthy helper. The helper process is independent of the watchdog request deadline.

Agent C owns the persistent claim. The adapter uses the existing `extend_claim` and does not change the store schema. The default claim is 120 seconds. A claim shorter than the helper call still needs this renewal loop, because a single extension before the call does not cover the whole call.

## Reconciliation budgets

Implemented in `watchdog_core::marmot_recovery::advance_phase`:

- Pending publication and accepted-pending: 8 message attempts or 15 minutes.
- Completion unknown: 4 attempts or 15 minutes, then terminal. The message phase stays `completion_unknown`.
- Missing recipient tokens: 2 waits, then `token_unavailable` is settled. The message stays `relay_accepted`.
- `unobservable`, `unknown`, and legacy `publication_attempted` or `prepared` settle to `unobservable` on the next observation. They are not reported as a publication attempt. The message stays `relay_accepted`.
- A stored push `rejected` settles immediately and preserves the message.
- Any operation older than 24 hours settles.
- Backoff is 15 seconds shifted by the phase attempt, capped at 5 minutes, returned as `retry_after_ms`.

When `message_phase` is `relay_accepted`, `preserve_message` is true, and `hold` is false, the adapter sets `accepted: true` and does not dead-letter the row because push is unverified. A push failure must not clear `message_event_id` or schedule another encryption.

Suggested store columns, separate from Agent C's scheduler attempt counter:

- `message_attempts`, `unknown_attempts`, `token_wait_attempts`, `unobservable_attempts`
- `started_at_ms`, `preserve_message`
- `push_event_id` remains null
- `push_envelope_json` remains null

Copy the helper counters. Do not derive them by counting phase strings.

## Operator API still required from Agent C

`POST /v1/diagnostics/marmot/onboard` with `Authorization: Bearer OPERATOR_TOKEN` and the body above. The handler reads the project sender secret from the server environment, calls helper `onboard`, and returns `operationId`, `phase`, `account` prefix, `group`, and `reused`. It does not return the secret or any token.

`GET /v1/diagnostics/marmot?project=` should call helper `readiness` and return `identityStep`, `group`, `recipientDevices`, and `activeRecipientTokens`.

Until those routes exist, `scripts/whitenoise-acceptance.sh` starts the helper itself and talks to its socket for init, conversation, and status. Alert commands use `POST /v1/diagnostics/test-alert` on `127.0.0.1:8791`. The native app reads `DATABASE_PATH`.

## Supervision and relays

Startup takes `helper.lock` before removing a socket. A socket is removed only when that lock is free and the socket is not accepting. Command handling is one request at a time, with a 64 KiB line limit. Health responses are capped at four concurrent connections and do not enter the command path. The helper sets umask `077`. Production spawn uses `env_clear` and does not pass `--allow-loopback`.

Configured relays are checked, including one DNS lookup, before MDK opens. MDK resolves names again and accepts domains without a lookup. That includes discovered group relays, key-package relays, notification-server hints, and inbox relays. This helper does not constrain those later connections and does not claim DNS-rebinding protection for them. Loopback is allowed only for the fixture flag.

`stop` in the acceptance script signals a pid only when `ps` reports `nostr-watchdog` or `watchdog-marmot` and `lsof` shows that process listening on the configured acceptance port or holding a socket under the acceptance state directory. A stale pid file is removed without a signal. If `lsof` is missing, the script does not signal. The default listen address is `127.0.0.1:8791`. Set `WATCHDOG_ACCEPTANCE_ADDR` when that port is taken. The script generates its own sender, operator token, database, and MDK directory. It does not read `WATCHDOG_CONFIG`, Telegram credentials, or a production sender secret.

## Agent B

Do not add a second push publisher. If a shared encoder is extracted, it has to match this MDK revision: kinds 446, 447, 448, 449, owner proof 451, legacy proof 450, server inbox 10050, version `marmot-push-v1`, 1084-byte records, and the HKDF labels in `marmot-app` `notifications.rs`. The native helper only reports the states above.

## Upstream limits

`publish_notification_trigger_best_effort` is `pub(crate)`, discards the event id and the relay acknowledgement, and logs only a failure. Success is silent. If every server is skipped, it returns success and logs nothing. `remember_message_notification_sent` runs even when publication failed, and that memory is not a public per-message query. A message id already marked notified is not triggered again. There is no push operation id and no durable pending push record, so independent push retry is not available. A structured callback would require changing `submit_text`'s return type. That is a fork of `marmot-app`, not a narrow patch, so this branch does not patch MDK.

`decrypt_push_token_for_test` and owner-proof verification are `pub(crate)`. The fixture unwraps the kind-1059 gift with the temporary server key and checks the kind-446 rumor against this revision. It does not decrypt the token and it does not prove APNs or FCM delivery.

Membership is checked with fresh `group_members` immediately before `submit_text`. A failed roster query refuses the send. Official MDK at this revision does not expose a guarded text send that holds membership across admission. `submit_custom_event_to_members` checks a member list later, and it is not the kind-9 path this helper uses. `submit_text` does not return `RefusedNewMembers`. A member can be removed, or a stale group can change, after the check returns and before the worker encrypts. That race is still open. After admission, the local-send status stays the publication record. A historical operation stays bound to its stored recipient and group and is not rerouted. A missing or replaced account or device store fails closed. An ambiguous onboarding operation does not create a second conversation. Extra devices of an authorized account are allowed by the membership rule. `active_recipient_tokens` counts two active leaves of the authorized recipient. This fixture does not pair a second live device. Out-of-order token records are not reordered by this helper.

`RelaySafetyPolicy` already drops discovered group, inbox, key-package, and notification endpoints that are private literals, localhost, or plaintext public URLs. Production does not pass `--allow-loopback`. The same policy accepts a `wss` domain without resolving it. nostr-sdk resolves that name when it dials. MDK's own dial-safety note calls this an accepted residual. There is no public connector in this revision that replaces that resolver. A one-time DNS lookup in this helper is not protection.

Native deployment is blocked until the host prevents `watchdog-marmot` from opening WebSockets except to the configured relay allowlist. On a Mac that is an application firewall or a `pf` rule scoped to that binary. Without it, a discovered relay name can be rebound to a private address after the URL check.

A physical locked-screen notification on the WhiteNoise relays has not been observed. Relay acceptance of the group message, gift-wrap acceptance, and a notification on the phone are three different results.

## What Agent C applies on the integration branch

This branch does not edit Agent C's store, scheduler, or `DeliveryOutcome`. The native adapter in `crates/watchdog-native/src/marmot.rs` still maps the flat helper fields onto the current `DeliveryOutcome`. That struct has no counter or retry-delay field, so the engine's own fallback delay is what the scheduler sees until the integration branch reads the helper JSON.

On `feat/rust-integration`, copy from the helper `send` response's `operation` object:

- `operationId` stays the alert id. Marmot dead-letter mode stays `Reconcile`.
- `messageState` and `pushState` through the existing parsers.
- `messageEventId`. Leave `pushEventId` null.
- `disposition` `settled` or `reconcile`.
- `retryAfterMs` as a relative delay: `now + retryAfterMs`, clamped to 15 seconds through 5 minutes. `retryAtMs` is the same relative value.
- `messageSubmissions`, `messagePublications`, `messageReconciles`, `ambiguousReconciles`, `tokenWaits`, `pushPublications`, and `pushReconciles` onto the nullable `auth_*` columns. Copy null as null. Do not map the flat `message_attempts` field onto `auth_message_submissions`.
- `startedAtMs` into `operation_started_at` once. Do not move it on later responses. `updatedAtMs` is not an age.

`onboard` request: `operation_id`, `nsec`, `relays`, `recipient`, `replace`. `onboard_status` returns `phase` `absent`, `importing`, `intending`, or `established`. `readiness` returns `identity.step`, `recipient_devices`, and `active_recipient_tokens`, and no token bytes. `MARMOT_REONBOARD=<project>` remains `reonboard:<project>` with `replace: true`.

Claim renewal is already in the adapter. After the claim is lost, the in-flight helper call may finish and the next owner reconciles the same operation id. It does not start another `submit_text`.

## Commands run on this branch

```bash
export ODIN="$HOME/.local/odin-dev-2026-10/odin"
export CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_DEV_INCREMENTAL=false
cargo test -p watchdog-core --lib marmot_recovery --offline
cargo test --manifest-path crates/watchdog-marmot/Cargo.toml --offline --lib
cargo test --manifest-path crates/watchdog-marmot/Cargo.toml --offline --test fixture_exchange -- --test-threads=1 --skip whitenoise_relays
```

Results on this handoff: `marmot_recovery` 15 passed. Helper lib tests passed, including torn-tail recovery, a read-only log that did not keep an unpersisted record, and 1,500 historical operations. `fixture_exchange` passed in 33.48 seconds with the public-relay test skipped. `whitenoise_relays_deliver_one_alert` then passed in 13.00 seconds against `wss://relay.eu.whitenoise.chat` and `wss://relay.us.whitenoise.chat` using generated identities. The phone procedure is `docs/acceptance.md`. It is not passed until the owner sees the notification.
