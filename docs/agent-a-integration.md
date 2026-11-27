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

A commit does five steps in order. It appends and syncs the WAL line. It atomically replaces and syncs the per-id file. It updates the in-memory map. It checkpoints only from that updated map, and only when the log exceeds 64 KiB or superseded lines are at least eight and more than twice the number of operation ids. It replaces the log with an empty file only after those per-id files match the map. Checkpointing does not copy historical ids back into the log.

An earlier order checkpointed before the memory update. `materialize_files` then wrote the previous record over the new per-id file and deleted the WAL that held the new record. An update of an existing operation could be reverted. That sequence is gone.

A checkpoint error after the per-id file is durable is not evidence that the operation never existed. The helper reloads the directory. If the reload shows the record, the journal stays usable and a later send sees it. If the reload fails, or the reloaded record is not the one just written, the journal is poisoned and later sends return `boundary_durable_failure` instead of calling `submit_text`. A failed WAL append does not leave the new record in memory. An unpersisted intent does not authorize encryption.

`released` means MDK returned a pre-admission validation error and `local_send_status` was empty. The id stays, with its project, sender, recipient, group, operation type, and payload hash. The same identity may be submitted again only in that case. Any other `submit_text` error, including a timeout, a storage error, a panicked admission task, or an empty status after a successful return, stays `completion_unknown` and is not encrypted again. When a later `local_send_status` appears, the same operation id is projected. A different recipient, sender, group, or payload returns `alert_identity_mismatch`.

A symlink is `boundary_symlink`. A directory owned by another user is `boundary_owner`.

Checkpoint still reads the per-id files. That is acceptable at the current volume. A local run of 1,500 operations took 20,018 ms, almost all of it `fsync`, left `operations.log` at 42,120 bytes, and reopened in 83 ms. An ordinary write does not copy those historical records back into the log.

Regression coverage for an update that crosses the checkpoint threshold: a pending operation becomes published and the published message id survives restart; a released operation becomes submitting and keeps its recipient and payload hash; an injected failure after the WAL append, after the per-id replacement, and before WAL truncation each leaves the published record; a process exit at those same three boundaries leaves the published record after reopen; a torn tail is still truncated before the next append. The published record keeps its message id, so the reverted-to-pending state that would allow another encryption does not occur.

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

Before MDK builds a client, the helper binds `127.0.0.1` on an ephemeral port, points `WN_SOCKS5_PROXY` at it, and clears `WN_SOCKS5_USERNAME` and `WN_SOCKS5_PASSWORD`. Pinned MDK sends every nostr-sdk relay connection through that proxy and does not fall back to a direct dial. The filter resolves the target, refuses the connection when any answer is private, loopback, link-local, multicast, or a metadata name (`.local`, `.internal`, `.home.arpa`, `metadata.google.internal`), and opens TCP only to an address that passed. A later DNS change cannot move that connection. Bootstrap, group, key-package, inbox, and notification-server relay hints share this client, so they share the filter. `--allow-loopback` allows loopback targets only, for the fixture. It does not allow RFC1918 or link-local addresses. Production spawn does not pass that flag.

The DNS lookup in `relays.rs` is a preflight for the operator's configured URLs. It is not the pin. This is not an application firewall and it is not a `pf` rule. The enforced boundary is the SOCKS filter MDK already consults.

`stop` in the acceptance script signals a pid only when `ps` reports `nostr-watchdog` or `watchdog-marmot` and `lsof` shows that process listening on the configured acceptance port or holding a socket under the acceptance state directory. A stale pid file is removed without a signal. If `lsof` is missing, the script does not signal. The default listen address is `127.0.0.1:8791`. Set `WATCHDOG_ACCEPTANCE_ADDR` when that port is taken. The script generates its own sender, operator token, database, and MDK directory. It does not read `WATCHDOG_CONFIG`, Telegram credentials, or a production sender secret.

## Agent B

Do not add a second push publisher. If a shared encoder is extracted, it has to match this MDK revision: kinds 446, 447, 448, 449, owner proof 451, legacy proof 450, server inbox 10050, version `marmot-push-v1`, 1084-byte records, and the HKDF labels in `marmot-app` `notifications.rs`. The native helper only reports the states above.

## Upstream limits

`publish_notification_trigger_best_effort` is `pub(crate)`, discards the event id and the relay acknowledgement, and logs only a failure. Success is silent. If every server is skipped, it returns success and logs nothing. `remember_message_notification_sent` runs even when publication failed, and that memory is not a public per-message query. A message id already marked notified is not triggered again. There is no push operation id and no durable pending push record, so independent push retry is not available. A structured callback would require changing `submit_text`'s return type. That is a fork of `marmot-app`, not a narrow patch, so this branch does not patch MDK.

`decrypt_push_token_for_test` and owner-proof verification are `pub(crate)`. The fixture unwraps the kind-1059 gift with the temporary server key and checks the kind-446 rumor against this revision. It does not decrypt the token and it does not prove APNs or FCM delivery.

Membership is checked with fresh `group_members` immediately before `submit_text`. A failed or empty roster refuses the send. A roster that passes is not held across admission. Official MDK at this revision has no API that checks the member set and admits the kind-9 message in one transaction. `submit_custom_event_to_members` checks a member list later, and it is not the kind-9 path this helper uses. `submit_text` does not return `RefusedNewMembers`.

The remaining race is the interval after `group_members` returns and before the worker encrypts. A recipient can be removed, or another account can be added, in that interval. The ciphertext can then include a member the pre-send check did not see, or omit a recipient the check required. This matters for any deployment where membership can change while an alert is being submitted. A single sender and one recipient, with no concurrent MLS commit, is the restricted case this helper can actually enforce. A group that accepts invites or removals during send is outside that case.

The smallest upstream change that would remove the race is one public function that, in the same storage transaction as `insert_local_submission`, reads the current member set and returns a pre-admission error when the sender or recipient is absent or an unexpected account is present, and then encrypts from that same member set. A later read is not enough. This branch does not fork MDK to invent that function, and the pre-send query is not atomic authorization.

After admission, the local-send status stays the publication record. A historical operation stays bound to its stored recipient and group and is not rerouted when onboarding is repeated. A missing or replaced account or device store fails closed. An ambiguous onboarding operation does not create a second conversation. Extra devices of an authorized account are allowed. `active_recipient_tokens` counts two active leaves of the authorized recipient. This fixture does not pair a second live device. Out-of-order token records are not reordered by this helper. A unit test shows that a later roster which drops the recipient returns `recipient_absent` and does not keep the earlier allowance. That test is not a live competing MLS commit.

`RelaySafetyPolicy` still drops discovered private literals, localhost, and plaintext public URLs before the dial. It accepts a `wss` domain without resolving it. The SOCKS filter above is what checks the address MDK actually connects to. MDK's dial-safety note still calls unresolved domains an accepted residual inside nostr-sdk. This helper does not rely on that residual for the connection.

A physical locked-screen notification on the WhiteNoise relays has not been observed. Relay acceptance of the group message, gift-wrap acceptance, and a notification on the phone are three different results.

## What Agent C applies on the integration branch

This branch does not edit Agent C's store, scheduler, or `DeliveryOutcome`. The native adapter in `crates/watchdog-native/src/marmot.rs` still maps the flat helper fields onto the current `DeliveryOutcome`. That struct has no counter or retry-delay field, so the engine's own fallback delay is what the scheduler sees until the integration branch reads the helper JSON.

Exact fixtures are in `docs/native-operation-fixtures.json`. The helper test `native_operation_fixtures_match_the_helper` builds those objects from `advance_phase` and `operation_contract`. `projectId` and `operationId` are required. Reject a response whose `projectId` is not the claimed project or whose `operationId` is not the claimed alert id. An empty id is invalid. Do not open a new submission to repair a mismatch.

`feat/rust-integration` at `84b2640a583d7d1224d160561452af57c7b8c6d0` still maps flat `message_attempts` onto `message_submissions` and does not read `messageSubmissions`, `messageReconciles`, `ambiguousReconciles`, `tokenWaits`, `pushPublications`, or `pushReconciles`. That mapping is not this contract. Copy the nested fields. Leave null as null. `message_attempts` counts `accepted_pending` reconciliations. It is not a submission count.

`retryAfterMs` and `retryAtMs` are the same relative delay, or null when settled. `operation_from_transport` already keeps a value in 1–300000 ms and ignores a Unix timestamp. Pass that relative value to the scheduler. The scheduler adds it to now when it arms the timer, clamped to 15 seconds through 5 minutes. Do not add now before the parser.

On `feat/rust-integration`, copy from the helper `send` response's `operation` object:

- `operationId` stays the alert id. Marmot dead-letter mode stays `Reconcile`.
- `messageState` and `pushState` through the existing parsers.
- `messageEventId`. Leave `pushEventId` null.
- `disposition` `settled` or `reconcile`. A settled `unobservable` push is permanent for this MDK revision and stops polling. `accepted_pending` and `completion_unknown` stay `reconcile`. `relay_accepted` stays `relay_accepted` while push is `token_unavailable` or `unobservable`.
- `messageSubmissions` is `1` once MDK has admitted the message, and null while admission is unknown. `messagePublications` and `pushPublications` stay null.
- `messageReconciles` is the `accepted_pending` count. `ambiguousReconciles` is the `completion_unknown` or `prepared` count. `tokenWaits` is the missing-token count and stops at 2. `pushReconciles` is the unobservable observation count.
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

Results on this handoff, after the checkpoint reorder and the SOCKS filter:

- `marmot_recovery`: 16 passed, including delayed upstream visibility, ambiguous completion, and re-onboard identity mismatch.
- `group_auth`: 2 passed, including a later roster that removes the recipient.
- Helper lib: 23 passed. That includes the checkpoint-update regressions, process exits at `after_wal`, `after_record`, and `checkpoint`, torn-tail repair, the read-only log, the egress filter, the operation fixtures, and 1,500 historical operations (20,018 ms, log 42,120 bytes, reopen 83 ms).
- `fixture_exchange`: 2 passed in 37.64 seconds. The public-relay test was skipped in that run.
- `whitenoise_relays_deliver_one_alert`: passed in 12.73 seconds against `wss://relay.eu.whitenoise.chat` and `wss://relay.us.whitenoise.chat` with generated identities. Those dials went through the helper filter.
- Release binaries: `target/release/nostr-watchdog` and `crates/watchdog-marmot/target/release/watchdog-marmot`.
- `scripts/whitenoise-acceptance.sh` on `127.0.0.1:62069` with a fresh directory and a generated recipient that has no key package: prepare, start, init, a second init, conversation, status (`intending`, account prefix `bf47a45c9619`), restart, status, and stop all completed. Both inits returned `no_eligible_member`. No alert was sent. The state directory was removed afterward.

## Owner commands for a phone notification

Build once, from this branch:

```bash
export ODIN="$HOME/.local/odin-dev-2026-10/odin"
export CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_DEV_INCREMENTAL=false
cargo build --manifest-path crates/watchdog-marmot/Cargo.toml --release
cargo build --release -p watchdog-native
```

Use a test phone's public key. If `127.0.0.1:8791` is already taken, set `WATCHDOG_ACCEPTANCE_ADDR` to another loopback port before every command. Do not use a production sender or the operator's daily WhiteNoise account.

```bash
scripts/whitenoise-acceptance.sh prepare <test phone hex or npub>
scripts/whitenoise-acceptance.sh start
scripts/whitenoise-acceptance.sh init
scripts/whitenoise-acceptance.sh conversation
scripts/whitenoise-acceptance.sh status
```

Continue only when status shows a group and `active_recipient_tokens` greater than 0. Then, with the phone unlocked:

```bash
scripts/whitenoise-acceptance.sh alert-foreground
```

Restart, lock the phone, and confirm the locked-screen alert. `alert-locked` reads from the terminal and sends only when the typed line is `send`:

```bash
scripts/whitenoise-acceptance.sh restart
scripts/whitenoise-acceptance.sh alert-locked
scripts/whitenoise-acceptance.sh stop
```

A physical notification is unverified until the phone owner sees it. Relay acceptance is not that observation.

## Gates

| Gate | Result |
| --- | --- |
| Journal checkpoint order and update regressions | verified |
| Fail-closed ambiguous admission, including re-onboard and delayed visibility | verified |
| Relay dial filter for private, loopback, link-local, and metadata targets | verified |
| Atomic membership with kind-9 send | partial. The pre-send roster check remains, and the race after it is documented above. |
| Nested operation contract and fixtures | verified on this branch. Agent C's parser at `84b2640` still reads the flat counters and has not been changed here. |
| Locked builds, recovery tests, fixture exchange, public WhiteNoise exchange | verified |
| Acceptance script prepare, start, onboard, status, restart, stop | verified |
| Acceptance-script alert to a phone, and a locked-screen notification | untested. The generated recipient had no key package, so no alert was sent. |

Handoff commit: the tip of `feat/rust-marmot-native` after this file is committed.
