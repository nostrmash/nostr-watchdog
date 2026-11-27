# Agent B integration contract

The Cloudflare Durable Object in `crates/watchdog-marmot-worker/worker` is the authority for one project's Marmot cryptographic state. Agent C calls it. This document does not change the production Worker entrypoint, the operational database, or the scheduler.

Pinned upstream revision: MDK `ca52a04718628f08ed76b777df9c444594074182`, OpenMLS `6100df3fb1d8c3eeab53e349fcbd621f98c44fe2`, rust-nostr `4904ffb85f60178375a1dda659a61793f36f03b8`. Push encoding follows `marmot-app/src/notifications.rs` at that MDK revision (MIT, copyright 2024-2026 Internet Privacy Foundation). The Worker does not link `marmot-app` or SQLCipher.

Agent A's helper, documented in `docs/agent-a-integration.md` on `feat/rust-marmot-native`, observes official MDK and does not publish the kind 446 gift wrap itself. This Durable Object publishes the trigger and can record a relay OK for that publication. `relay_accepted` on the push phase means the relay accepted the gift wrap. It does not mean the phone delivered the notification.

## Binding

One Durable Object per project sender. The object name is the project id.

Isolated Wrangler config: `crates/watchdog-marmot-worker/worker/wrangler.toml`.

| Setting | Value |
| --- | --- |
| Worker name | `marmot-sender-probe` |
| Entrypoint | `build/worker/shim.mjs` |
| Compatibility date | `2026-11-26` |
| Binding | `MARMOT_SENDER` class `MarmotSender` |
| Migration | tag `v1`, `new_sqlite_classes = ["MarmotSender"]` |
| `MARMOT_ALLOW_LOOPBACK` | `0` in the config. Set to `1` only for a local workerd test. |

There is no route, no production account binding, and no public unauthenticated mutation route. `workers_dev` is false.

Secrets, supplied locally by a gitignored `.dev.vars` and in production as Worker secrets:

| Name | Rule |
| --- | --- |
| `MARMOT_STORAGE_KEY` | 32 bytes, hex, 64 characters. A missing or wrong-length key fails closed. The object does not substitute a zero key. |
| `MARMOT_OPERATOR_TOKEN` | Bearer token for every mutation. Empty fails closed. |

The storage key is the ChaCha20-Poly1305 key for the account snapshot. Associated data binds the magic, format version, key version, project id, and account public key. A snapshot from another project or account does not decrypt. Key version 1 is the only accepted version. A new key version fails closed. Rotation is a new Durable Object and a new onboarding, not an online re-seal.

`MARMOT_ALLOW_LOOPBACK=1` additionally allows `http://127.0.0.1`, `ws://127.0.0.1`, and the other loopback forms below. Production must leave it at `0`.

## HTTP

`POST /marmot?sender=<projectId>`

The sender is 1 to 128 characters from `[A-Za-z0-9_:-]`. Any other path is 404. The body limit is 256 KiB. Authentication and `Content-Length` are checked before the body is read. The body is then streamed and the read stops at 256 KiB. A larger body is 413. `deliver`, `reconcile`, and `readiness` do not return prepared ciphertext, token records, or encrypted wake capabilities.

Authentication is `Authorization: Bearer <MARMOT_OPERATOR_TOKEN>`, compared in constant time. A missing or wrong token is 401 `unauthorized`. `http` is rejected with 403 unless the loopback test flag is set and the host is `127.0.0.1`, `localhost`, or `::1`.

Errors that contain `nsec`, `bearer`, or `token`, and errors longer than 180 characters, are replaced with `marmot_error`. Status output contains the public key, the recipient public key, the revision, the group count, and `databaseBytes`. It does not contain the snapshot, the storage key, or an encrypted push token.

The cryptographic mutation and its SQLite write run inside `blockConcurrencyWhile`. Relay I/O runs after that gate, then a second gate records the acknowledgement. Returning an application error does not reset the object. A crash after the sealed row is written is recovered by retrying the same operation id.

## Production interface

Agent C sends one of these operations. It does not sequence `send`, `ack`, `stage_push`, or a caller-supplied token. `publish: true` asks the object to perform the relay I/O. The object chooses destinations from the account binding and from validated token hints. A caller cannot substitute an arbitrary host for a notification trigger.

### establish

```json
{ "op": "establish", "operationId": "establish-1" }
```

Requires a prior `onboard` with the recipient public key and the account relays. The object pulls kind 30443 authored by that recipient, checks the event signature and the author, and rejects a package for any other account. It creates the group once, persists every Welcome, and publishes each Welcome to the relays stored with that group. A bound group id is not onboarding completion. The response `onboarding` object distinguishes `accountInitialized`, `recipientDiscovered`, `groupAdmitted`, `groupPersisted`, `welcomePrepared`, `welcomePublicationPending`, `welcomeAccepted`, `recipientParticipationObserved`, and `conversationReady`. `completion` is `not_started`, `pending`, `unknown`, or `ready`. `conversationReady` requires both a correlated Welcome acceptance and an observed recipient leaf. A later `establish`, including one with a different operation id, republishes the original Welcome bytes and does not create a replacement group. If the group row exists and the Welcome row does not, the response is `onboarding_completion_unknown` and no new group is created. Production callers cannot replace the publication relays. `relays` on the command is ignored unless `MARMOT_ALLOW_LOOPBACK=1`.

`deliver` does not onboard, establish, sync, or maintain. Agent C schedules those separately. `deliver` and `reconcile` encrypt or reuse one stored operation and, when `publish` is true, publish that operation. They do not advance onboarding or group catch-up.

Schedule, owned by Agent C:

| Operation | When |
| --- | --- |
| `onboard` | once per project object |
| `establish` | until `welcomeAccepted` is true. Repeat the same conversation; do not mint a second group |
| `sync` | every 30 seconds while any cursor is not caught up, otherwise every 2 minutes |
| `maintain` | every 6 hours |
| `deliver` / `reconcile` | per alert. Wait `retryAfterMs` while `disposition` is `reconcile` |

### deliver

```json
{
  "op": "deliver",
  "operationId": "alert-1",
  "text": "relay down",
  "publish": true
}
```

The object encrypts to the bound group, persists that ciphertext, persists a publication attempt, then publishes the application event. An `OK` counts only when its event id is the prepared event id. An unrelated `OK` does not end the exchange and does not accept the event. The recorded relay is the relay that sent the matching `OK`, which may be a later destination. A timeout or disconnect is `completion_unknown` for the message and `unobservable` for a trigger. It is not `rejected`. An explicit `OK false` for the prepared id is `rejected`. Acceptance is monotonic.

Only after the message is `relay_accepted` does the object select current tokens and publish kind 1059 triggers. Each trigger is its own publication record: server, event id, capability identities, destinations, attempt, and outcome. One accepted trigger does not mark the operation accepted while another trigger is unresolved. The aggregate `pushPhase` stays open, `disposition` stays `reconcile`, and `triggers` plus `targets` list the sanitized evidence. `evidence` becomes `partial_push` when more than one trigger exists. Already accepted triggers are not sent again.

A prepared capability is authorized only when the current record matches all of: group id, recipient account, MLS leaf, platform, notification-server public key, token fingerprint, owner timestamp, canonical record digest, and the SHA-256 of the encrypted token. The digest is the pinned marmot-app signed-record bytes. A fingerprint is not enough. The same fingerprint on another server, group, leaf, or replacement record does not authorize the stored event. A batch that fails that check is retired. Its signed event bytes are not edited and the application message is not encrypted again. Devices in that batch that still match a current record get a new trigger with a new event id. An accepted trigger stays accepted.

An authorized server with no usable inbox stays in `targets`. While discovery is unfinished the call returns that server in the internal discover set and does not publish. After a negative kind 10050 cache, or after rediscovery still finds no inbox, the object records `gap:<server>` with reason `push_unobservable`. That gap is not a publication attempt and does not increment `pushPublicationAttempts`. A retryable timeout stays `disposition: reconcile` with `error: publication_timeout`. A terminal gap plus an accepted sibling settles, keeps `evidence: partial_push`, and sets `error: push_unobservable` and `pushRetryable: false`. A revoked target becomes `token_unavailable`. It is not reported as notified. A later stale acknowledgement does not downgrade `relay_accepted`.

Tokens come from kind 447, 448, and 449 gossip. The sender's own tokens are excluded. A leaf is authorized only when it is this account's own leaf or an engine-reported leaf that is still a member and has not been removed. A second device of the recipient is another leaf of the same account, not a third account. A device that has never produced an engine-visible leaf is not authorized. Triggers go to a validated token hint or to relays taken from that server's signed kind 10050 event. Discovery relays are not publication destinations. A missing token sets `pushState` to `token_unavailable` and leaves the message accepted. `pushRetryable` is false for `push_unobservable` and true for a timeout, a disconnect, a prepared trigger, or a token wait. `error` is `publication_timeout` or `push_unobservable` when one of those reasons was recorded, and null otherwise.

### reconcile

```json
{ "op": "reconcile", "operationId": "alert-1", "publish": true }
```

Loads the stored operation and returns the projection of the persisted row after any publication in this call. It does not create a ciphertext. If the message is still unpublished it publishes the stored event. If the message is accepted and a trigger is still unresolved, it revalidates that trigger and publishes only the unresolved authorized batches. A retired operation returns its historical phases, `"resubmittable": false`, and `"pushRetryable": false`. An operation id with no journal row and no authoritative tombstone fails with `retired operation has no record`. That error is not a settled admission. `deliver` of a new id is the admission path. `reconcile` is not. A status or readiness read does not reconcile and does not increment publication counters. A missing or corrupt historical record fails the call instead of encrypting again. `pushPublicationAttempts` counts network publication attempts. `pushAttempts` counts recorded outcomes and is not a substitute for that count.

### readiness

```json
{ "op": "readiness" }
```

Returns `account`, `pubkey`, `groupBound`, `recipient`, `recipientTokenCount`, `onboarding`, `historicalOperations`, and `historicalCapacityRemaining`. It does not return token bytes. `historicalCapacityRemaining` is null once tombstones are in the SQLite index. It is a number while they still live only in the sealed snapshot. `status` returns the same readiness and capacity fields plus `revision`, `groups`, and `databaseBytes`.

### sync

```json
{ "op": "sync" }
```

Pulls three bounded pages of 20 from the account relays: kind 445 group events, kinds 447/448/449 token gossip, and kind 1059 addressed to this account. Each stream has a stored cursor. A short completed page advances `since` to the newest timestamp and marks that stream caught up. A full page whose oldest timestamp is shared by the whole page keeps `until` on that timestamp and does not skip the rest of the second. A full page that also contains newer timestamps sets `until` to one second before the oldest timestamp. A failed ingest, a missing event id, or a missing EOSE leaves `caughtUp` false and sets `until` to the oldest timestamp in the page. The cursor moves only after the ingest and the account commit. Production callers cannot substitute relays. A synchronization gap is not reported as catch-up.

### maintain

```json
{ "op": "maintain", "publish": true }
```

Republishes the stored kind 30443 key package. A failed publication does not mint a replacement package. Agent C should call it every 6 hours. It is the operational substitute for MDK's disabled periodic maintenance. It does not rotate the sender identity and it does not create a group.

### Outcome

`messagePhase` and `messageState` use the same vocabulary: `not_submitted`, `prepared`, `accepted_pending`, `relay_accepted`, `rejected`, `completion_unknown`. `pushPhase` and `pushState` use `unknown`, `not_required`, `not_attempted`, `token_unavailable`, `prepared`, `pending`, `publication_attempted`, `relay_accepted`, `rejected`, `expired`, `unobservable`, `terminal_failure`. `disposition` is `settled` or `reconcile`. `retryAtMs` and `reconcileAfterMs` are 15000 while reconcile is required and 0 when settled. `phoneDelivery` is always false. A relay OK is not phone delivery.

Counters, present when the operation row exists:

| Field | Advances when |
| --- | --- |
| `messageAttempts` | a new ciphertext is stored. Returning the stored ciphertext does not increment it |
| `messagePublicationAttempts` | a network publication attempt is persisted, before the socket opens |
| `messageReconcileAttempts` | a correlated message acceptance is recorded |
| `unknownAttempts` | the message becomes `completion_unknown` |
| `tokenWaitAttempts` | each token wait, including a repeated wait |
| `pushPublicationAttempts` | a trigger network attempt is persisted, before the socket opens. Preparing a trigger does not increment it |
| `unobservableAttempts` | a trigger outcome becomes `unobservable` |
| `pushAttempts` | a trigger reaches `relay_accepted`, `rejected`, or `unobservable`. An acknowledgement of an already recorded attempt does not increment it |

`retryAfterMs`, `retryAtMs`, and `reconcileAfterMs` are the same value: 15000 while `disposition` is `reconcile`, and 0 when `disposition` is `settled`. `startedAtMs` is immutable. `updatedAtMs` is the latest persisted update. The response is rebuilt from that persisted row after publication. A status read is not a submission.

Reading status does not increment these. `startedAtMs` is immutable. `updatedAtMs` changes when the row changes. `operationAgeMs` is wall time since `startedAtMs`. Unknown counters stay omitted rather than being invented. Agent C owns `attempt_count` for its scheduler. This object does not.

## Commands

The body is JSON. `operationId` is the stable operation id. `projectId` on `onboard` must equal the `sender` query. `ack`, `stage_push` with `serverPubkeyHex` and `encryptedTokenHex`, `fault`, `cas_self_test`, and `stale_write` exist only when `MARMOT_ALLOW_LOOPBACK=1`. A production caller cannot confirm a relay by sending `"accepted": true`, and cannot inject a wake capability.

### onboard

```json
{
  "op": "onboard",
  "projectId": "smartflowsocial",
  "operationId": "onboarding-operation-id",
  "replace": false,
  "recipient": "<64 lowercase hex chars>",
  "relays": ["wss://relay.example.com"]
}
```

`relays` may be omitted. The same project, recipient, and `replace: false` returns `reused: true` and the same public key. A different recipient is rejected once the account is bound. `replace` does not change the recipient after a group exists. This is the re-onboarding rule: a new sender identity is a new Durable Object, not an overwrite of a group that already has MLS state.

### key_package

```json
{ "op": "key_package", "operationId": "kp-1", "publish": false }
```

Response includes `bytesHex`, `protocolProfile: "current"`, `pubkey`, and the stored signed kind 30443 event. A repeated call returns that same event. A failed publication does not generate a replacement. `"publish": true` writes it to the account relays. In production the command's `relays` field is ignored. `maintain` is the same operation and is what Agent C should schedule. Periodic MLS maintenance stays disabled so an alert send does not emit a surprise commit.

### create_group

```json
{
  "op": "create_group",
  "operationId": "create-1",
  "name": "watchdog",
  "relays": ["wss://relay.example.com"],
  "members": [{
    "bytesHex": "<key package bytes>",
    "protocolProfile": "current",
    "eventIdHex": "<64 hex chars>"
  }]
}
```

`eventIdHex` is required. Without the key-package source, official MDK refuses the welcome. The response carries `groupIdHex` and `welcomes`. The welcome is persisted before any publication. `messagePhase` is `accepted_pending` until a relay OK is recorded. `wss://relay.example` and any `*.example` host are rejected.

### send

```json
{
  "op": "send",
  "operationId": "alert-1",
  "groupIdHex": "<hex>",
  "text": "relay down",
  "publish": false
}
```

The sender and the configured recipient are required. Every current member must be the sender, the recipient, or an extra authorized device recorded at onboarding. The engine call sets `expected_epoch` to the current epoch pin and `only_to_members` to that authorized set. A missing recipient, an unauthorized member, or an unsettled epoch fails the send and returns no new ciphertext.

The same operation id, group, kind, and payload returns the original transport message and does not increment `messageAttempts`. A different payload is `alert ... is already bound to a different payload`. A different group or kind is `operation ... is already bound to a different group or kind`. A retired id returns the historical result and does not encrypt again.

### ingest, sync, ack, publication, self_update, stage_push

`ingest` takes `{ "op": "ingest", "message": <TransportMessage> }` and returns `{ "chats": ["..."] }`.

`sync` reads the prepared relay filters outside the cryptographic section, pulls a bounded page per stream, then ingests inside a second gate. Streams are kind 445, kinds 447/448/449, and kind 1059. Cursors are persisted with the account. Production relays come from the account binding.

`ack` is test-only. `{ "op": "ack", "operationId": "alert-1", "accepted": true }` records acceptance without a relay response. Production acceptance comes from the relay `OK` for the prepared event id. Official `confirm_published` runs only when the stored operation still needs it, which is a commit, not an application message. `accepted: false` sets `completion_unknown` and keeps the original ciphertext.

`publication` reads the stored operation and does not encrypt again.

`self_update` prepares one commit under the operation id. Retry returns the same commit. `ack` with `accepted: true` is the MDK confirmation.

`stage_push` is test-only and is refused unless the application message is already `relay_accepted`. It takes `serverPubkeyHex` and `encryptedTokenHex`, the marmot-push-v1 ciphertext (1084 bytes), not a raw APNs or FCM token. A second call returns the original trigger. A failed push leaves the application message accepted.

`cas_self_test` and `stale_write` are storage probes. `fault` is `before_store` or `after_store` and is rejected unless the loopback flag is set. `before_store` drops the in-memory result and writes nothing. `after_store` writes the snapshot and returns 500 without the ciphertext.

## Outcome

```json
{
  "ok": true,
  "operationId": "alert-1",
  "messagePhase": "accepted_pending",
  "messageEventId": "<hex>",
  "pushPhase": "not_attempted",
  "pushEventId": null,
  "evidence": "prepared_message",
  "error": null,
  "settled": false,
  "reconcileAfterMs": 15000,
  "messageAttempts": 1,
  "pushAttempts": 0,
  "operationAgeMs": 12
}
```

`messagePhase` is one of `not_submitted`, `prepared`, `accepted_pending`, `relay_accepted`, `rejected`, `completion_unknown`. This object emits `not_submitted` for onboarding, `accepted_pending` after a durable cryptographic write, `relay_accepted` after a recorded relay OK, and `completion_unknown` when publication was attempted and not accepted. `prepared` is the stored default for a row that has not been advanced. `rejected` is reserved for an MDK rejection of the application message.

`pushPhase` matches `pushState`. This object emits `token_unavailable` when no authorized token remains, `unobservable` when a trigger publication times out or disconnects, and `relay_accepted` when the relay returns OK for the stored gift wrap. `expired` and `terminal_failure` are not inferred here. Counters this object cannot observe are omitted. Agent C may keep a separate scheduler-attempt counter.

`settled: false` means Agent C should reconcile. `reconcileAfterMs` is 15000 while unsettled and 0 when settled. Recommended scheduler policy, applied by Agent C rather than by this object:

- Poll every 15 seconds while `accepted_pending` or `completion_unknown`, adding the phase attempt count and capping the delay at 5 minutes.
- Stop message retries after 8 attempts or 15 minutes.
- Stop `completion_unknown` after 4 attempts or 15 minutes, then treat it as terminal. Do not encrypt again.
- A missing token waits twice, then `token_unavailable`, and the application message stays published.
- `publication_attempted` holds once, then `unobservable` after 2 attempts.
- `rejected` for push settles immediately and preserves the message.
- An operation older than 24 hours settles.
- Never report phone delivery from a relay OK.

`evidence` is `onboarding`, `prepared_welcome`, `prepared_message`, `prepared_commit`, `prepared_push`, `publication_recorded`, or `stored_publication`.

Send and publish responses also include `message` or `welcomes`, the original `TransportMessage` JSON. A retry returns that same value.

## Persistence

The SQLite table is `marmot_account`, one row, id `self`: `revision`, `writer`, `account_hex`, `floors`, `sealed`. Absence is no row. Revision 0 is not a stored row. Every committed mutation stores a new revision strictly above the loaded one and a fresh 16-byte writer id.

The compare-and-swap accepts the write only when the stored writer is this attempt's writer, the stored revision is the intended revision, and `rows_written` is 1 or 2. Workerd reports 1 for a winning update and 2 for the account insert. A second update from the same expected revision reports 0 and leaves the winner's writer in the row, so the loser is rejected and must not return ciphertext. The sealed write is one statement. There is no await between the snapshot encryption and that statement.

The epoch floor is inside the snapshot and is copied to the `floors` column. On open, the column must equal the snapshot floor. A corrupt floor column is an error. Restoring a backup of both the snapshot and the floor together still rolls the group back. The floor is not an independent anchor. The writer id is what rejects a losing concurrent writer.

Commit callbacks queued by MDK are held through the transaction and run only after the compare-and-swap succeeds. A rolled-back frame drops them. They are observers. A callback panic does not undo the committed row.

The in-memory provider implements the synchronous storage trait. `backend()` returns `Sqlite` because the upstream enum has no other variant. That is not SQLCipher. The pinned MDK revision does not export its storage-contract harness. The local tests cover transaction rollback, the pending-reference high-water mark, commit-callback rollback, and authenticated-snapshot rejection.

Journal rows live in the snapshot. The same operation id cannot change group, kind, payload hash, or ciphertext. Phase updates of the same ciphertext are allowed. The journal keeps 64 full rows. A row leaves the journal only when the message is `relay_accepted` or `rejected` and the push phase is not `unknown`, `not_attempted`, `prepared`, `pending`, or `publication_attempted`. An accepted message with an unresolved push stays in the journal. The removed row becomes a tombstone bound to the project, sender, recipient, group, operation type, operation id, payload hash, and the terminal phases. The tombstone has no ciphertext. A retry of that id returns the historical result and does not encrypt again.

Ordinary admission does not read `marmot_operation`. It looks up one `alert_id`. A commit writes only tombstones created or changed in that attempt. Each row carries `project_id`, `account_hex`, `bound_revision`, `bound_writer`, and an authenticator over those fields plus the payload hash, kind, group, and message phase. A row is authoritative only when the authenticator matches and its revision is older than the account row, or equal to it with the same writer. A higher revision is an uncommitted attempt and does not retire the operation. A losing compare-and-swap deletes the rows that attempt inserted. A crash between the insert and the account write leaves those rows non-authoritative because the stored account revision is still the previous one, and the journal row is still in the previous snapshot. The snapshot omits the tombstone list once incremental history is enabled. The row count is not the integrity check. A corrupt authenticator, a mismatched project or account, or a same-revision writer conflict fails closed. The sealed snapshot still refuses to grow past 4096 tombstones if incremental history is not enabled. `historicalOperations` is `SELECT COUNT(*)` and is a report, not a proof. `historicalCapacityRemaining` is null once incremental history is enabled.

Measured admission of 40 new operations, with 100, 1,000, and 10,000 historical ids kept outside the provider: 404 µs, 410 µs, and 1,085 µs. A full scan of the 10,000-id list was 8,413 µs. The Durable Object lookup is `SELECT record FROM marmot_operation WHERE alert_id = ?`. This is not a claim about Cloudflare CPU time.

## Relay transport

Destinations are 1 to 4 URLs. `wss` on port 443 is allowed for a public host. Credentials, query strings, fragments, port 0, `.example`, `.local`, `.internal`, and non-public addresses are rejected. `ws` and `wss` to loopback are allowed only with the test flag. The 5 second deadline starts before the socket connects and covers connection and the read. Sockets are closed on completion, timeout, and early failure. Queries accept `EVENT` and `EOSE` only for subscription id `marmot`. Frames are capped at 64, 64 KiB each, and 256 KiB total. The client does not answer NIP-42 `AUTH` and does not send the sender key. Publication uses the stored event bytes. It does not rebuild them on retry. Role-specific destinations are: account relays for account discovery, key-package publication, and group sync; the recipient's relays stored on the group for Welcome publication; a token hint or a signed kind 10050 inbox for notification triggers. Bootstrap relays used to find a kind 10050 event are not used as its publication destinations.

## Push

The logical token slot is group, member identity, MLS leaf index, platform, and notification-server public key. The token fingerprint is `sha256:` plus 24 hex characters and is not part of the slot. A newer owner timestamp replaces the slot. An equal timestamp uses the canonical record digest. An owner proof is required before a record is admitted. A removed record is a tombstone and blocks an older record from returning. The sender stores the encrypted wake capability, not the raw device token.

Leaf identity is this account's `own_leaf_index` plus leaves reported by the engine on `MessageReceived.sender_leaf_index` and cleared by `GroupMemberLeavesRemoved`. An observed leaf whose epoch is older than the current group epoch is not authorized. A newer epoch that binds the same leaf index to a different member marks the previous binding removed. The public engine roster is account-level and does not include every device leaf. A leaf that the engine has not reported at the current epoch is not authorized. Positions are not inferred from the number of accounts. Pending MDK application events are dropped in the same snapshot that records a successful ingest. A failed account commit restores the previous snapshot, including those events.

Kind 10050 is fetched from the account relays when a hint is missing, invalid, stale, or a previous publication to it was unresolved. The selected event must verify, must be authored by the notification server, and must be the newest such event, with the event id breaking a timestamp tie. Relays come only from that event's `relay` or `r` tags after the destination policy. Positive and negative results are cached for one hour. An empty or invalid result is a negative cache entry, not permission to publish to the discovery relays.

## What was executed

From `crates/watchdog-marmot-worker`:

```text
CARGO_INCREMENTAL=0 cargo test -p mdk-do-storage -p marmot-worker-runtime -p marmot-worker-interop --offline --lib --test two_member -- --test-threads=8
```

Result: storage 7 passed, runtime 29 passed, `two_member` 4 passed. That includes full capability-identity revalidation, terminal and retryable push gaps, sync cursors that do not skip a shared timestamp, historical revision authority, and admission that stayed under 1.1 ms at 10,000 external identities.

```text
cd worker && sh build-release.sh
```

This run deleted `build/` first, then `worker-build --release` exited 1 with `Resource deadlock avoided` (os error 11) after writing the bundle. The script accepted it only because `index_bg.wasm`, `index.js`, and `build/worker/shim.mjs` were non-empty, the shim loads `index.js`, and the wasm header was `00 61 73 6d`. It printed `wasm_bytes=10841293` and `gzip_bytes=4170699`. Nothing was deployed.

```text
CARGO_INCREMENTAL=0 cargo test -p marmot-worker-interop --offline --test workerd_conversation -- --ignored --nocapture --test-threads=1
```

Both local ignored tests passed against that bundle in 13.20s. The conversation test reported `wasm_bytes=10841293`, `database_bytes=397312`, `send_ms=37`, `revision=46`. It also rejected an unrelated positive OK as `completion_unknown` and accepted a matching OK that arrived after that unrelated frame. The autonomous test stopped Welcome publication after the group was stored, restarted workerd, recovered the same group and the original Welcome, then continued through token gossip, one alert, gift-wrap acceptance, revocation, an unobservable hint, restart, reconcile without a new ciphertext, and a second alert.

```text
CARGO_INCREMENTAL=0 cargo test -p marmot-worker-interop --offline --test workerd_conversation -- --ignored --nocapture --test-threads=1 public_network_marmot_exchange_survives_restart
```

Passed in 28.50s. The optimized Durable Object, a generated sender, and an independent official MDK recipient used `wss://relay.eu.whitenoise.chat` and `wss://relay.us.whitenoise.chat`. The recipient's kind 30443 was accepted by the EU relay. The object discovered it, created the group, and published the Welcome. The recipient joined, published a kind 445 chat, and the object's sync decrypted `public-reply`. Signed token gossip was ingested. `deliver` of `public-alert` returned `messagePhase: relay_accepted` and `pushPhase: relay_accepted`, with the trigger's relay `wss://relay.eu.whitenoise.chat`. After a workerd restart, `reconcile` returned the same `messageEventId` `495477dcbf3e1457959d01a8260a94544b803d76fc7e3c894d801f6e2c75d152`. A second deliver, `public-alert-2`, was accepted with a different message id. No production identity and no personal WhiteNoise account was used. Phone delivery was not observed.

`public_relay.rs` remains a connectivity probe. It publishes disposable kind 0 and kind 10050 events through Node.js and is not this result.

Cloudflare's published Worker limits remain 64 MiB uncompressed, 1 second startup, 128 MB isolate memory, and 10 ms CPU on Free or 30 seconds by default on Paid. Those platform figures were not measured. The 37 ms figure is local workerd wall time.

## Frozen result

`POST https://marmot-sender.internal/marmot?sender=<projectId>` with `Authorization: Bearer <MARMOT_OPERATOR_TOKEN>`.

Settled one-trigger deliver:

```json
{
  "projectId": "public-probe",
  "operationId": "public-alert",
  "messageState": "relay_accepted",
  "messagePhase": "relay_accepted",
  "messageEventId": "495477dcbf3e1457959d01a8260a94544b803d76fc7e3c894d801f6e2c75d152",
  "pushState": "relay_accepted",
  "pushPhase": "relay_accepted",
  "pushEventId": "87adeee3b371cdc2a4027ab5f060c1ac76aa3e22359b2a2dcac74f42b27eb205",
  "evidence": "prepared_message",
  "error": null,
  "disposition": "settled",
  "settled": true,
  "retryAfterMs": 0,
  "pushRetryable": false,
  "phoneDelivery": false,
  "pushPublicationAttempts": 1,
  "pushAttempts": 1,
  "messageAttempts": 1,
  "messagePublicationAttempts": 1
}
```

`messageEventId` is the transport message id. `pushEventId` is the Nostr event id. `evidence` stays `prepared_message` for a single accepted trigger. `partial_push` is used when more than one trigger is present.

One accepted trigger and one retryable timeout:

```json
{
  "disposition": "reconcile",
  "settled": false,
  "evidence": "partial_push",
  "error": "publication_timeout",
  "pushRetryable": true,
  "retryAfterMs": 15000,
  "pushState": "unobservable"
}
```

One accepted trigger and one terminal missing inbox:

```json
{
  "disposition": "settled",
  "settled": true,
  "evidence": "partial_push",
  "error": "push_unobservable",
  "pushRetryable": false,
  "retryAfterMs": 0,
  "targets": [
    {"eventId": "trigger-a", "phase": "relay_accepted", "retryable": false},
    {"eventId": "gap:server-b", "server": "server-b", "phase": "unobservable", "reason": "push_unobservable", "retryable": false}
  ]
}
```

Use `pushPublicationAttempts` for network attempts. Preparing a trigger does not increment it. A readiness or status read does not increment it and is not a reconcile.

## Deployment

Keep this object as a separately bound Worker. The wasm build, the loopback flag, and the storage key are isolated from Agent C's entrypoint. The supported binding is a cross-script Durable Object namespace. The object name is the project id. There is no public route between the two Workers.

Marmot script `marmot-sender-probe`, class export `MarmotSender`, migration tag `v1` with `new_sqlite_classes = ["MarmotSender"]`. On the watchdog Worker:

```toml
[[durable_objects.bindings]]
name = "MARMOT_SENDER"
class_name = "MarmotSender"
script_name = "marmot-sender-probe"
```

`MARMOT_OPERATOR_TOKEN` is present on both Workers. `MARMOT_STORAGE_KEY` is present only on `marmot-sender-probe`. The watchdog calls the namespace stub for `sender=<projectId>` and posts the JSON body to `/marmot`. A private service binding is the fallback if the runtime cannot bind another script's Durable Object class:

```toml
[[services]]
binding = "MARMOT"
service = "marmot-sender-probe"
```

That binding can serve `https://marmot-sender.internal/marmot?sender=<projectId>` without a public hostname. The namespace binding is the one to use. It addresses the object directly.

Deploy `marmot-sender-probe` and its migration before adding the watchdog binding. Roll back by removing the watchdog binding first. Do not delete the Marmot class while the watchdog still names it, and do not point a new account at an existing object id or reuse another account's storage key. This repository did not deploy either Worker. The local proof is one workerd process for the Marmot Worker. A combined two-Worker workerd was not run.

## Remaining limits

- The public engine trait exposes members without leaf indexes. A device is authorized only after the engine reports its leaf on a group event, or when the leaf is this account's own leaf. A silent extra device stays unauthorized until it speaks. That is fail-closed, not a guessed roster.
- `maintain` republishes one stored key package. It does not rotate the sender and it does not create a group. MDK periodic maintenance stays disabled so a send does not emit a surprise commit.
- Restoring a backup of the snapshot and the epoch-floor column together still rolls the group back. If that state cannot be shown to be current, re-onboard instead of replaying it. Historical rows are authoritative only when their authenticator and revision agree with that snapshot. A row count is not that proof.
- The relay client rejects credentials, unsafe ports, non-public hosts, `.example`, `.local`, and `.internal`. It does not answer NIP-42 AUTH. Loopback is unreachable unless `MARMOT_ALLOW_LOOPBACK=1`.
- The loopback fixture does not check Nostr signatures. Key-package admission and kind 10050 selection verify signatures in the object. Phone delivery is not claimed from a relay OK.
- `worker-build --release` can fail while moving its staging directory (`Resource deadlock avoided`, os error 11) after the wasm and shim already exist. `worker/build-release.sh` deletes `build/`, runs the release build, requires the wasm magic and `index.js`, copies the shim when the move failed, and exits nonzero when any required file is missing or empty. It does not deploy.
- Historical identity is one SQL row per operation, written with the account commit and ignored until that commit wins. The 4096 snapshot cap remains only when incremental history is off. Durable Object storage quota is still a platform limit.
- A device that has not spoken since the current epoch stays unauthorized. Group catch-up does not treat a missing or partial page as success.
- The public-network run used official MDK for the recipient and this crate's pinned token-gossip encoder. `marmot-app` and a Transponder server were not in this workspace. The EU relay accepted the gift wrap. That is not phone delivery.
- `deliver` does not onboard or sync. Agent C must schedule `onboard`, `establish`, `sync`, and `maintain`. The integrated adapter that posts `op: send` without a group id is not this contract.
- An upstream storage-contract harness is not available at this revision. SQLCipher remains unusable for `wasm32-unknown-unknown`; the Durable Object does not depend on it.
