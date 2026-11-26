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

Requires a prior `onboard` with the recipient public key and the account relays. The object pulls kind 30443 authored by that recipient, checks the event signature and the author, and rejects a package for any other account. It creates the group once, persists every Welcome, and publishes each Welcome to the account relays. A repeated call returns the bound group and does not create another conversation. An interrupted call retries the same operation id and reuses the persisted Welcomes.

### deliver

```json
{
  "op": "deliver",
  "operationId": "alert-1",
  "text": "relay down",
  "publish": true
}
```

The object encrypts to the bound group, persists that ciphertext, publishes the application event, and records the relay result against that event id. Only after `messageState` is `relay_accepted` does it select the recipient's current tokens and publish the kind 1059 triggers. Tokens come from kind 447, 448, and 449 gossip ingested from the group. The sender's own tokens are excluded. Selection checks group, member, leaf, and server again at send time. Triggers go to the token's validated relay hint, or else to that server's cached kind 10050 relays. They are not sent to the group or discovery relays. A missing token sets `pushState` to `token_unavailable` and leaves the message accepted. A timeout or disconnect sets `completion_unknown` for the message and `unobservable` for the push. An explicit relay `OK false` is `rejected`. A later failure does not downgrade `relay_accepted`. Ordinary retry republishes the stored bytes and does not encrypt again.

### reconcile

```json
{ "op": "reconcile", "operationId": "alert-1", "publish": true }
```

Loads the stored operation. It does not create a ciphertext. If the message is still unpublished it publishes the stored event. If the message is accepted and the push is not, it publishes the stored trigger. A retired operation returns its historical phases and `"resubmittable": false`.

### readiness

```json
{ "op": "readiness" }
```

Returns `account`, `pubkey`, `groupBound`, `recipient`, and `recipientTokenCount`. It does not return token bytes.

### Outcome

`messagePhase` and `messageState` use the same vocabulary: `not_submitted`, `prepared`, `accepted_pending`, `relay_accepted`, `rejected`, `completion_unknown`. `pushPhase` and `pushState` use `unknown`, `not_required`, `not_attempted`, `token_unavailable`, `prepared`, `pending`, `publication_attempted`, `relay_accepted`, `rejected`, `expired`, `unobservable`, `terminal_failure`. `disposition` is `settled` or `reconcile`. `retryAtMs` and `reconcileAfterMs` are 15000 while reconcile is required and 0 when settled. `phoneDelivery` is always false. A relay OK is not phone delivery.

Counters, present when the operation row exists:

| Field | Advances when |
| --- | --- |
| `messageAttempts` | a new ciphertext is stored |
| `messagePublicationAttempts` | a network publication of that message starts |
| `messageReconcileAttempts` | an open message phase changes |
| `unknownAttempts` | the message becomes `completion_unknown` or the push becomes `unknown` |
| `tokenWaitAttempts` | the push becomes `token_unavailable` |
| `pushPublicationAttempts` | a trigger is stored or a push publication starts |
| `unobservableAttempts` | the push becomes `unobservable` |
| `pushAttempts` | the push reaches `relay_accepted`, `rejected`, or `unobservable` |

Reading status does not increment these. `startedAtMs` is immutable. `updatedAtMs` changes when the row changes. `operationAgeMs` is wall time since `startedAtMs`. Unknown counters stay omitted rather than being invented. Agent C owns `attempt_count` for its scheduler. This object does not.

## Commands

The body is JSON. `operationId` is the stable operation id. `projectId` on `onboard` must equal the `sender` query. `ack`, `stage_push` with `serverPubkeyHex` and `encryptedTokenHex`, `fault`, `cas_self_test`, and `stale_write` exist only when `MARMOT_ALLOW_LOOPBACK=1`. A production caller cannot confirm a relay by sending `"accepted": true`, and cannot inject a wake capability.

### onboard

```json
{
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

Response includes `bytesHex`, `protocolProfile: "current"`, `pubkey`, and a signed kind 30443 event. The `i` tag is the hex SHA-256 of the key-package bytes. The pinned MDK revision does not expose `KeyPackageRef`, so this is the publication identity used here. `"publish": true` writes the event to the account's relays or to `relays` on the command. The scheduler should call this for renewal. Periodic MLS maintenance is disabled so an alert send does not emit a surprise commit.

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

`sync` reads the prepared relay filters outside the cryptographic section, pulls at most 32 frames per filter, then ingests inside a second gate. Filters are kind 445 for the stored Nostr group id and kind 1059 addressed to this account. Relays come from the command or from the account binding.

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

Journal rows live in the snapshot. The same operation id cannot change group, kind, payload hash, or ciphertext. Phase updates of the same ciphertext are allowed. The journal keeps 64 rows. A row leaves the journal only when the message is `relay_accepted` or `rejected` and the push phase is not `unknown`, `not_attempted`, `prepared`, `pending`, or `publication_attempted`. The removed row becomes a tombstone bound to the project, sender, recipient, group, operation type, operation id, payload hash, and the terminal phases. The tombstone has no ciphertext. A retry of that id returns the historical result. The journal refuses to grow past 128 open rows. The tombstone table refuses to grow past 4096 rather than forgetting an id.

## Relay transport

Destinations are 1 to 4 URLs. `wss` is allowed for a public host. `ws` and `wss` to loopback are allowed only with the test flag. `.example`, `.local`, `.internal`, and non-public addresses are rejected. Each event is at most 64 KiB. A publication waits 5 seconds and at most 32 frames. The client publishes the transport event bytes produced by official MDK. It does not rebuild them on retry.

## Push

The logical token slot is group, member identity, MLS leaf index, platform, and notification-server public key. The token fingerprint is `sha256:` plus 24 hex characters and is not part of the slot. A newer owner timestamp replaces the slot. An equal timestamp uses the canonical record digest. An owner proof is required before a record is admitted. A removed record is a tombstone and blocks an older record from returning. The sender stores the encrypted wake capability, not the raw device token.

Leaf identity uses the engine's own leaf and, for a two-member group whose own leaf is 0 or 1, the other member at `1 - own`. An ingested application message can also carry `sender_leaf_index`. Selection uses that set. This is not a projection of every MLS leaf in a larger group.

Kind 10050 relays, when observed, are cached per notification server, including a negative observation. A hint that fails the destination policy is ignored. There is no separate notification-server relay-list kind in the pinned specification; the fallback is the server's ordinary NIP-17 inbox.

## What was executed

Native, from `crates/watchdog-marmot-worker`:

```text
CARGO_INCREMENTAL=0 cargo test --offline --workspace -- --test-threads=1
```

The official SQLite recipient test, the push layout test, the snapshot tests, and the compare-and-swap decision test passed.

WASM and the local Durable Object:

```text
cd crates/watchdog-marmot-worker/worker
CARGO_INCREMENTAL=0 worker-build --release
cargo test -p marmot-worker-interop --offline --test workerd_conversation -- --ignored --nocapture
```

`worker-build --release` writes the wasm and then fails to move its staging directory (`Resource deadlock avoided`). The wasm is already at `worker/build/index_bg.wasm`, and `worker/build/worker/shim.mjs` is copied into place for the local test. Nothing was deployed.

The persistent conversation test and `autonomous_delivery_discovers_tokens_and_publishes_the_trigger` both passed against that optimized bundle in workerd. The second test publishes a recipient kind 30443 key package to the loopback relay, lets `establish` discover and verify it, joins the published Welcome, sends kind 447 and 449 gossip from the official native client, and calls `deliver` without a caller-supplied token. The trigger was unwrapped with `UnwrappedGift::from_gift_wrap`. A revoked token produced `token_unavailable`. A hint to a closed loopback port produced `unobservable` without a second ciphertext. After a workerd restart, `reconcile` returned the same message event. A later alert used a new event id. The conversation test also rejects `stage_push` while the message is `accepted_pending`, records a dead-port publication as `completion_unknown`, and keeps `relay_accepted` when a later attempt fails. That run reported `wasm_bytes=10651998`, `database_bytes=364544`, and `send_ms=35`.

The optimized wasm is 10,651,998 bytes. `gzip -c` of that file is 4,098,316 bytes. Cloudflare's current Workers limit, from the platform limits page, is 64 MiB uncompressed on both Free and Paid. There is no compressed-size limit. This bundle is under that size limit. The same page limits startup to 1 second, isolate memory to 128 MB, and CPU to 10 ms on Free or 30 seconds by default on Paid (raisable to 5 minutes). Startup time, isolate memory, and CPU time were not measured on Cloudflare because this bundle was not deployed. The 35 ms figure is local workerd wall time for one send, not platform CPU time.

A storage test inserts 80 terminal rows. The open push row stays in the journal. An older accepted row becomes a tombstone, and writing a different ciphertext for that id fails.

## Remaining limits

- Periodic MLS maintenance stays off. A `key_package` command can renew one package. The object does not rotate identities or create extra groups by itself.
- In a group larger than two members, leaf indexes are known for this account and for a sender whose application message carries `sender_leaf_index`. Other leaves are not inferred.
- Restoring a backup of the snapshot and the epoch-floor column together still rolls the group back. If that state cannot be shown to be current, re-onboard instead of replaying it.
- The relay client rejects non-public hosts, `.example`, `.local`, and `.internal`. It does not implement a separate DNS-rebinding defense beyond that destination check and the requirement that production use `wss`. Loopback is unreachable unless `MARMOT_ALLOW_LOOPBACK=1`.
- The loopback fixture does not check Nostr signatures. Key-package admission verifies the signature in the object. No public relay was contacted in this run. Phone delivery was not claimed.
- `worker-build` fails to move its staging directory after writing the wasm (`Resource deadlock avoided`). The local test copies `shim.mjs` into `build/worker/`.
- An upstream storage-contract harness is not available at this revision. SQLCipher remains unusable for `wasm32-unknown-unknown`; the Durable Object does not depend on it.
