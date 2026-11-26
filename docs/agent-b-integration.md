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

The sender is 1 to 128 characters from `[A-Za-z0-9_:-]`. Any other path is 404. The body limit is 256 KiB. A larger body is 413. The response is JSON and stays within the same order of size as one prepared transport message.

Authentication is `Authorization: Bearer <MARMOT_OPERATOR_TOKEN>`, compared in constant time. A missing or wrong token is 401 `unauthorized`. `http` is rejected with 403 unless the loopback test flag is set and the host is `127.0.0.1`, `localhost`, or `::1`.

Errors that contain `nsec`, `bearer`, or `token`, and errors longer than 180 characters, are replaced with `marmot_error`. Status output contains the public key, the recipient public key, the revision, the group count, and `databaseBytes`. It does not contain the snapshot, the storage key, or an encrypted push token.

The cryptographic mutation and its SQLite write run inside `blockConcurrencyWhile`. Relay I/O runs after that gate, then a second gate records the acknowledgement. Returning an application error does not reset the object. A crash after the sealed row is written is recovered by retrying the same operation id.

## Commands

The body is JSON. `operationId` is the stable operation id. `projectId` on `onboard` must equal the `sender` query.

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

The same operation id, group, kind, and payload returns the original transport message and increments `messageAttempts`. A different payload is `alert ... is already bound to a different payload`. A different group or kind is `operation ... is already bound to a different group or kind`.

### ingest, sync, ack, publication, self_update, stage_push

`ingest` takes `{ "op": "ingest", "message": <TransportMessage> }` and returns `{ "chats": ["..."] }`.

`sync` reads the prepared relay filters outside the cryptographic section, pulls at most 32 frames per filter, then ingests inside a second gate. Filters are kind 445 for the stored Nostr group id and kind 1059 addressed to this account. Relays come from the command or from the account binding.

`ack` is `{ "op": "ack", "operationId": "alert-1", "accepted": true }`. `accepted: true` records relay acceptance. Official `confirm_published` runs only when the stored operation still needs it, which is a commit, not an application message. `accepted: false` sets `completion_unknown` and keeps the original ciphertext. A later retry of the same operation id returns that ciphertext.

`publication` reads the stored operation and does not encrypt again.

`self_update` prepares one commit under the operation id. Retry returns the same commit. `ack` with `accepted: true` is the MDK confirmation.

`stage_push` takes `serverPubkeyHex` and `encryptedTokenHex`. The token is the marmot-push-v1 ciphertext (1084 bytes), not a raw APNs or FCM token. The response `trigger` is the kind 1059 gift wrap. A second call returns the original trigger bytes and does not change the application message or its event id. `"publish": true` publishes that same gift wrap. A rejected or failed push leaves the application message accepted.

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

`pushPhase` is one of `unknown`, `not_required`, `not_attempted`, `token_unavailable`, `prepared`, `pending`, `publication_attempted`, `relay_accepted`, `rejected`, `expired`, `unobservable`, `terminal_failure`. This object emits `not_required`, `not_attempted`, `prepared`, `relay_accepted`, and `rejected`. It does not infer `token_unavailable`, `expired`, `unobservable`, or `terminal_failure`; those belong to the scheduler when it has evidence this object does not. Counters that this object cannot observe are omitted, not reported as zero. `messageAttempts` and `pushAttempts` are the Durable Object counters. Agent C may keep a separate scheduler-attempt counter.

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

Journal rows live in the snapshot. The same operation id cannot change group, kind, payload hash, or ciphertext. Phase updates of the same ciphertext are allowed. The journal keeps 64 terminal rows and refuses to grow past 128.

## Relay transport

Destinations are 1 to 4 URLs. `wss` is allowed for a public host. `ws` and `wss` to loopback are allowed only with the test flag. `.example`, `.local`, `.internal`, and non-public addresses are rejected. Each event is at most 64 KiB. A publication waits 5 seconds and at most 32 frames. The client publishes the transport event bytes produced by official MDK. It does not rebuild them on retry.

## Push

The logical token slot is group, member identity, MLS leaf index, platform, and notification-server public key. The token fingerprint is not part of the slot. A newer owner timestamp replaces the slot. An equal timestamp uses the canonical record digest. An owner proof is required before a record is admitted. A removed record is a tombstone and blocks an older record from returning. The sender path stores the encrypted token and the gift wrap, not the raw device token.

## What was executed

Native, from `crates/watchdog-marmot-worker`:

```text
CARGO_INCREMENTAL=0 cargo test --offline --workspace -- --test-threads=1
```

The official SQLite recipient test, the push layout test, the snapshot tests, and the compare-and-swap decision test passed.

WASM and the local Durable Object:

```text
CARGO_INCREMENTAL=0 cargo build -p marmot-worker --target wasm32-unknown-unknown --offline
cd worker
CARGO_TARGET_DIR=../target CARGO_INCREMENTAL=0 worker-build --dev --no-opt --out-dir build .
cargo test -p marmot-worker-interop --offline --test workerd_conversation -- --ignored --nocapture
```

That ignored test starts workerd with this config, talks to `POST /marmot`, and uses `SqliteAccountStorage` plus `NostrMlsPeeler` in the test process. It generates a kind 30443 key package inside workerd, creates a group, delivers the welcome, exchanges application messages in both directions, publishes a key package and a push gift wrap to the loopback fixture, ingests a reply through `sync`, injects crashes before and after the SQLite write, runs two overlapping sends, stops workerd, restarts it on the same persist directory, repeats an alert id, advances the epoch, and continues. The passing run reported `wasm_bytes=38116373`, `database_bytes=352256`, and `send_ms=116`. The wasm figure is the unoptimized dev bundle. wasm-opt was not run. A release measurement was not taken.

## Remaining limits

- Periodic maintenance stays off. Renewal is the `key_package` command.
- Recipient replacement after a group exists is refused. A membership-removal race and a live sender rotation are not separate tests.
- The legacy `GroupCreated` confirmation path is implemented and was not the path this Current-profile run used. The run used `FoundingGroupCreated`, which does not confirm before publication.
- The loopback fixture does not check Nostr signatures. The Worker still publishes the signed events MDK produced. No public relay was contacted.
- An upstream storage-contract harness is not available at this revision. SQLCipher remains unusable for `wasm32-unknown-unknown`; the Durable Object does not depend on it.
