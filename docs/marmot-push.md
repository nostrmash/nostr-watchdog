# Marmot and WhiteNoise push

Marmot is the preferred transport because device tests of ordinary NIP-17 clients did not wake Damus or 0xChat, while WhiteNoise messages did. Those tests were of the clients, not of this Rust branch. This branch has not delivered a Marmot alert to a phone.

## What the protocol requires

The adopted note is [features/push-notifications.md](https://github.com/marmot-protocol/marmot/blob/master/features/push-notifications.md) in `marmot-protocol/marmot`. The pinned MDK `marmot-app` code is the interoperability reference.

From that MDK tree at the pinned revision, the push path uses:

- Gossip kinds 447, 448, and 449.
- Owner proof kind 451. Kind 450 is legacy.
- Rumor kind 446.
- Server inbox kind 10050.
- Version string `marmot-push-v1`.
- Encrypted token records of 1084 bytes over a 1024-byte plaintext.
- HKDF salt `marmot-push-token-v1` and info `marmot-push-token-encryption`, as implemented in that file.

The native helper calls `MarmotAppRuntime::submit_text` with the alert ID as the client token. The pinned runtime accepts the application message independently of push and gives the helper no alert-specific push acknowledgement. The helper reports `token_unavailable` or `unobservable` as appropriate.

The Cloudflare Marmot Worker processes signed recipient gossip, checks the active group, leaf and full capability identity, and generates kind-446 notification rumors. It publishes each gift wrap, records the relay acknowledgement for its exact event ID, and retries unresolved targets independently. Telegram fallback uses an independent outbox row. Both operational stores keep sanitized evidence.

## Identity

Each project keeps its own sender. SmartFlowSocial uses `SFS_BOT_NSEC`. NostrMash uses `NOSTRMASH_BOT_NSEC`. The operator's personal key is not a sender. Development must use separate test keys and a test WhiteNoise account. Do not point staging at the production recipient.

## Ordering

Before `submit_text`, the helper records the account, group, and payload hash. A later call with the same alert id reads `local_send_status` first. A stored `accepted_pending` result is not treated as final. `published` and `rejected` are the terminal dispositions. If MDK has no record after a submission was recorded, the helper reports `completion_unknown` and does not encrypt that alert again. None of these states means the phone displayed a notification.

Group creation uses the official runtime, which publishes the creator's key package when account import asks for it. Before a send, the helper reads `group_members` and rejects the send when any member is not the local account or the configured recipient. Extra devices of an allowed account share that account id and stay allowed. An unexpected account fails closed.

Welcome processing on native stays inside `marmot-app` catch-up. On Cloudflare the SQLite-backed sender restores its group and operation history from sealed state. An authorized retry keeps the original ciphertext and event identity. A revoked capability discovered during reconciliation is excluded before further publication.

Operator diagnostics require `OPERATOR_TOKEN` and expose readiness without exposing token bytes. The control fixture checked relay retrieval, independent decryption, notification gift-wrap structure, and restart. A recorded observation on the test phone is the physical gate. [Integration evidence](integration.md) · [Acceptance procedure](acceptance.md)
