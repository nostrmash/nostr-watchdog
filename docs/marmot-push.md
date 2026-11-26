# Marmot and WhiteNoise push

Marmot is the preferred transport because device tests of ordinary NIP-17 clients did not wake Damus or 0xChat, while WhiteNoise messages did. Those tests were of the clients, not of this Rust branch. This branch has not delivered a Marmot alert to a phone.

## What the protocol requires

The adopted note is [features/push-notifications.md](https://github.com/marmot-protocol/marmot/blob/master/features/push-notifications.md) in `marmot-protocol/marmot`. The implementation that WhiteNoise runs is the code in MDK `marmot-app`, not a summary of the latest markdown if they differ.

From that MDK tree at the pinned revision, the push path uses:

- Gossip kinds 447, 448, and 449.
- Owner proof kind 451. Kind 450 is legacy.
- Rumor kind 446.
- Server inbox kind 10050.
- Version string `marmot-push-v1`.
- Encrypted token records of 1084 bytes over a 1024-byte plaintext.
- HKDF salt `marmot-push-token-encryption` material as implemented in that file, not a scheme invented here.

`watchdog-marmot` does not implement those events itself. Chat alerts go through `MarmotAppRuntime::submit_text` with the alert id as the client token. The pinned runtime does not return a push-trigger publication result. After a message disposition of `published`, the helper reports `push_disposition_unknown` when the recipient has an active token, and `recipient_push_token_unavailable` when it does not. It does not report `trigger_attempted` or phone delivery. The Worker does not call this path. Neither process returns token bytes.

## Identity

Each project keeps its own sender. SmartFlowSocial uses `SFS_BOT_NSEC`. NostrMash uses `NOSTRMASH_BOT_NSEC`. The operator's personal key is not a sender. Development must use separate test keys and a test WhiteNoise account. Do not point staging at the production recipient.

## Ordering

Before `submit_text`, the helper records the account, group, and payload hash. A later call with the same alert id reads `local_send_status` first. A stored `accepted_pending` result is not treated as final. `published` and `rejected` are the terminal dispositions. If MDK has no record after a submission was recorded, the helper reports `completion_unknown` and does not encrypt that alert again. None of these states means the phone displayed a notification.

Group creation uses the official runtime, which publishes the creator's key package when account import asks for it. Before a send, the helper reads `group_members` and rejects the send when any member is not the local account or the configured recipient. Extra devices of an allowed account share that account id and stay allowed. An unexpected account fails closed.

Welcome processing stays inside `marmot-app` catch-up. On 2026-11-26 a helper sender and a separate official `MarmotApp` runtime, both using loopback with `--allow-loopback`, exchanged one kind-9 alert through `scripts/fixture-relay.mjs`. The recipient registered an FCM token for a throwaway notification-server key whose relay hint was that fixture. After the alert, the fixture's `/stats` recorded a kind-1059 gift wrap whose `p` tag was that server. The recipient decrypted the plaintext, and a helper restart reused the same message id. The pinned `submit_text` path publishes that trigger as best-effort and does not return the relay result, so the helper still reports `push_disposition_unknown`. Reconciliation of that unknown state stops after 8 attempts with `push_unobservable`. The fixture does not speak to WhiteNoise or to APNs. `/v1/diagnostics/marmot?project=smartflowsocial` requires `OPERATOR_TOKEN`.
