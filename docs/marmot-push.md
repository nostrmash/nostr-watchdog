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

`watchdog-marmot` does not implement those events itself. `MarmotAppRuntime::send_message` is the official sender, and that function publishes the notification trigger after the application message. The helper reports `trigger_attempted` only when MDK's accept disposition is `published`. It does not report phone delivery. The Worker does not call this path. Neither process returns token bytes.

## Identity

Each project keeps its own sender. SmartFlowSocial uses `SFS_BOT_NSEC`. NostrMash uses `NOSTRMASH_BOT_NSEC`. The operator's personal key is not a sender. Development must use separate test keys and a test WhiteNoise account. Do not point staging at the production recipient.

## Ordering

The helper writes a started marker for the alert id before `send_message`. A later call with the same id returns the stored result, or `completion_unknown` if the process died after the marker. It does not ask MDK to encrypt that alert again. `published` is recorded as relay acceptance. `accepted_pending` and `completion_unknown` stay retryable at the outbox layer and still do not create a second ciphertext. None of these states means the phone displayed a notification.

Group creation uses the official runtime, which publishes the creator's key package when account import asks for it. Before a send, the helper reads `group_members` and rejects the send when any member is not the local account or the configured recipient. Extra devices of an allowed account share that account id and stay allowed. An unexpected account fails closed.

Welcome processing, epoch repair, and token gossip stay inside `marmot-app` catch-up. This branch has not observed those steps against a second client. `/v1/diagnostics/marmot?project=smartflowsocial` requires `OPERATOR_TOKEN`.
