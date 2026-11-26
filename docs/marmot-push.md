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
- HKDF salt `marmot-push-token-v1` and info `marmot-push-token-encryption`, as implemented in that file.

`watchdog-marmot` does not implement those events itself. Chat alerts go through `MarmotAppRuntime::submit_text` with the alert id as the client token. The pinned runtime does not return a push-trigger publication result. After MDK reports the application message published, the helper reports `publication_attempted` when the recipient has an active token and no publish failure was logged, `rejected` when that publish logs a failure, and `token_unavailable` when no active recipient token exists. A later bounded refresh reports `unobservable`. It does not report push relay acceptance or phone delivery. The Worker does not call this path. Neither process returns token bytes. The exact states and the fields Agent C should store are in `docs/agent-a-integration.md`.

## Identity

Each project keeps its own sender. SmartFlowSocial uses `SFS_BOT_NSEC`. NostrMash uses `NOSTRMASH_BOT_NSEC`. The operator's personal key is not a sender. Development must use separate test keys and a test WhiteNoise account. Do not point staging at the production recipient.

## Ordering

Before `submit_text`, the helper records the account, group, and payload hash. A later call with the same alert id reads `local_send_status` first. A stored `accepted_pending` result is not treated as final. `published` and `rejected` are the terminal dispositions. If MDK has no record after a submission was recorded, the helper reports `completion_unknown` and does not encrypt that alert again. None of these states means the phone displayed a notification.

Group creation uses the official runtime, which publishes the creator's key package when account import asks for it. Before a send, the helper reads `group_members` and rejects the send when any member is not the local account or the configured recipient. Extra devices of an allowed account share that account id and stay allowed. An unexpected account fails closed.

Welcome processing stays inside `marmot-app` catch-up. The loopback fixture stores each event with a sequence number. The integration test unwraps a kind-1059 gift with the temporary notification server's key, checks the signature and the full `p` tag, and checks that the inner rumor is kind 446 with version `marmot-push-v1` and 1084-byte token records. An unrelated gift wrap to the same server does not satisfy that check. The fixture does not speak to WhiteNoise, APNs, or FCM. `/v1/diagnostics/marmot?project=smartflowsocial` requires `OPERATOR_TOKEN` and still does not read MDK token state; `scripts/whitenoise-acceptance.sh status` reads helper readiness until that route does.
