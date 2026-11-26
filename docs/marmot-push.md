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

This watchdog does not generate those events. Copying the constants into a new encryptor would fork the protocol. The native and Worker diagnostics say the engine is unavailable and they do not return token bytes.

## Identity

Each project keeps its own sender. SmartFlowSocial uses `SFS_BOT_NSEC`. NostrMash uses `NOSTRMASH_BOT_NSEC`. The operator's personal key is not a sender. Development must use separate test keys and a test WhiteNoise account. Do not point staging at the production recipient.

## Ordering, once an adapter exists

The encrypted group message has to be accepted by at least one group relay before a push trigger is published. Protocol maintenance must not create a user-visible alert. A relay `OK` is `message_accepted` or `push_trigger_accepted`. Neither state means the phone displayed a notification.

Retries must resend the stored publication, not a newly encrypted one, after the corresponding MLS state has been committed. If that state cannot be recovered, the conversation has to be re-onboarded. Restoring an older MLS snapshot is not a supported rollback.

## Onboarding that is not implemented yet

A working adapter would need key-package publication, welcome processing, membership checks that reject unexpected participants, epoch updates, and push-token gossip with owner-signature checks. None of those steps run in this build. `/v1/diagnostics/marmot?project=smartflowsocial` reports that explicitly and requires `OPERATOR_TOKEN`.
