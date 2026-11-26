# WhiteNoise acceptance

This procedure is for a person with a test phone. It is not something CI can pass. Do not run it against the production sender keys or the operator's existing WhiteNoise account. Automated tests in this repository do not prove that an iPhone displayed a notification.

Status: pending. No attempt has been made from this Rust code.

## Before any message is sent

1. Create a new Nostr keypair for the watchdog test sender. Do not reuse `SFS_BOT_NSEC` or `NOSTRMASH_BOT_NSEC` from production.
2. Install WhiteNoise on a device you control and create or use a test account that is not the daily driver.
3. Confirm the Rust process is the native binary, `ENABLE_MARMOT` is still false, and the diagnostic says the engine is unavailable.

Stop here with the current build. The steps below are the acceptance script for the day an official MDK storage adapter is linked. Running them now cannot succeed, because the process will not publish a Marmot message.

## When an adapter exists

1. Publish the test sender's key package and add the test WhiteNoise account as the only member.
2. Reject a second member. The diagnostic must not show that member as joined.
3. Send one test alert with `POST /v1/diagnostics/test-alert` and `"projectId": "smartflowsocial"` while selecting the Marmot transport. Confirm the alert text is visible in WhiteNoise while the app is open.
4. Repeat with the app backgrounded, then with the phone locked, then after force-quitting the app. Record wall-clock time from the relay `OK` for the group message to the notification. Those are three different results. Relay `OK` alone is not a pass.
5. Restart the watchdog process and send another alert. The same conversation must continue without creating a second group.
6. Leave the process idle past the sync interval, then send again.
7. Rotate the test device's push token, or reinstall WhiteNoise, and send again.
8. Block the relays, confirm the outbox stays retrying, restore the relays, and confirm the stored event is the one that is published.
9. With Telegram configured for critical alerts, create a critical incident and confirm Telegram still arrives when the Marmot publish fails, and that a Marmot failure does not cancel Telegram.

## Targets, not guarantees

These are the bars for calling the transport ready. They are not a claim about this branch.

- At least 100 controlled sends under ordinary connectivity.
- At least 99 of those observed on the device.
- Median time under 5 seconds and 95th percentile under 15 seconds, measured on the device.
- No duplicate notification for one stored publication during normal operation.
- No MLS state that fails to open after a restart.
- No manual repair between the sends after the initial join.

A pass still does not mean v1.0.0 until the staging deploy and the migration notes have been reviewed.
