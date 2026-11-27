# WhiteNoise acceptance

Use a dedicated WhiteNoise account on the test iPhone and a dedicated watchdog sender. Open WhiteNoise, enable its notifications, and allow the test account to publish an eligible key package. Leave the test account connected to the same relay set as the watchdog. An existing eligible key package and an active notification registration are prerequisites for the complete sequence.

## Native

Build both release executables as described in [deployment.md](deployment.md). The script creates isolated operational and MDK state under `data/whitenoise-acceptance` by default. Use `WATCHDOG_ACCEPTANCE_ROOT` for a new test directory and `WATCHDOG_ACCEPTANCE_ADDR` to avoid a local port collision.

```bash
scripts/whitenoise-acceptance.sh prepare <test-recipient-npub>
scripts/whitenoise-acceptance.sh start
scripts/whitenoise-acceptance.sh init
scripts/whitenoise-acceptance.sh conversation
scripts/whitenoise-acceptance.sh status
scripts/whitenoise-acceptance.sh alert-foreground
scripts/whitenoise-acceptance.sh alert-background
scripts/whitenoise-acceptance.sh alert-locked
scripts/whitenoise-acceptance.sh restart
scripts/whitenoise-acceptance.sh status
scripts/whitenoise-acceptance.sh alert-locked
scripts/whitenoise-acceptance.sh stop
```

Wait for the test conversation and an active recipient token before sending. Keep WhiteNoise on screen for the foreground alert. Put it in the background for the second alert, then lock the phone for the third. The background and locked commands ask before sending. After restart, verify that the follow-up alert appears in the same conversation and observe the locked screen again.

If `conversation` reports an unavailable conversation index, leave the helper running and retry the same command. If the recipient has no active token, open the test account and verify notification permissions before polling `status` again. The helper can confirm application-message relay acceptance while reporting native push acceptance as `unobservable`.

## Cloudflare

Use the isolated Worker pair from [deployment.md](deployment.md) after staging deployment is authorized. Onboard the dedicated sender using `POST /v1/diagnostics/marmot/onboard`. Wait for the authenticated `GET /v1/diagnostics/marmot?project=<id>` response to show Welcome acceptance, recipient participation and token readiness. Enable alerts only for the configured staging project. For each phone state, send one `POST /v1/diagnostics/test-alert` with the same project and `transport=marmot`. Record the outbox ID and observe the phone before moving to the next state. Rehearse a deployment restart against the same Durable Object and D1 state, then repeat the locked-screen alert in the same conversation.

## What to record

| Observation | Evidence |
| --- | --- |
| Group message published | A relay accepted its exact signed event ID and the recipient decrypted the message. |
| Trigger published | A relay accepted the kind-1059 gift wrap for the notification server, and the server key opened the kind-446 rumor. |
| Server processed the trigger | The notification server recorded processing for the test alert. |
| Physical notification | The owner saw the notification on the test iPhone and recorded the time and phone state. |

Record elapsed time from the send to observation. A phone notification is the physical acceptance criterion. Automated relay and decryption tests are supporting evidence.

After the first successful physical test, request separate authorization for the 100-send qualification. Targets are at least 99 observed deliveries under normal connectivity, median observed latency below 5 seconds, 95th-percentile latency below 15 seconds, zero unexplained duplicates, and intact cryptographic state across restart.
