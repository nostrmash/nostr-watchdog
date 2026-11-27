# WhiteNoise acceptance

On the iPhone, open WhiteNoise with the configured recipient account and enable its notifications. The account needs an eligible key package and an active notification registration. Use dedicated test identities for the native rehearsal and the existing authorized recipient and project senders for the production test.

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
# Wait until the first send is over an hour old.
scripts/whitenoise-acceptance.sh alert-locked
scripts/whitenoise-acceptance.sh stop
```

On the phone, open or accept the new test conversation. Wait for `active_recipient_tokens` to reach at least one before sending. Keep WhiteNoise on screen for the foreground alert. Put it in the background for the second alert, then lock the phone for the third. The background and locked commands ask before sending. After restart, verify that the follow-up alert appears in the same conversation and observe the locked screen again. The test-alert route allows three sends per project in a rolling hour. Schedule the follow-up after the first send leaves that window.

If `conversation` reports an unavailable conversation index, leave the helper running and retry the same command. If the recipient has no active token, open the test account and verify notification permissions before polling `status` again. The helper can confirm application-message relay acceptance while reporting native push acceptance as `unobservable`.

## Cloudflare

Use the [production Worker pair](deployment.md#cloudflare-production). Onboard once per project with a stable operation ID. On the phone, accept the SmartFlowSocial and NostrMash invitations where needed and open the conversations. Check Settings → Notifications → WhiteNoise on the iPhone and enable Allow Notifications and Lock Screen. Keep WhiteNoise open until the authenticated project diagnostics show recipient participation, canonical convergence, and `authority.recipientTokenReady: true`.

Send one test alert from the operational API for each state. Observe WhiteNoise in the foreground, then with another app in the foreground, then with the phone locked. Record the alert ID and observation before moving to the next state. For recovery, redeploy the private Worker with the same namespace, storage key, sender, and operational D1 binding. Verify the original group and operation evidence, then repeat a locked-screen alert after the rolling-hour limit allows a fourth send.

```bash
# Enter the operator token at the hidden prompt.
read -r -s watchdog_acceptance_token
watchdog_url="https://nostr-watchdog.birwix.workers.dev"
watchdog_request() {
  printf 'Authorization: Bearer %s\n' "$watchdog_acceptance_token" |
    curl --fail-with-body -sS --header @- "$@"
}
watchdog_request "$watchdog_url/v1/diagnostics/marmot/onboard" \
  --json '{"projectId":"smartflowsocial","operationId":"production-smartflowsocial-v1"}'
watchdog_request "$watchdog_url/v1/diagnostics/marmot?project=smartflowsocial"

# Run one send after setting the phone state.
watchdog_request "$watchdog_url/v1/diagnostics/test-alert" \
  --json '{"projectId":"smartflowsocial","transport":"marmot"}'
watchdog_request "$watchdog_url/v1/outbox/<alert-id>"
```

## What to record

| Observation | Evidence |
| --- | --- |
| Group message relay acceptance | The authority or outbox recorded acceptance of the exact signed event ID. |
| Independent message decryption | The recipient opened the alert in the named conversation. |
| Notification trigger relay acceptance | Cloudflare recorded acceptance of the exact kind-1059 trigger. Native reports `unobservable`. |
| Server processed the trigger | The notification server recorded processing for the test alert. |
| Physical notification | The owner saw the notification on the test iPhone and recorded the time and phone state. |

For each foreground, background, locked-screen and post-restart send, record the returned `alertId` (the delivery operation ID), phone state, send time, observation time, elapsed seconds and duplicate count. Record any missing notification and keep accepted event IDs when available. A phone notification is the physical acceptance criterion. Automated relay and decryption tests are supporting evidence.

After the first successful physical test, request separate authorization for the 100-send qualification. At the existing limit of three sends per project in a rolling hour, allow 34 rate-limit windows. Include foreground, background, locked-screen and post-restart sends. Targets are at least 99 observed deliveries under normal connectivity, median observed latency below 5 seconds, 95th-percentile latency below 15 seconds, zero unexplained duplicates, and intact cryptographic state across restart.
