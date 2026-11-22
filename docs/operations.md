# Operations

## Routes

| Route                                                | Auth            | Returns                                                                                                                               |
| ---------------------------------------------------- | --------------- | ------------------------------------------------------------------------------------------------------------------------------------- |
| `GET /healthz`                                       | none            | `status`, service name, and whether the cron flag is on. No D1 read                                                                   |
| `GET /v1/status`                                     | operator bearer | Counts of open incidents and dead letters, plus the last finished cron times. Body is HMAC-signed when `STATUS_SIGNING_SECRET` is set |
| `POST /v1/heartbeats/:monitorId`                     | HMAC            | `{ "status": "ok" }` or a generic error                                                                                               |
| `POST /v1/diagnostics/test-alert`                    | operator bearer | Sends one NIP-17 test for `{"projectId":"smartflowsocial"}` or `nostrmash`. Three per project per hour                                |
| `GET /v1/diagnostics/relays?project=smartflowsocial` | operator bearer | Discovered inbox relay URLs and a non-secret error code                                                                               |
| `POST /v1/incidents/:id/ack`                         | operator bearer | Stops reminders for that open incident                                                                                                |
| `POST /v1/incidents/:id/silence`                     | operator bearer | Optional JSON `{ "minutes": 60 }`. Stops reminders until then                                                                         |

Query strings are rejected except on the relay diagnostic. There is no browser UI.

`/v1/status` is the endpoint a second, non-Cloudflare monitor should call. Verify `X-Watchdog-Signature` against the raw body with `STATUS_SIGNING_SECRET`. `/healthz` only proves the Worker process answered. Neither endpoint proves a phone displayed an alert.

Example, with the token in the environment rather than the shell history where you can avoid it:

```sh
curl -sS -D - https://watchdog.example/v1/diagnostics/relays?project=smartflowsocial \
  -H "authorization: Bearer $OPERATOR_TOKEN"
```

A test alert:

```sh
curl -sS -X POST https://watchdog.example/v1/diagnostics/test-alert \
  -H "authorization: Bearer $OPERATOR_TOKEN" \
  -H "content-type: application/json" \
  -d '{"projectId":"smartflowsocial"}'
```

`delivery: "relay_accepted"` means at least one inbox relay returned `OK`. Repeat for `nostrmash`. The two sends use different keys and should appear as different chats. Then lock the phone and see whether that client actually pushes. Relay acceptance is not that test.

## Reading an alert

Incident messages include the project, severity, service, state, incident id, UTC time, a short reason, and a runbook link when `RUNBOOK_BASE_URL` is set. Version notices include the installed version, the latest stable tag, and an official GitHub release URL. They do not install anything. Security messages say whether the installed version is inside a published affected range or whether a human should review because the range could not be applied. They do not say the software is secure, and they do not claim anything about vulnerabilities that were not in the advisory feed.

`failed` rows in `alert_outbox` are the dead letters. `GET /v1/status` counts them. `last_error` is a short code such as `recipient_inbox_missing`, `relay_rejected`, or `telegram_failed`, not a response body.

Retries use exponential backoff starting at 30 seconds and capping at one hour, for at most 8 attempts. A missing sender key, a missing recipient, an empty bootstrap list, or a confirmed empty inbox fails immediately.

## Staging versus production

Use different secrets and a different recipient or a different client account in staging. Do not point staging at production bot keys. D1 is a different database per environment. Turning on a monitor in staging does not enable it in production.

## Silence and ack

Ack when a person has seen a critical incident and further reminders would only add noise. Silence when the service is in a known window. Neither closes the incident. Recovery still sends one recovery message after the success threshold, including to Telegram when dual critical delivery is on.

## Checklist before calling a project live

Do this once per project, in staging first.

1. Publish kind `10050` from the recipient account with at least one `wss` inbox relay. Confirm `GET /v1/diagnostics/relays` lists those relays and no others.
2. Send the test alert. Confirm the relay response is `relay_accepted`, the chat title matches that project's contact name, and the other project's bot did not send it.
3. Lock the phone and confirm the client shows a push, if that client supports locked-screen notifications for NIP-17. Record the client name. A failure here is a client or relay-push limit, not a successful delivery.
4. Point one non-critical or staging HTTP monitor at a URL that fails its predicate. Wait for two minute crons. Confirm one outage alert, not two. Restore the URL. Confirm one recovery after two successes.
5. For a heartbeat monitor, stop the emitter and confirm a stale heartbeat opens an outage. Start it with `idle: true` and confirm recovery. A side timer that updates `loopAt` to "now" on every send does not count: the loop timestamp has to move only when the job loop iterates.
6. Run two overlapping checks or re-send the same failed relay attempt and confirm the incident id and gift-wrap id do not change.
7. Confirm staging secrets are not the production secrets, and that production `ENABLE_*` flags for unverified URLs are still `false`.
8. From a network that is not Cloudflare, poll `/healthz` or signed `/v1/status` on a schedule. That checker is what pages you if Cloudflare itself is down.

## Blind spots

- This Worker cannot see a Cloudflare outage that takes the Worker down.
- Kind 10050 discovery depends on the bootstrap relays being reachable from Cloudflare.
- Blastr's public hostname was not verified. The template must stay disabled until it is.
- Blossom, the SmartFlowSocial app, and the NostrMash API have known readiness contracts, and their production URLs are still configuration, not defaults.
- Heartbeat monitors are implemented in the Worker and are not emitted by the applications yet. Enabling them now produces an outage because no heartbeat arrives.
- NostrMash web, the read gateway, and the publish gateway are not monitored.
- Quiet ingestion is not an outage. There is no freshness monitor in this version.
- Alby without a read-only token, and BTCPay without a read-only server-info key, cannot prove node health, processor availability, or installed version.
- One slow sample is recorded as latency and is not, by itself, an outage. A timeout is a failed sample and counts toward the failure threshold.
- GitHub advisory coverage is only the published advisories that the API returns for the two vendored repositories. Absence of an advisory is not a vulnerability assessment.
- Exactly-once publication to independent relays is not possible from here. The outbox makes the same event retryable and suppresses duplicate incident rows.
