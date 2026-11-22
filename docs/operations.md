# Operations

## Routes

| Route                                     | Auth            | Returns                                                                                                                                                              |
| ----------------------------------------- | --------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `GET /healthz`                            | none            | `status`, service name, and whether the cron flag is on. No D1 read. HTTP 200 means the process answered                                                             |
| `GET /v1/status`                          | operator bearer | Operational contract `watchdog-status-v1`. HTTP 200 only when `status` is `healthy`. Other states return 503. The body is signed when `STATUS_SIGNING_SECRET` is set |
| `GET /v1/outbox/failed`                   | operator bearer | Up to 50 dead letters. Payload text is truncated. It is the plaintext the Worker stored, not the gift wrap                                                           |
| `POST /v1/outbox/:id/retry`               | operator bearer | Requeues one `failed` row and keeps its signed envelope. The id matches `alt_` plus hex                                                                              |
| `POST /v1/heartbeats/:monitorId`          | HMAC            | `{ "status": "ok" }` or a generic error                                                                                                                              |
| `POST /v1/diagnostics/test-alert`         | operator bearer | Sends one NIP-17 test for a JSON body `{"projectId":"<id>"}`. Three per project per hour                                                                             |
| `GET /v1/diagnostics/relays?project=<id>` | operator bearer | Discovered inbox relay URLs and a non-secret error code                                                                                                              |
| `POST /v1/incidents/:id/ack`              | operator bearer | Stops reminders for that open incident                                                                                                                               |
| `POST /v1/incidents/:id/silence`          | operator bearer | Optional JSON `{ "minutes": 60 }`. Stops reminders until then                                                                                                        |

Query strings are rejected except on the relay diagnostic. There is no browser UI.

`/v1/status` is the endpoint a second monitor, running outside Cloudflare, should call. Verify `X-Watchdog-Signature` against the raw body with `STATUS_SIGNING_SECRET`. Treat any HTTP status other than 200 as not healthy. `/healthz` only proves the Worker process answered. Neither endpoint proves a phone displayed an alert.

`status` in the body is one of:

| Value            | Meaning                                                                                                                                     |
| ---------------- | ------------------------------------------------------------------------------------------------------------------------------------------- |
| `healthy`        | Monitoring is on, at least one monitor is enabled, required alert destinations are present, and the check cycle is current                  |
| `disabled`       | `WATCHDOG_ENABLED=false`                                                                                                                    |
| `not_configured` | Monitoring is on and every monitor is disabled                                                                                              |
| `misconfigured`  | Alerts are on without a sender, recipient, or bootstrap relays, or an enabled monitor is `misconfigured`                                    |
| `degraded`       | The last check is older than `SCHEDULER_STALE_SECONDS`, the last check failed, a dead letter exists, or more than three alerts are retrying |
| `unhealthy`      | No completed check, or the last check is older than three times `SCHEDULER_STALE_SECONDS`                                                   |

Customer `down` and `degraded` monitors stay in the body and in incidents. They do not by themselves change this status, so a service outage and a stopped watchdog are separate pages. The body also reports monitor counts, cycle age, open incidents, pending and retrying alerts, dead letters, stale or missing heartbeats, and recent delivery error codes. It does not include secrets.

```sh
curl -sS -D - "https://watchdog.example/v1/diagnostics/relays?project=PROJECT_ID" \
  -H "authorization: Bearer $OPERATOR_TOKEN"
```

A test alert:

```sh
curl -sS -X POST https://watchdog.example/v1/diagnostics/test-alert \
  -H "authorization: Bearer $OPERATOR_TOKEN" \
  -H "content-type: application/json" \
  -d '{"projectId":"PROJECT_ID"}'
```

`delivery: "relay_accepted"` means at least one inbox relay returned `OK`. Repeat for each project. The sends use different keys and should appear as different chats. Then lock the phone and see whether that client actually pushes. Relay acceptance is not that test.

## Reading an alert

Incident messages include the project, severity, service, state, incident id, UTC time, a short reason, and a runbook link when `RUNBOOK_BASE_URL` is set. Version notices include the installed version, the latest stable tag, and an official GitHub release URL. They do not install anything. Security messages say whether the installed version is inside a published affected range, or whether a human should review because the range could not be applied. They do not say the software is secure.

`failed` rows in `alert_outbox` are the dead letters. `GET /v1/status` counts them. `last_error` is a short code such as `recipient_inbox_missing`, `relay_rejected`, or `telegram_failed`, not a response body.

Retries use exponential backoff starting at 30 seconds and capping at one hour, for at most 8 attempts. A missing sender key, a missing recipient, an empty bootstrap list, or a confirmed empty inbox fails immediately.

## Staging and production

Use different secrets in each environment. D1 is a different database per environment. Enabling a monitor in staging does not enable it in production.

## Silence and ack

Ack when a person has seen a critical incident and further reminders would only add noise. Silence when the service is in a known window. Neither closes the incident. Recovery still sends one recovery message after the success threshold, including to Telegram when dual critical delivery is on.

## Checklist before enabling a project

1. Publish kind `10050` from the recipient account with at least one `wss` inbox relay. Confirm the relay diagnostic lists those relays and no others.
2. Send the test alert. Confirm the relay response is `relay_accepted` and the chat title matches that project's contact name.
3. Lock the phone and confirm the client shows a push, if that client supports locked-screen notifications for NIP-17. Record the client name. A failure here is a client or relay-push limit.
4. Point one HTTP monitor at a URL that fails its predicate. Wait for two minute crons. Confirm one outage alert. Restore the URL. Confirm one recovery after two successes.
5. For a heartbeat monitor, stop the emitter and confirm a stale heartbeat opens an outage. Start it with `idle: true` and confirm recovery. `loopAt` must move only when the job loop iterates. A timer that stamps `loopAt` with the send time hides a stuck loop.
6. Retry a failed relay publish and confirm the incident id and gift-wrap id do not change.
7. Confirm staging secrets are not the production secrets, and that enable flags for unverified URLs are still `false`.
8. From a network that is not Cloudflare, poll `/healthz` or signed `/v1/status` on a schedule. That checker is what pages you if Cloudflare itself is down.

## Limits

- This Worker cannot see a Cloudflare outage that takes the Worker down.
- Kind 10050 discovery depends on the bootstrap relays being reachable from Cloudflare.
- A quiet service is healthy when its heartbeat says the loop is idle. This version does not treat a low request count as an outage.
- An `alby_hub` monitor without a read-only token, and a `btcpay` monitor without a read-only server-info key, cannot prove node health, processor availability, or installed version.
- One slow sample is recorded as latency. A timeout is a failed sample and counts toward the failure threshold.
- GitHub advisory coverage is the published advisories and release text returned for the configured vendor repositories, plus the checked vendor statements in `src/updates/vendor-policy.ts`. A security-related release without an affected range is a review warning.
- Closed incidents are kept for 90 days, accepted gift wraps for 14 days, and dead letters for 30 days. Open incidents and queued or retrying alerts are not deleted. Heartbeat nonces and expired relay-list cache rows are removed when they expire. Upstream cache rows older than 7 days are removed unless a rate-limit window is still open.
- D1 stores alert plaintext. The relay copy is the NIP-17 gift wrap. See [security.md](security.md).
- Staging acceptance against live relays, phones, Alby Hub, and BTCPay was not run in this repository. The commands in this file are the operator sequence. Relay `OK` is not phone delivery.
- Exactly-once publication to independent relays is not available. The outbox makes the same event retryable and suppresses duplicate incident rows.
