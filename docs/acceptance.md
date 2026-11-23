# Staging acceptance

Run this against a staging Worker. Do not point it at production payment or publishing services. A relay acknowledgement is not phone delivery.

Automated tests cover the code paths. The steps below are the ones that need a real account, a real relay, or a phone.

## Before starting

1. Create a staging D1 database and paste its id into `wrangler.jsonc` under `env.staging`. Do not invent an id.
2. Apply migrations through `0005_source_failures.sql`: `pnpm migrate:staging`.
3. Set staging secrets: `OPERATOR_TOKEN`, `STATUS_READ_TOKEN`, `STATUS_SIGNING_SECRET`, separate `SFS_BOT_NSEC` and `NOSTRMASH_BOT_NSEC`, `HEARTBEAT_KEYS`, read-only `ALBY_AUTH_TOKEN` and `BTCPAY_API_KEY`, and optional `TELEGRAM_BOT_TOKEN` plus `TELEGRAM_CHAT_IDS`.
4. Set `PROJECT_RECIPIENTS` or `ADMIN_NPUB` to an npub that has published a signed kind `10050` inbox relay list. Set `BOOTSTRAP_RELAYS` to relays that store that list.
5. Set `READ_GATEWAY_HEALTH_TOKEN` and `PUBLISH_GATEWAY_HEALTH_TOKEN` to the same values as each gateway's `HEALTH_PROBE_TOKEN`.
6. Leave monitors disabled until the matching URL or heartbeat secret is set. An enabled monitor with an empty URL is misconfigured and `/v1/status` stays non-200.
7. Deploy with `pnpm deploy:staging`. Confirm the cron triggers exist. Do not deploy production from this checklist.

## Checks

| #   | Check                 | How                                                                                                                   | Pass                                                                                                                   |
| --- | --------------------- | --------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------- |
| 1   | Deploy and cron       | Wrangler tail for one minute and one hour trigger                                                                     | Both jobs finish without `cycle_failed`                                                                                |
| 2   | D1                    | `GET /v1/status` with `STATUS_READ_TOKEN`                                                                             | HTTP 200 only when `status` is `healthy`; the body includes `securityChecks`                                           |
| 3   | Inbox discovery       | Operator relay diagnostic                                                                                             | The newest valid kind `10050` relays are listed                                                                        |
| 4   | Two sender identities | One test alert per project                                                                                            | The gift wraps use different pubkeys                                                                                   |
| 5   | Relay acknowledgement | Outbox row                                                                                                            | State is `relay_accepted` on at least one advertised inbox relay                                                       |
| 6   | Phone                 | Locked-screen notification in a client that reads the recipient's inbox                                               | The message is visible. Do not mark this passed because a relay accepted the event                                     |
| 7   | Outage and recovery   | Point one staging monitor at a closed port, wait for the failure threshold, then restore it                           | One open incident, then one recovery. No second outage alert                                                           |
| 8   | Stalled worker        | Send a signed heartbeat with unchanged `progress` and `idle: false` until `HEARTBEAT_PROGRESS_SECONDS`                | The monitor becomes degraded. A fresh idle heartbeat does not                                                          |
| 9   | Alby or BTCPay        | Use a read-only token against a staging hub or server, including a locked or unsynchronized response                  | The result is degraded or down, and the token cannot pay or spend                                                      |
| 10  | Confirmed advisory    | Install a version inside a verified affected range, or use the bundled BTCPay policy on a staging version below 2.4.2 | One critical security alert                                                                                            |
| 11  | Advisory outage       | Block only `api.github.com` security-advisories while releases still answer                                           | The release alert is kept. After three hourly failures, `/v1/status` is degraded. Recovery does not send a second copy |
| 12  | Relay outage          | Use an inbox relay that refuses the gift wrap and set `TELEGRAM_CRITICAL_MODE` to `nostr_fallback`                    | One Telegram message. No second fallback for the same alert                                                            |
| 13  | Dead letter           | Leave a row failing until eight attempts                                                                              | State is `failed` and `/v1/status` is non-200. Retry from the operator route queues it once                            |
| 14  | External checker      | The non-Cloudflare probe in `docs/deployment.md`                                                                      | It pages on a timeout and on a forced `ALERTS_ENABLED=false` deploy, through its own channel                           |
| 15  | Rollback              | `wrangler rollback --env staging`, then deploy the new version again                                                  | A queued alert is not sent twice. D1 rows are not rolled back by the Worker rollback                                   |

Record which rows were executed. Leave phone delivery, production uptime, and the external check unmarked until they actually happened.
