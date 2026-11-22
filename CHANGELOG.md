# Changelog

## 0.2.0 - unreleased

This is a release candidate. It is not a published GitHub release and it has not been deployed.

- Open outbound Nostr sockets with the Workers `https` WebSocket upgrade. Relay configuration stays `wss://`. `ws://` is rejected.
- Verify kind `10050` event ids and signatures before using inbox relays. Aggregate bootstrap relays and keep the newest valid event.
- Fence outbox claims, extend the lease past relay work, and retry the original gift-wrap id. Partial relay acceptance is recorded. Telegram fallback is one message per critical incident.
- Open a warning when monitoring stays inconclusive, without closing a confirmed outage on an unknown sample.
- Report watchdog health on `GET /v1/status` with contract `watchdog-status-v1`. HTTP 200 is reserved for `healthy`.
- Classify BTCPay security updates from GitHub releases, GitHub Security Advisories, and checked vendor statements. A security release without an affected range is a review warning.
- Treat public-only BTCPay health as incomplete coverage. Keep Alby Hub monitoring read-only.
- Add disabled-by-default read and publish gateway monitors. Add retention for closed incidents, accepted alerts, and dead letters.
- Keep TypeScript on 6.0.3, which is the newest stable release `typescript-eslint` 8.73 supports. Do not take the TypeScript 7 Dependabot update until the linter supports it.
- Report `alerts_disabled` when monitoring is on and `ALERTS_ENABLED=false`. HTTP 200 remains reserved for `healthy`.
- Record per-vendor update success separately from the hourly cron finishing. A failed or stale vendor check degrades `/v1/status` and does not replace the last verified advisory.
- Add optional `STATUS_READ_TOKEN` for an external status probe, and optional `/health/deep` monitors for the read and publish gateways.
- Send gateway deep probes with separate bearer secrets, and do not follow redirects on those requests.
- Treat a publish-gateway deep probe as degraded when only some configured relays open.
- Report a software release when the advisory feed is down, and keep verified vendor affected-range alerts usable during a GitHub outage.
- Report incomplete security coverage when the installed version is unknown instead of calling that check successful.

## 0.1.0

- Describe the Worker as a standalone monitor for any configured service.
- Split CI into validate, unit, integration, security, coverage, a dry-run build, a production dependency audit, and a secret scan.
- Add issue templates, a pull request template, Dependabot, and a pre-commit format hook.
