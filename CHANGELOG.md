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

## 0.1.0

- Describe the Worker as a standalone monitor for any configured service.
- Split CI into validate, unit, integration, security, coverage, a dry-run build, a production dependency audit, and a secret scan.
- Add issue templates, a pull request template, Dependabot, and a pre-commit format hook.
