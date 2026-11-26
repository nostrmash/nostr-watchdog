# Functional parity

The TypeScript Worker on `main` at `a236b35a9dda14aa6f1a96dc37fc2daccc838ed8` is the behavioural reference. There are no git tags. This matrix is the Rust branch, not a claim that production has moved.

Status values remain `healthy`, `degraded`, `down`, `unknown`, and `misconfigured`. A skipped or inconclusive result is not stored as healthy. One probe error does not stop the other monitors. Unknown samples do not increment the success or failure counters and do not close an outage. After `UNKNOWN_THRESHOLD` consecutive unknowns (default 5) one warning inconclusive incident is opened. Misconfigured opens on the first sample. Degraded opens an incident only when the monitor says so. Reminders are only for critical outages that are not acknowledged or silenced.

| Behaviour | TypeScript | Rust | Tests | Notes |
| --- | --- | --- | --- | --- |
| Projects and 13 monitors, fail-safe enable flags | `src/config/monitors.ts` | `watchdog-core` catalog | catalog is executed by the engine | Same ids and env names. |
| Incident open, close, remind, unknown, integrity | `src/state/transition.ts` | `watchdog-core` transition | `transition` unit tests | Ported from the vitest cases. |
| Generation check so a stale writer cannot commit | `src/state/store.ts` | `watchdog-store` | store test | |
| Outbox claim, extend, same envelope, stale token rejected | `src/cycles/dispatch.ts` | store + engine dispatch | store test | |
| NIP-17 gift wrap and kind 10050 inbox selection | `src/alerts/nip17.ts`, `relay.ts` | `watchdog-notify` | gift-wrap round trip, inbox selection | Same `nostr` revision MDK pins (`4904ffb`). |
| Telegram dual and nostr fallback | `src/alerts/telegram.ts` | engine cycle + native | not separately tested | Critical only. |
| Marmot message and WhiteNoise push | not in the TypeScript app | native helper calls `marmot-app`; Worker still unavailable | fixture exchange, gift wrap on the fixture, and one WhiteNoise-relay decrypt | Phone delivery and Worker MDK remain open. |
| HTTP JSON, redirects, size limit | `src/checks/http-json.ts` | engine probes | URL policy tests | Authenticated probes do not follow redirects. |
| Signed heartbeat and nonce replay | `src/checks/heartbeat.ts` | core + store | store replay test | HMAC over `timestamp\nnonce\nMETHOD\npath\nsha256(body)`. |
| Alby Hub and BTCPay classification | `src/checks/alby-hub.ts`, `btcpay.ts` | `watchdog-core` classify + probes | policy test for BTCPay 2.4.1 | |
| SSRF and relay URL policy | `src/security/url-policy.ts` | `watchdog-core` url policy | security tests ported | |
| Status contract `watchdog-status-v1` | `src/http/status.ts` | `watchdog-core` status | not a golden-file test | Extra Marmot error codes are additive. |
| Operator auth | `src/http/app.ts` | engine `http_api` | not a route test | Missing token is 503. Bad token is 401. |
| Vendor feeds, retention of previous findings | `src/cycles/updates.ts` | engine `updates` | missing version is not "secure" | Empty advisories are not a clean bill of health. |
| Ack, silence, dead letter, test alert | `src/http/app.ts` | engine `http_api` | not a route test | Test alerts stay rate limited at 3 per project per hour. |
| Cloudflare cron and D1 | `wrangler.jsonc` | Worker scheduled handler and `D1Store` | local workerd health and readiness | Scheduled handler not invoked. Production database is not referenced. |
| Relay fixture and local dev vars | `src/http/relay-fixture.ts` | not ported | | Use real `wss` relays on port 443, or skip NIP-17. |

## Deliberate differences

- Marmot is a new destination. It is off unless `ENABLE_MARMOT=true`.
- NIP-17 can be turned off with `ENABLE_NIP17=false`. The TypeScript Worker always attempted it when alerts were on.
- The native process is the runtime that has executed the monitoring tests. The watchdog Worker has been loaded in local workerd. Its scheduled handler has not been invoked.
- Query strings still 404 on operator routes except `project` on `/v1/diagnostics/marmot`.
- `/v1/diagnostics/relays` is served by the native process and the Worker. Inbox selection still happens inside NIP-17 delivery.

## Not silently removed

Security-update monitoring, both projects, Blossom, Blastr, optional gateways, heartbeat signing, Telegram fallback, and the outbox fence are in the Rust core. Native Marmot uses official `marmot-app` in a side process. A scheduled Worker cycle, Worker NIP-17 publication, and a physical WhiteNoise notification are still open.
