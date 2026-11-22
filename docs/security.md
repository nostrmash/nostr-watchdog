# Security

## Secrets

Secrets are Cloudflare secret bindings or `.dev.vars`. They are not written to source, Wrangler vars, D1, logs, alert text, or URLs. The logger drops field names that look like tokens, secrets, keys, passwords, or cookies, and alert text redacts `nsec`, `npub`, bearer tokens, `token=` / `secret=` assignments, long hex strings, and URL userinfo.

`.dev.vars.example` has empty values. `.gitignore` ignores `.dev.vars`. Tests generate sender keys in the Vitest config and inject them as bindings. Those keys are not printed and are not in git. Vitest may warn that `secrets.required` is unset in the process environment. The test bindings supply them inside the Worker.

Operator routes require `Authorization: Bearer <OPERATOR_TOKEN>` compared in constant time. If the token is missing, those routes return 503. There is no CORS middleware and no public test-alert route. `GET /healthz` returns only liveness.

Report vulnerabilities privately. See [SECURITY.md](../SECURITY.md).

## Outbound probes

Every probe URL comes from configuration, and the host must match the host of that configured URL. The Worker does not accept a caller-supplied URL or header. Probes are HTTPS on port 443 unless `PRIVATE_NETWORK_PROFILE=true`, which is off by default. Userinfo, redirects to another host, and redirects that fail the same policy are rejected. A probe that sends `Authorization` does not follow any redirect. Vendor calls refuse every redirect so a token cannot be replayed to another host. Gateway health tokens are separate from publish and read API tokens.

Blocked destinations, unless the private-network profile is explicitly on, include loopback, private ranges, link-local, multicast, documentation ranges, IPv6 unique-local and link-local, IPv4-mapped private addresses, decimal and hex IP literals, `localhost`, and metadata hostnames.

Response bodies are capped. Vendor response bodies are not logged. Alerts include a version string only when it matches a short safe character set.

## Vendor credentials

Alby Hub monitoring uses GET and a read-only token. It does not unlock a wallet, request a mnemonic, or ask for payment permission. BTCPay monitoring uses GET. It does not create invoices. The BTCPay key, when set, is sent only to the configured origin as `Authorization: token <key>`.

## Heartbeats

`POST /v1/heartbeats/:monitorId` requires HMAC-SHA256 over:

```text
timestamp
nonce
POST
/v1/heartbeats/:monitorId
sha256-hex of the raw body
```

Headers are `X-Watchdog-Timestamp` (unix seconds), `X-Watchdog-Nonce` (16–128 characters from `[A-Za-z0-9_-]`), and `X-Watchdog-Signature` (64 hex characters). Verification uses WebCrypto. The nonce is stored in D1 until the skew window ends, so a replay inside that window fails. A body over the configured cap is rejected before it is parsed. The signing key is the key for that monitor id only. Clock skew outside `HEARTBEAT_MAX_SKEW_SECONDS` is rejected.

## Delivery

Gift wraps go only to kind 10050 inbox relays whose event id and signature verify. Telegram requests go only to `api.telegram.org`, and the bot token is not logged. The chat id must be an integer string. Critical Telegram text is the same short incident text as the Nostr message. When Telegram is configured, dual delivery is the default because a relay can accept an event that no phone displays. That also sends the alert text to Telegram. Use `nostr_fallback` when you would rather risk a missed page than send the text to Telegram on every critical incident. Fallback sends one Telegram message per incident, not one per Nostr retry.

## Data stored in D1

The outbox stores the alert plaintext and, after the first signing, the gift-wrap JSON so a retry keeps the same event id. Relays store the encrypted gift wrap. D1 does not. Do not put wallet seeds, unlock passwords, payment tokens, or NWC secrets in alert text. The Worker does not add them. Accepted rows are deleted after 14 days and dead letters after 30 days. Open incidents and alerts that can still be retried are kept.

Cloudflare operates D1 and the Worker isolate. This repository cannot promise that Cloudflare staff, a legal request, or a platform compromise cannot read that plaintext. Use a separate D1 database, operator token, and sender key for staging and production. Heartbeat secrets rotate by publishing the new key in `HEARTBEAT_KEYS` and the old key in `HEARTBEAT_KEYS_PREVIOUS`, then clearing the previous key after emitters have restarted.

Test alerts are limited to three per project per hour.

## Licenses

This project's `LICENSE` is the Unlicense and stays the Unlicense. Production dependencies reported by `pnpm licenses list --prod`:

| Package                                            | License   |
| -------------------------------------------------- | --------- |
| `nostr-tools`                                      | Unlicense |
| `@noble/ciphers`, `@noble/curves`, `@noble/hashes` | MIT       |
| `@scure/base`, `@scure/bip32`, `@scure/bip39`      | MIT       |

The MIT packages are transitive dependencies of `nostr-tools` and are bundled into the Worker. Their MIT terms still apply to that code. Dev tooling is not part of the runtime bundle. Source files do not add an extra license header.

## What a healthy check does not prove

A healthy check does not prove that a wallet can pay, that a phone displayed an alert, or that software with no published advisory is free of vulnerabilities. `unknown` and `no_published_advisories` are not "secure". Cloudflare cannot observe an outage of Cloudflare. Run a second checker somewhere else against `/healthz` and, if you can keep the token outside Cloudflare, against signed `GET /v1/status`.
