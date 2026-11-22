# Security

## Secrets

Secrets are Cloudflare secret bindings or `.dev.vars`. They are not written to source, Wrangler vars, D1, logs, alert text, or URLs. The logger drops field names that look like tokens, secrets, keys, passwords, or cookies, and alert text redacts `nsec`, `npub`, bearer tokens, `token=` / `secret=` assignments, long hex strings, and URL userinfo.

`.dev.vars.example` has empty values. `.gitignore` ignores `.dev.vars`. Tests generate bot keys in the Vitest config and inject them as bindings. Those keys are not printed and are not in git. Vitest may warn that `secrets.required` is unset in the process environment; the test bindings supply them inside the Worker.

Operator routes require `Authorization: Bearer <OPERATOR_TOKEN>` compared in constant time. If the token is missing, those routes return 503. There is no CORS middleware and no public test-alert route. `GET /healthz` returns only liveness.

## Outbound probes

Every probe URL comes from configuration, and the host must match the host of that configured URL. The Worker does not accept a caller-supplied URL. Probes are HTTPS on port 443 unless `PRIVATE_NETWORK_PROFILE=true`, which is off by default. Userinfo, redirects to another host, and redirects that fail the same policy are rejected. Vendor calls additionally refuse every redirect so an Alby or BTCPay token cannot be replayed.

Blocked destinations, unless the private-network profile is explicitly on, include loopback, RFC1918, CGNAT, link-local, multicast, documentation ranges, IPv6 unique-local and link-local, IPv4-mapped private addresses, decimal and hex IP literals, `localhost`, and metadata hostnames such as `metadata.google.internal`.

Response bodies are capped. Alby and BTCPay response bodies are not logged. Alerts include a version string only when it matches a short safe character set.

## Vendor credentials

Alby monitoring uses GET and a read-only token. It does not unlock a wallet, request a mnemonic, or ask for NWC payment permission. BTCPay monitoring uses GET. It does not create invoices or reuse a payment-capable key. The BTCPay key, when set, is sent only to the configured BTCPay origin as `Authorization: token <key>`.

## Heartbeats

`POST /v1/heartbeats/:monitorId` requires HMAC-SHA256 over:

```text
timestamp
nonce
POST
/v1/heartbeats/:monitorId
sha256-hex of the raw body
```

Headers are `X-Watchdog-Timestamp` (unix seconds), `X-Watchdog-Nonce` (16–128 characters from `[A-Za-z0-9_-]`), and `X-Watchdog-Signature` (64 hex characters). Verification uses WebCrypto. The nonce is stored in D1 until the skew window ends, so a replay inside that window fails. A body over the configured cap is rejected before it is parsed. The signing key is the key for that monitor id only; a key for another monitor or project does not authenticate. Clock skew outside `HEARTBEAT_MAX_SKEW_SECONDS` is rejected.

## Delivery

Gift wraps go only to validated kind 10050 inbox relays. Telegram requests go only to `api.telegram.org`, and the bot token is not logged. The chat id must be an integer string. Critical Telegram text is the same short incident text as the Nostr message. When Telegram is configured, dual delivery is the default because a relay can accept an event that no phone displays. That sends the alert text to Telegram as well. Use `nostr_fallback` if you would rather risk a missed page than send the text to Telegram on every critical incident.

Test alerts are limited to three per project per hour.

## Licenses

This project's `LICENSE` is the Unlicense and stays the Unlicense. Production dependencies reported by `pnpm licenses list --prod`:

| Package                                            | License   |
| -------------------------------------------------- | --------- |
| `nostr-tools`                                      | Unlicense |
| `@noble/ciphers`, `@noble/curves`, `@noble/hashes` | MIT       |
| `@scure/base`, `@scure/bip32`, `@scure/bip39`      | MIT       |

Those MIT packages are transitive dependencies of `nostr-tools` and are bundled into the Worker. Their MIT terms still apply to that code. Dev tooling such as Wrangler, TypeScript, ESLint, and Vitest is not part of the runtime bundle. No extra license header is added to source files.

## What this does not claim

A healthy check is not proof that a wallet can pay, that a phone displayed an alert, or that software with no published advisory is free of vulnerabilities. `unknown` and `no_published_advisories` are not "secure". Cloudflare cannot observe an outage of Cloudflare. Run a second checker somewhere else against `/healthz` and, if you can keep the token outside Cloudflare, against signed `GET /v1/status`.
