# Security model

Nostr Watchdog sends operational alerts. Treat the sender keys, operator token, vendor tokens, and any future MLS state as secrets. The service does not need the operator's personal Nostr key.

## What the native process protects

- Probe URLs must be `https`, or `http` only when `PRIVATE_NETWORK_PROFILE=true`, on the host that was configured. Credentials, non-default ports, localhost, `.local`, `.internal`, `.home.arpa`, and private, link-local, metadata, CGNAT, and documentation addresses are rejected. Decimal and hex IPv4 literals are rejected.
- Redirects are limited to two hops and the original host. An authenticated probe does not follow a redirect.
- Relay URLs must be `wss` on port 443 and must not be a private address. `ws://` is rejected. Inbox relays that fail that check are dropped before use.
- GitHub requests are limited to `https` hosts `api.github.com` or `*.github.com`. Other bases are treated as unavailable. Redirects are not followed.
- Heartbeats use HMAC-SHA256. The current key and, on failure, the previous key are checked. Nonces are stored and a repeat is `401`. A valid older observation is `409` and does not replace newer progress. Equal timestamps keep the first committed row.
- Operator and status tokens are compared by hashing both sides and comparing the digests. The status body can be signed with `STATUS_SIGNING_SECRET`.
- Logs go through the existing redaction idea for token-like fields. Private keys, MLS secrets, and push tokens are not written by this code because it does not hold the latter two. Do not add debug prints of `nsec`, `TELEGRAM_BOT_TOKEN`, `GITHUB_TOKEN`, or authorization headers.
- The SQLite file is created mode `0600` on Unix. That is filesystem permissions, not encryption. Anyone who can read the file can read alert text and the stored NIP-17 gift wrap.
- There is no `unsafe` block in the watchdog crates.

## What it does not protect

- D1 and SQLite are not application-level encrypted. A copy of the database is a copy of the alert history.
- Memory zeroization of secrets is limited. `nsec` values are ordinary `String`s. WASM and a moving garbage-collected host would not honor zeroize anyway. The native process drops them when the request ends, which is not a guarantee against swapping or core dumps.
- Relay `OK` is not evidence the operator's phone showed the alert.
- Native HTTP, Telegram, and relay sockets resolve once, reject private answers unless the monitor explicitly allows them, and connect to that address while TLS still checks the original name. DNS, TCP, TLS, and the body share one deadline. The Worker `fetch` API cannot pin DNS. Its URL policy rejects literal private hosts before the request, which is weaker than the native pin.
- Discovery relays never receive a signed NIP-42 identity. Publication relays are signed only after they require authentication, and the original event is resent once with the same id.
- Operator routes require the operator token. The status reader token can read status and cannot acknowledge, silence, or onboard.
- Marmot push tokens, if they are stored later, are wake capabilities. `0006` has a column for the encrypted token. This build does not write it. Diagnostics must never return it.

## Dependencies

`deny.toml` allows common permissive licenses and denies unknown ones. `cargo audit` belongs in CI. Neither check proves the MDK pin is free of protocol bugs. The pin is an unpublished git revision and should be moved to a release tag when WhiteNoise publishes one.

## Cloudflare staging

`wrangler.staging.toml` uses a placeholder D1 id and the Worker name `nostr-watchdog-rust-staging`. Do not replace that id with `fbb00d08-4cd1-40a3-a4c5-437a439c1a09`. Do not put production secrets in the staging Worker.
