# Architecture

Nostr Watchdog is one monitoring service with two process shapes. The domain rules live once, in `watchdog-core`. The native binary and the Worker both call `watchdog-engine`. The Worker storage is D1. The native storage is SQLite. MDK state is not in either of those databases.

```text
watchdog-core          decisions, URL policy, incident transitions, alert text
watchdog-store         OperationalStore trait, SQLite behind the sqlite feature
watchdog-notify        NIP-17 gift wrap and inbox selection
watchdog-engine        probe cycle, vendor cycle, operator API
watchdog-native        Tokio, axum, reqwest, WebSocket relays, Marmot helper client
watchdog-worker        wasm32 Worker: D1, Fetch, scheduled checks
watchdog-marmot        separate process; official marmot-app session
probes/mdk-engine      compile probe for cgka-engine, not a running group
```

`probes/mdk-engine` is outside the Cargo workspace. `cargo test --workspace` does not download OpenMLS.

## What is shared

Incident thresholds, monitor status, alert text, SSRF checks, heartbeat canonicalization, and NIP-17 construction are not copied per deployment. `OperationalStore` is an async trait of domain operations. `SqliteStore` implements it when the `sqlite` feature is on. `D1Store` implements it in the Worker. rusqlite is not a dependency of the wasm graph. The official MDK store stays in `watchdog-marmot` because its SQLCipher `libsqlite3-sys` cannot be linked beside the operational SQLite.

## Notification transports

Transports are independent. One failure does not cancel the others.

| Transport | Role in this branch |
| --- | --- |
| Marmot | Preferred on the native process when `ENABLE_MARMOT=true`. The helper calls `marmot-app` create, send, and catch-up. Membership that is not the sender plus the configured recipient fails closed. The Worker still returns Marmot as unavailable. |
| NIP-17 | Default compatibility transport. The native process stores the gift wrap and retries that event. The Worker currently publishes a new wrap to the first bootstrap relay only. |
| Telegram | Optional. `dual` sends it with the Nostr alert for critical open, remind, and close. `nostr_fallback` sends one Telegram after the first critical NIP-17 or Marmot failure. |

NIP-04 is not implemented.

Marmot phases on the outbox are `message_prepared`, `message_accepted`, `push_token_unavailable`, `push_trigger_prepared`, and `push_trigger_accepted`. This build does not write the accepted phases, because it does not publish MLS messages or push triggers.

## State

SQLite (native) and D1 use migrations `0001` through `0007`. `0006` is left as it was. `0007` adds the push-record identity `(group, member, leaf, platform, server)` and does not treat a fingerprint as a primary key. The application database is plaintext, mode `0600` on Unix. It stores operational rows and Marmot metadata. MLS private keys stay in the helper's SQLCipher database. Push-token plaintext is not stored here.

Claim tokens fence outbox updates. A stale claimant cannot finish or replace an envelope. Gift-wrap JSON is written only while `envelope_json` is null. Delivery is at least once. It is not exactly once. A lost response after a relay accepted an event can be retried and the relay may see a duplicate of the same event id.

## Scheduling

The native process wakes about once a minute, runs due monitors with the configured concurrency, and attempts delivery even when the check lease is already held. The check lease grows with the number of probe waves and stays between 50 and 180 seconds. Vendor checks run when the last update attempt is missing or older than one hour. When Marmot is enabled, the same loop asks the helper to catch up on `MARMOT_SYNC_SECONDS`. A sync failure does not stop monitoring.

## Cloudflare

The Worker scheduled handler calls the same check and update functions, with D1 as the store. Fetch serves the operator routes. Marmot state is not a Durable Object yet: `storage-sqlite` does not build for `wasm32-unknown-unknown`. See [mdk-compatibility.md](mdk-compatibility.md). The Worker has been type-checked for wasm and has not been run under `workerd` in this pass.

The staging Worker name is `nostr-watchdog-rust-staging`. It must not be given the production D1 id.
