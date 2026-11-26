# Architecture

Nostr Watchdog is one monitoring service with two process shapes. The domain rules live once, in `watchdog-core`. The native binary is the working deployment. The Cloudflare crate is a separate staging entrypoint and does not yet run that core, because the storage crates it would need do not build for Workers.

```text
watchdog-core          decisions, URL policy, incident transitions, alert text
watchdog-store         SQLite schema, leases, outbox, Marmot metadata
watchdog-notify        NIP-17 gift wrap and inbox selection
watchdog-engine        probe cycle, vendor cycle, operator API
watchdog-native        Tokio, axum, reqwest, WebSocket relays
watchdog-worker        wasm32 health entrypoint for staging
probes/mdk-engine      compile probe for the pinned cgka-engine, not linked into the app
```

`probes/mdk-engine` is outside the Cargo workspace. `cargo test --workspace` does not download OpenMLS.

## What is shared

Incident thresholds, monitor status, alert text, SSRF checks, heartbeat canonicalization, NIP-17 construction, and the SQL statements are not copied per deployment. `watchdog-native` supplies HTTP, WebSockets, the clock, and the process. A future Worker adapter would supply D1 and Durable Object storage behind the same `SqliteStore` operations. That adapter is not written. rusqlite does not compile to `wasm32-unknown-unknown`, and the official MDK store is SQLCipher.

## Notification transports

Transports are independent. One failure does not cancel the others.

| Transport | Role in this branch |
| --- | --- |
| Marmot | Preferred. Queued when `ENABLE_MARMOT=true` for warning and critical alerts. Not encrypted or pushed. Status `marmot_engine_unavailable`. |
| NIP-17 | Default compatibility transport. Gift wrap is built once and stored. Retries publish that same event. |
| Telegram | Optional. `dual` sends it with the Nostr alert for critical open, remind, and close. `nostr_fallback` sends one Telegram after the first critical NIP-17 failure. |

NIP-04 is not implemented.

Marmot phases on the outbox are `message_prepared`, `message_accepted`, `push_token_unavailable`, `push_trigger_prepared`, and `push_trigger_accepted`. This build does not write the accepted phases, because it does not publish MLS messages or push triggers.

## State

SQLite (native) uses the existing D1 migrations `0001` through `0005`, plus additive `migrations/0006_marmot.sql`. The application database is plaintext, mode `0600` on Unix. It stores operational rows and Marmot metadata. It does not store MLS private keys, key-package secrets, or push-token plaintext.

Claim tokens fence outbox updates. A stale claimant cannot finish or replace an envelope. Gift-wrap JSON is written only while `envelope_json` is null. Delivery is at least once. It is not exactly once. A lost response after a relay accepted an event can be retried and the relay may see a duplicate of the same event id.

## Scheduling

The native process wakes about once a minute, runs due monitors, and always attempts delivery even when the check lease is already held. Vendor checks run when the last update attempt is missing or older than one hour. Leases are 50 seconds for checks and 10 minutes for updates.

## Cloudflare shape that is not built

The intended Worker shape remains: one Worker, D1 for the operational tables, one Durable Object per project sender for Marmot state, and cron triggers. That shape is blocked on an official `StorageProvider` that can persist the MDK engine without SQLCipher and Tokio. See [mdk-compatibility.md](mdk-compatibility.md).

The staging Worker name is `nostr-watchdog-rust-staging`. It must not be given the production D1 id.
