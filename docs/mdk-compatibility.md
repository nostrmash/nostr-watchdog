# MDK and Cloudflare compatibility

Checked against the public repositories on 2026-11-26.

| Component | What this branch uses |
| --- | --- |
| MDK git | `https://github.com/marmot-protocol/mdk` rev `ca52a04718628f08ed76b777df9c444594074182` |
| Crate version at that rev | unpublished `0.20.0-dev` (`publish = false`). This is not crates.io `mdk-core` 0.8.0. |
| OpenMLS | `https://github.com/openmls/openmls` rev `6100df3fb1d8c3eeab53e349fcbd621f98c44fe2`, via the MDK pin |
| nostr | `https://github.com/nostrdevkit/nostr` rev `4904ffb85f60178375a1dda659a61793f36f03b8` (`nostr` 0.45.7) |
| Linked into `nostr-watchdog` | `nostr`, for NIP-17. Not MDK. |
| Linked into `watchdog-marmot` | `marmot-app` and its MDK crates, in a separate Cargo workspace. |

`mdk-core` 0.8.0 on crates.io is an older API. WhiteNoise current code follows the unpublished MDK tree. Nightly MarmotKit builds are deleted after about 30 days, so the git revision above is the pin, not a crates.io version.

## What upstream already separates

`cgka-engine` is generic over `StorageProvider` and has a wasm32 target (getrandom js, gloo timers, OpenMLS `js`). Its own wasm check compiles the engine, the traits, and a Nostr transport peel. It does not prove storage, a Worker, or a running group.

`storage-sqlite` and `marmot-session` use SQLCipher. `marmot-app` is where group sync, the CLI, and push notifications live. That crate also uses OpenSSL, Tokio networking, reqwest, and the filesystem. Push kinds, the 1084-byte token encoding, and gift-wrap limits are implemented there, not in a small reusable crate.

## Decision

This repository does not vendor a fork of MDK and does not reimplement MLS, NIP-44, or the push token format. Native Marmot is `watchdog-marmot`, which calls `MarmotAppRuntime` (`create_or_import_account`, `existing_direct_conversation`, `create_group_detailed`, `group_members`, `submit_text`, `local_send_status`, `catch_up_accounts`). Chat alerts stay kind 9. This branch does not claim that a phone displayed one.

The helper is not linked into `nostr-watchdog`. MDK's `rusqlite` 0.40 SQLCipher build and the operational `rusqlite` 0.37 build both set `links = "sqlite3"`. Cargo rejects that combination in one binary. Putting SQLCipher under the operational database would also stop it from opening the existing plaintext SQLite file. The helper is a local process started with `MARMOT_HELPER`. It is not a hosted gateway and it is not the Cloudflare design.

Building the helper requires the Odin compiler `dev-2026-10` (`84bc3fc`) because `marmot-app` depends on `marmot-markdown`. That is a build tool, not a runtime service.

## Cloudflare

`workers-rs` 0.9 is the SDK used by `watchdog-worker`. The scheduled handler runs the shared check cycle and then notification dispatch, and the fetch handler serves the operator routes, when a D1 binding named `DB` is present and the schema ledger matches `0008_commit_token`. Runtime requests do not apply DDL. Marmot delivery in the production Worker returns unavailable. NIP-17 publication uses the shared delivery path: gift wraps go only to validated recipient inbox relays, and the signed event is stored before the first publish. The linked watchdog bundle has been loaded by local workerd. `GET /healthz` returned the live JSON body and `GET /readyz` returned ready after Wrangler applied migrations `0001` through `0008` to a local D1 database. `GET /v1/status` reached the shared engine and returned `not_configured` because that local config has no reader token. Scheduled monitoring and gift-wrap publication were not executed in that process.

`probes/mls-durable` is a separate Worker. It creates an OpenMLS group, stores the `MemoryStorage` map in a SQLite Durable Object, and on the next request loads that map, advances the epoch, and creates an application message. On 2026-11-26 local workerd returned `{"created":true,"epoch":0,"messageBytes":0,"storageEntries":13}`, then `{"created":false,"epoch":1,"messageBytes":153,"storageEntries":13}`. After that process was stopped and started again, the next request returned epoch 2 and 153 message bytes. The snapshot is taken after OpenMLS returns. It is not the MDK `StorageProvider`, not a mid-operation journal, and not a WhiteNoise session. The probe is not wired into the watchdog Worker.

The production D1 database is not named in `wrangler.staging.toml`.

A Durable Object per project sender is still the intended home for a full MDK session. The probe shows that OpenMLS state can survive a workerd restart in Durable Object SQLite. It does not show that `marmot-app` can. Workers are single-threaded, and a Durable Object still needs the snapshot written before a ciphertext is treated as sent.

## Evidence

On 2026-11-26, with rustc 1.100.0 on `aarch64-apple-darwin`:

- `cargo build --manifest-path crates/watchdog-marmot/Cargo.toml --release` produced `crates/watchdog-marmot/target/release/watchdog-marmot` with Odin `dev-2026-10:84bc3fc`. A local process answered a health-socket ping with `{"ok":true,"pong":true}`. Import against `wss://127.0.0.1` returned `relay endpoint host is not a public address`. Import against `wss://relay.damus.io` returned `account directory lookup did not complete`.
- `cargo test --manifest-path crates/watchdog-marmot/Cargo.toml --test fixture_exchange` passed. The sender was the helper. The recipient was a second `MarmotApp` runtime. The relay was `scripts/fixture-relay.mjs` on `ws://127.0.0.1` with the helper's `--allow-loopback` flag. The recipient decrypted `watchdog fixture alert`, and a restart of the helper returned the same message ids.
- `cargo check -p watchdog-worker --target wasm32-unknown-unknown` finished successfully. The watchdog Worker has been loaded in local workerd for health and readiness. Its scheduled handler has not been invoked.
- `probes/mdk-engine` still only reads `DEFAULT_MAX_PAST_EPOCHS`. The OpenMLS execution is `probes/mls-durable`.

`storage-sqlite` and `marmot-app` were not compiled for wasm. Their Cargo manifests depend on SQLCipher, OpenSSL, and Tokio, which is why they were left out of the probe.

## Upstream work that would unblock Workers

- A `StorageProvider` that is synchronous or Worker-friendly and does not require SQLCipher.
- Publishing the current MDK crates, or a stable tag that WhiteNoise actually ships, so the pin is not an unpublished revision.
- Moving `marmot-app` push encoding into a crate that does not depend on the CLI runtime.

No patch against those crates is included in this branch.
