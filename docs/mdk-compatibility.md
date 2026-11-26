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

This repository does not vendor a fork of MDK and does not reimplement MLS, NIP-44, or the push token format. Native Marmot is `watchdog-marmot`, which calls `MarmotAppRuntime` (`create_or_import_account`, `create_group`, `group_members`, `send_message`, `catch_up_accounts`). `send_message` is the official path that also attempts a notification trigger. This branch does not claim that a phone displayed one.

The helper is not linked into `nostr-watchdog`. MDK's `rusqlite` 0.40 SQLCipher build and the operational `rusqlite` 0.37 build both set `links = "sqlite3"`. Cargo rejects that combination in one binary. Putting SQLCipher under the operational database would also stop it from opening the existing plaintext SQLite file. The helper is a local process started with `MARMOT_HELPER`. It is not a hosted gateway and it is not the Cloudflare design.

Building the helper requires the Odin compiler `dev-2026-10` (`84bc3fc`) because `marmot-app` depends on `marmot-markdown`. That is a build tool, not a runtime service.

## Cloudflare

`workers-rs` 0.9 is the SDK used by `watchdog-worker`. The scheduled handler runs the shared check cycle and then notification dispatch, and the fetch handler serves the operator routes, when a D1 binding named `DB` is present and the schema ledger matches `0008_commit_token`. Runtime requests do not apply DDL. Marmot delivery in the Worker returns unavailable. No Durable Object is constructed. NIP-17 publication uses the shared delivery path: gift wraps go only to validated recipient inbox relays, and the signed event is stored before the first publish. The linked wasm bundle has been loaded by local workerd. `GET /healthz` returned the live JSON body and `GET /readyz` returned ready after Wrangler applied migrations `0001` through `0008` to a local D1 database. `GET /v1/status` reached the shared engine and returned `not_configured` because that local config has no reader token. Scheduled monitoring, gift-wrap publication, and Durable Object MLS were not executed in that process.

The production D1 database is not named in `wrangler.staging.toml`.

A Durable Object per project sender is still the right place for MLS state if an official storage adapter appears. It is not implemented here. Workers are single-threaded, but a Durable Object still needs an explicit transaction around cryptographic state. That design is unused until the engine can persist.

## Evidence

On 2026-11-26, with rustc 1.100.0 on `aarch64-apple-darwin`:

- `cargo check --manifest-path crates/watchdog-marmot/Cargo.toml` type-checked `marmot-app` 0.20.0-dev. `cargo build` produced `watchdog-marmot`. A local run answered `{"op":"ping"}` with `{"ok":true,"pong":true}`. That shows the process and the linked runtime start. It does not show a group, a relay publish, or a phone notification.
- `cargo check -p watchdog-worker --target wasm32-unknown-unknown` finished successfully after `getrandom` `wasm_js` and `uuid` `js`. The Worker was not executed inside `workerd`.
- `probes/mdk-engine` still only reads `DEFAULT_MAX_PAST_EPOCHS`. It is not the integration.

`storage-sqlite` and `marmot-app` were not compiled for wasm. Their Cargo manifests depend on SQLCipher, OpenSSL, and Tokio, which is why they were left out of the probe.

## Upstream work that would unblock Workers

- A `StorageProvider` that is synchronous or Worker-friendly and does not require SQLCipher.
- Publishing the current MDK crates, or a stable tag that WhiteNoise actually ships, so the pin is not an unpublished revision.
- Moving `marmot-app` push encoding into a crate that does not depend on the CLI runtime.

No patch against those crates is included in this branch.
