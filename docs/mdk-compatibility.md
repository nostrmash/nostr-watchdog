# MDK and Cloudflare compatibility

Checked against the public repositories on 2026-11-26.

| Component | What this branch uses |
| --- | --- |
| MDK git | `https://github.com/marmot-protocol/mdk` rev `ca52a04718628f08ed76b777df9c444594074182` |
| Crate version at that rev | unpublished `0.20.0-dev` (`publish = false`). This is not crates.io `mdk-core` 0.8.0. |
| OpenMLS | `https://github.com/openmls/openmls` rev `6100df3fb1d8c3eeab53e349fcbd621f98c44fe2`, via the MDK pin |
| nostr | `https://github.com/nostrdevkit/nostr` rev `4904ffb85f60178375a1dda659a61793f36f03b8` (`nostr` 0.45.7) |
| Linked into the watchdog | `nostr` only, for NIP-17. `cgka-engine` is compiled by `probes/mdk-engine` and is not a workspace dependency. |

`mdk-core` 0.8.0 on crates.io is an older API. WhiteNoise current code follows the unpublished MDK tree. Nightly MarmotKit builds are deleted after about 30 days, so the git revision above is the pin, not a crates.io version.

## What upstream already separates

`cgka-engine` is generic over `StorageProvider` and has a wasm32 target (getrandom js, gloo timers, OpenMLS `js`). Its own wasm check compiles the engine, the traits, and a Nostr transport peel. It does not prove storage, a Worker, or a running group.

`storage-sqlite` and `marmot-session` use SQLCipher. `marmot-app` is where group sync, the CLI, and push notifications live. That crate also uses OpenSSL, Tokio networking, reqwest, and the filesystem. Push kinds, the 1084-byte token encoding, and gift-wrap limits are implemented there, not in a small reusable crate.

## Decision

This repository does not vendor a fork of MDK and does not reimplement MLS, NIP-44, or the push token format. The native binary could later link `cgka-engine` plus `storage-sqlite`. That link was not finished: it pulls SQLCipher and OpenSSL into the watchdog process, and it still would not run on Workers. Until that adapter exists, Marmot delivery returns `marmot_engine_unavailable` and no ciphertext is published.

## Cloudflare

`workers-rs` 0.9 is the SDK used by `watchdog-worker`. The Worker exposes `GET /healthz` and `GET /v1/diagnostics/marmot` and a scheduled handler that logs and returns. It does not open D1, does not construct a Durable Object, and does not send alerts.

The production D1 database is not named in `wrangler.staging.toml`.

A Durable Object per project sender is still the right place for MLS state if an official storage adapter appears. It is not implemented here. Workers are single-threaded, but a Durable Object still needs an explicit transaction around cryptographic state. That design is unused until the engine can persist.

## Evidence

On 2026-11-26, with rustc 1.100.0 on `aarch64-apple-darwin`:

- `cargo check --manifest-path probes/mdk-engine/Cargo.toml` type-checked `cgka-engine` for the host. `Engine<S>` requires a `StorageProvider`. The probe only reads `DEFAULT_MAX_PAST_EPOCHS`. It does not create a group.
- `cargo check --manifest-path probes/mdk-engine/Cargo.toml --target wasm32-unknown-unknown` finished successfully. The resolved crates included `openmls` 0.9.0 from git rev `6100df3`, `cgka-engine` 0.20.0-dev, and `nostr` 0.45.7. That is a wasm compile of the engine, not a running MLS group, key package, or push notification.
- `cargo check -p watchdog-worker --target wasm32-unknown-unknown` finished successfully. The Worker is the health entrypoint described above. It was not executed inside `workerd` in this pass, so fetch behaviour on the Cloudflare runtime is compiled, not observed.

`storage-sqlite` and `marmot-app` were not compiled for wasm. Their Cargo manifests depend on SQLCipher, OpenSSL, and Tokio, which is why they were left out of the probe.

## Upstream work that would unblock Workers

- A `StorageProvider` that is synchronous or Worker-friendly and does not require SQLCipher.
- Publishing the current MDK crates, or a stable tag that WhiteNoise actually ships, so the pin is not an unpublished revision.
- Moving `marmot-app` push encoding into a crate that does not depend on the CLI runtime.

No patch against those crates is included in this branch.
