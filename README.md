# Nostr Watchdog

Nostr Watchdog is an open-source infrastructure monitoring service with private, encrypted Nostr notifications. Deploy on Cloudflare or run it on your own infrastructure.

This branch, `feat/rust-rewrite`, is the Rust implementation. The TypeScript Worker that is in production stays on `main` and is not changed by this branch. Do not deploy this branch over the production Worker.

The project is licensed under the [Unlicense](LICENSE). Third-party crates keep their own licenses. See [deny.toml](deny.toml).

## What works in this branch

The native binary (`nostr-watchdog`) runs the shared monitoring core:

- The same projects and monitors, all disabled until their enable flag is set.
- HTTP JSON checks, signed heartbeats, Alby Hub, and BTCPay Server.
- Incident thresholds, recovery, reminders, acknowledgement, and silence.
- A durable notification outbox with claim leases and the same prepared NIP-17 event on retry.
- Optional Telegram delivery for critical alerts.
- Hourly GitHub release and advisory checks for Alby Hub and BTCPay.
- Operator routes for status, heartbeats, test alerts, failed outbox rows, and incident ack/silence.

Marmot is the intended notification transport. It is not able to publish WhiteNoise-compatible messages from this build. The official Marmot session and push implementation depends on SQLCipher, OpenSSL, a filesystem, and Tokio. This repository does not substitute a private MLS or push implementation. A Marmot delivery is recorded as `marmot_engine_unavailable`. Relay acceptance is not phone delivery, including for NIP-17.

The Cloudflare crate in this branch is a staging health entrypoint only. It does not run the monitoring engine and it does not use the production D1 database. See [docs/mdk-compatibility.md](docs/mdk-compatibility.md).

## Requirements

- Rust 1.100.0, pinned in `rust-toolchain.toml`. The workspace MSRV is 1.91.
- No Node.js runtime for the native binary.
- `worker-build` and Wrangler are build and deploy tools for the staging Worker. They are not required to run the native binary.

## Native quick start

```bash
cargo run -p watchdog-native
```

The process listens on `127.0.0.1:8787` and stores state in `data/watchdog.sqlite` (file mode `0600` on Unix). `GET /healthz` is liveness. `GET /readyz` checks that the database opened.

```bash
curl -sS http://127.0.0.1:8787/healthz
```

Configuration is environment variables, with the same names as the TypeScript Worker, plus:

| Variable | Meaning |
| --- | --- |
| `DATABASE_PATH` | SQLite file. Default `data/watchdog.sqlite`. |
| `LISTEN_ADDR` | Default `127.0.0.1:8787`. |
| `WATCHDOG_CONFIG` | Optional TOML file whose `[vars]` table is loaded before the environment. Environment variables win. |
| `ENABLE_MARMOT` | `true` queues Marmot alerts. Delivery still fails closed until an official engine adapter exists. |
| `ENABLE_NIP17` | Set to `false` to stop NIP-17. Default is on. |
| `MARMOT_SYNC_SECONDS` | Reserved sync interval, clamped to 30–3600. Default 60. The sync does not open an MLS session in this build. |

Every monitor stays off until its `ENABLE_*` flag is `true` and its URL or key is set. `OPERATOR_TOKEN` must be set before operator routes answer. A missing token is `503 not_configured`, not a successful anonymous read.

## Checks

`cargo fmt --all -- --check`

`cargo clippy --workspace --exclude watchdog-worker --all-targets -- -W clippy::all`

`cargo test --workspace --exclude watchdog-worker`

The Worker crate is excluded from host tests because its fetch handler is `wasm32` only:

`cargo check -p watchdog-worker --target wasm32-unknown-unknown`

The MDK compile probe is outside the workspace so normal tests do not download OpenMLS:

`cargo check --manifest-path probes/mdk-engine/Cargo.toml --target wasm32-unknown-unknown`

## Documentation

- [Architecture](docs/architecture.md)
- [Parity with the TypeScript Worker](docs/parity.md)
- [MDK and Cloudflare compatibility](docs/mdk-compatibility.md)
- [Marmot and push notifications](docs/marmot-push.md)
- [Security model](docs/security.md)
- [Deployment](docs/deployment.md)
- [WhiteNoise acceptance](docs/acceptance.md)
- [Migration and rollback](docs/migration.md)
- [Contributing](CONTRIBUTING.md)

## Release status

This branch is not a v1.0.0 release. Real WhiteNoise push delivery has not been observed from this code. Do not merge it to `main` or point it at production secrets until that acceptance procedure has been run and the Cloudflare storage blocker is resolved or explicitly accepted.
