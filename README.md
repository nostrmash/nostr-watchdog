# Nostr Watchdog

Nostr Watchdog is an open-source infrastructure monitoring service with private, encrypted Nostr notifications. Deploy on Cloudflare or run it on your own infrastructure.

Cloudflare production uses the Rust `nostr-watchdog` Worker and the private `nostr-watchdog-marmot` Worker. See the [deployment runbook](docs/deployment.md#cloudflare-production) and [WhiteNoise acceptance procedure](docs/acceptance.md#cloudflare).

The project is licensed under the [Unlicense](LICENSE). Third-party crates keep their own licenses. See [deny.toml](deny.toml).

## Capabilities

The native binary (`nostr-watchdog`) runs the shared monitoring core:

- The same projects and monitors, all disabled until their enable flag is set.
- HTTP JSON checks, signed heartbeats, Alby Hub, and BTCPay Server.
- Incident thresholds, recovery, reminders, acknowledgement, and silence.
- A durable notification outbox with claim leases and the same prepared NIP-17 event on retry.
- Optional Telegram delivery for critical alerts.
- Hourly GitHub release and advisory checks for Alby Hub and BTCPay.
- Operator routes for status, heartbeats, test alerts, failed outbox rows, and incident ack/silence.

Marmot delivery on the native process goes through `watchdog-marmot`, a separate executable that links official `marmot-app` at MDK `ca52a04`. It is a separate process because that crate's SQLCipher build and the operational SQLite database both export `links = "sqlite3"`, and Cargo can link only one of them. The helper reports application-message relay acceptance and native push uncertainty separately. Physical WhiteNoise acceptance remains pending.

On Cloudflare, the operational Worker runs the shared engine and D1 outbox. It contacts the private Marmot Durable Object through `MARMOT_SENDER`. Local workerd tests exercised a scheduled incident, independent MDK decryption, trigger recovery, and restart. See [integration evidence](docs/integration.md) and [deployment](docs/deployment.md).

## Requirements

- Rust 1.100.0, pinned in `rust-toolchain.toml`. The workspace MSRV is 1.91.
- No Node.js runtime for the native binary.
- Cloudflare bundles use `worker-build` 0.9.0 and the Wrangler version pinned in the lockfile.

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
| `ENABLE_MARMOT` | `true` queues Marmot alerts. Delivery needs the helper below. |
| `ENABLE_NIP17` | Set to `false` to stop NIP-17. Default is on. |
| `MARMOT_ROOT` | Directory for the helper's SQLCipher state. Mode `0700`. |
| `MARMOT_SOCKET` | Unix socket. Default `$MARMOT_ROOT/watchdog.sock`. |
| `MARMOT_HELPER` | Path to `watchdog-marmot`. The native process spawns it when the socket is absent. |
| `MARMOT_SYNC_SECONDS` | How often the native process asks the helper to catch up. Clamped to 30–3600. Default 60. |
| `NOTIFY_<PROJECT>_<TRANSPORT>` | Optional per-project override. `false` disables that transport. `true` allows every severity. A comma list such as `warning,critical` filters. Empty inherits the global default. |

Build the helper with the Odin compiler MDK pins (`dev-2026-10`, commit `84bc3fc`). The upstream installer is `scripts/install-odin.sh` in the MDK checkout:

```bash
export ODIN="$HOME/.local/share/mdk-odin/odin"
cargo build --manifest-path crates/watchdog-marmot/Cargo.toml
```

`watchdog-marmot --root data/marmot --socket data/marmot/watchdog.sock --relay wss://relay.example` serves one JSON command per connection. The socket mode is `0600`. Commands are `import`, `create_group`, `members`, `send`, `sync`, and `ping`. `send` refuses a group whose members are not the sender plus the configured recipient, and it does not encrypt the same alert id twice.

Every monitor stays off until its `ENABLE_*` flag is `true` and its URL or key is set. `OPERATOR_TOKEN` must be set before operator routes answer. A missing token is `503 not_configured`, not a successful anonymous read.

## Checks

`cargo fmt --all -- --check`

`cargo clippy --workspace --exclude watchdog-worker --all-targets -- -W clippy::all`

`cargo test --workspace --exclude watchdog-worker`

The Worker crate is excluded from host tests because its fetch handler is `wasm32` only:

`cargo check -p watchdog-worker --target wasm32-unknown-unknown`

The MDK helper and the compile probe are outside the workspace. The helper needs `ODIN` pointing at `dev-2026-10`:

`cargo check --manifest-path crates/watchdog-marmot/Cargo.toml`

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

See the [integration evidence](docs/integration.md) for the qualified runtime behavior. The [production and phone procedures](docs/acceptance.md) describe how to verify relay evidence and observe delivery on an iPhone.
