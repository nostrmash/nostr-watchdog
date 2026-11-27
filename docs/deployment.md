# Deployment

Two targets exist. Only the native binary runs the monitors. The staging Worker is a health check and must stay separate from production.

## Native process

```bash
cargo build --release -p watchdog-native
./target/release/nostr-watchdog
```

Environment variables use the names already documented for the TypeScript Worker. Add `DATABASE_PATH` and `LISTEN_ADDR`. Optional `WATCHDOG_CONFIG` points at a TOML file:

```toml
[vars]
WATCHDOG_ENABLED = "true"
ALERTS_ENABLED = "true"
OPERATOR_TOKEN = "replace-me"
ENABLE_NIP17 = "true"
ENABLE_MARMOT = "false"
```

The environment overrides the file. Leave monitor `ENABLE_*` flags false until the endpoint is set.

`GET /healthz` returns 200 when the process is up. `GET /readyz` returns 200 when the database, schema, configuration, scheduler freshness, and required transports pass. A disabled optional transport does not fail readiness. Unknown Marmot state is reported and does not fail readiness. Enabled Marmot on the Worker is unavailable.

Stop the process with SIGINT or SIGTERM. New scheduler ticks stop immediately. Active work drains for 25 seconds, open claims are released without deleting stored envelopes, and the Marmot helper is then signalled. Stored gift wraps are reused.

### systemd

```ini
[Unit]
Description=Nostr Watchdog
After=network-online.target

[Service]
Type=simple
User=watchdog
Group=watchdog
EnvironmentFile=/etc/nostr-watchdog.env
ExecStart=/usr/local/bin/nostr-watchdog
Restart=on-failure
TimeoutStopSec=30
KillSignal=SIGTERM
NoNewPrivileges=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
```

Put secrets in `/etc/nostr-watchdog.env` with mode `0600`. The SQLite directory must be writable by `watchdog` and not by other users.

### Backup

Stop the process or use SQLite's backup API. Copying the file while the process is writing can tear a page. `sqlite3 data/watchdog.sqlite ".backup data/watchdog.sqlite.bak"` is the safe copy. Restoring that file restores incidents and outbox rows. It does not restore an MLS conversation, because this build does not have one. When Marmot state exists, do not copy an old snapshot back over a newer epoch. Re-onboard instead.

### Docker

```bash
docker build -t nostr-watchdog .
docker run --rm -p 8787:8787 -v watchdog-data:/data -e OPERATOR_TOKEN=replace-me nostr-watchdog
```

The image runs as uid 10001 and keeps the database on `/data`. It contains `nostr-watchdog` and `watchdog-marmot`. Odin, Node.js, and the Rust toolchain stay in the build stage. Set `MARMOT_HELPER=/usr/local/bin/watchdog-marmot` and `MARMOT_ROOT=/var/lib/watchdog/marmot` before enabling Marmot. The image does not contact Cloudflare.

## Cloudflare staging

Two Workers. Neither has been deployed. The production Worker and production D1 database stay untouched. `wrangler.jsonc` belongs to the TypeScript Worker.

1. Build the Marmot Worker with `crates/watchdog-marmot-worker/worker/build-release.sh`.
2. Build the operational Worker with `worker-build --release` from `wrangler.staging.toml`.
3. Create a staging D1 database named `nostr-watchdog-rust-staging`. Put only that id into `wrangler.staging.toml`.
4. Apply `migrations/` to that database, including `0012_transport_evidence.sql`.
5. Deploy `wrangler.marmot-staging.toml` first so class `MarmotSender` exists. Its migration tag is `v1`.
6. Deploy `wrangler.staging.toml`. Its `MARMOT_SENDER` binding names script `nostr-watchdog-marmot-staging`.
7. Store `MARMOT_OPERATOR_TOKEN` on the operational Worker and `MARMOT_STORAGE_KEY` on the Marmot Worker. Do not put the storage key on the operational Worker.
8. Leave `WATCHDOG_ENABLED`, `ALERTS_ENABLED`, and `ENABLE_MARMOT` false until a deliberate activation.

Local counterparts are `wrangler.marmot-local.toml` and `wrangler.rust-local.toml`. The runtime suite config does not declare the binding, so the scheduled suite does not call the Durable Object.

That deploy is manual. GitHub Actions on this branch does not publish a Worker. Do not bind production secrets to either config.

Building the Worker requires the `wasm32-unknown-unknown` target and `worker-build` 0.9. Wrangler is a Node tool used only at deploy time.

## Resource notes

No production traffic was measured. The native check loop is one process, one SQLite file, and one HTTP client. It does not keep relay sockets open between alerts. Vendor checks run hourly and store the GitHub JSON they parsed, bounded by the existing 7-day upstream retention.

No Worker CPU sample exists. Local workerd has served health and the OpenMLS probe, and neither run was timed as a cost measurement. The TypeScript notes still apply to `main`: paid-plan cron CPU is required for gift-wrap work, and the free plan's 10 ms budget is not enough. The operational Worker does not embed the Marmot class. It binds the class exported by the dedicated Marmot Worker. That cost was not measured. The native helper debug binary was about 222 MB; that is an unoptimized debug build, not a release size.
