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

`wrangler.staging.toml` is the only Wrangler config for this branch's Worker. The existing `wrangler.jsonc` belongs to the TypeScript Worker. Do not deploy it from this branch over the production name.

```bash
npx wrangler d1 create nostr-watchdog-rust-staging
```

Put the new database id into `wrangler.staging.toml`. Leave the production id alone. Then:

```bash
npx wrangler deploy --config wrangler.staging.toml
```

That deploy is manual. GitHub Actions on this branch does not publish a Worker. The staging config has not been deployed. A local workerd process has served health and readiness from `wrangler.rust-local.toml`. Do not bind production secrets to either config.

Building the Worker requires the `wasm32-unknown-unknown` target and `worker-build` 0.9. Wrangler is a Node tool used only at deploy time.

## Resource notes

No production traffic was measured. The native check loop is one process, one SQLite file, and one HTTP client. It does not keep relay sockets open between alerts. Vendor checks run hourly and store the GitHub JSON they parsed, bounded by the existing 7-day upstream retention.

No Worker CPU sample exists. Local workerd has served health and the OpenMLS probe, and neither run was timed as a cost measurement. The TypeScript notes still apply to `main`: paid-plan cron CPU is required for gift-wrap work, and the free plan's 10 ms budget is not enough. The watchdog Worker does not construct a Durable Object. The OpenMLS probe does, and that cost was not measured. The native helper debug binary was about 222 MB; that is an unoptimized debug build, not a release size.
