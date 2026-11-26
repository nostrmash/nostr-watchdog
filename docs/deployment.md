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

`GET /healthz` returns 200 when the process is up. `GET /readyz` returns 200 when SQLite answers.

Stop the process with SIGINT. The current minute's probes finish or are dropped when the runtime shuts down. State that was committed stays in SQLite. On the next start the outbox claim leases expire and those rows can be claimed again. Stored gift wraps are reused.

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

The image runs as uid 10001 and keeps the database on `/data`. It does not include Node.js. It does not contact Cloudflare.

## Cloudflare staging

`wrangler.staging.toml` is the only Wrangler config for this branch's Worker. The existing `wrangler.jsonc` belongs to the TypeScript Worker. Do not deploy it from this branch over the production name.

```bash
npx wrangler d1 create nostr-watchdog-rust-staging
```

Put the new database id into `wrangler.staging.toml`. Leave the production id alone. Then:

```bash
npx wrangler deploy --config wrangler.staging.toml
```

That deploy is manual. GitHub Actions on this branch does not publish a Worker. The staging Worker code can run checks when D1 and the monitor variables are bound. This branch has not deployed it and has not executed it in `workerd`. Do not bind production secrets to it.

Building the Worker requires the `wasm32-unknown-unknown` target and `worker-build` 0.9. Wrangler is a Node tool used only at deploy time.

## Resource notes

No production traffic was measured. The native check loop is one process, one SQLite file, and one HTTP client. It does not keep relay sockets open between alerts. Vendor checks run hourly and store the GitHub JSON they parsed, bounded by the existing 7-day upstream retention.

No Worker CPU sample exists. The crate type-checks for wasm and has not been timed inside `workerd`. The TypeScript notes still apply to `main`: paid-plan cron CPU is required for gift-wrap work, and the free plan's 10 ms budget is not enough. MLS on the Worker is not linked, so there is no Durable Object cost to report. The native helper debug binary was about 222 MB; that is an unoptimized debug build, not a release size.
