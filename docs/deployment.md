# Deployment

The Rust watchdog runs as a native executable or as an operational Cloudflare Worker. Both can send through Marmot, NIP-17, or Telegram according to the project's routing policy. The native process uses a separate MDK helper. Cloudflare uses the private `MARMOT_SENDER` Durable Object namespace on the dedicated Marmot Worker.

## Native process

```bash
export ODIN="$HOME/.local/odin-dev-2026-10/odin"
"$ODIN" version
cargo build --locked --release -p watchdog-native
cargo build --locked --release --manifest-path crates/watchdog-marmot/Cargo.toml
```

Use Odin `dev-2026-10` revision `84bc3fc`. Configure `DATABASE_PATH`, `LISTEN_ADDR`, `MARMOT_HELPER`, and `MARMOT_ROOT`. The watchdog accepts a `WATCHDOG_CONFIG` TOML file with a `[vars]` table. Environment variables override the file. Keep configuration files containing credentials mode `0600`.

```toml
[vars]
WATCHDOG_ENABLED = "false"
ALERTS_ENABLED = "false"
ENABLE_MARMOT = "false"
ENABLE_NIP17 = "false"
DATABASE_PATH = "/var/lib/nostr-watchdog/watchdog.sqlite"
MARMOT_HELPER = "/usr/local/bin/watchdog-marmot"
MARMOT_ROOT = "/var/lib/nostr-watchdog/marmot"
```

Set the project sender and recipient, complete onboarding, and check the authenticated Marmot diagnostics before enabling monitors and alerts. `/healthz` is process liveness. `/readyz` checks operational storage, scheduler progress, and required transport state. Native Marmot diagnostics can report token availability, group membership, and the helper's upstream publication limits.

SIGINT and SIGTERM stop the scheduler, allow active work to drain for up to 25 seconds, release owned claims, and signal the helper. A systemd service should use a dedicated account, a protected environment file, and `TimeoutStopSec=30` or longer.

### Backup and recovery

Use SQLite's online backup API for the operational database or stop the process before copying it. Back up the helper's SQLCipher database and journal together while the helper is stopped. The watchdog's SQLite backup contains incidents, heartbeats, and outbox metadata. The helper's state is needed to restore an MLS conversation.

After state loss or a point-in-time restore, suspend Marmot delivery until the original state and operation history are reconciled. Treat a complete rollback as an operator recovery event. A fully rolled-back database can carry internally consistent old metadata. If recovery cannot prove the live epoch and the original operation identities, quarantine affected outbox rows and onboard a fresh sender, group, and storage namespace.

### Docker

```bash
docker build --platform linux/amd64 -t nostr-watchdog:local .
docker run --rm -p 127.0.0.1:8787:8787 -v watchdog-data:/data \
  --env-file /path/to/isolated-watchdog.env nostr-watchdog:local
```

The shipped image supports Linux amd64. It runs as UID 10001 with `/data/watchdog.sqlite`, `/data/marmot`, and the helper at `/usr/local/bin/watchdog-marmot`. Keep the same volume when replacing a container. Keep these paths together for backup and recovery. Odin and the Rust toolchain stay in build stages. The optional `image-test-driver` stage builds the independent MDK qualification driver used in CI.

## Isolated Cloudflare staging

Provisioning and deploying staging requires owner authorization. Use dedicated project identities, a dedicated recipient, and staging-only operator and internal credentials. The existing TypeScript deployment continues to use `wrangler.jsonc`.

### Build and dry-run

```bash
rustup target add wasm32-unknown-unknown
cargo install worker-build --version 0.9.0 --locked
npm ci --prefix crates/watchdog-marmot-worker/worker
worker-build --release crates/watchdog-worker -- --locked
sh crates/watchdog-marmot-worker/worker/build-release.sh
wrangler="$PWD/crates/watchdog-marmot-worker/worker/node_modules/.bin/wrangler"
"$wrangler" deploy --config wrangler.marmot-staging.toml --dry-run --outdir /tmp/watchdog-marmot-staging
"$wrangler" deploy --config wrangler.staging.toml --dry-run --outdir /tmp/watchdog-operational-staging
```

The operational bundle lives under `crates/watchdog-worker/build/worker`. The Marmot bundle lives under `crates/watchdog-marmot-worker/worker/build/worker`. Both staging manifests point at those entry points.

### Provision and deploy after authorization

1. Create a dedicated D1 database with `"$wrangler" d1 create nostr-watchdog-rust-staging`. Add its returned ID to a staging-only copy of `wrangler.staging.toml` as a `[[d1_databases]]` binding named `DB`. Set `database_name = "nostr-watchdog-rust-staging"` and `migrations_dir = "migrations"`. Keep the copy beside the repository manifests.
2. Apply the D1 migrations with `"$wrangler" d1 migrations apply nostr-watchdog-rust-staging --remote --config <staging-copy>`. Confirm the deployed schema includes `0012_transport_evidence.sql`.
3. Deploy the private worker with `"$wrangler" deploy --config wrangler.marmot-staging.toml`. Its `v1` migration creates the SQLite-backed `MarmotSender` class. Leave `workers_dev = false` and assign no public route.
4. Install the internal `MARMOT_OPERATOR_TOKEN` on the Marmot Worker with `wrangler secret put`. The Marmot Worker also needs a distinct, randomly generated 32-byte `MARMOT_STORAGE_KEY` encoded as hex. Store it on that Worker only. Use the Wrangler prompt so the value stays out of command history.
5. Deploy the operational Worker from the staging copy with `WATCHDOG_ENABLED`, `ALERTS_ENABLED`, and `ENABLE_MARMOT` false. Its `MARMOT_SENDER` binding must name `nostr-watchdog-marmot-staging`. Install the same internal `MARMOT_OPERATOR_TOKEN`, the operational `OPERATOR_TOKEN`, the staging sender secret for the selected project, and its authorized `PROJECT_RECIPIENTS` entry. Set `BOOTSTRAP_RELAYS` for the staging experiment. Use explicit project overrides to leave unused projects disabled.
6. Call the authenticated `POST /v1/diagnostics/marmot/onboard` with the selected `projectId` and a durable `operationId`. Activate the scoped Marmot route with alerts kept off. Check `GET /v1/diagnostics/marmot?project=<id>` for authenticated binding, Welcome acceptance, recipient participation and token readiness.
7. Enable alerts for the controlled test, send one authenticated `POST /v1/diagnostics/test-alert` for the project with `transport=marmot`, and check the returned outbox ID. After the controlled test, enable one monitor and scheduled operation. Verify scheduler freshness and inspect the actual staging D1 row, Worker metrics, and Durable Object recovery before expanding the rehearsal.

Use the same staging D1 database and Durable Object namespace when exercising Worker version rollback. First set the emergency Marmot switch or disable alerts. Roll back the operational Worker to its previous reviewed version with `wrangler rollback <version-id> --config <staging-copy>`. Roll back the cryptographic Worker only to a version that understands the persisted snapshot and history format. Preserve the Durable Object namespace and avoid restoring older snapshots or destructive D1 schema changes during a code rollback. Keep delivery disabled if the previous version cannot open the current cryptographic state.

### Local reproduction

Start both actual Workers in one Wrangler invocation to resolve the cross-script namespace. The first configuration is the operational front door. The controlled integration test creates its own config copies, generates identities, applies the migrations, opens an incident, and verifies relay events from an independent recipient. [Cloudflare multi-Worker development](https://developers.cloudflare.com/workers/local-development/multi-workers/)

```bash
"$wrangler" dev -c wrangler.rust-local.toml -c wrangler.marmot-local.toml
```

Measure startup time, isolate memory, CPU, remote D1 convergence, and recovery in the actual staging account. Local workerd measurements belong to the local evidence in [integration.md](integration.md).
