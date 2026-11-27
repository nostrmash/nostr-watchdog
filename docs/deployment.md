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

Run native Marmot in a dedicated two-account conversation. Keep membership and device provisioning stable while dispatch is enabled. Before changing a member, adding or removing a device, or re-onboarding, stop new dispatch and drain or fence the existing outbox. Verify the canonical roster, the original operation bindings and the active recipient token before resuming. The helper refuses a missing or unusable roster. Its separate roster check and upstream kind-9 submission leave a race if membership changes during a send. The pinned upstream membership-guarded custom API rejects reserved kind 9. The helper reports alert-specific native push publication as `unobservable`.

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

## Cloudflare production

| Component | Production configuration |
| --- | --- |
| Public operational Worker | `nostr-watchdog` at `https://nostr-watchdog.birwix.workers.dev`, managed by `wrangler.production.toml` |
| Operational storage | The existing `nostr-watchdog` D1 database through `DB` |
| Scheduled jobs | Checks and dispatch each minute, vendor updates each hour |
| Private cryptographic Worker | `nostr-watchdog-marmot`, managed by `wrangler.marmot-production.toml` |
| Private cryptographic storage | The SQLite-backed `MarmotSender` Durable Object class created by migration `v1` |

The operational manifest binds `MARMOT_SENDER` to the private script by name. Leave both `workers.dev` and preview URLs disabled on the private Worker, with no route or domain. Both Workers use the Paid account CPU budget of 30 seconds. Preserve the production monitor and recipient variables already attached to the operational Worker. Set project routing flags on that Worker so they survive subsequent deployments. `MARMOT_BOOTSTRAP_RELAYS` configures initial Marmot key-package discovery without changing the existing NIP-17 `BOOTSTRAP_RELAYS`.

### Build and deploy

Cloudflare Workers Builds watches `main`. Use `sh scripts/build-production-workers.sh --install-toolchain` as the build command and `npm run deploy:production` as the deploy command. The deploy command requires both built bundles, deploys the private Worker first, and records the Git commit on each Worker version. Leave branch previews disabled. GitHub Actions runs qualification on the integration branch and `main`.

For an explicitly authorized local deploy, install the pinned Rust toolchain and Wrangler dependencies, then use the same build and deploy scripts.

```bash
rustup target add wasm32-unknown-unknown
rustup component add llvm-tools
cargo install worker-build --version 0.9.0 --locked
pnpm install --frozen-lockfile
pnpm build:production
pnpm deploy:production
```

`wrangler.jsonc` and the TypeScript tree are retained for rollback reference and development. Their production environment belongs to the legacy deployment.

### First cutover and migrations

1. Record the active Worker version, deployment ID, routes, cron, settings, and D1 migration history. Export the production database to a protected location and verify a local restore. Retain the Time Travel bookmark alongside the export. Follow the compatibility and queue checks in [migration.md](migration.md).
2. Provision `nostr-watchdog-marmot` using the private manifest and a protected JSON file supplied through Wrangler's `--secrets-file`. Generate a strong `MARMOT_OPERATOR_TOKEN` and an independent 32-byte hex `MARMOT_STORAGE_KEY` once. Save them in the production recovery secret store. Bind the same internal token to the operational Worker and bind the storage key exclusively to the private Worker. Subsequent deployments inherit the secrets.
3. List the pending D1 migrations with `pnpm exec wrangler d1 migrations list DB --config wrangler.production.toml --remote`. Review the ledger and apply the expected pending files with `pnpm migrate:production`. The TypeScript cutover starts at `0005` and applies `0006` through `0012`. Apply any future schema changes before deploying a Worker that requires them.
4. Deploy the Rust Worker pair. Verify `/healthz`, `/readyz`, signed `/v1/status`, D1 bindings, scheduler freshness, and existing heartbeat integrations. Confirm the private Worker has no public access.
5. Onboard each project through the operational API with its existing sender and configured recipient, using a stable project-specific operation ID. Enable the project's Marmot route for scheduled synchronization and preserve working NIP-17 while acceptance is pending. Check Welcome acceptance, canonical member convergence, token readiness, and the last successful sync before relying on Marmot. Leave disabled destinations disabled. [WhiteNoise procedure](acceptance.md#cloudflare)

### Capacity and recovery

Watch `authority.storageCapacity` in the authenticated project diagnostics, including sealed state size, publication journal, retired operations, and the largest history bucket. Watch pending operation age and collect CPU, wall time, exceptions, and Durable Object storage from the production account. Preserve the same namespace and storage key throughout code rollbacks and redeployments. [Rollback procedure](migration.md#production-rollback)

## Isolated Cloudflare staging

These isolated manifests were used for release qualification and can be used for a separate rehearsal. Use dedicated project identities, a dedicated recipient, and staging-only operator and internal credentials.

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

Before deployment, verify the staging account and the two staging Worker names. Use the Workers Paid plan for the configured 30-second cron CPU budget. Use a new D1 database, the staging-only `MarmotSender` SQLite namespace, a generated sender for each enabled project, a dedicated WhiteNoise recipient and separate operational credentials. Keep distinct operational and internal bearer tokens. Share `MARMOT_OPERATOR_TOKEN` across the two Workers and put `MARMOT_STORAGE_KEY` on the private Marmot Worker only. Keep monitoring, alerts, NIP-17 and other destinations disabled until the scoped rehearsal. [Cloudflare Workers limits](https://developers.cloudflare.com/workers/platform/limits/)

1. Create a dedicated D1 database with `"$wrangler" d1 create nostr-watchdog-rust-staging`. Add its returned ID to a staging-only copy of `wrangler.staging.toml` as a `[[d1_databases]]` binding named `DB`. Set `database_name = "nostr-watchdog-rust-staging"` and `migrations_dir = "migrations"`. Keep the copy beside the repository manifests.
2. Apply the D1 migrations with `"$wrangler" d1 migrations apply nostr-watchdog-rust-staging --remote --config <staging-copy>`. Confirm all 12 ordered migrations are applied, from `0001_init.sql` through `0012_transport_evidence.sql`.
3. Deploy the private worker with `"$wrangler" deploy --config wrangler.marmot-staging.toml`. Its `v1` migration creates the SQLite-backed `MarmotSender` class. Leave `workers_dev = false` and assign no public route.
4. Install the internal `MARMOT_OPERATOR_TOKEN` on the Marmot Worker with `wrangler secret put`. The Marmot Worker also needs a distinct, randomly generated 32-byte `MARMOT_STORAGE_KEY` encoded as hex. Store it on that Worker only. Use the Wrangler prompt so the value stays out of command history.
5. Deploy the operational Worker from the staging copy with `WATCHDOG_ENABLED`, `ALERTS_ENABLED`, and `ENABLE_MARMOT` false. Its `MARMOT_SENDER` binding must name `nostr-watchdog-marmot-staging`. Install the same internal `MARMOT_OPERATOR_TOKEN`, the operational `OPERATOR_TOKEN`, `SFS_BOT_NSEC` for SmartFlowSocial or `NOSTRMASH_BOT_NSEC` for NostrMash, and the selected project's authorized `PROJECT_RECIPIENTS` entry. Set `BOOTSTRAP_RELAYS` for the staging experiment. Use explicit project overrides to leave unused projects disabled.
6. Call the authenticated `POST /v1/diagnostics/marmot/onboard` with the selected `projectId` and a durable `operationId`. Activate the scoped Marmot route with alerts kept off. For a SmartFlowSocial-only rehearsal, set `NOTIFY_SMARTFLOWSOCIAL_MARMOT=true` and leave the global Marmot default and the NostrMash route disabled. Check `GET /v1/diagnostics/marmot?project=<id>` for authenticated binding, Welcome acceptance, recipient participation and token readiness.
7. Enable alerts for the controlled test, send one authenticated `POST /v1/diagnostics/test-alert` for the project with `transport=marmot`, and check the returned outbox ID. After the controlled test, enable one monitor and scheduled operation. Verify scheduler freshness and inspect the actual staging D1 row, Worker metrics, and Durable Object recovery before expanding the rehearsal.

Use the same staging D1 database and Durable Object namespace when exercising Worker version rollback. First disable monitoring and new alerts with `WATCHDOG_ENABLED=false` and `ALERTS_ENABLED=false`. Set `EMERGENCY_DISABLE_MARMOT=true` when delivery must stop immediately. Check the disposition of any in-flight operations before changing versions. Roll back the operational Worker to its previous reviewed version with `wrangler rollback <version-id> --config <staging-copy>`. Roll back the cryptographic Worker only to a version that understands the persisted snapshot and history format. Preserve the Durable Object namespace and avoid restoring older snapshots or destructive D1 schema changes during a code rollback. Keep delivery disabled if the previous version cannot open the current cryptographic state.

### Capacity and staging measurements

Collect authenticated `GET /v1/diagnostics/marmot?project=<id>` samples at onboarding, after each controlled send and after a restart. Record usage, limits, `authority.storageCapacity.warnings`, the retired-operation count, the peak history bucket and the age and acceptance of pending outbox rows. Confirm clean recovery and unchanged operation IDs. Record remote Worker wall time, CPU time, platform memory-limit errors, Durable Object storage and remote D1 convergence using the staging account observability and usage data. Record available platform limits and the deployed version alongside the samples. Local process RSS cannot establish remote isolate headroom.

Investigate any rising warning before enabling more traffic. A journal target warning during settled traffic can be normal. Growth toward the hard journal limit calls for reconciling unresolved publication and trigger evidence. Sustained growth in persisted state or a history bucket calls for planned rotation. Stop new Marmot dispatch and finish or quarantine existing outbox rows with their original identity and receipts. Keep the old account, operation history, encryption key and backup together and available for reconciliation. After owner authorization, use a fresh generated sender in a fresh namespace, onboard the dedicated recipient, verify readiness and resume with new operations. Leave old outbox rows fenced to their original identity. Preserve the existing namespace and its history when rolling back application code.

### Local reproduction

Start both actual Workers in one Wrangler invocation to resolve the cross-script namespace. The first configuration is the operational front door. The controlled integration test creates its own config copies, generates identities, applies the migrations, opens an incident, and verifies relay events from an independent recipient. [Cloudflare multi-Worker development](https://developers.cloudflare.com/workers/local-development/multi-workers/)

```bash
"$wrangler" dev -c wrangler.rust-local.toml -c wrangler.marmot-local.toml
```

The recorded uncompressed bundles are below the documented 64 MiB Worker size limit. Confirm the staging account supports the configured cron CPU budget. Measure startup time, isolate memory, CPU, remote D1 convergence, and recovery in the staging account. Local workerd evidence is recorded with the qualification results. [Cloudflare Workers limits](https://developers.cloudflare.com/workers/platform/limits/) · [Integration evidence](integration.md)
