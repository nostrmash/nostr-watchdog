# Deployment

Do not deploy until you mean to. CI runs `wrangler deploy --dry-run` and does not publish. `pnpm deploy:staging` and `pnpm deploy:production` do publish.

## Plan

Use Cloudflare Workers Paid. As of 22 November 2026, the documented Cron Trigger CPU limits are:

| Plan                                          | Cron CPU                                                |
| --------------------------------------------- | ------------------------------------------------------- |
| Workers Free                                  | 10 ms                                                   |
| Workers Paid, cron interval under 1 hour      | 30 seconds default, up to 5 minutes via `limits.cpu_ms` |
| Workers Paid, cron interval of 1 hour or more | up to 15 minutes of CPU                                 |

Network time spent waiting on probes is not CPU time. This Worker sets `limits.cpu_ms` to 30000. A Workers-runtime test builds one gift wrap and expects it to finish in under 2 seconds. That is a budget, not a measured production CPU trace, and it is already more than the Free plan's 10 ms cron budget before D1 and a second project. The Free plan is not supported. Confirm the limit on the account you deploy to.

The minute cron is the uptime path. The hour cron is the only path that calls GitHub. One Worker and one D1 database per environment is the whole footprint. There is no queue, KV namespace, or second Worker.

## Databases

Create one database per environment and replace the placeholder ids in `wrangler.jsonc`.

```sh
wrangler d1 create nostr-watchdog
wrangler d1 create nostr-watchdog-staging
```

Put each returned `database_id` on the matching `d1_databases` entry. The top-level entry is local and development. `env.staging` is `nostr-watchdog-staging`. `env.production` is `nostr-watchdog`.

Apply migrations yourself. These commands talk to Cloudflare when you pass `--remote`:

```sh
pnpm migrate:local
wrangler d1 migrations apply nostr-watchdog-staging --env staging --remote
wrangler d1 migrations apply nostr-watchdog --env production --remote
```

`pnpm migrate:staging` and `pnpm migrate:production` are the same remote commands. They are not run by CI. `0002_hardening.sql` adds columns and replaces the one-open-incident index with one open incident per monitor and kind. `0003_vendor_checks.sql` adds `scheduler_runs.last_success_at` and the `vendor_checks` table. Both apply to an empty database and to a database that already has `0001_init.sql`. They do not delete rows. Apply `0003` before deploying the code that reads those columns. Do not run a migration twice by hand: D1 records applied migrations. The ids in `wrangler.jsonc` are placeholders until you paste the ids these commands return. Do not invent ids.

## Secrets and environments

Use a different sender key, operator token, and heartbeat secret in each environment so a test alert does not land in the production conversation.

```sh
wrangler secret put OPERATOR_TOKEN --env staging
wrangler secret put STATUS_READ_TOKEN --env staging
wrangler secret put SFS_BOT_NSEC --env staging
# repeat for every name in docs/configuration.md, then again for production
```

The `SFS_BOT_NSEC` name is a sample binding. Use the secret name declared by each project you keep. Local development reads `.dev.vars`, which is gitignored. Start from `.dev.vars.example`.

Set `ADMIN_NPUB`, `BOOTSTRAP_RELAYS`, and any URL vars in the environment you are deploying. Leave enable flags false on the first deploy. Turn one monitor on only after a manual request against the real URL matches the contract you configured.

## Deploy and roll back

```sh
pnpm build
pnpm deploy:staging
```

Deploy production only after staging has been checked:

```sh
pnpm deploy:production
```

To stop probes without deleting the Worker, set `WATCHDOG_ENABLED` to `false` and deploy again. To keep recording incidents but stop delivery, set `ALERTS_ENABLED` to `false`. `/v1/status` then reports `alerts_disabled` and returns HTTP 503. To stop one service, set its enable flag to `false`. A disabled monitor is skipped, and a skipped check does not close an open incident. Silence that incident from the operator route if reminders should stop.

`wrangler rollback --env staging` or `wrangler rollback --env production` restores the previous Worker version. It does not roll back D1 rows. Old outbox rows can still be delivered if they are `queued` or `retrying` and alerts are enabled.

## GitHub rate limit

The hour cron requests releases and advisories for each enabled monitor that names a vendor. Anonymous GitHub API usage is 60 requests per hour per origin. A 403 or 429 stores `x-ratelimit-reset` and the next run uses the cache until that time. Requests time out and stop at 256 KiB. Do not point the minute cron at the GitHub API. `GITHUB_TOKEN` is optional and should be a public-repo read token.

## An external checker

Run one HTTPS check from outside Cloudflare against `GET /v1/status`. Prefer `STATUS_READ_TOKEN` for that probe. It can read status and cannot acknowledge incidents, retry alerts, or send diagnostics. `OPERATOR_TOKEN` also works and should stay with the operator. Page when the response is not HTTP 200. That covers the Worker being unreachable, monitoring disabled, alerts disabled, no monitors enabled, a stale scheduler, a stale security-update cycle, dead letters, and missing alert configuration. A customer service being down does not by itself make this status non-200. `/healthz` only answers whether the isolate is up. Verifying `X-Watchdog-Signature` is optional and catches a proxy that replaces the body. This repository does not ship that second checker. A hosted uptime probe is enough. Do not point it at a customer service to test an outage.
