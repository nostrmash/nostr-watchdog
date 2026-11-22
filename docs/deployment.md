# Deployment

Do not deploy until you mean to. CI runs `wrangler deploy --dry-run` and does not publish. `pnpm deploy:staging` and `pnpm deploy:production` do publish.

## Plan

Use Cloudflare Workers Paid. As of 22 November 2026, the documented Cron Trigger CPU limits are:

| Plan                                          | Cron CPU                                                |
| --------------------------------------------- | ------------------------------------------------------- |
| Workers Free                                  | 10 ms                                                   |
| Workers Paid, cron interval under 1 hour      | 30 seconds default, up to 5 minutes via `limits.cpu_ms` |
| Workers Paid, cron interval of 1 hour or more | up to 15 minutes of CPU                                 |

Network time spent waiting on probes is not CPU time. This Worker sets `limits.cpu_ms` to 30000. A local Node measurement of `nostr-tools` `wrapEvent` was about 6.6 ms per gift wrap after one warmup call. That number is not a Cloudflare trace. It is already most of the Free plan's 10 ms cron budget before D1, JSON, and a second project are included, so the Free plan is not supported. Confirm the limit on the account you deploy to.

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

`pnpm migrate:staging` and `pnpm migrate:production` are the same remote commands. They are not run by CI.

## Secrets and environments

Use a different sender key, operator token, and heartbeat secret in each environment so a test alert does not land in the production conversation.

```sh
wrangler secret put OPERATOR_TOKEN --env staging
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

To stop probes without deleting the Worker, set `WATCHDOG_ENABLED` to `false` and deploy again. To keep recording incidents but stop delivery, set `ALERTS_ENABLED` to `false`. To stop one service, set its enable flag to `false`. A disabled monitor is skipped, and a skipped check does not close an open incident. Silence that incident from the operator route if reminders should stop.

`wrangler rollback --env staging` or `wrangler rollback --env production` restores the previous Worker version. It does not roll back D1 rows. Old outbox rows can still be delivered if they are `queued` or `retrying` and alerts are enabled.

## GitHub rate limit

The hour cron requests releases and advisories for each enabled monitor that names a vendor. Anonymous GitHub API usage is 60 requests per hour per origin. A 403 or 429 stores `x-ratelimit-reset` and the next run uses the cache until that time. Do not point the minute cron at the GitHub API. `GITHUB_TOKEN` is optional and should be a public-repo read token.
