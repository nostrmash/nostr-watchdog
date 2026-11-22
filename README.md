# Nostr Watchdog

Nostr Watchdog is a standalone Cloudflare Worker that checks the services you configure and sends encrypted [NIP-17](https://github.com/nostr-protocol/nips/blob/master/17.md) messages to an operator. SmartFlowSocial and NostrMash each have their own sender key, so the alerts arrive as two conversations. Critical alerts can also go to Telegram. There is no dashboard, subscription service, or payment flow.

The Worker is an independent failure domain. The applications it watches keep running when the watchdog is down, and this project does not replace customer notification code in those applications.

Every shipped monitor is **disabled**. A check becomes live only after you set its URL or credential and flip its `ENABLE_*` var to `true`. An empty URL is a configuration error, not a successful check.

## Requirements

- Node.js 22 or newer
- pnpm 12
- A Cloudflare Workers **Paid** plan. Cron Triggers on the Free plan stop at 10 ms of CPU. Building one NIP-17 gift wrap took about 7 ms locally on Node 24, before D1 and JSON work, so the Free plan is not a supported target. See [docs/deployment.md](docs/deployment.md).

## Scripts

| Script               | What it does                                                  |
| -------------------- | ------------------------------------------------------------- |
| `pnpm dev`           | `wrangler dev` against the local Worker                       |
| `pnpm test`          | Vitest inside the Workers runtime, with a local D1            |
| `pnpm typecheck`     | Typecheck `src` and `tests`                                   |
| `pnpm lint`          | ESLint                                                        |
| `pnpm format`        | Prettier write                                                |
| `pnpm migrate:local` | Apply D1 migrations to the local database                     |
| `pnpm build`         | Bundle with `wrangler deploy --dry-run`. This does not deploy |
| `pnpm check`         | Typecheck, lint, format check, test, and dry-run bundle       |

`pnpm deploy:staging` and `pnpm deploy:production` deploy. They are not part of `pnpm check` or CI. Do not run them until the placeholder D1 database ids in `wrangler.jsonc` have been replaced and you intend to deploy.

## Layout

`src/index.ts` is the fetch and scheduled entry. Checks, release tracking, NIP-17 and Telegram delivery, D1 state, and request authentication live in the directories next to it. Monitor templates are in `src/config/monitors.ts`. SQL migrations are in `migrations/`. Operator documentation is in `docs/`.

## First local run

```sh
pnpm install
cp .dev.vars.example .dev.vars
pnpm migrate:local
pnpm dev
```

Leave secret values empty until you are ready to send a test alert. `GET /healthz` returns liveness without reading D1. Operational routes fail closed until `OPERATOR_TOKEN` is set.

Read [docs/configuration.md](docs/configuration.md) before putting a key in `.dev.vars`, and [docs/operations.md](docs/operations.md) for the rollout checklist.
