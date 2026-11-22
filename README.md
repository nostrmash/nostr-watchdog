# Nostr Watchdog

[![CI](https://github.com/nostrmash/nostr-watchdog/actions/workflows/ci.yml/badge.svg)](https://github.com/nostrmash/nostr-watchdog/actions/workflows/ci.yml)
[![License: Unlicense](https://img.shields.io/badge/license-Unlicense-blue)](LICENSE)
[![Node 26.13.1+](https://img.shields.io/badge/node-26.13.1%2B-339933?logo=node.js&logoColor=white)](https://nodejs.org/)
[![pnpm](https://img.shields.io/badge/maintained%20with-pnpm-cc00ff.svg)](https://pnpm.io/)

Nostr Watchdog is an independent Cloudflare Worker. It probes the services you configure and sends encrypted [NIP-17](https://github.com/nostr-protocol/nips/blob/master/17.md) messages to an operator. Each project uses its own sender key, so alerts arrive as separate conversations. Critical alerts can also go to Telegram.

It does not host a dashboard, accounts, or payments. The applications you monitor keep running when this Worker is down. This Worker does not publish or cache their Nostr traffic.

Every monitor ships disabled. A check runs only after you set its endpoint or credential and turn its enable flag on.

## Contents

- [Requirements](#requirements)
- [Quick start](#quick-start)
- [Checks](#checks)
- [Development](#development)
- [Documentation](#documentation)
- [Contributing](#contributing)
- [License](#license)

## Requirements

- Node.js 26.13.1 or newer (`.nvmrc`)
- pnpm 12.21.0
- A Cloudflare Workers **Paid** plan. Cron Triggers on the Free plan stop at 10 ms of CPU. Gift-wrap work already exceeds that budget. See [docs/deployment.md](docs/deployment.md).

## Quick start

```bash
pnpm install
cp .dev.vars.example .dev.vars
pnpm migrate:local
pnpm dev
```

Leave secret values empty until you send a test alert. `GET /healthz` is liveness only. Operator routes fail closed until `OPERATOR_TOKEN` is set.

```bash
curl -sS http://127.0.0.1:8787/healthz
```

## Checks

| Kind               | What it decides                                                                               |
| ------------------ | --------------------------------------------------------------------------------------------- |
| `http_json`        | HTTPS GET against an allowlisted URL, expected path, status, and JSON fields                  |
| `signed_heartbeat` | A process reports that its own job loop is alive. HTTP 200 from a web app is not a substitute |
| `alby_hub`         | Read-only Alby Hub info, health, and node status                                              |
| `btcpay`           | BTCPay Greenfield health, and server info when a separate read-only key is set                |

Add a project, a sender secret, and monitors in `src/config/` without changing the check loop, incident rules, or delivery code. Live URLs and keys stay in Wrangler vars and secrets.

## Development

```bash
pnpm validate
pnpm test
pnpm test:unit
pnpm test:integration
pnpm test:security
pnpm test:coverage
pnpm build
```

`pnpm validate` checks formatting, lint, and types. `pnpm build` bundles with `wrangler deploy --dry-run` and does not deploy. `pnpm check` runs validate, the full test suite, coverage, and the dry-run build.

Husky runs lint-staged before each commit.

## Documentation

| Document                                       | What it covers                                                |
| ---------------------------------------------- | ------------------------------------------------------------- |
| [docs/README.md](docs/README.md)               | Index                                                         |
| [docs/architecture.md](docs/architecture.md)   | Check loop, D1 state, incidents, and NIP-17 delivery          |
| [docs/configuration.md](docs/configuration.md) | Projects, monitors, secrets, and thresholds                   |
| [docs/deployment.md](docs/deployment.md)       | Plan, D1, environments, deploy, and rollback                  |
| [docs/operations.md](docs/operations.md)       | Routes, test alerts, and the rollout checklist                |
| [docs/security.md](docs/security.md)           | SSRF limits, credentials, heartbeats, and dependency licenses |
| [docs/integrations.md](docs/integrations.md)   | How any application exposes readiness and a signed heartbeat  |
| [CONTRIBUTING.md](CONTRIBUTING.md)             | Local checks and pull requests                                |
| [SECURITY.md](SECURITY.md)                     | How to report a vulnerability                                 |

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

[Unlicense](LICENSE). Bundled dependencies keep their own licenses. See [docs/security.md](docs/security.md).
