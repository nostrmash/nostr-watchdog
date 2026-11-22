# Contributing

## Before you start

- Node.js 26.13.1 or newer (`.nvmrc`) and pnpm 12.21.0.
- `pnpm install`
- Run validation and tests before opening a pull request.

Do not commit `.dev.vars`, sender keys, wallet material, or live API tokens. `.dev.vars.example` stays empty.

## Checks

```bash
pnpm validate
pnpm test
pnpm test:unit
pnpm test:integration
pnpm test:security
pnpm test:coverage
pnpm build
```

`pnpm validate` runs Prettier, ESLint, and TypeScript. `pnpm build` is a Wrangler dry-run and does not deploy.

`pnpm format` and `pnpm lint:fix` apply the automatic fixes. Husky runs lint-staged on commit after `pnpm install` (`pnpm prepare`).

## Tests

Tests run inside the Workers runtime with a local D1. External APIs are mocked. Suites:

- `tests/unit` for pure checks, versions, incidents, and NIP-17 construction
- `tests/integration` for D1 cycles, delivery, heartbeats, and the scheduled entry
- `tests/security` for URL policy, redaction, and operator-route authentication

Keep new tests deterministic. Do not call live relays, wallet APIs, or production hosts.

`pnpm test:coverage` enforces a floor of 74% statements, 68% branches, 85% functions, and 80% lines. Those numbers are the regression gate for this Worker. Raise them when new tests cover more of `src/http/app.ts` and the vendor adapters.

## Pull requests

1. Branch from `main`.
2. Describe what changed and why.
3. Update `docs/` when behavior or configuration changes.
4. Wait for CI: validate and the production dependency audit, unit, integration, and security tests, coverage, and the dry-run build. The secret scan is a separate workflow.

## Code

- TypeScript strict mode. Read configuration through the helpers in `src/runtime.ts`.
- A new monitor kind returns the same `CheckResult` as the existing probes.
- Do not log vendor response bodies or put credentials in alerts.
- The Unlicense file stays unchanged.
