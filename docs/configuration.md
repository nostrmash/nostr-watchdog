# Configuration

Non-secret settings live in `wrangler.jsonc` `vars`. Secrets are bound with `wrangler secret put` and, locally, `.dev.vars`. Wrangler does not inherit `vars` into named environments, so the top-level environment, `staging`, and `production` each carry a full copy.

Placeholder D1 ids in `wrangler.jsonc` must be replaced with the ids from `wrangler d1 create` before any remote command. See [deployment.md](deployment.md).

After changing `wrangler.jsonc`, regenerate types:

```sh
pnpm cf-typegen
```

## Projects

A project is an id, a display name, a contact name, and the name of the secret that holds its sender `nsec`. Define it in `src/config/projects.ts`. Alerts from different projects use different keys, so a messenger shows them as different chats.

The recipient is `ADMIN_NPUB`, unless `PROJECT_RECIPIENTS` contains a value for that project id. Values are `npub` or 64-character hex. Invalid JSON in `PROJECT_RECIPIENTS` disables delivery for every project, even when `ADMIN_NPUB` is set.

`BOOTSTRAP_RELAYS` is a comma-separated list of `wss://` URLs used only to read kind `10050`. The recipient publishes kind `10050` with `relay` tags for the inboxes that should receive gift wraps. This Worker does not fall back to kind `10002` relays.

Generate one sender identity per project. The command prints an `nsec`. Paste it only into `wrangler secret put` or `.dev.vars`, then clear the terminal scrollback.

```sh
pnpm exec node --input-type=module -e '
import { generateSecretKey, getPublicKey } from "nostr-tools/pure";
import { nsecEncode, npubEncode } from "nostr-tools/nip19";
const key = generateSecretKey();
console.log("npub", npubEncode(getPublicKey(key)));
console.log("nsec", nsecEncode(key));
'
```

Publish the `npub` under the project's contact name. Some clients hide messages from unknown senders. Do not reuse a wallet seed, a personal key, or an application's signing key.

The sample projects bind `SFS_BOT_NSEC` and `NOSTRMASH_BOT_NSEC`. Those names are only the current sample bindings. When you replace the samples, change `secrets.required` to the secret names you actually use.

## Monitors

A monitor has an id, a project, a kind, a display name, an enable flag, an interval, failure and recovery thresholds, a severity, and either an HTTP contract, a heartbeat id, or a vendor adapter. Add it in `src/config/monitors.ts` and add its enable flag and URL vars to every Wrangler environment.

HTTP checks require an expected path, expected statuses, and JSON predicates. HTTP 200 by itself is not success. Heartbeat ids must match a key in `HEARTBEAT_KEYS`.

The tree ships sample monitors with every enable flag set to `false`. Their URLs are empty. An empty URL is `misconfigured`, not healthy. Replace the samples before you enable anything.

## Secrets

| Name                           | When you need it               | Purpose                                                                                  |
| ------------------------------ | ------------------------------ | ---------------------------------------------------------------------------------------- |
| `OPERATOR_TOKEN`               | operator routes                | Bearer token for diagnostics, status, silence, and ack                                   |
| `STATUS_READ_TOKEN`            | `GET /v1/status` only          | Optional bearer for an external uptime check. It cannot ack, retry, or send a test alert |
| `READ_GATEWAY_HEALTH_TOKEN`    | deep read-gateway probe        | Sent only to that monitor's URL. Leave empty while the deep monitor is disabled          |
| `PUBLISH_GATEWAY_HEALTH_TOKEN` | deep publish-gateway probe     | Separate from the read token and from the gateway's publish API token                    |
| `STATUS_SIGNING_SECRET`        | a signed status body           | HMAC key for `X-Watchdog-Signature` on `GET /v1/status`                                  |
| sender `nsec` bindings         | sending for that project       | Dedicated bot key. One binding per project                                               |
| `HEARTBEAT_KEYS`               | a heartbeat monitor is enabled | JSON object of monitor id to a secret of at least 32 characters                          |
| `HEARTBEAT_KEYS_PREVIOUS`      | key rotation                   | Same shape. Use `{}` when nothing is rotating                                            |
| `ALBY_AUTH_TOKEN`              | an `alby_hub` monitor          | Read-only Hub JWT. Empty until then                                                      |
| `BTCPAY_API_KEY`               | version and processor detail   | Separate read-only Greenfield key. Empty skips server info                               |
| `TELEGRAM_BOT_TOKEN`           | Telegram                       | Bot token. Empty disables Telegram                                                       |
| `TELEGRAM_CHAT_IDS`            | Telegram                       | JSON object of project id to a numeric chat id                                           |
| `GITHUB_TOKEN`                 | optional                       | Raises the GitHub API rate limit. Empty uses the anonymous limit                         |

`secrets.required` makes Wrangler refuse to start when a name is missing. An empty value is still present. Heartbeats fail closed when `HEARTBEAT_KEYS` is empty. Vendor calls that need a token report `misconfigured` instead of healthy.

Generate heartbeat secrets with `openssl rand -base64 32`. The JSON keys are monitor ids:

```json
{ "worker-loop": "replace-with-a-random-string-at-least-32-chars" }
```

Rotation: copy the current JSON to `HEARTBEAT_KEYS_PREVIOUS`, put the new JSON in `HEARTBEAT_KEYS`, deploy, restart the emitters, then set the previous secret back to `{}`. Both keys verify during the overlap. A secret shorter than 32 characters is rejected.

## Schedule and thresholds

| Var                          | Default                  | Meaning                                                                                             |
| ---------------------------- | ------------------------ | --------------------------------------------------------------------------------------------------- |
| `WATCHDOG_ENABLED`           | `true`                   | `false` skips both crons                                                                            |
| `ALERTS_ENABLED`             | `true`                   | `false` still stores incidents and outbox rows, and does not deliver them. A test alert still sends |
| `CHECK_CONCURRENCY`          | `4`                      | Parallel probes, clamped to 1–6                                                                     |
| `CHECK_TIMEOUT_MS`           | `5000`                   | Per request, clamped to 1–15 seconds                                                                |
| `FAILURE_THRESHOLD`          | empty                    | Empty uses each monitor's own threshold, which defaults to 2                                        |
| `RECOVERY_THRESHOLD`         | empty                    | Empty uses 2                                                                                        |
| `CRITICAL_REMINDER_SECONDS`  | `0`                      | `0` disables reminders. Otherwise the gap between critical outage reminders                         |
| `UNKNOWN_THRESHOLD`          | `5`                      | Consecutive `unknown` samples before one monitoring-integrity warning. Clamped to 2–100             |
| `DELIVERY_CLAIM_MS`          | `120000`                 | Outbox claim lease. Clamped to 30–300 seconds. Extended again before publish                        |
| `SCHEDULER_STALE_SECONDS`    | `180`                    | Age of the last check cycle before `/v1/status` becomes degraded. Three times that is unhealthy     |
| `RELAY_LIST_TTL_SECONDS`     | `3600`                   | Kind 10050 cache lifetime                                                                           |
| `HEARTBEAT_MAX_SKEW_SECONDS` | `300`                    | Accepted clock skew for signed heartbeats                                                           |
| `HEARTBEAT_STALE_SECONDS`    | `180`                    | Age after which a heartbeat or loop timestamp is down                                               |
| `HEARTBEAT_PROGRESS_SECONDS` | `600`                    | A non-idle heartbeat with unchanged progress becomes degraded                                       |
| `TELEGRAM_CRITICAL_MODE`     | `dual`                   | `dual` or `nostr_fallback`                                                                          |
| `PRIVATE_NETWORK_PROFILE`    | `false`                  | `true` allows HTTP and private addresses. Leave this false for public probes                        |
| `RUNBOOK_BASE_URL`           | empty                    | HTTPS origin prepended to each monitor's runbook path                                               |
| `GITHUB_API_BASE`            | `https://api.github.com` | Only `api.github.com` or a `*.github.com` HTTPS host is accepted                                    |

## Alby Hub

`ALBY_ROUTING_PROFILE` is `self_hosted` or `alby_cloud`.

- Self-hosted: `ALBY_BASE_URL` is that hub's origin. `https://my.albyhub.com` is rejected unless the profile is `alby_cloud`.
- Cloud: profile `alby_cloud`, base URL `https://my.albyhub.com`, `ALBY_HUB_NAME` set, and `ALBY_HUB_REGION` set when the hub is not in the default region. The Worker sends `AlbyHub-Name` and, when set, `AlbyHub-Region`.

`ALBY_AUTH_TOKEN` must be a read-only JWT from `hub-cli unlock --permission readonly`. Do not use a wallet password, mnemonic, full-access JWT, or an NWC connection string. Without the token, a successful info response is still `misconfigured`. Redirects are not followed.

- The API is unreachable: `down`.
- HTTP 401 or 403 on health or node status: `misconfigured`.
- The node is not running or not ready: `degraded`, not a host-down outage.
- Known channel, relay, subscription, or service alarms: `degraded`.
- An unrecognized alarm or a body that does not match the schema: `unknown`.

The adapter does not log node internals.

## BTCPay Server

`GET /api/v1/health` is called without a key. `synchronized: true` and no key is `degraded` with `coverage_incomplete`: the public endpoint answered, and version and processor status were not checked. `synchronized: false` is degraded. A public-only check is not full monitoring.

With `BTCPAY_API_KEY`, the Worker also calls `GET /api/v1/server/info`. Create that key as its own read-only credential. Do not reuse a key that can create invoices or move funds.

- 401 or 403 on server info: `misconfigured`. The instance may still be up.
- `fullySynched: false`: degraded.
- A payment processor reported unavailable: degraded.
- Redirects are not followed. The check never creates an invoice.
