# Configuration

Non-secret settings live in `wrangler.jsonc` `vars`. Secrets are bound with `wrangler secret put` and, locally, `.dev.vars`. Wrangler does not inherit `vars` into named environments, so `development` (top level), `staging`, and `production` each carry a full copy. Change all three when you change a default.

Placeholder D1 ids `00000000-0000-4000-8000-000000000001` through `000000000003` must be replaced with the ids from `wrangler d1 create` before any remote command. See [deployment.md](deployment.md).

After changing `wrangler.jsonc`, regenerate types:

```sh
pnpm cf-typegen
```

## Secrets

Names only. Do not put values in git, issues, or chat logs.

| Name                      | Required                                 | Purpose                                                                  |
| ------------------------- | ---------------------------------------- | ------------------------------------------------------------------------ |
| `OPERATOR_TOKEN`          | yes, for operator routes                 | Bearer token for diagnostics, status, silence, and ack                   |
| `STATUS_SIGNING_SECRET`   | yes, for a signed status body            | HMAC key for `X-Watchdog-Signature` on `GET /v1/status`                  |
| `SFS_BOT_NSEC`            | yes, to send SmartFlowSocial alerts      | Dedicated bot `nsec`. Not a wallet seed, personal key, or brand key      |
| `NOSTRMASH_BOT_NSEC`      | yes, to send NostrMash alerts            | A different dedicated bot `nsec`                                         |
| `HEARTBEAT_KEYS`          | yes, once a heartbeat monitor is enabled | JSON object of `monitorId` to a secret of at least 32 characters         |
| `HEARTBEAT_KEYS_PREVIOUS` | yes                                      | Same shape, used only during rotation. Use `{}` when nothing is rotating |
| `ALBY_AUTH_TOKEN`         | only with Alby enabled                   | Read-only Hub JWT. Empty until then                                      |
| `BTCPAY_API_KEY`          | only for version and processor detail    | Separate read-only Greenfield key. Empty skips server info               |
| `TELEGRAM_BOT_TOKEN`      | only for Telegram                        | Bot token. Empty disables Telegram                                       |
| `TELEGRAM_CHAT_IDS`       | only for Telegram                        | JSON object of `projectId` to a numeric chat id                          |
| `GITHUB_TOKEN`            | no                                       | Raises GitHub API rate limit. Empty uses the anonymous limit             |

`secrets.required` makes Wrangler refuse to start when a name is missing. An empty value is still a value: heartbeats fail closed when `HEARTBEAT_KEYS` is empty, and vendor calls that need a token report `misconfigured` instead of healthy.

Create one bot identity per project. The command prints an `nsec`. Paste that only into `wrangler secret put` or `.dev.vars`, then clear the terminal scrollback. Do not commit it.

```sh
pnpm exec node --input-type=module -e '
import { generateSecretKey, getPublicKey } from "nostr-tools/pure";
import { nsecEncode, npubEncode } from "nostr-tools/nip19";
const key = generateSecretKey();
console.log("npub", npubEncode(getPublicKey(key)));
console.log("nsec", nsecEncode(key));
'
```

Publish the bot `npub` as the contact the recipient expects to see: "SmartFlowSocial Watchdog" or "NostrMash Watchdog". Some clients hide DMs from unknown senders. The `nsec` stays in the secret store.

Generate heartbeat secrets with `openssl rand -base64 32`. Example shape, with fake values:

```json
{
  "sfs-worker": "replace-with-a-random-string-at-least-32-chars",
  "nostrmash-ingestor": "replace-with-another-random-string-32",
  "nostrmash-worker": "replace-with-a-third-random-string-32"
}
```

Rotation: put the current JSON into `HEARTBEAT_KEYS_PREVIOUS`, put the new JSON into `HEARTBEAT_KEYS`, deploy, restart the emitters, then set `HEARTBEAT_KEYS_PREVIOUS` back to `{}` on a later deploy. Both keys verify during the overlap. A secret shorter than 32 characters is rejected as misconfiguration.

## Recipients and relays

`ADMIN_NPUB` is the default recipient. `PROJECT_RECIPIENTS` is a JSON object keyed by `smartflowsocial` and `nostrmash`. An invalid JSON object disables delivery for both projects even if `ADMIN_NPUB` is set. Values must be `npub` or 64-character hex.

`BOOTSTRAP_RELAYS` is a comma-separated list of `wss://` URLs used only to read kind `10050`. The recipient's client must publish kind `10050` with one or more `relay` tags pointing at the inbox relays that should receive gift wraps. This Worker will not fall back to the recipient's kind `10002` read/write relays. White Noise and Marmot conversations are not NIP-17 inboxes.

## Schedule and thresholds

| Var                          | Default                  | Meaning                                                                                                       |
| ---------------------------- | ------------------------ | ------------------------------------------------------------------------------------------------------------- |
| `WATCHDOG_ENABLED`           | `true`                   | `false` skips both crons                                                                                      |
| `ALERTS_ENABLED`             | `true`                   | `false` still stores incidents and outbox rows, and does not deliver them. An explicit test alert still sends |
| `CHECK_CONCURRENCY`          | `4`                      | Parallel probes, clamped to 1–6                                                                               |
| `CHECK_TIMEOUT_MS`           | `5000`                   | Per request, clamped to 1–15 seconds                                                                          |
| `FAILURE_THRESHOLD`          | empty                    | Empty uses each monitor's own threshold, which is 2                                                           |
| `RECOVERY_THRESHOLD`         | empty                    | Empty uses 2                                                                                                  |
| `CRITICAL_REMINDER_SECONDS`  | `0`                      | `0` disables reminders. Otherwise the gap between critical outage reminders                                   |
| `RELAY_LIST_TTL_SECONDS`     | `3600`                   | Kind 10050 cache lifetime                                                                                     |
| `HEARTBEAT_MAX_SKEW_SECONDS` | `300`                    | Accepted clock skew for signed heartbeats                                                                     |
| `HEARTBEAT_STALE_SECONDS`    | `180`                    | Age after which a heartbeat or loop timestamp is down                                                         |
| `HEARTBEAT_PROGRESS_SECONDS` | `600`                    | Non-idle heartbeat with unchanged progress becomes degraded                                                   |
| `TELEGRAM_CRITICAL_MODE`     | `dual`                   | `dual` or `nostr_fallback`                                                                                    |
| `PRIVATE_NETWORK_PROFILE`    | `false`                  | `true` allows HTTP and private addresses. Leave false for public probes                                       |
| `RUNBOOK_BASE_URL`           | empty                    | HTTPS origin prepended to each monitor's runbook path                                                         |
| `GITHUB_API_BASE`            | `https://api.github.com` | Only `api.github.com` or a `*.github.com` HTTPS host is accepted                                              |

## Monitors

All of these ship with `ENABLE_*=false`. Set the URL or credential first, confirm it, then set the flag to `true`.

| Id                   | Enable                      | Endpoint var                      | Contract                                                                 |
| -------------------- | --------------------------- | --------------------------------- | ------------------------------------------------------------------------ |
| `sfs-web`            | `ENABLE_SFS_WEB`            | `SFS_WEB_READY_URL`               | `GET /healthcheck`, JSON `/status` equals `ok`                           |
| `sfs-worker`         | `ENABLE_SFS_WORKER`         | heartbeat `sfs-worker`            | Signed loop heartbeat. Not implemented in the app yet                    |
| `sfs-blossom`        | `ENABLE_SFS_BLOSSOM`        | `SFS_BLOSSOM_READY_URL`           | `GET /ready`, `/status` equals `ready`                                   |
| `sfs-blastr`         | `ENABLE_SFS_BLASTR`         | `SFS_BLASTR_READY_URL`            | `GET /ready`, `/status` equals `ok`. Warning severity. Host not verified |
| `sfs-alby-hub`       | `ENABLE_SFS_ALBY`           | `ALBY_BASE_URL` plus routing vars | See below                                                                |
| `sfs-btcpay`         | `ENABLE_SFS_BTCPAY`         | `BTCPAY_BASE_URL`                 | See below                                                                |
| `nostrmash-api`      | `ENABLE_NOSTRMASH_API`      | `NOSTRMASH_API_READY_URL`         | `GET /ready`, `/status` equals `ready`                                   |
| `nostrmash-ingestor` | `ENABLE_NOSTRMASH_INGESTOR` | heartbeat `nostrmash-ingestor`    | Not implemented in the app yet                                           |
| `nostrmash-worker`   | `ENABLE_NOSTRMASH_WORKER`   | heartbeat `nostrmash-worker`      | Not implemented in the app yet                                           |

There is no monitor for the NostrMash web app, the read gateway, or the publish gateway. Those were not confirmed as independently deployed production dependencies.

### Alby Hub

`ALBY_ROUTING_PROFILE` is `self_hosted` or `alby_cloud`.

- Self-hosted: `ALBY_BASE_URL` is the hub origin, for example `https://hub.example`. The shared site `https://my.albyhub.com` is rejected unless the profile is `alby_cloud`.
- Cloud: profile `alby_cloud`, base URL `https://my.albyhub.com`, `ALBY_HUB_NAME` set to the hub name, and `ALBY_HUB_REGION` set when the hub is not in the default region. The Worker sends `AlbyHub-Name` and, when set, `AlbyHub-Region`. No account id is hardcoded.

`ALBY_AUTH_TOKEN` must be a read-only JWT from `hub-cli unlock --permission readonly`. Do not use a wallet password, mnemonic, full-access JWT, or NWC connection string. Without the token, a successful `GET /api/info` is still `misconfigured`: the public info route does not prove node health. Redirects are not followed, so the token is not replayed to another host.

Classification, from the Hub source used for this adapter:

- Hub API unreachable: `down`.
- HTTP 401 or 403 on health or node status: `misconfigured` (`unauthorized`), including an expired token.
- `running: false`, alarm `node_not_ready`, or node `isReady: false`: `degraded`, not a host-down outage.
- Alarms `alby_service`, `channels_offline`, `nostr_relay_offline`, and `vss_no_subscription`: `degraded` warning incidents.
- An alarm kind that is not in that set, or a body that is not the expected JSON: `unknown`. That does not clear an open incident and does not page as a new critical outage.
- A non-empty `startupError` string is `degraded`. The string itself is not copied into the alert.

The adapter does not read or log `internalNodeStatus`.

### BTCPay Server

`GET /api/v1/health` is called without a key. `synchronized: true` and no key is healthy, with a summary that server info was not checked. `synchronized: false` is degraded (`unsynchronized`).

With `BTCPAY_API_KEY`, the Worker also calls `GET /api/v1/server/info` using the `token` authorization scheme. Create that key as a separate read-only credential. Do not reuse an invoice or payment key.

- 401 or 403 on server info: `misconfigured`. The instance may still be up.
- `fullySynched: false`: degraded, unsynchronized.
- A `syncStatus` entry with `available: false`: degraded, payment processor unavailable.
- Onion hostnames, chain heights, and other chain metadata are not copied into alerts.
- The check never creates an invoice or a payment. Redirects are not followed.

## Adding a monitor

Add a `MonitorDefinition` in `src/config/monitors.ts`, an `ENABLE_*` var in all three Wrangler environments, and regenerate types. HTTP checks need an expected path, expected statuses, and JSON predicates. Do not treat HTTP 200 by itself as success. Heartbeat ids must match a key in `HEARTBEAT_KEYS`. Vendor kinds go through `src/checks/` and return the same `CheckResult` as the other probes. Keep new URLs in vars, not in source.
