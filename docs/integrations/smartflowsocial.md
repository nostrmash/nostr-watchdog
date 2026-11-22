# SmartFlowSocial integration

Status: **not integrated**. The SmartFlowSocial repository was inspected and was not modified. Enabling `ENABLE_SFS_WORKER` before an emitter exists will open an outage after two missed intervals.

The app already has `GET /healthcheck`. Point `SFS_WEB_READY_URL` at that path on the real origin and require JSON `status: "ok"`. Do not point it at the homepage. That endpoint does not prove the BullMQ worker.

The worker process in `worker.ts` is a long-running Node service. Its existing metrics timer is not a watchdog heartbeat: a timer can keep firing while a queue processor is stuck. Do not change the customer NIP-04 or NIP-17 broadcast path. The emitter below is opt-in and does nothing when `WATCHDOG_HEARTBEAT_URL` is unset, so the worker keeps processing jobs if the watchdog is down.

## Emitter shape

Track two clocks inside the worker:

- `loopAt`: the last time a BullMQ worker event ran (`active`, `completed`, `failed`, or `drained`) or the process confirmed every queue was idle. Do not set this to `Date.now()` at the moment of the HTTP send.
- `progress`: a counter incremented only when a job reaches `completed`. A stalled loop keeps the same counter.

Send `idle: true` only when waiting and active counts are all zero. Send `idle: false` with the progress counter otherwise. Use a short timeout, one retry, and jitter. Swallow errors. Never await this from a payment or publish path.

The canonical request is `createHeartbeatRequest` in `src/integrations/heartbeat-client.ts`. A Node copy of that behavior:

```ts
import { createHeartbeatRequest } from "./heartbeat-client";

const url = process.env.WATCHDOG_HEARTBEAT_URL;
const secret = process.env.WATCHDOG_HEARTBEAT_SECRET;
if (url && secret) {
  const request = await createHeartbeatRequest({
    url,
    secret,
    payload: { progress: String(completedJobs), idle, loopAt },
  });
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 3000);
  try {
    await fetch(request.url, {
      method: "POST",
      headers: request.headers,
      body: request.body,
      signal: controller.signal,
    });
  } catch {
    // The job loop must continue when the watchdog is unreachable.
  } finally {
    clearTimeout(timer);
  }
}
```

Copy the client, or depend on a published build later. Do not add this repository as a runtime dependency of the app. The secret is the `sfs-worker` entry of `HEARTBEAT_KEYS` and belongs in the worker environment, not in the Cloudflare Worker vars and not in git.

Call the send from the same process as the queue workers, after a processor event or an idle observation. A `setInterval` that only reads queue counts and stamps `loopAt` with the current time will look healthy while the processors are stuck. That does not satisfy the monitor.

## Other SmartFlowSocial checks

| Monitor        | How to enable later                                                                                              |
| -------------- | ---------------------------------------------------------------------------------------------------------------- |
| `sfs-web`      | Set `SFS_WEB_READY_URL` to the deployed `/healthcheck`, then `ENABLE_SFS_WEB=true`                               |
| `sfs-blossom`  | Set `SFS_BLOSSOM_READY_URL` to the deployed `/ready` after confirming the host, then enable                      |
| `sfs-blastr`   | Enable only after a public `/ready` host is confirmed. The Blastr route was commented out in its Wrangler config |
| `sfs-alby-hub` | Read-only token, routing profile, and base URL. See [configuration.md](../configuration.md)                      |
| `sfs-btcpay`   | Base URL and a separate read-only API key                                                                        |

Customer subscription DMs stay in SmartFlowSocial. This watchdog never sends them.
