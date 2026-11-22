# Integrating an application

This Worker does not import your application, and your application should not import this repository to do its normal work. Two optional signals are enough.

## Readiness

Expose one uncached HTTPS endpoint that checks the dependencies the process actually needs, and fails when they are unavailable. Return a small JSON document. Point an `http_json` monitor at that path and require the fields that mean ready. Do not point it at a homepage or a process liveness route that stays green while a database is down.

The response should not include secrets, hostnames of internal databases, or wallet data.

## Signed heartbeat

Use a heartbeat when the thing you care about is a job loop rather than an HTTP server. The Worker treats these as different signals:

- `receivedAt` is when the signed request arrived.
- `loopAt` is the last time that job loop iterated, including an iteration that found no work.
- `idle` is true only when the loop observed an empty queue.
- `progress` changes only when a unit of work finishes.

A fresh request with `idle: true` is healthy. A fresh request that is not idle, and whose progress has not changed, becomes degraded. A stale `loopAt` is down even if the HTTP request just arrived. A timer that sets `loopAt` to the send time stays green while the job loop is stuck. Do not do that.

The canonical request is `createHeartbeatRequest` in `src/integrations/heartbeat-client.ts`. Copy that function into the application, or call the same canonical string from another language. Do not add this Worker as a runtime dependency. If the heartbeat URL is unset, send nothing. A failed send must not block publishing, payments, or the job itself.

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
    // The job loop continues when the watchdog is unreachable.
  } finally {
    clearTimeout(timer);
  }
}
```

`secret` is the `HEARTBEAT_KEYS` entry for that monitor id. It belongs in the application's environment, not in git and not in a Wrangler var.

Call this from the job loop, after a real iteration. Use a timeout of a few seconds, jitter, and at most one retry. Drop the sample if a request is already in flight.

## SmartFlowSocial

The app's `/healthcheck` route is the HTTP monitor. The Worker sends `Accept: application/json` and requires `status` equal to `ok`.

The BullMQ process in `worker.ts` can emit a heartbeat for monitor `sfs-worker`. Set both of these on that process, not in the browser:

| Variable               | Value                                                               |
| ---------------------- | ------------------------------------------------------------------- |
| `WATCHDOG_URL`         | Full `https` URL, including `/v1/heartbeats/sfs-worker`             |
| `WATCHDOG_HMAC_SECRET` | The `HEARTBEAT_KEYS` value for `sfs-worker`, at least 32 characters |

Unset either value and the worker does not call the watchdog. Every 30 seconds it reads waiting, active, delayed, and completed counts for the existing queues. An empty backlog is `idle: true`. A backlog uses the completed count as `progress`. The send times out after 3 seconds, retries once, and does not throw. There is no second background service and no event-ingestion API. User-facing DMs stay in SmartFlowSocial.

Blossom `/ready` already reports database, storage, pending commits, dead letters, and policy. Blastr `/ready` reports whether its database, KV, and queue binding exist. The Worker uses those routes. Blastr cannot see queue depth from `/ready`, and an empty-queue heartbeat would look like a stall, so neither service gained a heartbeat.

## NostrMash

`GET /health` and `GET /ready` remain the HTTP monitors. The worker and ingestor optionally post heartbeats when `WATCHDOG_URL` and `WATCHDOG_HMAC_SECRET` are set in that process. The worker URL path is `/v1/heartbeats/nostrmash-worker`. The ingestor path is `/v1/heartbeats/nostrmash-ingestor`. The secret matches that monitor id in `HEARTBEAT_KEYS`.

The worker heartbeat's `loopAt` is the last claim-loop iteration. `idle` is true when the last claim succeeded, the queue was empty, and no job is in flight. Completing a job changes `progress`. Repeated claim failures or jobs that do not finish are not idle. The ingestor heartbeat's `progress` is the valid-event count. `idle` stays true when at least one relay is connected, including a quiet relay. It is false when relays are configured and none are healthy. A quiet network is not by itself a failed ingestion process.

## Read and publish gateways

`nostrmash-read-gateway` and `nostrmash-publish-gateway` are HTTP monitors. Both stay disabled until `ENABLE_NOSTRMASH_READ_GATEWAY` or `ENABLE_NOSTRMASH_PUBLISH_GATEWAY` is `true` and the matching URL is set. Readiness is `GET /health` with `status` equal to `ok`. The publish gateway health route does not prove that an event can be published. This Worker does not publish a public Nostr event to test that.

## What stays out of scope

Do not page on a quiet period by itself. An idle loop is healthy. Do not require Cloudflare for the application to process its own work. Do not send customer messages through this Worker. Do not add a dependency from either application back to this repository. Copy the canonical string instead.
