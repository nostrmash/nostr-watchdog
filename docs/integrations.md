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

## What stays out of scope

Do not page on a quiet period by itself. An idle loop is healthy. Do not require Cloudflare for the application to process its own work. Do not send customer messages through this Worker.
