# NostrMash integration

Status: **not integrated**. The NostrMash repository was inspected and was not modified. `ENABLE_NOSTRMASH_INGESTOR` and `ENABLE_NOSTRMASH_WORKER` must stay false until those processes emit heartbeats. Enabling either monitor with no emitter opens an outage.

`GET /ready` is the API check. It returns `200` and `{"status":"ready"}` when Postgres answers within two seconds, and `503` otherwise. `GET /health` only proves the process is up, so the template uses `/ready`. Set `NOSTRMASH_API_READY_URL` to the real origin. The public hostname was not confirmed from the checkout, and no hostname is baked into the Worker. The web frontend had no confirmed readiness route, so it is not a monitor.

The read and publish gateway repositories are not current SmartFlowSocial production dependencies and are not separate NostrMash services that this Worker should probe under those repository names.

## Worker and ingestor

`cmd/worker/job_runner.go` `runClaimLoop` blocks in `WaitForWork` when the queue is empty, and it blocks on the job-queue send when the pool is full. A side goroutine with its own ticker would stay fresh in both cases and would hide a stuck loop. The heartbeat has to be driven by the claim loop.

Suggested shape, not applied to the Go module:

- At the top of every `runClaimLoop` iteration, including the error path and the empty-claim path, record `loopAt = time.Now()` and whether the claim was empty.
- Increment a progress counter only where a job is successfully processed, not when it is claimed and not from a ticker.
- A separate goroutine reads the latest sample from an atomic value and POSTs it. The claim loop must not wait for HTTP. Use a timeout of a few seconds. On failure, log a class of error and continue. Drop a sample if a request is already in flight.
- Body: `{"progress":"<counter>","idle":true,"loopAt":<unix milliseconds>}` when the last claim was empty. `idle: false` when work was claimed. `loopAt` is the claim loop's timestamp, not the send time.
- Sign with the same canonical string as `src/integrations/heartbeat-client.ts`. The monitor id is `nostrmash-worker` or `nostrmash-ingestor`, and the HMAC key is that entry in `HEARTBEAT_KEYS`.

The ingestor should record its loop time inside `Run` / `runLifecycle`, on each pass, including a pass that finds nothing to ingest. An empty pass is `idle: true`. A quiet relay is then healthy. A lifecycle function that stops returning is not.

Trust-worker heartbeats are not a template in this version. Add one the same way, as another monitor id, if that process needs its own page.

## What not to treat as an outage

Do not alert on a zero ingestion count by itself. Normal quiet periods are idle heartbeats. Do not alert because Prometheus is empty. Do not require Cloudflare for the API, the ingestor, or the worker to do their jobs. If `WATCHDOG_HEARTBEAT_URL` is unset, the processes should not open a connection.
