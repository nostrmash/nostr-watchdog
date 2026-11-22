import { formatTestMessage } from "../alerts/format";
import { discoverInbox, workersRelayConnect } from "../alerts/nip17";
import { recipientPubkey } from "../alerts/nip17";
import { deriveOperationalStatus } from "./status";
import { handleTestRelay, testRelayAllowed } from "./relay-fixture";
import { canonicalHeartbeat } from "../security/canonical";
import { verifyHmacSha256, hmacSha256Hex, secretsEqual } from "../security/hmac";
import { readLimited } from "../security/body";
import { PROJECTS, projectRecipient } from "../config/projects";
import { monitorById } from "../config/monitors";
import { loadSettings } from "../config/settings";
import { defaultDependencies, type Dependencies } from "../deps";
import { log, readString } from "../runtime";
import { runCheckCycle } from "../cycles/checks";
import { deliver } from "../cycles/dispatch";
import { runUpdateCycle } from "../cycles/updates";
import {
  ackIncident,
  countRecent,
  insertAlert,
  listOpenIncident,
  listFailedAlerts,
  operationalSnapshot,
  relayCache,
  retryDeadLetter,
  saveRelayCache,
  silenceIncident,
  storeHeartbeat,
} from "../state/store";
import type { AlertDraft, ProjectId } from "../types";

export async function handleFetch(
  request: Request,
  env: Env,
  deps: Dependencies = defaultDependencies(),
): Promise<Response> {
  const url = new URL(request.url);
  try {
    if (testRelayAllowed(env) && url.pathname.startsWith("/__test_relay")) {
      return handleTestRelay(request);
    }
    const relayDiagnostics = request.method === "GET" && url.pathname === "/v1/diagnostics/relays";
    if (url.search !== "" && !relayDiagnostics) return json({ error: "not_found" }, 404);
    if (request.method === "GET" && url.pathname === "/healthz") return healthz(env);
    if (request.method === "GET" && url.pathname === "/v1/status")
      return status(request, env, deps);
    if (request.method === "POST" && url.pathname.startsWith("/v1/heartbeats/")) {
      return heartbeat(request, env, url.pathname, deps);
    }
    if (request.method === "POST" && url.pathname === "/v1/diagnostics/test-alert") {
      return testAlert(request, env, deps);
    }
    if (request.method === "GET" && url.pathname === "/v1/diagnostics/relays") {
      return relayDiagnostic(request, env, url, deps);
    }
    if (request.method === "GET" && url.pathname === "/v1/outbox/failed") {
      return failedOutbox(request, env);
    }
    const retry = /^\/v1\/outbox\/(alt_[0-9a-f-]{8,80})\/retry$/.exec(url.pathname);
    if (request.method === "POST" && retry?.[1]) return retryOutbox(request, env, retry[1], deps);
    const incident = /^\/v1\/incidents\/(inc_[0-9a-f-]{36})\/(silence|ack)$/.exec(url.pathname);
    if (request.method === "POST" && incident?.[1] && incident[2]) {
      return incidentAction(request, env, incident[1], incident[2], deps);
    }
    return json({ error: "not_found" }, 404);
  } catch {
    log("error", "request_failed", { path: url.pathname });
    return json({ error: "internal_error" }, 500);
  }
}

export async function handleScheduled(
  controller: ScheduledController,
  env: Env,
  deps: Dependencies = defaultDependencies(),
): Promise<void> {
  if (controller.cron === "0 * * * *") await runUpdateCycle(env, deps);
  else await runCheckCycle(env, deps);
}

function healthz(env: Env): Response {
  return json({
    status: "ok",
    service: "nostr-watchdog",
    enabled: readString(env, "WATCHDOG_ENABLED") !== "false",
  });
}

async function status(request: Request, env: Env, deps: Dependencies): Promise<Response> {
  const auth = await authorize(request, env, "status");
  if (auth !== "ok") return authResponse(auth);
  try {
    const settings = loadSettings(env);
    const snapshot = await operationalSnapshot(env.DB);
    const derived = deriveOperationalStatus({ env, settings, now: deps.now(), snapshot });
    const body = JSON.stringify(derived.body);
    const headers = new Headers({
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store",
    });
    const signing = readString(env, "STATUS_SIGNING_SECRET");
    if (signing !== "") headers.set("x-watchdog-signature", await hmacSha256Hex(signing, body));
    return new Response(body, { status: derived.httpStatus, headers });
  } catch {
    return json({ error: "status_unavailable" }, 503);
  }
}

async function heartbeat(
  request: Request,
  env: Env,
  pathname: string,
  deps: Dependencies,
): Promise<Response> {
  const match = /^\/v1\/heartbeats\/([a-z0-9][a-z0-9-]{0,63})$/.exec(pathname);
  const monitor = match?.[1] ? monitorById(match[1]) : null;
  if (!monitor || monitor.kind !== "signed_heartbeat") return json({ error: "not_found" }, 404);
  const settings = loadSettings(env);
  if (readString(env, "HEARTBEAT_KEYS").trim() === "")
    return json({ error: "not_configured" }, 503);
  const bytes = await readLimited(request, settings.maxBody);
  if (bytes === "too_large") return json({ error: "payload_too_large" }, 413);
  if ((request.headers.get("content-type") ?? "").split(";")[0]?.trim() !== "application/json") {
    return json({ error: "unsupported_media_type" }, 415);
  }
  const timestamp = request.headers.get("x-watchdog-timestamp") ?? "";
  const nonce = request.headers.get("x-watchdog-nonce") ?? "";
  const signature = request.headers.get("x-watchdog-signature") ?? "";
  if (!/^\d{10}$/.test(timestamp) || !/^[A-Za-z0-9_-]{16,128}$/.test(nonce)) {
    return json({ error: "unauthorized" }, 401);
  }
  const reportedAt = Number(timestamp) * 1000;
  if (Math.abs(deps.now() - reportedAt) > settings.skewSeconds * 1000)
    return json({ error: "unauthorized" }, 401);
  const current = keyFor(readString(env, "HEARTBEAT_KEYS"), monitor.id);
  if (current === "invalid") return json({ error: "not_configured" }, 503);
  if (current === null) return json({ error: "unauthorized" }, 401);
  const canonical = await canonicalHeartbeat({
    timestamp,
    nonce,
    method: "POST",
    path: pathname,
    body: bytes,
  });
  const currentOk = await verifyHmacSha256(current, canonical, signature);
  const previous = currentOk
    ? null
    : keyFor(readString(env, "HEARTBEAT_KEYS_PREVIOUS"), monitor.id);
  const previousOk =
    previous && previous !== "invalid"
      ? await verifyHmacSha256(previous, canonical, signature)
      : false;
  if (!currentOk && !previousOk) return json({ error: "unauthorized" }, 401);
  let payload: { progress?: string; idle?: boolean; loopAt?: number };
  try {
    payload = parseHeartbeat(JSON.parse(new TextDecoder().decode(bytes)) as unknown);
  } catch {
    return json({ error: "bad_request" }, 400);
  }
  const stored = await storeHeartbeat(env.DB, {
    monitorId: monitor.id,
    projectId: monitor.projectId,
    now: deps.now(),
    reportedAt,
    nonce,
    nonceExpiresAt: reportedAt + settings.skewSeconds * 1000,
    progress: payload.progress ?? null,
    idle: payload.idle ?? false,
    loopAt: payload.loopAt ?? null,
  });
  if (stored === "replay") return json({ error: "replay" }, 401);
  return json({ status: "ok" });
}

async function testAlert(request: Request, env: Env, deps: Dependencies): Promise<Response> {
  const auth = await authorize(request, env);
  if (auth !== "ok") return authResponse(auth);
  const settings = loadSettings(env);
  const bytes = await readLimited(request, 2048);
  if (bytes === "too_large") return json({ error: "payload_too_large" }, 413);
  let projectId: ProjectId;
  try {
    const body = JSON.parse(new TextDecoder().decode(bytes)) as { projectId?: unknown };
    if (body.projectId !== "smartflowsocial" && body.projectId !== "nostrmash")
      return json({ error: "bad_request" }, 400);
    projectId = body.projectId;
  } catch {
    return json({ error: "bad_request" }, 400);
  }
  const recent = await countRecent(env.DB, `test:${projectId}:`, deps.now() - 3_600_000);
  if (recent >= 3) return json({ error: "rate_limited" }, 429);
  const now = deps.now();
  const alert: AlertDraft = {
    id: `alt_${crypto.randomUUID()}`,
    alertClass: "test",
    incidentId: null,
    monitorId: `test-${projectId}`,
    projectId,
    dedupeKey: `test:${projectId}:${crypto.randomUUID()}`,
    destination: "nostr",
    severity: "info",
    text: formatTestMessage({ projectName: PROJECTS[projectId].displayName, occurredAt: now }),
  };
  await insertAlert(env.DB, alert, now);
  const state = await deliver(env, deps, settings, {
    id: alert.id,
    alert_class: alert.alertClass,
    incident_id: null,
    monitor_id: alert.monitorId,
    project_id: alert.projectId,
    dedupe_key: alert.dedupeKey,
    destination: "nostr",
    severity: "info",
    state: "queued",
    payload_text: alert.text,
    envelope_json: null,
    attempt_count: 0,
    next_attempt_at: now,
    claim_until: null,
    claim_token: null,
    accepted_relays: null,
    failed_relays: null,
    last_error: null,
    created_at: now,
    updated_at: now,
  });
  return json({ queued: true, delivery: state });
}

async function relayDiagnostic(
  request: Request,
  env: Env,
  url: URL,
  deps: Dependencies,
): Promise<Response> {
  const auth = await authorize(request, env);
  if (auth !== "ok") return authResponse(auth);
  const projectId = url.searchParams.get("project");
  if (projectId !== "smartflowsocial" && projectId !== "nostrmash")
    return json({ error: "bad_request" }, 400);
  const settings = loadSettings(env);
  const raw = projectRecipient(env, projectId);
  if (!raw) return json({ error: "recipient_missing", inboxRelays: [] }, 409);
  let author: string;
  try {
    author = recipientPubkey(raw);
  } catch {
    return json({ error: "recipient_invalid", inboxRelays: [] }, 409);
  }
  const cached = await relayCache(env.DB, author, deps.now());
  if (cached && !cached.negative)
    return json({ projectId, inboxRelays: cached.relays, cached: true, error: null });
  if (settings.bootstrap.length === 0)
    return json({ projectId, inboxRelays: [], cached: false, error: "bootstrap_relays_missing" });
  const found = await discoverInbox({
    author,
    bootstrap: settings.bootstrap,
    connect: deps.connectRelay ?? workersRelayConnect(deps.fetch, settings.timeoutMs),
    timeoutMs: settings.timeoutMs,
    nowMs: deps.now(),
  });
  const now = deps.now();
  if (found.relays.length > 0) {
    await saveRelayCache(
      env.DB,
      author,
      found.relays,
      false,
      now,
      now + settings.relayTtlSeconds * 1000,
    );
    return json({ projectId, inboxRelays: found.relays, cached: false, error: null });
  }
  return json({
    projectId,
    inboxRelays: [],
    cached: false,
    error: found.definitiveEmpty ? "recipient_inbox_missing" : "inbox_discovery_failed",
  });
}

async function failedOutbox(request: Request, env: Env): Promise<Response> {
  const auth = await authorize(request, env);
  if (auth !== "ok") return authResponse(auth);
  const alerts = await listFailedAlerts(env.DB);
  return json({ alerts });
}

async function retryOutbox(
  request: Request,
  env: Env,
  id: string,
  deps: Dependencies,
): Promise<Response> {
  const auth = await authorize(request, env);
  if (auth !== "ok") return authResponse(auth);
  const retried = await retryDeadLetter(env.DB, id, deps.now());
  if (!retried) return json({ error: "not_found" }, 404);
  return json({ id, status: "queued" });
}

async function incidentAction(
  request: Request,
  env: Env,
  id: string,
  action: string,
  deps: Dependencies,
): Promise<Response> {
  const auth = await authorize(request, env);
  if (auth !== "ok") return authResponse(auth);
  const incident = await listOpenIncident(env.DB, id);
  if (!incident || incident.status !== "open") return json({ error: "not_found" }, 404);
  if (action === "ack") {
    await ackIncident(env.DB, id, deps.now());
    return json({ id, monitorId: incident.monitorId, status: "acked" });
  }
  const bytes = await readLimited(request, 1024);
  if (bytes === "too_large") return json({ error: "payload_too_large" }, 413);
  let minutes = 60;
  if (bytes.byteLength > 0) {
    try {
      const body = JSON.parse(new TextDecoder().decode(bytes)) as { minutes?: unknown };
      if (
        typeof body.minutes !== "number" ||
        !Number.isInteger(body.minutes) ||
        body.minutes < 1 ||
        body.minutes > 10_080
      ) {
        return json({ error: "bad_request" }, 400);
      }
      minutes = body.minutes;
    } catch {
      return json({ error: "bad_request" }, 400);
    }
  }
  await silenceIncident(env.DB, id, deps.now() + minutes * 60_000, deps.now());
  return json({ id, monitorId: incident.monitorId, status: "silenced" });
}

async function authorize(
  request: Request,
  env: Env,
  scope: "operator" | "status" = "operator",
): Promise<"ok" | "missing" | "rejected"> {
  const operator = readString(env, "OPERATOR_TOKEN");
  const reader = scope === "status" ? readString(env, "STATUS_READ_TOKEN") : "";
  if (operator === "" && reader === "") return "missing";
  const header = request.headers.get("authorization") ?? "";
  const token = header.toLowerCase().startsWith("bearer ") ? header.slice(7).trim() : "";
  if (operator !== "" && (await secretsEqual(operator, token))) return "ok";
  if (reader !== "" && (await secretsEqual(reader, token))) return "ok";
  return "rejected";
}

function authResponse(result: "missing" | "rejected"): Response {
  return json(
    result === "missing" ? { error: "not_configured" } : { error: "unauthorized" },
    result === "missing" ? 503 : 401,
  );
}

function keyFor(raw: string, monitorId: string): string | null | "invalid" {
  if (raw.trim() === "") return null;
  try {
    const parsed = JSON.parse(raw) as unknown;
    if (!parsed || typeof parsed !== "object") return "invalid";
    const value = (parsed as Record<string, unknown>)[monitorId];
    if (typeof value !== "string") return null;
    return value.length >= 32 ? value : "invalid";
  } catch {
    return "invalid";
  }
}

function parseHeartbeat(value: unknown): { progress?: string; idle?: boolean; loopAt?: number } {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("bad_heartbeat");
  const body = value as Record<string, unknown>;
  const progress = body.progress;
  const idle = body.idle;
  const loopAt = body.loopAt;
  if (
    progress !== undefined &&
    (typeof progress !== "string" || progress.length > 128 || !/^[\w.:-]+$/.test(progress))
  ) {
    throw new Error("bad_heartbeat");
  }
  if (idle !== undefined && typeof idle !== "boolean") throw new Error("bad_heartbeat");
  if (loopAt !== undefined && (typeof loopAt !== "number" || !Number.isFinite(loopAt)))
    throw new Error("bad_heartbeat");
  const payload: { progress?: string; idle?: boolean; loopAt?: number } = {};
  if (typeof progress === "string") payload.progress = progress;
  if (typeof idle === "boolean") payload.idle = idle;
  if (typeof loopAt === "number") payload.loopAt = loopAt;
  return payload;
}

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" },
  });
}
