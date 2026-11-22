import { env } from "cloudflare:workers";
import { afterEach, describe, expect, it } from "vitest";

import { handleFetch } from "../../src/http/app";
import { createHeartbeatRequest } from "../../src/integrations/heartbeat-client";
import { bind } from "../helpers";
import { HEARTBEAT_KEYS, OPERATOR_TOKEN } from "../secrets";

const INCIDENT = "inc_11111111-1111-4111-8111-111111111111";
const DEAD = "alt_deadbeefdeadbeef";

afterEach(() => {
  bind({ OPERATOR_TOKEN, STATUS_READ_TOKEN: "" });
});

function operator(path: string, method = "GET", body?: string): Request {
  return new Request(`https://watchdog.example${path}`, {
    method,
    headers: {
      authorization: `Bearer ${OPERATOR_TOKEN}`,
      "content-type": "application/json",
    },
    body,
  });
}

describe("operator routes", () => {
  it("acks and silences an open incident, and rejects a bad silence window", async () => {
    await env.DB.prepare(
      `INSERT INTO incidents (
        id, monitor_id, project_id, status, kind, severity, opened_at, open_reason, updated_at
      ) VALUES (?, 'sfs-blossom', 'smartflowsocial', 'open', 'outage', 'critical', 1, 'down', 1)`,
    )
      .bind(INCIDENT)
      .run();
    const reader = await handleFetch(
      new Request(`https://watchdog.example/v1/incidents/${INCIDENT}/ack`, {
        method: "POST",
        headers: { authorization: "Bearer reader-token" },
      }),
      env,
    );
    expect(reader.status).toBe(401);
    bind({ STATUS_READ_TOKEN: "reader-token" });
    const stillDenied = await handleFetch(
      new Request(`https://watchdog.example/v1/incidents/${INCIDENT}/ack`, {
        method: "POST",
        headers: { authorization: "Bearer reader-token" },
      }),
      env,
    );
    expect(stillDenied.status).toBe(401);
    const acked = await handleFetch(operator(`/v1/incidents/${INCIDENT}/ack`, "POST"), env);
    expect(acked.status).toBe(200);
    expect(await acked.json()).toMatchObject({ status: "acked" });
    const bad = await handleFetch(
      operator(`/v1/incidents/${INCIDENT}/silence`, "POST", JSON.stringify({ minutes: 0 })),
      env,
    );
    expect(bad.status).toBe(400);
    const silenced = await handleFetch(
      operator(`/v1/incidents/${INCIDENT}/silence`, "POST", JSON.stringify({ minutes: 30 })),
      env,
    );
    expect(silenced.status).toBe(200);
    const row = await env.DB.prepare("SELECT acked_at, silenced_until FROM incidents WHERE id = ?")
      .bind(INCIDENT)
      .first<{ acked_at: number | null; silenced_until: number | null }>();
    expect(row?.acked_at).not.toBeNull();
    expect(row?.silenced_until).not.toBeNull();
    const missing = await handleFetch(
      operator("/v1/incidents/inc_22222222-2222-4222-8222-222222222222/ack", "POST"),
      env,
    );
    expect(missing.status).toBe(404);
  });

  it("lists a dead letter and queues it once", async () => {
    await env.DB.prepare(
      `INSERT INTO alert_outbox (
        id, alert_class, monitor_id, project_id, dedupe_key, destination, severity, state,
        payload_text, attempt_count, next_attempt_at, last_error, created_at, updated_at
      ) VALUES (?, 'outage', 'sfs-web', 'smartflowsocial', ?, 'nostr', 'critical', 'failed',
        'dead', 8, 1, 'relay_rejected', 1, 1)`,
    )
      .bind(DEAD, DEAD)
      .run();
    const denied = await handleFetch(new Request("https://watchdog.example/v1/outbox/failed"), env);
    expect(denied.status).toBe(401);
    const listed = await handleFetch(operator("/v1/outbox/failed"), env);
    expect(listed.status).toBe(200);
    const body = (await listed.json()) as { alerts: Array<{ id: string }> };
    expect(body.alerts.some((row) => row.id === DEAD)).toBe(true);
    const retried = await handleFetch(operator(`/v1/outbox/${DEAD}/retry`, "POST"), env);
    expect(retried.status).toBe(200);
    const again = await handleFetch(operator(`/v1/outbox/${DEAD}/retry`, "POST"), env);
    expect(again.status).toBe(404);
    const row = await env.DB.prepare("SELECT state, attempt_count FROM alert_outbox WHERE id = ?")
      .bind(DEAD)
      .first<{ state: string; attempt_count: number }>();
    expect(row).toEqual({ state: "queued", attempt_count: 0 });
  });

  it("rejects a malformed heartbeat before storing it", async () => {
    const now = 1_760_000_000_000;
    const signed = await createHeartbeatRequest({
      url: "https://watchdog.example/v1/heartbeats/sfs-worker",
      secret: HEARTBEAT_KEYS["sfs-worker"],
      payload: { progress: "bad value", idle: true, loopAt: now },
      now,
    });
    const malformed = await handleFetch(
      new Request(signed.url, { method: "POST", headers: signed.headers, body: signed.body }),
      env,
      { now: () => now, fetch: async () => new Response("") },
    );
    expect(malformed.status).toBe(400);
    const plain = await handleFetch(
      new Request(signed.url, {
        method: "POST",
        headers: { ...signed.headers, "content-type": "text/plain" },
        body: signed.body,
      }),
      env,
      { now: () => now, fetch: async () => new Response("") },
    );
    expect(plain.status).toBe(415);
  });
});
