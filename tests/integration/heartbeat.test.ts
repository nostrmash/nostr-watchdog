import { env } from "cloudflare:workers";
import { describe, expect, it } from "vitest";

import { handleFetch } from "../../src/http/app";
import { runCheckCycle } from "../../src/cycles/checks";
import { createHeartbeatRequest } from "../../src/integrations/heartbeat-client";
import { bind, jsonResponse } from "../helpers";
import { HEARTBEAT_KEYS, HEARTBEAT_KEYS_PREVIOUS, OPERATOR_TOKEN } from "../secrets";

const url = "https://watchdog.example/v1/heartbeats/sfs-worker";

async function post(
  secret: string,
  body: { progress?: string; idle?: boolean; loopAt?: number },
  now: number,
  nonce = crypto.randomUUID().replace(/-/g, ""),
  clock = now,
) {
  const request = await createHeartbeatRequest({ url, secret, payload: body, now, nonce });
  return handleFetch(
    new Request(request.url, {
      method: request.method,
      headers: request.headers,
      body: request.body,
    }),
    env,
    {
      now: () => clock,
      fetch: async () => jsonResponse({}),
    },
  );
}

describe("heartbeat ingestion", () => {
  it("accepts a current key and a previous key, and rejects tampering, the wrong service, skew, replay, and unknown monitors", async () => {
    const now = 1_730_000_000_000;
    expect(
      (await post(HEARTBEAT_KEYS["sfs-worker"], { idle: true, loopAt: now }, now)).status,
    ).toBe(200);
    expect(
      (await post(HEARTBEAT_KEYS_PREVIOUS["sfs-worker"], { idle: true, loopAt: now }, now)).status,
    ).toBe(200);
    const signed = await createHeartbeatRequest({
      url,
      secret: HEARTBEAT_KEYS["sfs-worker"],
      payload: { idle: true, loopAt: now },
      now,
    });
    const tampered = await handleFetch(
      new Request(signed.url, {
        method: "POST",
        headers: signed.headers,
        body: JSON.stringify({ idle: false, progress: "changed" }),
      }),
      env,
      { now: () => now, fetch: async () => jsonResponse({}) },
    );
    expect(tampered.status).toBe(401);
    expect(
      (await post(HEARTBEAT_KEYS["nostrmash-ingestor"], { idle: true, loopAt: now }, now)).status,
    ).toBe(401);
    expect(
      (
        await post(
          HEARTBEAT_KEYS["sfs-worker"],
          { idle: true, loopAt: now },
          now - 1_000_000,
          undefined,
          now,
        )
      ).status,
    ).toBe(401);
    const nonce = "replayednoncevalue01";
    expect(
      (await post(HEARTBEAT_KEYS["sfs-worker"], { idle: true, loopAt: now }, now, nonce)).status,
    ).toBe(200);
    expect(
      (await post(HEARTBEAT_KEYS["sfs-worker"], { idle: true, loopAt: now }, now, nonce)).status,
    ).toBe(401);
    expect(
      (
        await handleFetch(
          new Request("https://watchdog.example/v1/heartbeats/not-a-monitor", {
            method: "POST",
            body: "{}",
          }),
          env,
        )
      ).status,
    ).toBe(404);
    const huge = await createHeartbeatRequest({
      url,
      secret: HEARTBEAT_KEYS["sfs-worker"],
      payload: { progress: "x".repeat(5000), idle: false, loopAt: now },
      now,
    });
    expect(
      (
        await handleFetch(
          new Request(huge.url, { method: "POST", headers: huge.headers, body: huge.body }),
          env,
          { now: () => now, fetch: async () => jsonResponse({}) },
        )
      ).status,
    ).toBe(413);
  });

  it("does not describe a fresh idle worker as down and does describe a missing heartbeat as down", async () => {
    bind({ ENABLE_SFS_WORKER: "true", ALERTS_ENABLED: "false" });
    const now = { value: 1_740_000_000_000 };
    await post(HEARTBEAT_KEYS["sfs-worker"], { idle: true, loopAt: now.value }, now.value);
    await runCheckCycle(env, { now: () => now.value, fetch: async () => jsonResponse({}) });
    const row = await env.DB.prepare("SELECT status FROM monitor_state WHERE monitor_id = ?")
      .bind("sfs-worker")
      .first<{ status: string }>();
    expect(row?.status).toBe("healthy");
    bind({ ENABLE_SFS_WORKER: "false", ENABLE_NOSTRMASH_INGESTOR: "true" });
    now.value += 60_000;
    await runCheckCycle(env, { now: () => now.value, fetch: async () => jsonResponse({}) });
    now.value += 60_000;
    await runCheckCycle(env, { now: () => now.value, fetch: async () => jsonResponse({}) });
    const incident = await env.DB.prepare(
      "SELECT kind FROM incidents WHERE monitor_id = ? AND status = 'open'",
    )
      .bind("nostrmash-ingestor")
      .first<{ kind: string }>();
    expect(incident?.kind).toBe("outage");
    bind({ ENABLE_NOSTRMASH_INGESTOR: "false" });
  });

  it("requires the operator token for diagnostics and signs status without operational detail", async () => {
    const open = await handleFetch(
      new Request("https://watchdog.example/v1/diagnostics/test-alert", {
        method: "POST",
        body: JSON.stringify({ projectId: "smartflowsocial" }),
      }),
      env,
    );
    expect(open.status).toBe(401);
    const health = await handleFetch(new Request("https://watchdog.example/healthz"), env);
    expect(await health.json()).toMatchObject({ status: "ok" });
    const status = await handleFetch(
      new Request("https://watchdog.example/v1/status", {
        headers: { authorization: `Bearer ${OPERATOR_TOKEN}` },
      }),
      env,
    );
    expect(status.headers.get("x-watchdog-signature")).toMatch(/^[0-9a-f]{64}$/);
    const body = (await status.json()) as Record<string, unknown>;
    expect(body).not.toHaveProperty("nsec");
    expect(JSON.stringify(body)).not.toContain(OPERATOR_TOKEN);
  });
});
