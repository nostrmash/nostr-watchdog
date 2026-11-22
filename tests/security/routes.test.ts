import { env } from "cloudflare:workers";
import { afterEach, describe, expect, it } from "vitest";

import { handleFetch } from "../../src/http/app";
import { bind } from "../helpers";

afterEach(() => {
  bind({ OPERATOR_TOKEN: "test-operator-token" });
});

describe("operator route protection", () => {
  it("rejects an unauthenticated test alert and drops unexpected query strings", async () => {
    const denied = await handleFetch(
      new Request("https://watchdog.example/v1/diagnostics/test-alert", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ projectId: "smartflowsocial" }),
      }),
      env,
    );
    expect(denied.status).toBe(401);

    const health = await handleFetch(new Request("https://watchdog.example/healthz?debug=1"), env);
    expect(health.status).toBe(404);
  });

  it("fails closed when the operator token is not configured", async () => {
    bind({ OPERATOR_TOKEN: "" });
    const response = await handleFetch(new Request("https://watchdog.example/v1/status"), env);
    expect(response.status).toBe(503);
    expect(await response.json()).toEqual({ error: "not_configured" });
  });

  it("accepts a read-only status token for status and rejects it for operator actions", async () => {
    bind({ OPERATOR_TOKEN: "operator-token", STATUS_READ_TOKEN: "reader-token" });
    const status = await handleFetch(
      new Request("https://watchdog.example/v1/status", {
        headers: { authorization: "Bearer reader-token" },
      }),
      env,
    );
    expect(status.status).not.toBe(401);
    const denied = await handleFetch(
      new Request("https://watchdog.example/v1/diagnostics/test-alert", {
        method: "POST",
        headers: { authorization: "Bearer reader-token", "content-type": "application/json" },
        body: JSON.stringify({ projectId: "smartflowsocial" }),
      }),
      env,
    );
    expect(denied.status).toBe(401);
  });
});
