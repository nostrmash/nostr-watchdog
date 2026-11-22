import { describe, expect, it } from "vitest";

import { runAlbyHubCheck } from "../../src/checks/alby-hub";
import { runBtcpayCheck } from "../../src/checks/btcpay";
import { evaluateHeartbeat } from "../../src/checks/heartbeat";
import { runHttpJsonCheck } from "../../src/checks/http-json";
import type { FetchLike, HttpCheckSpec } from "../../src/types";
import { jsonResponse, routed } from "../helpers";

const spec: HttpCheckSpec = {
  urlVar: "SFS_WEB_READY_URL",
  expectedPath: "/healthcheck",
  headers: { accept: "application/json" },
  expectedStatuses: [200],
  predicates: [{ pointer: "/status", equals: "ok" }],
  maxBytes: 1024,
};

const http = (url: string, fetch: FetchLike) =>
  runHttpJsonCheck({ spec, url, privateNetwork: false, timeoutMs: 1000, fetch });

describe("http json", () => {
  it("requires the success contract, not merely HTTP 200", async () => {
    const healthy = await http(
      "https://app.example/healthcheck",
      routed({
        "https://app.example/healthcheck": () => jsonResponse({ status: "ok" }),
      }),
    );
    expect(healthy.status).toBe("healthy");
    const html = await http(
      "https://app.example/healthcheck",
      routed({
        "https://app.example/healthcheck": () => new Response("<html></html>", { status: 200 }),
      }),
    );
    expect(html.status).toBe("unknown");
    const wrong = await http(
      "https://app.example/healthcheck",
      routed({
        "https://app.example/healthcheck": () => jsonResponse({ status: "degraded" }),
      }),
    );
    expect(wrong.status).toBe("down");
  });

  it("rejects the homepage path, redirects, unauthorized, and transport failures", async () => {
    expect((await http("https://app.example/", routed({}))).status).toBe("misconfigured");
    const redirected = await http(
      "https://app.example/healthcheck",
      routed({
        "https://app.example/healthcheck": () =>
          new Response(null, {
            status: 302,
            headers: { location: "https://169.254.169.254/healthcheck" },
          }),
      }),
    );
    expect(redirected.status).toBe("misconfigured");
    const denied = await http(
      "https://app.example/healthcheck",
      routed({
        "https://app.example/healthcheck": () => jsonResponse({ error: "no" }, 401),
      }),
    );
    expect(denied.status).toBe("misconfigured");
    const timeout = await http("https://app.example/healthcheck", async () => {
      throw new DOMException("The operation was aborted", "TimeoutError");
    });
    expect(timeout.errorClass).toBe("timeout");
    const dns = await http("https://app.example/healthcheck", async () => {
      throw new Error("getaddrinfo ENOTFOUND");
    });
    expect(dns.errorClass).toBe("dns");
    const tls = await http("https://app.example/healthcheck", async () => {
      throw new Error("tls certificate verify failed");
    });
    expect(tls.errorClass).toBe("tls");
  });
});

const alby = (overrides: Partial<Parameters<typeof runAlbyHubCheck>[0]> = {}) =>
  runAlbyHubCheck({
    baseUrl: "https://hub.example",
    routingProfile: "self_hosted",
    hubName: "",
    hubRegion: "",
    token: "readonly-token",
    privateNetwork: false,
    timeoutMs: 1000,
    fetch: albyFetch(),
    ...overrides,
  });

function albyFetch(
  info: Record<string, unknown> = { version: "1.2.3", running: true, unlocked: true },
  alarms: string[] = [],
  ready = true,
) {
  return routed({
    "https://hub.example/api/info": () => jsonResponse(info),
    "https://hub.example/api/health": () =>
      jsonResponse({ alarms: alarms.map((kind) => ({ kind })) }),
    "https://hub.example/api/node/status": () =>
      jsonResponse({ isReady: ready, internalNodeStatus: "do-not-log" }),
  });
}

describe("alby hub", () => {
  it("accepts a healthy hub and keeps wallet fields out of the summary", async () => {
    const result = await alby();
    expect(result.status).toBe("healthy");
    expect(result.observedVersion).toBe("1.2.3");
    expect(result.summary).not.toContain("do-not-log");
  });

  it("does not treat the shared origin or an info response without a token as healthy", async () => {
    const shared = await alby({ baseUrl: "https://my.albyhub.com", routingProfile: "" });
    expect(shared.status).toBe("misconfigured");
    const missing = await alby({ token: "" });
    expect(missing.status).toBe("misconfigured");
    expect(missing.observedVersion).toBe("1.2.3");
  });

  it("separates node readiness, channel alarms, expired credentials, and schema drift", async () => {
    expect((await alby({ fetch: albyFetch(undefined, [], false) })).errorClass).toBe(
      "node_not_ready",
    );
    expect((await alby({ fetch: albyFetch(undefined, ["channels_offline"]) })).status).toBe(
      "degraded",
    );
    expect((await alby({ fetch: albyFetch(undefined, ["mystery_alarm"]) })).status).toBe("unknown");
    const denied = await alby({
      fetch: routed({
        "https://hub.example/api/info": () =>
          jsonResponse({ version: "1.2.3", running: true, unlocked: false }),
        "https://hub.example/api/health": () => jsonResponse({ error: "expired" }, 401),
        "https://hub.example/api/node/status": () => jsonResponse({ error: "expired" }, 401),
      }),
    });
    expect(denied.status).toBe("misconfigured");
    expect(denied.errorClass).toBe("unauthorized");
  });
});

describe("btcpay", () => {
  it("accepts synchronized public health without a key and distinguishes sync and processor failures", async () => {
    const healthy = await runBtcpayCheck({
      baseUrl: "https://pay.example",
      apiKey: "",
      privateNetwork: false,
      timeoutMs: 1000,
      fetch: routed({
        "https://pay.example/api/v1/health": () => jsonResponse({ synchronized: true }),
      }),
    });
    expect(healthy.status).toBe("degraded");
    expect(healthy.errorClass).toBe("coverage_incomplete");
    expect(healthy.summary).toContain("no read-only key");
    const unsynced = await runBtcpayCheck({
      baseUrl: "https://pay.example",
      apiKey: "read-only",
      privateNetwork: false,
      timeoutMs: 1000,
      fetch: routed({
        "https://pay.example/api/v1/health": () => jsonResponse({ synchronized: true }),
        "https://pay.example/api/v1/server/info": () =>
          jsonResponse({
            version: "2.2.1",
            fullySynched: false,
            onion: "secret.onion",
            syncStatus: [{ available: false, chainHeight: 999 }],
          }),
      }),
    });
    expect(unsynced.status).toBe("degraded");
    expect(unsynced.observedVersion).toBe("2.2.1");
    expect(unsynced.summary).not.toContain("999");
    expect(unsynced.summary).not.toContain("onion");
  });

  it("classifies unauthorized info, schema drift, and an unreachable instance separately", async () => {
    const denied = await runBtcpayCheck({
      baseUrl: "https://pay.example",
      apiKey: "read-only",
      privateNetwork: false,
      timeoutMs: 1000,
      fetch: routed({
        "https://pay.example/api/v1/health": () => jsonResponse({ synchronized: true }),
        "https://pay.example/api/v1/server/info": () => jsonResponse({}, 403),
      }),
    });
    expect(denied.status).toBe("misconfigured");
    const drift = await runBtcpayCheck({
      baseUrl: "https://pay.example",
      apiKey: "",
      privateNetwork: false,
      timeoutMs: 1000,
      fetch: routed({ "https://pay.example/api/v1/health": () => jsonResponse({ ok: true }) }),
    });
    expect(drift.status).toBe("unknown");
    const down = await runBtcpayCheck({
      baseUrl: "https://pay.example",
      apiKey: "",
      privateNetwork: false,
      timeoutMs: 1000,
      fetch: async () => {
        throw new Error("connect failed");
      },
    });
    expect(down.status).toBe("down");
  });
});

describe("heartbeat evaluation", () => {
  const now = 1_700_000_000_000;
  it("treats a fresh idle loop as healthy and frozen work as degraded", () => {
    expect(
      evaluateHeartbeat({
        row: {
          receivedAt: now,
          progressToken: null,
          progressChangedAt: now - 10_000_000,
          idle: true,
          loopAt: now,
        },
        now,
        staleSeconds: 180,
        progressSeconds: 600,
      }).status,
    ).toBe("healthy");
    expect(
      evaluateHeartbeat({
        row: {
          receivedAt: now,
          progressToken: "job-1",
          progressChangedAt: now - 601_000,
          idle: false,
          loopAt: now,
        },
        now,
        staleSeconds: 180,
        progressSeconds: 600,
      }).status,
    ).toBe("degraded");
  });

  it("treats a missing or stale loop as down", () => {
    expect(
      evaluateHeartbeat({ row: null, now, staleSeconds: 180, progressSeconds: 600 }).status,
    ).toBe("down");
    expect(
      evaluateHeartbeat({
        row: {
          receivedAt: now,
          progressToken: "job-1",
          progressChangedAt: now,
          idle: false,
          loopAt: now - 181_000,
        },
        now,
        staleSeconds: 180,
        progressSeconds: 600,
      }).errorClass,
    ).toBe("stale");
  });
});
