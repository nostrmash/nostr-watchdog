import { env } from "cloudflare:workers";
import { afterEach, describe, expect, it } from "vitest";

import { loadSettings } from "../../src/config/settings";
import { deriveOperationalStatus } from "../../src/http/status";
import type { OperationalSnapshot } from "../../src/state/store";
import { bind } from "../helpers";

const NOW = 1_700_000_000_000;

function empty(): OperationalSnapshot {
  return { states: [], openIncidents: 0, outbox: [], errors: [], runs: [], heartbeats: [] };
}

function derive(snapshot: OperationalSnapshot = empty()) {
  return deriveOperationalStatus({
    env,
    settings: loadSettings(env),
    now: NOW,
    snapshot,
  });
}

afterEach(() => {
  bind({
    WATCHDOG_ENABLED: "true",
    ALERTS_ENABLED: "true",
    ENABLE_SFS_WEB: "false",
    ENABLE_SFS_WORKER: "false",
    ENABLE_SFS_ALBY: "false",
    BOOTSTRAP_RELAYS: "",
    SFS_BOT_NSEC: "",
    PROJECT_RECIPIENTS: "{}",
    ADMIN_NPUB: "",
    TELEGRAM_BOT_TOKEN: "",
    TELEGRAM_CHAT_IDS: "",
  });
});

describe("operational status", () => {
  it("is not configured when every monitor is disabled", () => {
    const result = derive();
    expect(result.status).toBe("not_configured");
    expect(result.httpStatus).toBe(503);
    expect(result.body.contract).toBe("watchdog-status-v1");
  });

  it("is disabled when monitoring is turned off, even if a monitor is enabled", () => {
    bind({ WATCHDOG_ENABLED: "false", ENABLE_SFS_WEB: "true" });
    expect(derive().status).toBe("disabled");
  });

  it("is misconfigured when alerts are enabled without a sender, recipient, and bootstrap relays", () => {
    bind({ ENABLE_SFS_WEB: "true" });
    const result = derive();
    expect(result.status).toBe("misconfigured");
    expect(result.body.delivery).toMatchObject({
      destinationsConfigured: { nostr: false, telegram: false },
    });
  });

  it("is unhealthy when an enabled monitor has never completed a check", () => {
    bind({ ENABLE_SFS_WEB: "true", ALERTS_ENABLED: "false" });
    const result = derive({
      ...empty(),
      states: [{ monitorId: "sfs-web", status: "healthy", lastCheckAt: NOW }],
    });
    expect(result.status).toBe("unhealthy");
    expect(result.body.lastCycleAgeMs).toBeNull();
  });

  it("is degraded by dead letters and healthy when the scheduler is current and alerts are off", () => {
    bind({
      ENABLE_SFS_WEB: "true",
      ENABLE_SFS_WORKER: "true",
      ENABLE_SFS_ALBY: "true",
      ALERTS_ENABLED: "false",
    });
    const recent = {
      ...empty(),
      states: [
        { monitorId: "sfs-web", status: "down" as const, lastCheckAt: NOW },
        { monitorId: "sfs-worker", status: "other", lastCheckAt: NOW },
      ],
      outbox: [
        { state: "failed", count: 1 },
        { state: "retrying", count: 1 },
      ],
      errors: [
        { error: "relay_rejected", count: 2 },
        { error: "not_a_known_code", count: 1 },
      ],
      runs: [
        { name: "checks", startedAt: NOW - 10_000, finishedAt: NOW - 1_000, error: null },
        { name: "updates", startedAt: NOW - 10_000, finishedAt: NOW - 1_000, error: "disabled" },
      ],
      heartbeats: [{ monitorId: "sfs-worker", receivedAt: NOW - 1_000_000 }],
      openIncidents: 1,
    };
    const degraded = derive(recent);
    expect(degraded.status).toBe("degraded");
    expect(degraded.body.deadLetters).toBe(1);
    expect(degraded.body.heartbeats).toEqual({ stale: 1, missing: 0 });
    expect(derive({ ...recent, heartbeats: [] }).body.heartbeats).toEqual({
      stale: 0,
      missing: 1,
    });
    expect(
      derive({
        ...recent,
        outbox: [],
        states: [{ monitorId: "sfs-web", status: "misconfigured", lastCheckAt: NOW }],
      }).status,
    ).toBe("misconfigured");
    expect(degraded.body.delivery).toMatchObject({ recentErrors: { relay_rejected: 2 } });
    const healthy = derive({
      ...recent,
      outbox: [],
      errors: [],
      heartbeats: [{ monitorId: "sfs-worker", receivedAt: NOW }],
    });
    expect(healthy.status).toBe("healthy");
    expect(healthy.httpStatus).toBe(200);
    const failedRun = derive({
      ...recent,
      outbox: [],
      runs: [
        { name: "checks", startedAt: NOW - 10_000, finishedAt: NOW - 1_000, error: "cycle_failed" },
      ],
    });
    expect(failedRun.status).toBe("degraded");
  });
});
