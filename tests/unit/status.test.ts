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
    bind({ ENABLE_SFS_ALBY: "false" });
    const alertsOff = derive({
      ...recent,
      outbox: [],
      errors: [],
      heartbeats: [{ monitorId: "sfs-worker", receivedAt: NOW }],
    });
    expect(alertsOff.status).toBe("alerts_disabled");
    expect(alertsOff.httpStatus).toBe(503);
    expect(alertsOff.body.alertsEnabled).toBe(false);
    const failedRun = derive({
      ...recent,
      outbox: [],
      runs: [
        { name: "checks", startedAt: NOW - 10_000, finishedAt: NOW - 1_000, error: "cycle_failed" },
      ],
    });
    expect(failedRun.status).toBe("degraded");
  });

  it("stays healthy while a customer monitor is down and alerts are configured", () => {
    bind({
      ENABLE_SFS_WEB: "true",
      ALERTS_ENABLED: "true",
      SFS_BOT_NSEC: "nsec-test",
      ADMIN_NPUB: "npub-test",
      BOOTSTRAP_RELAYS: "wss://relay.example",
    });
    const result = derive({
      ...empty(),
      states: [{ monitorId: "sfs-web", status: "down", lastCheckAt: NOW }],
      openIncidents: 1,
      runs: [
        {
          name: "checks",
          startedAt: NOW - 10_000,
          finishedAt: NOW - 1_000,
          successAt: NOW - 1_000,
          error: null,
        },
      ],
    });
    expect(result.status).toBe("healthy");
    expect(result.httpStatus).toBe(200);
    expect(result.body.monitors).toMatchObject({ down: 1 });
  });

  it("degrades when a required security-update cycle has not succeeded", () => {
    bind({
      ENABLE_SFS_ALBY: "true",
      ALERTS_ENABLED: "true",
      SFS_BOT_NSEC: "nsec-test",
      ADMIN_NPUB: "npub-test",
      BOOTSTRAP_RELAYS: "wss://relay.example",
    });
    const missing = derive({
      ...empty(),
      runs: [
        {
          name: "checks",
          startedAt: NOW - 10_000,
          finishedAt: NOW - 1_000,
          successAt: NOW - 1_000,
          error: null,
        },
        {
          name: "updates",
          startedAt: NOW - 10_000,
          finishedAt: NOW - 1_000,
          successAt: null,
          error: "vendor_checks_failed",
        },
      ],
      vendorChecks: [
        {
          monitorId: "sfs-alby-hub",
          vendor: "getAlby/hub",
          attemptedAt: NOW - 1_000,
          succeededAt: null,
          releasesCheckedAt: null,
          advisoriesCheckedAt: null,
          releasesStale: true,
          advisoriesStale: true,
          releasesState: "unavailable",
          advisoriesState: "unavailable",
          coverage: "unavailable",
          errorCode: "unavailable",
          consecutiveFailures: 3,
          partialSucceededAt: null,
          releasesFailures: 3,
          advisoriesFailures: 3,
        },
      ],
    });
    expect(missing.status).toBe("degraded");
    const incomplete = derive({
      ...empty(),
      runs: [
        {
          name: "checks",
          startedAt: NOW - 10_000,
          finishedAt: NOW - 1_000,
          successAt: NOW - 1_000,
          error: null,
        },
        {
          name: "updates",
          startedAt: NOW - 10_000,
          finishedAt: NOW - 1_000,
          successAt: null,
          error: "coverage_incomplete",
        },
      ],
      vendorChecks: [
        {
          monitorId: "sfs-alby-hub",
          vendor: "getAlby/hub",
          attemptedAt: NOW - 1_000,
          succeededAt: null,
          releasesCheckedAt: NOW - 1_000,
          advisoriesCheckedAt: NOW - 1_000,
          releasesStale: false,
          advisoriesStale: false,
          releasesState: "fresh",
          advisoriesState: "fresh",
          coverage: "incomplete",
          errorCode: "coverage_incomplete",
          consecutiveFailures: 0,
          partialSucceededAt: null,
          releasesFailures: 0,
          advisoriesFailures: 0,
        },
      ],
    });
    expect(incomplete.status).toBe("degraded");
    expect(incomplete.body.securityChecks).toMatchObject([{ coverage: "incomplete" }]);
    expect(missing.body.securityChecks).toMatchObject([
      { monitorId: "sfs-alby-hub", errorCode: "unavailable", consecutiveFailures: 3 },
    ]);
    const staleSuccess = derive({
      ...empty(),
      runs: [
        {
          name: "checks",
          startedAt: NOW - 10_000,
          finishedAt: NOW - 1_000,
          successAt: NOW - 1_000,
          error: null,
        },
        {
          name: "updates",
          startedAt: NOW - 1_000,
          finishedAt: NOW - 1_000,
          successAt: NOW - 7 * 3_600_000,
          error: null,
        },
      ],
    });
    expect(staleSuccess.status).toBe("unhealthy");
  });

  it("keeps a fresh partial security check healthy and degrades it after the source grace", () => {
    bind({
      ENABLE_SFS_ALBY: "true",
      ALERTS_ENABLED: "true",
      SFS_BOT_NSEC: "nsec-test",
      ADMIN_NPUB: "npub-test",
      BOOTSTRAP_RELAYS: "wss://relay.example",
    });
    const base = {
      ...empty(),
      states: [{ monitorId: "sfs-alby-hub", status: "healthy", lastCheckAt: NOW }],
      runs: [
        {
          name: "checks",
          startedAt: NOW - 10_000,
          finishedAt: NOW - 1_000,
          successAt: NOW - 1_000,
          error: null,
        },
        {
          name: "updates",
          startedAt: NOW - 30 * 60_000,
          finishedAt: NOW - 30 * 60_000,
          successAt: NOW - 30 * 60_000,
          error: "coverage_partial",
        },
      ],
    };
    const withinGrace = derive({
      ...base,
      vendorChecks: [
        {
          monitorId: "sfs-alby-hub",
          vendor: "getAlby/hub",
          attemptedAt: NOW - 30 * 60_000,
          succeededAt: NOW - 30 * 60_000,
          partialSucceededAt: NOW - 30 * 60_000,
          releasesCheckedAt: NOW - 30 * 60_000,
          advisoriesCheckedAt: NOW - 30 * 60_000,
          releasesStale: false,
          advisoriesStale: true,
          releasesState: "fresh",
          advisoriesState: "unavailable",
          coverage: "partial",
          errorCode: "unavailable",
          consecutiveFailures: 0,
          releasesFailures: 0,
          advisoriesFailures: 1,
        },
      ],
    });
    expect(withinGrace.status).toBe("healthy");
    const persistent = derive({
      ...base,
      runs: [
        base.runs[0]!,
        {
          name: "updates",
          startedAt: NOW - 3 * 3_600_000,
          finishedAt: NOW - 1_000,
          successAt: NOW - 3 * 3_600_000,
          error: "coverage_partial",
        },
      ],
      vendorChecks: [
        {
          monitorId: "sfs-alby-hub",
          vendor: "getAlby/hub",
          attemptedAt: NOW - 1_000,
          succeededAt: NOW - 3 * 3_600_000,
          partialSucceededAt: NOW - 1_000,
          releasesCheckedAt: NOW - 1_000,
          advisoriesCheckedAt: NOW - 3 * 3_600_000,
          releasesStale: false,
          advisoriesStale: true,
          releasesState: "fresh",
          advisoriesState: "unavailable",
          coverage: "partial",
          errorCode: "unavailable",
          consecutiveFailures: 0,
          releasesFailures: 0,
          advisoriesFailures: 3,
        },
      ],
    });
    expect(persistent.status).toBe("degraded");
    expect(persistent.body.securityChecks).toMatchObject([
      { advisoriesFailures: 3, coverage: "partial" },
    ]);
  });

  it("ignores disabled-monitor history and reports a stale enabled result on its own", () => {
    bind({
      ENABLE_SFS_WEB: "true",
      ALERTS_ENABLED: "true",
      SFS_BOT_NSEC: "nsec-test",
      ADMIN_NPUB: "npub-test",
      BOOTSTRAP_RELAYS: "wss://relay.example",
    });
    const historical = derive({
      ...empty(),
      states: [{ monitorId: "sfs-web", status: "healthy", lastCheckAt: NOW }],
      runs: [
        {
          name: "checks",
          startedAt: NOW - 10_000,
          finishedAt: NOW - 1_000,
          successAt: NOW - 1_000,
          error: null,
        },
      ],
      openIncidents: 4,
      openIncidentMonitorIds: ["sfs-alby-hub", "sfs-btcpay"],
      outbox: [{ state: "failed", count: 2 }],
      outboxByMonitor: [{ monitorId: "sfs-alby-hub", state: "failed", count: 2 }],
      vendorChecks: [
        {
          monitorId: "sfs-alby-hub",
          vendor: "getAlby/hub",
          attemptedAt: NOW,
          succeededAt: null,
          partialSucceededAt: null,
          releasesCheckedAt: null,
          advisoriesCheckedAt: null,
          releasesStale: true,
          advisoriesStale: true,
          releasesState: "unavailable",
          advisoriesState: "unavailable",
          coverage: "unavailable",
          errorCode: "unavailable",
          consecutiveFailures: 9,
          releasesFailures: 9,
          advisoriesFailures: 9,
        },
      ],
    });
    expect(historical.status).toBe("healthy");
    expect(historical.body.deadLetters).toBe(0);
    expect(historical.body.inactiveDeadLetters).toBe(2);
    expect(historical.body.openIncidents).toBe(0);
    expect(historical.body.inactiveOpenIncidents).toBe(2);
    expect(historical.body.securityChecks).toEqual([]);
    const staleResult = derive({
      ...empty(),
      states: [{ monitorId: "sfs-web", status: "healthy", lastCheckAt: NOW - 10 * 60_000 }],
      runs: [
        {
          name: "checks",
          startedAt: NOW - 10_000,
          finishedAt: NOW - 1_000,
          successAt: NOW - 1_000,
          error: null,
        },
      ],
    });
    expect(staleResult.status).toBe("degraded");
    expect(staleResult.body.staleMonitorResults).toBe(1);
    expect(staleResult.body.monitors).toMatchObject({ healthy: 1 });
  });
});
