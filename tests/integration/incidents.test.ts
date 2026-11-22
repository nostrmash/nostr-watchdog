import { env } from "cloudflare:workers";
import { afterEach, describe, expect, it } from "vitest";

import { runCheckCycle } from "../../src/cycles/checks";
import { acquireLease } from "../../src/state/store";
import { bind, jsonResponse } from "../helpers";

const ready = "https://app.example/healthcheck";

afterEach(() => {
  bind({
    ENABLE_SFS_WEB: "false",
    SFS_WEB_READY_URL: "",
    ALERTS_ENABLED: "true",
    BOOTSTRAP_RELAYS: "",
    CRITICAL_REMINDER_SECONDS: "0",
  });
});

function deps(status: number, body: unknown, now: { value: number }) {
  let calls = 0;
  return {
    calls: () => calls,
    deps: {
      now: () => now.value,
      fetch: async () => {
        calls += 1;
        return jsonResponse(body, status);
      },
    },
  };
}

describe("check cycle", () => {
  it("opens one outage after two failures, suppresses duplicates, and recovers after two successes", async () => {
    bind({ ENABLE_SFS_WEB: "true", SFS_WEB_READY_URL: ready, ALERTS_ENABLED: "false" });
    const now = { value: 1_700_000_000_000 };
    const failing = deps(503, { status: "down" }, now);
    await runCheckCycle(env, failing.deps);
    now.value += 60_000;
    await runCheckCycle(env, failing.deps);
    now.value += 60_000;
    await runCheckCycle(env, failing.deps);
    const open = await env.DB.prepare(
      "SELECT id, severity FROM incidents WHERE monitor_id = ? AND status = 'open'",
    )
      .bind("sfs-web")
      .all();
    expect(open.results).toHaveLength(1);
    const alerts = await env.DB.prepare(
      "SELECT COUNT(*) AS count FROM alert_outbox WHERE monitor_id = ?",
    )
      .bind("sfs-web")
      .first<{ count: number }>();
    expect(alerts?.count).toBe(1);
    const healthy = deps(200, { status: "ok" }, now);
    now.value += 60_000;
    await runCheckCycle(env, healthy.deps);
    now.value += 60_000;
    await runCheckCycle(env, healthy.deps);
    const closed = await env.DB.prepare("SELECT status FROM incidents WHERE monitor_id = ?")
      .bind("sfs-web")
      .all<{ status: string }>();
    expect(closed.results.map((row) => row.status)).toEqual(["closed"]);
    const recovery = await env.DB.prepare(
      "SELECT alert_class FROM alert_outbox WHERE monitor_id = ? ORDER BY created_at",
    )
      .bind("sfs-web")
      .all<{ alert_class: string }>();
    expect(recovery.results.map((row) => row.alert_class)).toEqual(["outage", "recovery"]);
  });

  it("does not probe while another run holds the lease and does not mark a skipped check healthy", async () => {
    bind({ ENABLE_SFS_WEB: "true", SFS_WEB_READY_URL: ready, ALERTS_ENABLED: "false" });
    const now = { value: 1_800_000_000_000 };
    const probe = deps(503, { status: "down" }, now);
    await runCheckCycle(env, probe.deps);
    expect(probe.calls()).toBe(1);
    await acquireLease(env.DB, "checks", "other-runner", now.value + 50_000, now.value);
    await runCheckCycle(env, probe.deps);
    expect(probe.calls()).toBe(1);
    const state = await env.DB.prepare(
      "SELECT consecutive_failures, status FROM monitor_state WHERE monitor_id = ?",
    )
      .bind("sfs-web")
      .first<{ consecutive_failures: number; status: string }>();
    expect(state).toEqual({ consecutive_failures: 1, status: "down" });
  });

  it("lets one of two overlapping runs probe the monitor", async () => {
    bind({ ENABLE_SFS_WEB: "true", SFS_WEB_READY_URL: ready, ALERTS_ENABLED: "false" });
    const now = { value: 1_900_000_000_000 };
    const probe = deps(200, { status: "ok" }, now);
    await Promise.all([runCheckCycle(env, probe.deps), runCheckCycle(env, probe.deps)]);
    expect(probe.calls()).toBe(1);
    const rows = await env.DB.prepare(
      "SELECT COUNT(*) AS count FROM monitor_state WHERE monitor_id = ?",
    )
      .bind("sfs-web")
      .first<{ count: number }>();
    expect(rows?.count).toBe(1);
  });
});
