import { env } from "cloudflare:workers";
import { createExecutionContext, waitOnExecutionContext } from "cloudflare:test";
import { describe, expect, it } from "vitest";

import worker from "../../src/index";

describe("scheduled entrypoint", () => {
  it("runs the minute check cycle without probing disabled monitors", async () => {
    const ctx = createExecutionContext();
    const scheduledTime = 1_780_000_000_000;
    const controller: ScheduledController = { cron: "* * * * *", scheduledTime, noRetry() {} };
    await worker.scheduled(controller, env, ctx);
    await waitOnExecutionContext(ctx);
    const row = await env.DB.prepare(
      "SELECT last_finished_at FROM scheduler_runs WHERE job_name = ?",
    )
      .bind("checks")
      .first<{ last_finished_at: number | null }>();
    expect(row?.last_finished_at).not.toBeNull();
    const monitors = await env.DB.prepare("SELECT COUNT(*) AS count FROM monitor_state").first<{
      count: number;
    }>();
    expect(monitors?.count ?? 0).toBe(0);
  });
});
