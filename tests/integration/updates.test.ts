import { env } from "cloudflare:workers";
import { afterEach, describe, expect, it } from "vitest";

import { runUpdateCycle } from "../../src/cycles/updates";
import { githubAffected } from "../fixtures/advisories";
import { hubReleases } from "../fixtures/releases";
import { bind, jsonResponse } from "../helpers";

afterEach(() => {
  bind({ ENABLE_SFS_ALBY: "false", ALERTS_ENABLED: "true" });
});

function github(releases: unknown, advisories: unknown, status = 200) {
  const calls: string[] = [];
  return {
    calls,
    deps: {
      now: () => 1_750_000_000_000,
      fetch: async (input: RequestInfo | URL) => {
        const url = String(input);
        calls.push(url);
        if (url.includes("/releases")) return jsonResponse(releases, status, { etag: '"rel"' });
        if (url.includes("/security-advisories"))
          return jsonResponse(advisories, status, { etag: '"adv"' });
        throw new Error(`unexpected ${url}`);
      },
    },
  };
}

describe("update cycle", () => {
  it("sends one update notice and one confirmed security alert, then deduplicates them", async () => {
    bind({ ENABLE_SFS_ALBY: "true", ALERTS_ENABLED: "false" });
    await env.DB.prepare(
      "INSERT INTO monitor_state (monitor_id, project_id, observed_version, generation, updated_at) VALUES (?, ?, ?, 1, ?)",
    )
      .bind("sfs-alby-hub", "smartflowsocial", "1.2.0", 1_750_000_000_000)
      .run();
    const feed = github(hubReleases, githubAffected);
    await runUpdateCycle(env, feed.deps);
    await runUpdateCycle(env, { ...feed.deps, now: () => 1_750_003_600_000 });
    const rows = await env.DB.prepare(
      "SELECT alert_class, severity, payload_text FROM alert_outbox WHERE monitor_id = ? ORDER BY alert_class",
    )
      .bind("sfs-alby-hub")
      .all<{ alert_class: string; severity: string; payload_text: string }>();
    expect(rows.results.map((row) => `${row.alert_class}:${row.severity}`)).toEqual([
      "security:critical",
      "update:info",
    ]);
    expect(rows.results.find((row) => row.alert_class === "security")?.payload_text).toContain(
      "1.2.0",
    );
    expect(feed.calls.length).toBeGreaterThan(0);
  });

  it("keeps security status unknown when the feed fails and does not call that state secure", async () => {
    bind({ ENABLE_SFS_ALBY: "true", ALERTS_ENABLED: "false" });
    await env.DB.prepare("DELETE FROM observed_versions WHERE monitor_id = ?")
      .bind("sfs-alby-hub")
      .run();
    await env.DB.prepare("DELETE FROM upstream_cache").run();
    await env.DB.prepare(
      "INSERT INTO monitor_state (monitor_id, project_id, observed_version, generation, updated_at) VALUES (?, ?, ?, 1, ?) ON CONFLICT(monitor_id) DO UPDATE SET observed_version = excluded.observed_version",
    )
      .bind("sfs-alby-hub", "smartflowsocial", "3.0.0", 1_760_000_000_000)
      .run();
    await runUpdateCycle(env, {
      now: () => 1_760_000_000_000,
      fetch: async () => new Response("no", { status: 500 }),
    });
    const version = await env.DB.prepare(
      "SELECT security_status FROM observed_versions WHERE monitor_id = ?",
    )
      .bind("sfs-alby-hub")
      .first<{ security_status: string }>();
    expect(version?.security_status).toBe("unknown");
    const alerts = await env.DB.prepare(
      "SELECT COUNT(*) AS count FROM alert_outbox WHERE monitor_id = ? AND alert_class = 'security' AND created_at >= ?",
    )
      .bind("sfs-alby-hub", 1_760_000_000_000)
      .first<{ count: number }>();
    expect(alerts?.count).toBe(0);
  });

  it("does not hammer GitHub while a rate limit is cached", async () => {
    bind({ ENABLE_SFS_ALBY: "true", ALERTS_ENABLED: "false" });
    let calls = 0;
    const deps = {
      now: () => 1_770_000_000_000,
      fetch: async () => {
        calls += 1;
        return new Response("", { status: 429, headers: { "x-ratelimit-reset": "1770003600" } });
      },
    };
    await runUpdateCycle(env, deps);
    expect(calls).toBeGreaterThan(0);
    const afterFirst = calls;
    await runUpdateCycle(env, deps);
    expect(calls).toBe(afterFirst);
  });
});
