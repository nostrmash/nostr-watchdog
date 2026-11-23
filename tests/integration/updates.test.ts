import { env } from "cloudflare:workers";
import { afterEach, describe, expect, it } from "vitest";

import { runUpdateCycle } from "../../src/cycles/updates";
import { githubAffected } from "../fixtures/advisories";
import { hubReleases } from "../fixtures/releases";
import { bind, jsonResponse } from "../helpers";

afterEach(() => {
  bind({
    ENABLE_SFS_ALBY: "false",
    ENABLE_SFS_BTCPAY: "false",
    ALERTS_ENABLED: "true",
    CRITICAL_REMINDER_SECONDS: "0",
  });
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

  it("reports a fresh release when the advisory feed is down", async () => {
    await prepare("sfs-alby-hub", "smartflowsocial", "1.2.0", 1_800_000_000_000);
    bind({ ENABLE_SFS_ALBY: "true", ENABLE_SFS_BTCPAY: "false", ALERTS_ENABLED: "false" });
    await runUpdateCycle(env, splitFeeds(release("v1.9.0", "Bug fixes"), 500, 1_800_000_000_000));
    const rows = await alerts("sfs-alby-hub");
    expect(rows.map((row) => row.alert_class)).toEqual(["update"]);
    const vendor = await vendorRow("sfs-alby-hub");
    expect(vendor?.releases_state).toBe("fresh");
    expect(vendor?.advisories_state).toBe("unavailable");
    expect(vendor?.coverage).toBe("partial");
  });

  it("warns on a security release without waiting for advisories", async () => {
    await prepare("sfs-alby-hub", "smartflowsocial", "1.2.0", 1_810_000_000_000);
    bind({ ENABLE_SFS_ALBY: "true", ENABLE_SFS_BTCPAY: "false", ALERTS_ENABLED: "false" });
    await runUpdateCycle(
      env,
      splitFeeds(release("v1.9.0", "This release fixes a vulnerability"), 500, 1_810_000_000_000),
    );
    const rows = await alerts("sfs-alby-hub");
    expect(rows.map((row) => `${row.alert_class}:${row.severity}`).sort()).toEqual([
      "security:warning",
      "update:info",
    ]);
    expect(rows.find((row) => row.alert_class === "security")?.payload_text).toContain(
      "Review the release notes",
    );
  });

  it("alerts from the verified BTCPay policy when GitHub is unavailable", async () => {
    await prepare("sfs-btcpay", "smartflowsocial", "2.4.0", 1_820_000_000_000);
    bind({ ENABLE_SFS_ALBY: "false", ENABLE_SFS_BTCPAY: "true", ALERTS_ENABLED: "false" });
    await runUpdateCycle(env, {
      now: () => 1_820_000_000_000,
      fetch: async () => new Response("down", { status: 500 }),
    });
    const rows = await alerts("sfs-btcpay");
    expect(rows.map((row) => `${row.alert_class}:${row.severity}`)).toEqual(["security:critical"]);
    expect(rows[0]?.payload_text).toContain("2.4.0");
    const vendor = await vendorRow("sfs-btcpay");
    expect(vendor?.coverage).toBe("policy_only");
    expect(vendor?.releases_state).toBe("unavailable");
  });

  it("uses a fresh advisory when the release feed is down and does not repeat it after recovery", async () => {
    await prepare("sfs-alby-hub", "smartflowsocial", "1.2.0", 1_830_000_000_000);
    bind({ ENABLE_SFS_ALBY: "true", ENABLE_SFS_BTCPAY: "false", ALERTS_ENABLED: "false" });
    await runUpdateCycle(env, splitFeeds(500, githubAffected, 1_830_000_000_000));
    await runUpdateCycle(env, splitFeeds(500, 500, 1_830_003_600_000));
    await runUpdateCycle(env, splitFeeds(release("v1.9.0"), githubAffected, 1_830_007_200_000));
    const rows = await alerts("sfs-alby-hub");
    expect(rows.filter((row) => row.alert_class === "security")).toHaveLength(1);
    expect(rows.filter((row) => row.alert_class === "update")).toHaveLength(1);
  });

  it("marks advisory data stale on rate limit without dropping a fresh release", async () => {
    await prepare("sfs-alby-hub", "smartflowsocial", "1.2.0", 1_840_000_000_000);
    bind({ ENABLE_SFS_ALBY: "true", ENABLE_SFS_BTCPAY: "false", ALERTS_ENABLED: "false" });
    await runUpdateCycle(
      env,
      splitFeeds(release("v1.9.0"), 429, 1_840_000_000_000, { "x-ratelimit-reset": "1840003600" }),
    );
    expect((await alerts("sfs-alby-hub")).map((row) => row.alert_class)).toEqual(["update"]);
    const vendor = await vendorRow("sfs-alby-hub");
    expect(vendor?.releases_state).toBe("fresh");
    expect(vendor?.advisories_state).toBe("unavailable");
    expect(vendor?.error_code).toBe("rate_limited");
  });

  it("does not invent a new alert from cached data during an outage", async () => {
    await prepare("sfs-alby-hub", "smartflowsocial", "1.2.0", 1_850_000_000_000);
    bind({ ENABLE_SFS_ALBY: "true", ENABLE_SFS_BTCPAY: "false", ALERTS_ENABLED: "false" });
    await runUpdateCycle(env, splitFeeds(release("v1.9.0"), githubAffected, 1_850_000_000_000));
    await env.DB.prepare("DELETE FROM alert_outbox WHERE monitor_id = ?")
      .bind("sfs-alby-hub")
      .run();
    await runUpdateCycle(env, {
      now: () => 1_850_003_600_000,
      fetch: async () => new Response("down", { status: 500 }),
    });
    expect(await alerts("sfs-alby-hub")).toEqual([]);
    const version = await env.DB.prepare(
      "SELECT security_status FROM observed_versions WHERE monitor_id = ?",
    )
      .bind("sfs-alby-hub")
      .first<{ security_status: string }>();
    expect(version?.security_status).toBe("affected");
  });

  it("warns when feeds are fresh but the installed version is unknown", async () => {
    await prepare("sfs-alby-hub", "smartflowsocial", null, 1_860_000_000_000);
    bind({ ENABLE_SFS_ALBY: "true", ENABLE_SFS_BTCPAY: "false", ALERTS_ENABLED: "false" });
    await runUpdateCycle(env, splitFeeds(release("v1.9.0"), [], 1_860_000_000_000));
    const rows = await alerts("sfs-alby-hub");
    expect(rows.map((row) => `${row.alert_class}:${row.severity}`)).toEqual(["security:warning"]);
    expect(rows[0]?.payload_text).not.toContain("matches a confirmed affected range");
    const vendor = await vendorRow("sfs-alby-hub");
    expect(vendor?.coverage).toBe("incomplete");
    expect(vendor?.error_code).toBe("coverage_incomplete");
  });

  it("treats not-modified and malformed bodies independently", async () => {
    await prepare("sfs-alby-hub", "smartflowsocial", "1.2.0", 1_870_000_000_000);
    bind({ ENABLE_SFS_ALBY: "true", ENABLE_SFS_BTCPAY: "false", ALERTS_ENABLED: "false" });
    let phase: "first" | "not_modified" | "malformed" = "first";
    const deps = {
      now: () => 1_870_000_000_000,
      fetch: async (input: RequestInfo | URL) => {
        const url = String(input);
        if (phase === "malformed") return new Response("{", { status: 200 });
        if (phase === "not_modified")
          return new Response(null, { status: 304, headers: { etag: '"same"' } });
        const body = url.includes("/releases") ? release("v1.9.0") : githubAffected;
        return jsonResponse(body, 200, { etag: '"same"' });
      },
    };
    await runUpdateCycle(env, deps);
    phase = "not_modified";
    deps.now = () => 1_870_003_600_000;
    await runUpdateCycle(env, deps);
    expect(await alerts("sfs-alby-hub")).toHaveLength(2);
    phase = "malformed";
    deps.now = () => 1_870_007_200_000;
    await runUpdateCycle(env, deps);
    expect(await alerts("sfs-alby-hub")).toHaveLength(2);
    const vendor = await vendorRow("sfs-alby-hub");
    expect(vendor?.releases_state).toBe("cached");
  });

  it("does not refresh a complete security check while one feed stays down", async () => {
    const start = 1_880_000_000_000;
    await prepare("sfs-alby-hub", "smartflowsocial", "1.2.0", start);
    bind({ ENABLE_SFS_ALBY: "true", ENABLE_SFS_BTCPAY: "false", ALERTS_ENABLED: "false" });
    await runUpdateCycle(env, splitFeeds(release("v1.9.0"), githubAffected, start));
    const complete = await vendorTimes("sfs-alby-hub");
    expect(complete?.succeeded_at).toBe(start);
    expect(complete?.coverage).toBe("complete");
    for (let hour = 1; hour <= 3; hour += 1) {
      await runUpdateCycle(env, splitFeeds(release("v1.9.0"), 500, start + hour * 3_600_000));
    }
    const stalled = await vendorTimes("sfs-alby-hub");
    expect(stalled?.succeeded_at).toBe(start);
    expect(stalled?.advisories_failures).toBe(3);
    expect(stalled?.releases_failures).toBe(0);
    expect(stalled?.coverage).toBe("partial");
    expect(stalled?.partial_succeeded_at).toBe(start + 3 * 3_600_000);
    const run = await env.DB.prepare(
      "SELECT last_success_at, last_error FROM scheduler_runs WHERE job_name = 'updates'",
    ).first<{ last_success_at: number | null; last_error: string | null }>();
    expect(run?.last_success_at).toBe(start);
    expect(run?.last_error).toBe("coverage_partial");
    const before = (await alerts("sfs-alby-hub")).length;
    await runUpdateCycle(env, splitFeeds(release("v1.9.0"), githubAffected, start + 4 * 3_600_000));
    const recovered = await vendorTimes("sfs-alby-hub");
    expect(recovered?.succeeded_at).toBe(start + 4 * 3_600_000);
    expect(recovered?.advisories_failures).toBe(0);
    expect(recovered?.coverage).toBe("complete");
    expect(await alerts("sfs-alby-hub")).toHaveLength(before);
  });

  it("repeats one confirmed finding after the reminder interval without duplicating it inside that interval", async () => {
    const start = 1_890_000_000_000;
    await prepare("sfs-alby-hub", "smartflowsocial", "1.2.0", start);
    bind({
      ENABLE_SFS_ALBY: "true",
      ENABLE_SFS_BTCPAY: "false",
      ALERTS_ENABLED: "false",
      CRITICAL_REMINDER_SECONDS: "3600",
    });
    await runUpdateCycle(env, splitFeeds(release("v1.9.0"), githubAffected, start));
    await runUpdateCycle(env, splitFeeds(release("v1.9.0"), githubAffected, start + 3_600_000));
    await runUpdateCycle(
      env,
      splitFeeds(release("v1.9.0"), githubAffected, start + 3_600_000 + 1_000),
    );
    const rows = await alerts("sfs-alby-hub");
    expect(rows.filter((row) => row.alert_class === "security")).toHaveLength(1);
    expect(rows.filter((row) => row.alert_class === "reminder")).toHaveLength(1);
    expect(rows.find((row) => row.alert_class === "reminder")?.payload_text).toContain(
      "still open",
    );
  });
});

function release(tag: string, body = "Bug fixes") {
  return [
    {
      tag_name: tag,
      html_url: `https://github.com/getAlby/hub/releases/tag/${tag}`,
      name: tag,
      body,
      prerelease: false,
      draft: false,
    },
  ];
}

function splitFeeds(
  releases: unknown,
  advisories: unknown,
  now: number,
  extraHeaders: Record<string, string> = {},
) {
  return {
    now: () => now,
    fetch: async (input: RequestInfo | URL) => {
      const url = String(input);
      const status = url.includes("/releases")
        ? typeof releases === "number"
          ? releases
          : 200
        : typeof advisories === "number"
          ? advisories
          : 200;
      const body = url.includes("/releases") ? releases : advisories;
      if (typeof body === "number") {
        return new Response("upstream", { status: body, headers: extraHeaders });
      }
      return jsonResponse(body, status, { etag: '"feed"' });
    },
  };
}

async function prepare(id: string, project: string, version: string | null, now: number) {
  await env.DB.prepare("DELETE FROM alert_outbox WHERE monitor_id = ?").bind(id).run();
  await env.DB.prepare("DELETE FROM observed_versions WHERE monitor_id = ?").bind(id).run();
  await env.DB.prepare("DELETE FROM vendor_checks WHERE monitor_id = ?").bind(id).run();
  await env.DB.prepare("DELETE FROM upstream_cache").run();
  await env.DB.prepare("DELETE FROM scheduler_runs WHERE job_name = ?").bind("updates").run();
  if (version === null) {
    await env.DB.prepare("DELETE FROM monitor_state WHERE monitor_id = ?").bind(id).run();
    return;
  }
  await env.DB.prepare(
    `INSERT INTO monitor_state (monitor_id, project_id, observed_version, generation, updated_at)
     VALUES (?, ?, ?, 1, ?)
     ON CONFLICT(monitor_id) DO UPDATE SET observed_version = excluded.observed_version, updated_at = excluded.updated_at`,
  )
    .bind(id, project, version, now)
    .run();
}

async function alerts(id: string) {
  const rows = await env.DB.prepare(
    "SELECT alert_class, severity, payload_text FROM alert_outbox WHERE monitor_id = ? ORDER BY alert_class, severity",
  )
    .bind(id)
    .all<{ alert_class: string; severity: string; payload_text: string }>();
  return rows.results;
}

async function vendorTimes(id: string) {
  return env.DB.prepare(
    `SELECT succeeded_at, partial_succeeded_at, releases_failures, advisories_failures, coverage
     FROM vendor_checks WHERE monitor_id = ?`,
  )
    .bind(id)
    .first<{
      succeeded_at: number | null;
      partial_succeeded_at: number | null;
      releases_failures: number;
      advisories_failures: number;
      coverage: string;
    }>();
}

async function vendorRow(id: string) {
  return env.DB.prepare(
    "SELECT releases_state, advisories_state, coverage, error_code FROM vendor_checks WHERE monitor_id = ?",
  )
    .bind(id)
    .first<{
      releases_state: string;
      advisories_state: string;
      coverage: string;
      error_code: string | null;
    }>();
}
