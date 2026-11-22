import { describe, expect, it } from "vitest";

import { assessAdvisories } from "../../src/updates/advisories";
import { fetchAdvisories, fetchReleases } from "../../src/updates/github";
import { jsonResponse } from "../helpers";
import { affectedAdvisory, reviewAdvisory } from "../fixtures/advisories";
import { hubReleases } from "../fixtures/releases";

const input = {
  apiBase: "https://api.github.com",
  owner: "getAlby",
  repo: "hub",
  token: "",
  etag: null,
};

describe("advisories", () => {
  it("confirms an affected version from a structured range", () => {
    const result = assessAdvisories("1.2.0", [affectedAdvisory]);
    expect(result.status).toBe("affected");
    expect(result.fingerprint).toContain("GHSA-1111-2222-3333");
    expect(result.summary).toContain("1.2.0");
  });

  it("does not call a newer unaffected version secure when the range excludes it", () => {
    const result = assessAdvisories("3.0.0", [affectedAdvisory]);
    expect(result.status).toBe("outside_published_ranges");
    expect(result.summary).toContain("not a claim");
  });

  it("recommends review when the range cannot be parsed", () => {
    const result = assessAdvisories("1.2.0", [reviewAdvisory]);
    expect(result.status).toBe("review_recommended");
    expect(result.summary).toContain("Security review is recommended");
  });

  it("keeps an empty feed distinct from a claim of safety", () => {
    const result = assessAdvisories("1.2.0", []);
    expect(result.status).toBe("no_published_advisories");
    expect(result.summary).toContain("not a claim");
  });

  it("reports unknown when the feed is unavailable", () => {
    expect(assessAdvisories("1.2.0", null).status).toBe("unknown");
  });

  it("parses official releases and ignores non-github urls", async () => {
    const fetched = await fetchReleases({
      ...input,
      fetch: async () => jsonResponse(hubReleases, 200, { etag: '"rel"' }),
    });
    expect(fetched.kind).toBe("ok");
    if (fetched.kind !== "ok") return;
    expect(fetched.releases?.map((item) => item.tag)).toEqual(["v2.0.0-rc.1", "v1.9.0"]);
  });

  it("treats GitHub 403 and 429 as rate limits and 304 as not modified", async () => {
    const limited = await fetchAdvisories({
      ...input,
      fetch: async () =>
        new Response("", { status: 429, headers: { "x-ratelimit-reset": "1700003600" } }),
    });
    expect(limited).toEqual({ kind: "rate_limited", retryAt: 1_700_003_600_000 });
    const cached = await fetchReleases({
      ...input,
      etag: '"rel"',
      fetch: async () => new Response(null, { status: 304 }),
    });
    expect(cached.kind).toBe("not_modified");
  });
});
