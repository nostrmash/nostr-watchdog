import { describe, expect, it } from "vitest";

import { assessAdvisories } from "../../src/updates/advisories";
import { assessSecurity } from "../../src/updates/security";
import { VENDOR_POLICY } from "../../src/updates/vendor-policy";
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

  it("classifies BTCPay policy ranges and security releases without inventing a vulnerability", () => {
    const policy = VENDOR_POLICY.filter((entry) => entry.vendorId === "btcpayserver/btcpayserver");
    const affected = assessSecurity({
      vendorId: "btcpayserver/btcpayserver",
      installed: "2.4.1",
      advisories: [],
      releases: [],
      policy,
    });
    expect(affected.status).toBe("affected");
    expect(affected.summary).toContain("2.4.1");
    const review = assessSecurity({
      vendorId: "btcpayserver/btcpayserver",
      installed: "2.4.3",
      advisories: [],
      releases: [
        {
          tag: "v2.4.7",
          url: "https://github.com/btcpayserver/btcpayserver/releases/tag/v2.4.7",
          prerelease: false,
          draft: false,
          securityRelated: true,
        },
        {
          tag: "v2.4.6",
          url: "https://github.com/btcpayserver/btcpayserver/releases/tag/v2.4.6",
          prerelease: false,
          draft: false,
          securityRelated: false,
        },
      ],
      policy,
    });
    expect(review.status).toBe("review_recommended");
    expect(review.summary).toContain("no verified affected range");
    const current = assessSecurity({
      vendorId: "btcpayserver/btcpayserver",
      installed: "2.4.7",
      advisories: [],
      releases: [
        {
          tag: "v2.4.7",
          url: "https://github.com/btcpayserver/btcpayserver/releases/tag/v2.4.7",
          prerelease: false,
          draft: false,
          securityRelated: true,
        },
      ],
      policy,
    });
    expect(current.status).toBe("no_published_advisories");
    expect(
      assessSecurity({
        vendorId: "btcpayserver/btcpayserver",
        installed: null,
        advisories: [],
        releases: [],
        policy,
      }).status,
    ).toBe("version_unavailable");
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
