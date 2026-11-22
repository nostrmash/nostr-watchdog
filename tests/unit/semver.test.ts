import { describe, expect, it } from "vitest";

import {
  compareSemVer,
  latestStable,
  parseSemVer,
  satisfiesRange,
  updateAvailable,
} from "../../src/updates/semver";

describe("semver", () => {
  it("parses stable, v-prefixed, prerelease, and build metadata", () => {
    expect(parseSemVer("v1.2.3")).toEqual({ major: 1, minor: 2, patch: 3, prerelease: [] });
    expect(parseSemVer("1.2.3-rc.1")).toEqual({
      major: 1,
      minor: 2,
      patch: 3,
      prerelease: ["rc", "1"],
    });
    expect(parseSemVer("1.2.3+build.7")?.prerelease).toEqual([]);
  });

  it("rejects leading zeros, incomplete versions, and custom builds", () => {
    expect(parseSemVer("01.2.3")).toBeNull();
    expect(parseSemVer("1.2")).toBeNull();
    expect(parseSemVer("custom-build")).toBeNull();
    expect(parseSemVer("")).toBeNull();
  });

  it("orders prereleases below the matching release", () => {
    const pre = parseSemVer("1.2.3-rc.1");
    const stable = parseSemVer("1.2.3");
    if (!pre || !stable) throw new Error("parse");
    expect(compareSemVer(pre, stable)).toBeLessThan(0);
  });

  it("ignores prereleases and drafts when choosing the latest stable release", () => {
    const latest = latestStable([
      {
        tag: "v2.0.0-rc.1",
        url: "https://github.com/getAlby/hub/releases/tag/v2.0.0-rc.1",
        prerelease: true,
        draft: false,
      },
      {
        tag: "v1.9.0",
        url: "https://github.com/getAlby/hub/releases/tag/v1.9.0",
        prerelease: false,
        draft: false,
      },
      {
        tag: "v2.1.0",
        url: "https://github.com/getAlby/hub/releases/tag/v2.1.0",
        prerelease: false,
        draft: true,
      },
      {
        tag: "nightly",
        url: "https://github.com/getAlby/hub/releases/tag/nightly",
        prerelease: false,
        draft: false,
      },
    ]);
    expect(latest?.tag).toBe("v1.9.0");
  });

  it("reports an update only when both versions parse and the stable release is newer", () => {
    expect(updateAvailable("1.8.0", "v1.9.0")).toBe(true);
    expect(updateAvailable("1.9.0", "1.9.0")).toBe(false);
    expect(updateAvailable("1.9.0", "2.0.0-rc.1")).toBeNull();
    expect(updateAvailable("custom-build", "1.9.0")).toBeNull();
  });

  it("evaluates comparator ranges and refuses or-expressions", () => {
    const version = parseSemVer("1.2.0");
    if (!version) throw new Error("parse");
    expect(satisfiesRange(version, ">= 1.0.0, < 2.0.0")).toBe(true);
    expect(satisfiesRange(version, ">= 2.0.0")).toBe(false);
    expect(satisfiesRange(version, ">= 1.0.0 || < 0.1.0")).toBeNull();
  });
});
