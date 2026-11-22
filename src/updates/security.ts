import type { VendorId } from "../types";
import {
  assessAdvisories,
  type AdvisoryRef,
  type SecurityAssessment,
  type SecurityStatus,
} from "./advisories";
import { parseSemVer, satisfiesRange, updateAvailable, type ReleaseRef } from "./semver";
import { policyFor, type ConfirmedAdvisory } from "./vendor-policy";

export interface SecurityInput {
  vendorId: VendorId;
  installed: string | null;
  advisories: AdvisoryRef[] | null;
  releases: ReleaseRef[] | null;
  policy?: ConfirmedAdvisory[];
}

export function assessSecurity(input: SecurityInput): SecurityAssessment {
  const policy = input.policy ?? policyFor(input.vendorId);
  if (!input.installed) {
    return {
      status: "version_unavailable",
      fingerprint: "version-unavailable",
      advisoryUrl: null,
      summary:
        "No installed version has been observed, so security applicability cannot be decided. This is not a healthy security check.",
    };
  }
  const definite = definiteMatches(input.installed, input.advisories, policy);
  if (definite.length > 0) {
    const ids = definite.map((item) => item.id).sort();
    return {
      status: "affected",
      fingerprint: `affected:${input.installed}:${ids.join(",")}`,
      advisoryUrl: definite[0]?.url ?? null,
      summary: `Installed version ${input.installed} matches a confirmed affected range for ${ids.join(", ")}.`,
    };
  }
  const securityRelease = newestSecurityRelease(input.releases, input.installed);
  const unparsed = hasUnparsedAdvisory(input.installed, input.advisories);
  if (securityRelease || unparsed) {
    const ids = [
      ...(input.advisories ?? []).map((item) => item.id),
      ...policy.map((item) => item.id),
      securityRelease ? `release:${securityRelease.tag}` : "",
    ]
      .filter((item) => item !== "")
      .sort();
    const summary = securityRelease
      ? `Security-related release ${securityRelease.tag} is newer than ${input.installed}, and no verified affected range confirms impact. Review the release notes before treating this as a vulnerability.`
      : "Security information exists, but impact on the installed version could not be confirmed. Security review is recommended.";
    return {
      status: "review_recommended",
      fingerprint: `review:${input.installed}:${ids.join(",")}`,
      advisoryUrl: securityRelease?.url ?? input.advisories?.[0]?.url ?? null,
      summary,
    };
  }
  if (
    input.advisories === null &&
    (input.releases === null || !input.releases.some((item) => item.securityRelated))
  ) {
    return {
      status: "unknown",
      fingerprint: "feed-unavailable",
      advisoryUrl: null,
      summary:
        "Upstream security information was unavailable. The installed version was not marked safe or vulnerable.",
    };
  }
  return assessAdvisories(input.installed, input.advisories ?? []);
}

function definiteMatches(
  installed: string,
  advisories: AdvisoryRef[] | null,
  policy: ConfirmedAdvisory[],
): Array<{ id: string; url: string }> {
  const version = parseSemVer(installed);
  if (!version) return [];
  const matched: Array<{ id: string; url: string }> = [];
  for (const advisory of advisories ?? []) {
    if (advisory.ranges.length === 0) continue;
    if (advisory.ranges.some((range) => satisfiesRange(version, range) === true)) {
      matched.push({ id: advisory.id, url: advisory.url });
    }
  }
  for (const entry of policy) {
    if (entry.ranges.some((range) => satisfiesRange(version, range) === true)) {
      matched.push({ id: entry.id, url: entry.url });
    }
  }
  return matched;
}

function hasUnparsedAdvisory(installed: string, advisories: AdvisoryRef[] | null): boolean {
  if (!advisories) return false;
  const version = parseSemVer(installed);
  if (!version) return advisories.length > 0;
  return advisories.some((advisory) => {
    if (advisory.ranges.length === 0) return true;
    return advisory.ranges.some((range) => satisfiesRange(version, range) === null);
  });
}

function newestSecurityRelease(
  releases: ReleaseRef[] | null,
  installed: string,
): ReleaseRef | null {
  if (!releases) return null;
  let best: ReleaseRef | null = null;
  for (const release of releases) {
    if (!release.securityRelated || release.draft || release.prerelease) continue;
    if (updateAvailable(installed, release.tag) !== true) continue;
    if (!best || updateAvailable(best.tag, release.tag) === true) best = release;
  }
  return best;
}

export function alertSeverity(status: SecurityStatus): "critical" | "warning" | null {
  if (status === "affected") return "critical";
  if (status === "review_recommended" || status === "version_unavailable" || status === "unknown") {
    return "warning";
  }
  return null;
}
