import { parseSemVer, satisfiesRange } from "./semver";

export interface AdvisoryRef {
  id: string;
  url: string;
  severity: string | null;
  ranges: string[];
}

export type SecurityStatus =
  | "unknown"
  | "review_recommended"
  | "affected"
  | "no_published_advisories"
  | "outside_published_ranges";

export interface SecurityAssessment {
  status: SecurityStatus;
  fingerprint: string;
  advisoryUrl: string | null;
  summary: string;
}

export function assessAdvisories(
  installed: string | null,
  advisories: AdvisoryRef[] | null,
): SecurityAssessment {
  if (advisories === null) {
    return {
      status: "unknown",
      fingerprint: "feed-unavailable",
      advisoryUrl: null,
      summary: "Security advisory status is unknown because the official feed was unavailable.",
    };
  }
  if (advisories.length === 0) {
    return {
      status: "no_published_advisories",
      fingerprint: "none",
      advisoryUrl: null,
      summary:
        "No published GitHub Security Advisories were returned. This is not a claim that the software is secure.",
    };
  }
  const version = installed ? parseSemVer(installed) : null;
  const affected: AdvisoryRef[] = [];
  let unparsed = false;
  for (const advisory of advisories) {
    if (advisory.ranges.length === 0) {
      unparsed = true;
      continue;
    }
    if (!version) {
      unparsed = true;
      continue;
    }
    let matched = false;
    for (const range of advisory.ranges) {
      const result = satisfiesRange(version, range);
      if (result === null) unparsed = true;
      if (result === true) matched = true;
    }
    if (matched) affected.push(advisory);
  }
  if (affected.length > 0) {
    const ids = affected.map((item) => item.id).sort();
    return {
      status: "affected",
      fingerprint: `affected:${installed}:${ids.join(",")}`,
      advisoryUrl: affected[0]?.url ?? null,
      summary: `Installed version ${installed} is in the affected range for ${ids.join(", ")}.`,
    };
  }
  if (unparsed || !version) {
    const ids = advisories.map((item) => item.id).sort();
    return {
      status: "review_recommended",
      fingerprint: `review:${installed ?? "unknown"}:${ids.join(",")}`,
      advisoryUrl: advisories[0]?.url ?? null,
      summary:
        "A published advisory exists, but impact on the installed version could not be confirmed. Security review is recommended.",
    };
  }
  return {
    status: "outside_published_ranges",
    fingerprint: `outside:${installed}:${advisories
      .map((item) => item.id)
      .sort()
      .join(",")}`,
    advisoryUrl: null,
    summary:
      "Published advisories were checked and the installed version is outside their parsed affected ranges. This is not a claim that the software is secure.",
  };
}

export function officialGithubUrl(value: unknown): string | null {
  if (typeof value !== "string") return null;
  try {
    const url = new URL(value);
    if (url.protocol !== "https:") return null;
    if (url.hostname !== "github.com" && url.hostname !== "www.github.com") return null;
    return url.toString();
  } catch {
    return null;
  }
}
