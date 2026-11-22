export interface SemVer {
  major: number;
  minor: number;
  patch: number;
  prerelease: string[];
}

const SEMVER =
  /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$/;

export function parseSemVer(input: string): SemVer | null {
  const match = SEMVER.exec(input.trim().replace(/^v/i, ""));
  if (!match) return null;
  return {
    major: Number(match[1]),
    minor: Number(match[2]),
    patch: Number(match[3]),
    prerelease: match[4] ? match[4].split(".") : [],
  };
}

export function compareSemVer(left: SemVer, right: SemVer): number {
  if (left.major !== right.major) return left.major > right.major ? 1 : -1;
  if (left.minor !== right.minor) return left.minor > right.minor ? 1 : -1;
  if (left.patch !== right.patch) return left.patch > right.patch ? 1 : -1;
  if (left.prerelease.length === 0 && right.prerelease.length === 0) return 0;
  if (left.prerelease.length === 0) return 1;
  if (right.prerelease.length === 0) return -1;
  const length = Math.max(left.prerelease.length, right.prerelease.length);
  for (let i = 0; i < length; i += 1) {
    const a = left.prerelease[i];
    const b = right.prerelease[i];
    if (a === undefined) return -1;
    if (b === undefined) return 1;
    const aNum = /^\d+$/.test(a);
    const bNum = /^\d+$/.test(b);
    if (aNum && bNum && a !== b) return Number(a) > Number(b) ? 1 : -1;
    if (aNum !== bNum) return aNum ? -1 : 1;
    if (a !== b) return a > b ? 1 : -1;
  }
  return 0;
}

export function satisfiesRange(version: SemVer, range: string): boolean | null {
  const trimmed = range.trim();
  if (trimmed === "" || trimmed.includes("||")) return null;
  const parts = trimmed
    .split(",")
    .map((part) => part.trim())
    .filter((part) => part !== "");
  if (parts.length === 0) return null;
  for (const part of parts) {
    const match =
      /^(<=|>=|<|>|=)?\s*v?(\d+\.\d+\.\d+(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?)$/i.exec(part);
    if (!match?.[2]) return null;
    const boundary = parseSemVer(match[2]);
    if (!boundary) return null;
    const operator = match[1] ?? "=";
    const order = compareSemVer(version, boundary);
    const ok =
      (operator === "=" && order === 0) ||
      (operator === "<" && order < 0) ||
      (operator === "<=" && order <= 0) ||
      (operator === ">" && order > 0) ||
      (operator === ">=" && order >= 0);
    if (!ok) return false;
  }
  return true;
}

export interface ReleaseRef {
  tag: string;
  url: string;
  prerelease: boolean;
  draft: boolean;
  securityRelated?: boolean;
}

export function latestStable(releases: ReleaseRef[], includePrerelease = false): ReleaseRef | null {
  let best: { release: ReleaseRef; version: SemVer } | null = null;
  for (const release of releases) {
    if (release.draft) continue;
    if (release.prerelease && !includePrerelease) continue;
    const version = parseSemVer(release.tag);
    if (!version) continue;
    if (version.prerelease.length > 0 && !includePrerelease) continue;
    if (!best || compareSemVer(version, best.version) > 0) best = { release, version };
  }
  return best?.release ?? null;
}

export function updateAvailable(installed: string, latest: string): boolean | null {
  const current = parseSemVer(installed);
  const upstream = parseSemVer(latest);
  if (!current || !upstream) return null;
  if (upstream.prerelease.length > 0) return null;
  return compareSemVer(current, upstream) < 0;
}
