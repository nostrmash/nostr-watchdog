import { readResponseLimited } from "../security/body";
import type { FetchLike } from "../types";
import { officialGithubUrl } from "./advisories";
import type { AdvisoryRef } from "./advisories";
import type { ReleaseRef } from "./semver";

export type GithubFetch =
  | { kind: "ok"; etag: string | null; releases?: ReleaseRef[]; advisories?: AdvisoryRef[] }
  | { kind: "not_modified" }
  | { kind: "rate_limited"; retryAt: number | null }
  | { kind: "unavailable" };

export async function fetchReleases(input: {
  apiBase: string;
  owner: string;
  repo: string;
  token: string;
  etag: string | null;
  fetch: FetchLike;
}): Promise<GithubFetch> {
  const response = await requestGithub(
    input,
    `/repos/${input.owner}/${input.repo}/releases?per_page=20`,
  );
  if (response.kind !== "ok") return response.kind === "body" ? { kind: "unavailable" } : response;
  if (!Array.isArray(response.body)) return { kind: "unavailable" };
  const releases: ReleaseRef[] = [];
  for (const item of response.body) {
    if (!item || typeof item !== "object") continue;
    const record = item as Record<string, unknown>;
    if (typeof record.tag_name !== "string") continue;
    const url = officialGithubUrl(record.html_url);
    if (!url) continue;
    releases.push({
      tag: record.tag_name,
      url,
      prerelease: record.prerelease === true,
      draft: record.draft === true,
    });
  }
  return { kind: "ok", etag: response.etag, releases };
}

export async function fetchAdvisories(input: {
  apiBase: string;
  owner: string;
  repo: string;
  token: string;
  etag: string | null;
  fetch: FetchLike;
}): Promise<GithubFetch> {
  const response = await requestGithub(
    input,
    `/repos/${input.owner}/${input.repo}/security-advisories?per_page=30&state=published`,
  );
  if (response.kind !== "ok") return response.kind === "body" ? { kind: "unavailable" } : response;
  if (!Array.isArray(response.body)) return { kind: "unavailable" };
  const advisories: AdvisoryRef[] = [];
  for (const item of response.body) {
    if (!item || typeof item !== "object") continue;
    const record = item as Record<string, unknown>;
    if (typeof record.ghsa_id !== "string") continue;
    if (record.state !== undefined && record.state !== "published") continue;
    const url = officialGithubUrl(record.html_url);
    if (!url) continue;
    const ranges: string[] = [];
    if (Array.isArray(record.vulnerabilities)) {
      for (const vulnerability of record.vulnerabilities) {
        if (!vulnerability || typeof vulnerability !== "object") continue;
        const range = (vulnerability as { vulnerable_version_range?: unknown })
          .vulnerable_version_range;
        if (typeof range === "string" && range.trim() !== "") ranges.push(range.trim());
      }
    }
    advisories.push({
      id: record.ghsa_id,
      url,
      severity: typeof record.severity === "string" ? record.severity : null,
      ranges,
    });
  }
  return { kind: "ok", etag: response.etag, advisories };
}

async function requestGithub(
  input: { apiBase: string; token: string; etag: string | null; fetch: FetchLike },
  path: string,
): Promise<
  | { kind: "ok"; etag: string | null; body: unknown }
  | { kind: "not_modified" }
  | { kind: "rate_limited"; retryAt: number | null }
  | { kind: "unavailable" }
  | { kind: "body" }
> {
  let url: URL;
  try {
    url = new URL(path, input.apiBase.endsWith("/") ? input.apiBase : `${input.apiBase}/`);
  } catch {
    return { kind: "unavailable" };
  }
  if (
    url.protocol !== "https:" ||
    (url.hostname !== "api.github.com" && !url.hostname.endsWith(".github.com"))
  ) {
    return { kind: "unavailable" };
  }
  const headers = new Headers({
    accept: "application/vnd.github+json",
    "user-agent": "nostr-watchdog",
    "x-github-api-version": "2022-11-28",
  });
  if (input.etag) headers.set("if-none-match", input.etag);
  if (input.token !== "") headers.set("authorization", `Bearer ${input.token}`);
  const response = await input.fetch(url.toString(), {
    method: "GET",
    headers,
    redirect: "manual",
  });
  if (response.status === 304) {
    await response.body?.cancel();
    return { kind: "not_modified" };
  }
  if (response.status >= 300 && response.status < 400) {
    await response.body?.cancel();
    return { kind: "unavailable" };
  }
  if (response.status === 403 || response.status === 429) {
    await response.body?.cancel();
    const reset = response.headers.get("x-ratelimit-reset");
    const retryAt = reset && /^\d+$/.test(reset) ? Number(reset) * 1000 : null;
    return { kind: "rate_limited", retryAt };
  }
  if (response.status < 200 || response.status >= 300) {
    await response.body?.cancel();
    return { kind: "unavailable" };
  }
  const text = await readResponseLimited(response, 262_144);
  if (text === "too_large" || text === "") return { kind: "body" };
  try {
    return { kind: "ok", etag: response.headers.get("etag"), body: JSON.parse(text) as unknown };
  } catch {
    return { kind: "body" };
  }
}
