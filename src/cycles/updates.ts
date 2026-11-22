import { formatSecurityMessage, formatVersionMessage } from "../alerts/format";
import { telegramChat } from "../alerts/telegram";
import { PROJECTS } from "../config/projects";
import { enabledMonitors } from "../config/monitors";
import { loadSettings, type Settings } from "../config/settings";
import type { Dependencies } from "../deps";
import { log, readString } from "../runtime";
import {
  acquireLease,
  insertAlert,
  installedVersion,
  markRun,
  readUpstream,
  readVersion,
  releaseLease,
  writeUpstream,
  writeVersion,
} from "../state/store";
import { assessAdvisories, type AdvisoryRef, type SecurityStatus } from "../updates/advisories";
import { fetchAdvisories, fetchReleases } from "../updates/github";
import { latestStable, updateAvailable, type ReleaseRef } from "../updates/semver";
import type { AlertDraft, MonitorDefinition, VendorId } from "../types";
import { dispatchDue } from "./dispatch";

const VENDORS: Record<VendorId, { owner: string; repo: string }> = {
  "getAlby/hub": { owner: "getAlby", repo: "hub" },
  "btcpayserver/btcpayserver": { owner: "btcpayserver", repo: "btcpayserver" },
};

export async function runUpdateCycle(env: Env, deps: Dependencies): Promise<void> {
  const settings = loadSettings(env);
  if (!settings.enabled) return;
  const owner = crypto.randomUUID();
  const started = deps.now();
  if (!(await acquireLease(env.DB, "updates", owner, started + 10 * 60_000, started))) return;
  try {
    await markRun(env.DB, "updates", started, null, null);
    for (const monitor of enabledMonitors(env)) {
      if (!monitor.versionVendor) continue;
      await checkVendor(env, deps, settings, monitor, monitor.versionVendor);
    }
    await dispatchDue(env, deps, settings);
    await markRun(env.DB, "updates", null, deps.now(), null);
  } catch {
    await markRun(env.DB, "updates", null, deps.now(), "cycle_failed");
    log("error", "updates_failed", {});
  } finally {
    await releaseLease(env.DB, "updates", owner, deps.now());
  }
}

async function checkVendor(
  env: Env,
  deps: Dependencies,
  settings: Settings,
  monitor: MonitorDefinition,
  vendorId: VendorId,
): Promise<void> {
  const vendor = VENDORS[vendorId];
  const now = deps.now();
  const installed = await installedVersion(env.DB, monitor.id);
  const releases = await loadReleases(env, deps, settings, vendorId, vendor, now);
  const advisoryFeed = await loadAdvisories(env, deps, settings, vendorId, vendor, now);
  const previous = await readVersion(env.DB, monitor.id);
  const latest = releases ? latestStable(releases) : null;
  const comparison = installed && latest ? updateAvailable(installed, latest.tag) : null;
  const assessment =
    advisoryFeed.failed && !advisoryFeed.advisories
      ? assessAdvisories(installed, null)
      : assessAdvisories(installed, advisoryFeed.advisories);
  const securityStatus: SecurityStatus =
    advisoryFeed.failed && previous
      ? (previous.securityStatus as SecurityStatus)
      : assessment.status;
  const alerts: AlertDraft[] = [];
  let notice = previous?.noticeFingerprint ?? null;
  if (comparison === true && latest && previous?.latest !== latest.tag) {
    alerts.push(versionAlert(monitor, installed ?? "", latest.tag, latest.url, now));
    notice = `update:${latest.tag}`;
  }
  if (
    !advisoryFeed.failed &&
    (assessment.status === "affected" || assessment.status === "review_recommended") &&
    assessment.fingerprint !== previous?.advisoryFingerprint
  ) {
    alerts.push(
      ...securityAlerts(
        env,
        settings,
        monitor,
        assessment.status,
        assessment.fingerprint,
        installed,
        assessment.summary,
        assessment.advisoryUrl,
        now,
      ),
    );
  }
  await writeVersion(
    env.DB,
    monitor.id,
    {
      installed,
      latest: latest?.tag ?? previous?.latest ?? null,
      latestUrl: latest?.url ?? previous?.latestUrl ?? null,
      securityStatus,
      advisoryFingerprint: advisoryFeed.failed
        ? (previous?.advisoryFingerprint ?? null)
        : assessment.fingerprint,
      noticeFingerprint: notice,
    },
    now,
  );
  for (const alert of alerts) await insertAlert(env.DB, alert, now);
}

async function loadReleases(
  env: Env,
  deps: Dependencies,
  settings: Settings,
  vendorId: string,
  vendor: { owner: string; repo: string },
  now: number,
): Promise<ReleaseRef[] | null> {
  const key = `releases:${vendorId}`;
  const cache = await readUpstream(env.DB, key);
  if (cache?.rateLimitedUntil && cache.rateLimitedUntil > now) return asReleases(cache.payload);
  const fetched = await fetchReleases({
    apiBase: settings.githubApi,
    owner: vendor.owner,
    repo: vendor.repo,
    token: readString(env, "GITHUB_TOKEN"),
    etag: cache?.etag ?? null,
    fetch: deps.fetch,
  });
  if (fetched.kind === "not_modified") return asReleases(cache?.payload);
  if (fetched.kind === "rate_limited") {
    await writeUpstream(env.DB, key, {
      etag: cache?.etag ?? null,
      payload: cache?.payload ?? null,
      fetchedAt: cache?.fetchedAt ?? now,
      rateLimitedUntil: fetched.retryAt,
    });
    return asReleases(cache?.payload);
  }
  if (fetched.kind !== "ok" || !fetched.releases) return asReleases(cache?.payload);
  await writeUpstream(env.DB, key, {
    etag: fetched.etag,
    payload: fetched.releases,
    fetchedAt: now,
    rateLimitedUntil: null,
  });
  return fetched.releases;
}

async function loadAdvisories(
  env: Env,
  deps: Dependencies,
  settings: Settings,
  vendorId: string,
  vendor: { owner: string; repo: string },
  now: number,
): Promise<{ advisories: AdvisoryRef[] | null; failed: boolean }> {
  const key = `advisories:${vendorId}`;
  const cache = await readUpstream(env.DB, key);
  if (cache?.rateLimitedUntil && cache.rateLimitedUntil > now)
    return { advisories: asAdvisories(cache.payload), failed: false };
  const fetched = await fetchAdvisories({
    apiBase: settings.githubApi,
    owner: vendor.owner,
    repo: vendor.repo,
    token: readString(env, "GITHUB_TOKEN"),
    etag: cache?.etag ?? null,
    fetch: deps.fetch,
  });
  if (fetched.kind === "not_modified")
    return { advisories: asAdvisories(cache?.payload), failed: false };
  if (fetched.kind === "rate_limited") {
    await writeUpstream(env.DB, key, {
      etag: cache?.etag ?? null,
      payload: cache?.payload ?? null,
      fetchedAt: cache?.fetchedAt ?? now,
      rateLimitedUntil: fetched.retryAt,
    });
    return { advisories: asAdvisories(cache?.payload), failed: cache?.payload == null };
  }
  if (fetched.kind !== "ok" || !fetched.advisories)
    return { advisories: asAdvisories(cache?.payload), failed: true };
  await writeUpstream(env.DB, key, {
    etag: fetched.etag,
    payload: fetched.advisories,
    fetchedAt: now,
    rateLimitedUntil: null,
  });
  return { advisories: fetched.advisories, failed: false };
}

function versionAlert(
  monitor: MonitorDefinition,
  installed: string,
  latest: string,
  url: string,
  now: number,
): AlertDraft {
  return {
    id: `alt_${crypto.randomUUID()}`,
    alertClass: "update",
    incidentId: null,
    monitorId: monitor.id,
    projectId: monitor.projectId,
    dedupeKey: `update:${monitor.id}:${latest}:nostr`,
    destination: "nostr",
    severity: "info",
    text: formatVersionMessage({
      projectName: PROJECTS[monitor.projectId].displayName,
      displayName: monitor.displayName,
      installed,
      latest,
      url,
      occurredAt: now,
    }),
  };
}

function securityAlerts(
  env: Env,
  settings: Settings,
  monitor: MonitorDefinition,
  status: SecurityStatus,
  fingerprint: string,
  installed: string | null,
  summary: string,
  url: string | null,
  now: number,
): AlertDraft[] {
  const severity = status === "affected" ? "critical" : "warning";
  const text = formatSecurityMessage({
    projectName: PROJECTS[monitor.projectId].displayName,
    displayName: monitor.displayName,
    severity,
    installed,
    summary,
    url,
    occurredAt: now,
  });
  const drafts = [securityDraft(monitor, severity, fingerprint, "nostr", text)];
  if (
    severity === "critical" &&
    settings.telegramMode === "dual" &&
    telegramChat(readString(env, "TELEGRAM_CHAT_IDS"), monitor.projectId)
  ) {
    drafts.push(securityDraft(monitor, severity, fingerprint, "telegram", text));
  }
  return drafts;
}

function securityDraft(
  monitor: MonitorDefinition,
  severity: AlertDraft["severity"],
  fingerprint: string,
  destination: "nostr" | "telegram",
  text: string,
): AlertDraft {
  return {
    id: `alt_${crypto.randomUUID()}`,
    alertClass: "security",
    incidentId: null,
    monitorId: monitor.id,
    projectId: monitor.projectId,
    dedupeKey: `security:${monitor.id}:${fingerprint}:${destination}`,
    destination,
    severity,
    text,
  };
}

function asReleases(value: unknown): ReleaseRef[] | null {
  if (!Array.isArray(value)) return null;
  return value.filter((item): item is ReleaseRef => {
    if (!item || typeof item !== "object") return false;
    const record = item as ReleaseRef;
    return typeof record.tag === "string" && typeof record.url === "string";
  });
}

function asAdvisories(value: unknown): AdvisoryRef[] | null {
  if (!Array.isArray(value)) return null;
  return value.filter((item): item is AdvisoryRef => {
    if (!item || typeof item !== "object") return false;
    const record = item as AdvisoryRef;
    return (
      typeof record.id === "string" &&
      typeof record.url === "string" &&
      Array.isArray(record.ranges)
    );
  });
}
