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
  readVendorCheck,
  readVersion,
  releaseLease,
  writeUpstream,
  writeVendorCheck,
  writeVersion,
} from "../state/store";
import type { AdvisoryRef, SecurityStatus } from "../updates/advisories";
import { fetchAdvisories, fetchReleases } from "../updates/github";
import { alertSeverity, assessSecurity } from "../updates/security";
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
    const vendors = enabledMonitors(env).filter((monitor) => monitor.versionVendor);
    let failed = 0;
    for (const monitor of vendors) {
      const vendorId = monitor.versionVendor;
      if (!vendorId) continue;
      let outcome: VendorCheckOutcome;
      try {
        outcome = await checkVendor(env, deps, settings, monitor, vendorId);
      } catch {
        outcome = {
          vendor: vendorId,
          monitorId: monitor.id,
          succeeded: false,
          releasesFresh: false,
          advisoriesFresh: false,
          errorCode: "vendor_check_failed",
          checkedAt: deps.now(),
        };
        log("error", "vendor_check_failed", { monitor: monitor.id });
      }
      if (!outcome.succeeded) failed += 1;
      await recordVendorOutcome(env, outcome);
    }
    await dispatchDue(env, deps, settings);
    const finished = deps.now();
    await markRun(
      env.DB,
      "updates",
      null,
      finished,
      failed > 0 ? "vendor_checks_failed" : null,
      failed > 0 ? null : finished,
    );
  } catch {
    await markRun(env.DB, "updates", null, deps.now(), "cycle_failed");
    log("error", "updates_failed", {});
  } finally {
    await releaseLease(env.DB, "updates", owner, deps.now());
  }
}

interface VendorCheckOutcome {
  vendor: VendorId;
  monitorId: string;
  succeeded: boolean;
  releasesFresh: boolean;
  advisoriesFresh: boolean;
  errorCode: string | null;
  checkedAt: number;
}

interface Feed<T> {
  value: T | null;
  fresh: boolean;
  errorCode: string | null;
}

async function checkVendor(
  env: Env,
  deps: Dependencies,
  settings: Settings,
  monitor: MonitorDefinition,
  vendorId: VendorId,
): Promise<VendorCheckOutcome> {
  const vendor = VENDORS[vendorId];
  const now = deps.now();
  const installed = await installedVersion(env.DB, monitor.id);
  const releases = await loadReleases(env, deps, settings, vendorId, vendor, now);
  const advisoryFeed = await loadAdvisories(env, deps, settings, vendorId, vendor, now);
  const previous = await readVersion(env.DB, monitor.id);
  const latest = releases.value ? latestStable(releases.value) : null;
  const comparison =
    releases.fresh && installed && latest ? updateAvailable(installed, latest.tag) : null;
  const assessment = assessSecurity({
    vendorId,
    installed,
    advisories: advisoryFeed.value,
    releases: releases.value,
  });
  const fresh = releases.fresh && advisoryFeed.fresh;
  const keepPrevious = !fresh && previous && assessment.status === "unknown";
  const securityStatus: SecurityStatus = keepPrevious
    ? (previous.securityStatus as SecurityStatus)
    : assessment.status;
  const alerts: AlertDraft[] = [];
  let notice = previous?.noticeFingerprint ?? null;
  if (fresh && comparison === true && latest && previous?.latest !== latest.tag) {
    alerts.push(versionAlert(monitor, installed ?? "", latest.tag, latest.url, now));
    notice = `update:${latest.tag}`;
  }
  const severity = alertSeverity(assessment.status);
  if (
    fresh &&
    severity &&
    assessment.status !== "unknown" &&
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
      advisoryFingerprint: advisoryFeed.fresh
        ? assessment.fingerprint
        : (previous?.advisoryFingerprint ?? null),
      noticeFingerprint: notice,
    },
    now,
  );
  if (fresh) {
    for (const alert of alerts) await insertAlert(env.DB, alert, now);
  }
  const errorCode = fresh
    ? installed
      ? null
      : "version_unavailable"
    : (releases.errorCode ?? advisoryFeed.errorCode ?? "unavailable");
  return {
    vendor: vendorId,
    monitorId: monitor.id,
    succeeded: fresh,
    releasesFresh: releases.fresh,
    advisoriesFresh: advisoryFeed.fresh,
    errorCode,
    checkedAt: now,
  };
}

async function recordVendorOutcome(env: Env, outcome: VendorCheckOutcome): Promise<void> {
  const previous = await readVendorCheck(env.DB, outcome.monitorId);
  const rateLimited = outcome.errorCode === "rate_limited";
  const consecutiveFailures = outcome.succeeded
    ? 0
    : rateLimited
      ? (previous?.consecutiveFailures ?? 0)
      : (previous?.consecutiveFailures ?? 0) + 1;
  await writeVendorCheck(
    env.DB,
    {
      monitorId: outcome.monitorId,
      vendor: outcome.vendor,
      attemptedAt: outcome.checkedAt,
      succeededAt: outcome.succeeded ? outcome.checkedAt : null,
      releasesCheckedAt: outcome.releasesFresh ? outcome.checkedAt : null,
      advisoriesCheckedAt: outcome.advisoriesFresh ? outcome.checkedAt : null,
      releasesStale: !outcome.releasesFresh,
      advisoriesStale: !outcome.advisoriesFresh,
      errorCode: outcome.errorCode,
      consecutiveFailures,
    },
    outcome.checkedAt,
  );
  if (!outcome.succeeded && !rateLimited && consecutiveFailures === 3) {
    const monitor = enabledMonitors(env).find((item) => item.id === outcome.monitorId);
    if (!monitor) return;
    await insertAlert(
      env.DB,
      {
        id: `alt_${crypto.randomUUID()}`,
        alertClass: "integrity",
        incidentId: null,
        monitorId: monitor.id,
        projectId: monitor.projectId,
        dedupeKey: `integrity:${monitor.id}:vendor:${previous?.succeededAt ?? 0}`,
        destination: "nostr",
        severity: "warning",
        text: `${PROJECTS[monitor.projectId].displayName} ${monitor.displayName} security checks failed ${consecutiveFailures} times (${outcome.errorCode ?? "unavailable"}). Cached advisories were kept.`,
      },
      outcome.checkedAt,
    );
  }
}

async function loadReleases(
  env: Env,
  deps: Dependencies,
  settings: Settings,
  vendorId: string,
  vendor: { owner: string; repo: string },
  now: number,
): Promise<Feed<ReleaseRef[]>> {
  const key = `releases:${vendorId}`;
  const cache = await readUpstream(env.DB, key);
  if (cache?.rateLimitedUntil && cache.rateLimitedUntil > now) {
    return { value: asReleases(cache.payload), fresh: false, errorCode: "rate_limited" };
  }
  const fetched = await fetchReleases({
    apiBase: settings.githubApi,
    owner: vendor.owner,
    repo: vendor.repo,
    token: readString(env, "GITHUB_TOKEN"),
    etag: cache?.etag ?? null,
    fetch: deps.fetch,
    timeoutMs: settings.timeoutMs,
  });
  if (fetched.kind === "not_modified") {
    return { value: asReleases(cache?.payload), fresh: cache?.payload != null, errorCode: null };
  }
  if (fetched.kind === "rate_limited") {
    await writeUpstream(env.DB, key, {
      etag: cache?.etag ?? null,
      payload: cache?.payload ?? null,
      fetchedAt: cache?.fetchedAt ?? now,
      rateLimitedUntil: fetched.retryAt,
    });
    return { value: asReleases(cache?.payload), fresh: false, errorCode: "rate_limited" };
  }
  if (fetched.kind !== "ok" || !fetched.releases) {
    return { value: asReleases(cache?.payload), fresh: false, errorCode: "unavailable" };
  }
  await writeUpstream(env.DB, key, {
    etag: fetched.etag,
    payload: fetched.releases,
    fetchedAt: now,
    rateLimitedUntil: null,
  });
  return { value: fetched.releases, fresh: true, errorCode: null };
}

async function loadAdvisories(
  env: Env,
  deps: Dependencies,
  settings: Settings,
  vendorId: string,
  vendor: { owner: string; repo: string },
  now: number,
): Promise<Feed<AdvisoryRef[]>> {
  const key = `advisories:${vendorId}`;
  const cache = await readUpstream(env.DB, key);
  if (cache?.rateLimitedUntil && cache.rateLimitedUntil > now) {
    return { value: asAdvisories(cache.payload), fresh: false, errorCode: "rate_limited" };
  }
  const fetched = await fetchAdvisories({
    apiBase: settings.githubApi,
    owner: vendor.owner,
    repo: vendor.repo,
    token: readString(env, "GITHUB_TOKEN"),
    etag: cache?.etag ?? null,
    fetch: deps.fetch,
    timeoutMs: settings.timeoutMs,
  });
  if (fetched.kind === "not_modified") {
    return { value: asAdvisories(cache?.payload), fresh: cache?.payload != null, errorCode: null };
  }
  if (fetched.kind === "rate_limited") {
    await writeUpstream(env.DB, key, {
      etag: cache?.etag ?? null,
      payload: cache?.payload ?? null,
      fetchedAt: cache?.fetchedAt ?? now,
      rateLimitedUntil: fetched.retryAt,
    });
    return { value: asAdvisories(cache?.payload), fresh: false, errorCode: "rate_limited" };
  }
  if (fetched.kind !== "ok" || !fetched.advisories) {
    return { value: asAdvisories(cache?.payload), fresh: false, errorCode: "unavailable" };
  }
  await writeUpstream(env.DB, key, {
    etag: fetched.etag,
    payload: fetched.advisories,
    fetchedAt: now,
    rateLimitedUntil: null,
  });
  return { value: fetched.advisories, fresh: true, errorCode: null };
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
    classification: status,
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
