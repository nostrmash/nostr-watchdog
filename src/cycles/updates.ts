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
import { assessSecurity } from "../updates/security";
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
    let incomplete = 0;
    let rateLimited = 0;
    let partial = 0;
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
          releasesState: "unavailable",
          advisoriesState: "unavailable",
          coverage: "unavailable",
          errorCode: "vendor_check_failed",
          releasesRateLimited: false,
          advisoriesRateLimited: false,
          checkedAt: deps.now(),
        };
        log("error", "vendor_check_failed", { monitor: monitor.id });
      }
      if (outcome.coverage !== "complete") {
        if (outcome.errorCode === "rate_limited") rateLimited += 1;
        else if (outcome.coverage === "unavailable") failed += 1;
        else if (outcome.coverage === "incomplete") incomplete += 1;
        else partial += 1;
      }
      await recordVendorOutcome(env, outcome);
    }
    await dispatchDue(env, deps, settings);
    const finished = deps.now();
    const error =
      failed > 0
        ? "vendor_checks_failed"
        : rateLimited > 0
          ? "rate_limited"
          : incomplete > 0
            ? "coverage_incomplete"
            : partial > 0
              ? "coverage_partial"
              : null;
    await markRun(env.DB, "updates", null, finished, error, error === null ? finished : null);
  } catch {
    await markRun(env.DB, "updates", null, deps.now(), "cycle_failed");
    log("error", "updates_failed", {});
  } finally {
    await releaseLease(env.DB, "updates", owner, deps.now());
  }
}

type SourceState = "fresh" | "cached" | "stale" | "unavailable";
type Coverage = "complete" | "partial" | "incomplete" | "unavailable" | "policy_only";

interface VendorCheckOutcome {
  vendor: VendorId;
  monitorId: string;
  succeeded: boolean;
  releasesState: SourceState;
  advisoriesState: SourceState;
  coverage: Coverage;
  errorCode: string | null;
  releasesRateLimited: boolean;
  advisoriesRateLimited: boolean;
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
  const releaseState = sourceState(releases);
  const advisoryState = sourceState(advisoryFeed);
  const releaseFresh = releaseState === "fresh";
  const advisoryFresh = advisoryState === "fresh";
  const latest = releaseFresh && releases.value ? latestStable(releases.value) : null;
  const comparison = installed && latest ? updateAvailable(installed, latest.tag) : null;
  const assessment = assessSecurity({
    vendorId,
    installed,
    advisories: advisoryFresh ? advisoryFeed.value : null,
    releases: releaseFresh ? releases.value : null,
  });
  let securityStatus = assessment.status;
  let fingerprint = assessment.fingerprint;
  let summary = assessment.summary;
  let advisoryUrl = assessment.advisoryUrl;
  if (!installed) {
    securityStatus = releaseFresh || advisoryFresh ? "version_unavailable" : "unknown";
    fingerprint = "version-unavailable";
    summary =
      "No installed version has been observed, so update and security coverage is incomplete. The server was not marked safe or vulnerable.";
    advisoryUrl = null;
  } else if (
    assessment.status === "unknown" &&
    previous &&
    (previous.securityStatus === "affected" || previous.securityStatus === "review_recommended")
  ) {
    securityStatus = previous.securityStatus as SecurityStatus;
    fingerprint = previous.advisoryFingerprint ?? fingerprint;
    summary =
      "A previously confirmed security finding was kept because a newer feed was unavailable.";
    advisoryUrl = previous.latestUrl;
  }
  const coverage = coverageFor(installed, releaseFresh, advisoryFresh, securityStatus);
  const alerts: AlertDraft[] = [];
  let notice = previous?.noticeFingerprint ?? null;
  if (releaseFresh && comparison === true && latest && previous?.latest !== latest.tag) {
    alerts.push(versionAlert(monitor, installed ?? "", latest.tag, latest.url, now));
    notice = `update:${latest.tag}`;
  }
  const canAlert =
    securityStatus === "affected" ||
    ((securityStatus === "review_recommended" || securityStatus === "version_unavailable") &&
      (releaseFresh || advisoryFresh));
  let securityRemindedAt = previous?.securityRemindedAt ?? null;
  const initialSecurity = canAlert && fingerprint !== previous?.advisoryFingerprint;
  const remind =
    !initialSecurity &&
    securityStatus === "affected" &&
    fingerprint === previous?.advisoryFingerprint &&
    settings.reminderSeconds > 0 &&
    securityRemindedAt !== null &&
    now - securityRemindedAt >= settings.reminderSeconds * 1000;
  if (initialSecurity) {
    securityRemindedAt = now;
    alerts.push(
      ...securityAlerts(
        env,
        settings,
        monitor,
        securityStatus,
        fingerprint,
        installed,
        summary,
        advisoryUrl,
        now,
        "",
        "security",
      ),
    );
  } else if (remind) {
    securityRemindedAt = now;
    alerts.push(
      ...securityAlerts(
        env,
        settings,
        monitor,
        securityStatus,
        fingerprint,
        installed,
        `This confirmed finding is still open. ${summary}`,
        advisoryUrl,
        now,
        `remind:${now}:`,
        "reminder",
      ),
    );
  }
  if (securityStatus !== "affected") securityRemindedAt = null;
  await writeVersion(
    env.DB,
    monitor.id,
    {
      installed,
      latest: latest?.tag ?? previous?.latest ?? null,
      latestUrl: latest?.url ?? previous?.latestUrl ?? null,
      securityStatus,
      advisoryFingerprint:
        securityStatus === "unknown" ? (previous?.advisoryFingerprint ?? fingerprint) : fingerprint,
      noticeFingerprint: notice,
      securityRemindedAt,
    },
    now,
  );
  for (const alert of alerts) await insertAlert(env.DB, alert, now);
  return {
    vendor: vendorId,
    monitorId: monitor.id,
    succeeded: coverage === "complete",
    releasesState: releaseState,
    advisoriesState: advisoryState,
    coverage,
    errorCode: vendorError(coverage, releaseState, advisoryState, releases, advisoryFeed),
    releasesRateLimited: releases.errorCode === "rate_limited",
    advisoriesRateLimited: advisoryFeed.errorCode === "rate_limited",
    checkedAt: now,
  };
}

function sourceFailures(state: SourceState, rateLimited: boolean, previous: number): number {
  if (state === "fresh") return 0;
  if (rateLimited) return previous;
  return previous + 1;
}

function sourceState<T>(feed: Feed<T>): SourceState {
  if (feed.fresh && feed.value) return "fresh";
  if (feed.errorCode === "rate_limited") return feed.value ? "stale" : "unavailable";
  if (feed.value) return "cached";
  return "unavailable";
}

function coverageFor(
  installed: string | null,
  releaseFresh: boolean,
  advisoryFresh: boolean,
  status: SecurityStatus,
): Coverage {
  if (!installed) return releaseFresh || advisoryFresh ? "incomplete" : "unavailable";
  if (releaseFresh && advisoryFresh) return "complete";
  if (releaseFresh || advisoryFresh) return "partial";
  if (status === "affected") return "policy_only";
  return "unavailable";
}

function vendorError(
  coverage: Coverage,
  releases: SourceState,
  advisories: SourceState,
  releaseFeed: Feed<ReleaseRef[]>,
  advisoryFeed: Feed<AdvisoryRef[]>,
): string | null {
  if (coverage === "incomplete") return "coverage_incomplete";
  if (coverage === "complete") return null;
  if (releaseFeed.errorCode === "rate_limited" || advisoryFeed.errorCode === "rate_limited") {
    return "rate_limited";
  }
  if (coverage === "policy_only" || coverage === "unavailable") {
    return releases === "unavailable" && advisories === "unavailable"
      ? "feeds_unavailable"
      : "feeds_not_fresh";
  }
  if (releases !== "fresh") return releaseFeed.errorCode ?? `releases_${releases}`;
  if (advisories !== "fresh") return advisoryFeed.errorCode ?? `advisories_${advisories}`;
  return null;
}

async function recordVendorOutcome(env: Env, outcome: VendorCheckOutcome): Promise<void> {
  const previous = await readVendorCheck(env.DB, outcome.monitorId);
  const rateLimited = outcome.errorCode === "rate_limited";
  const hardFailure = outcome.coverage === "unavailable" && !rateLimited;
  const consecutiveFailures = outcome.succeeded
    ? 0
    : hardFailure
      ? (previous?.consecutiveFailures ?? 0) + 1
      : (previous?.consecutiveFailures ?? 0);
  const releasesFailures = sourceFailures(
    outcome.releasesState,
    outcome.releasesRateLimited,
    previous?.releasesFailures ?? 0,
  );
  const advisoriesFailures = sourceFailures(
    outcome.advisoriesState,
    outcome.advisoriesRateLimited,
    previous?.advisoriesFailures ?? 0,
  );
  const partial = outcome.coverage === "partial" || outcome.coverage === "policy_only";
  await writeVendorCheck(
    env.DB,
    {
      monitorId: outcome.monitorId,
      vendor: outcome.vendor,
      attemptedAt: outcome.checkedAt,
      succeededAt: outcome.succeeded ? outcome.checkedAt : null,
      partialSucceededAt: partial ? outcome.checkedAt : null,
      releasesCheckedAt: outcome.releasesState === "fresh" ? outcome.checkedAt : null,
      advisoriesCheckedAt: outcome.advisoriesState === "fresh" ? outcome.checkedAt : null,
      releasesStale: outcome.releasesState !== "fresh",
      advisoriesStale: outcome.advisoriesState !== "fresh",
      releasesState: outcome.releasesState,
      advisoriesState: outcome.advisoriesState,
      coverage: outcome.coverage,
      errorCode: outcome.errorCode,
      consecutiveFailures,
      releasesFailures,
      advisoriesFailures,
    },
    outcome.checkedAt,
  );
  if (hardFailure && consecutiveFailures === 3) {
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
  dedupeSuffix = "",
  alertClass: AlertDraft["alertClass"] = "security",
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
  const drafts = [
    securityDraft(monitor, severity, fingerprint, "nostr", text, dedupeSuffix, alertClass),
  ];
  if (
    severity === "critical" &&
    settings.telegramMode === "dual" &&
    telegramChat(readString(env, "TELEGRAM_CHAT_IDS"), monitor.projectId)
  ) {
    drafts.push(
      securityDraft(monitor, severity, fingerprint, "telegram", text, dedupeSuffix, alertClass),
    );
  }
  return drafts;
}

function securityDraft(
  monitor: MonitorDefinition,
  severity: AlertDraft["severity"],
  fingerprint: string,
  destination: "nostr" | "telegram",
  text: string,
  dedupeSuffix: string,
  alertClass: AlertDraft["alertClass"],
): AlertDraft {
  return {
    id: `alt_${crypto.randomUUID()}`,
    alertClass,
    incidentId: null,
    monitorId: monitor.id,
    projectId: monitor.projectId,
    dedupeKey: `security:${monitor.id}:${fingerprint}:${dedupeSuffix}${destination}`,
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
