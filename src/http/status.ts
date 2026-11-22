import { enabledMonitors, MONITORS } from "../config/monitors";
import { PROJECTS } from "../config/projects";
import { projectRecipient } from "../config/projects";
import type { Settings } from "../config/settings";
import { readString } from "../runtime";
import type { OperationalSnapshot } from "../state/store";

export type WatchdogStatus =
  | "healthy"
  | "alerts_disabled"
  | "disabled"
  | "not_configured"
  | "degraded"
  | "unhealthy"
  | "misconfigured";

const UPDATE_OVERDUE_MS = 2 * 3_600_000;
const UPDATE_UNHEALTHY_MS = 6 * 3_600_000;

const KNOWN_ERRORS = [
  "sender_key_missing",
  "sender_key_invalid",
  "recipient_missing",
  "recipient_invalid",
  "recipient_inbox_missing",
  "bootstrap_relays_missing",
  "inbox_discovery_failed",
  "relay_rejected",
  "partial_relay_acceptance",
  "envelope_invalid",
  "delivery_failed",
  "telegram_failed",
  "telegram_unavailable",
  "project_invalid",
  "claim_lost",
] as const;

export function deriveOperationalStatus(input: {
  env: Env;
  settings: Settings;
  now: number;
  snapshot: OperationalSnapshot;
}): { status: WatchdogStatus; httpStatus: number; body: Record<string, unknown> } {
  const enabled = enabledMonitors(input.env);
  const counts = { healthy: 0, degraded: 0, down: 0, unknown: 0, misconfigured: 0 };
  let staleHeartbeats = 0;
  let missingHeartbeats = 0;
  for (const monitor of enabled) {
    const state = input.snapshot.states.find((item) => item.monitorId === monitor.id);
    const status = state?.status;
    if (
      status === "healthy" ||
      status === "degraded" ||
      status === "down" ||
      status === "unknown" ||
      status === "misconfigured"
    ) {
      counts[status] += 1;
    } else counts.unknown += 1;
    if (monitor.kind === "signed_heartbeat") {
      const beat = input.snapshot.heartbeats.find((item) => item.monitorId === monitor.id);
      if (!beat) missingHeartbeats += 1;
      else if (input.now - beat.receivedAt > input.settings.staleSeconds * 1000)
        staleHeartbeats += 1;
    }
  }
  const runs = {
    checks: runOf(input.snapshot, "checks"),
    updates: runOf(input.snapshot, "updates"),
  };
  const outbox = Object.fromEntries(input.snapshot.outbox.map((row) => [row.state, row.count]));
  const pending = outbox.queued ?? 0;
  const retrying = outbox.retrying ?? 0;
  const deadLetters = outbox.failed ?? 0;
  const errors: Record<string, number> = {};
  for (const row of input.snapshot.errors) {
    if ((KNOWN_ERRORS as readonly string[]).includes(row.error)) errors[row.error] = row.count;
  }
  const checkAge = runs.checks.finishedAt === null ? null : input.now - runs.checks.finishedAt;
  const schedulerStale =
    enabled.length > 0 &&
    (checkAge === null || checkAge > input.settings.schedulerStaleSeconds * 1000);
  const schedulerFailed = runs.checks.error !== null && runs.checks.error !== "disabled";
  const repeatedDeliveryFailures = deadLetters > 0 || retrying > 3;
  const destinations = destinationHealth(
    input.env,
    enabled.map((monitor) => monitor.projectId),
  );
  const versionMonitors = enabled.filter((monitor) => monitor.versionVendor);
  const vendorChecks = input.snapshot.vendorChecks ?? [];
  const updateAge = runs.updates.successAt === null ? null : input.now - runs.updates.successAt;
  const updatesRequired = versionMonitors.length > 0;
  const updateOverdue = updatesRequired && (updateAge === null || updateAge > UPDATE_OVERDUE_MS);
  const updateUnhealthy = updatesRequired && updateAge !== null && updateAge > UPDATE_UNHEALTHY_MS;
  const updateFailed =
    updatesRequired && runs.updates.error !== null && runs.updates.error !== "disabled";
  const vendorFailing = vendorChecks.some((row) => row.consecutiveFailures >= 3);
  const vendorStale = vendorChecks.some(
    (row) =>
      (row.releasesStale || row.advisoriesStale) &&
      (row.succeededAt === null || input.now - row.succeededAt > UPDATE_OVERDUE_MS),
  );
  const checkUnhealthy =
    schedulerStale &&
    (checkAge === null || checkAge > input.settings.schedulerStaleSeconds * 3 * 1000);
  const degraded =
    (schedulerStale && !checkUnhealthy) ||
    schedulerFailed ||
    repeatedDeliveryFailures ||
    (updateOverdue && !updateUnhealthy) ||
    updateFailed ||
    vendorFailing ||
    vendorStale;
  let status: WatchdogStatus = "healthy";
  if (!input.settings.enabled) status = "disabled";
  else if (enabled.length === 0) status = "not_configured";
  else if (!destinations.ready) status = "misconfigured";
  else if (counts.misconfigured > 0) status = "misconfigured";
  else if (checkUnhealthy || updateUnhealthy) status = "unhealthy";
  else if (degraded) status = "degraded";
  else if (!input.settings.alertsEnabled) status = "alerts_disabled";
  const body = {
    contract: "watchdog-status-v1",
    status,
    environment: input.settings.environment,
    checkedAt: new Date(input.now).toISOString(),
    monitoringEnabled: input.settings.enabled,
    alertsEnabled: input.settings.alertsEnabled,
    monitors: {
      configured: MONITORS.length,
      enabled: enabled.length,
      ...counts,
    },
    lastSuccessfulCheckAt: runs.checks.successAt
      ? new Date(runs.checks.successAt).toISOString()
      : null,
    lastSuccessfulUpdateAt: runs.updates.successAt
      ? new Date(runs.updates.successAt).toISOString()
      : null,
    lastCycleAgeMs: checkAge,
    scheduler: {
      checks: { ...publicRun(runs.checks), overdue: schedulerStale },
      updates: {
        ...publicRun(runs.updates),
        overdue: updateOverdue,
        failedVendors: vendorChecks.filter((row) => row.consecutiveFailures > 0).length,
      },
    },
    securityChecks: vendorChecks.map((row) => ({
      monitorId: row.monitorId,
      vendor: row.vendor,
      attemptedAt: row.attemptedAt ? new Date(row.attemptedAt).toISOString() : null,
      succeededAt: row.succeededAt ? new Date(row.succeededAt).toISOString() : null,
      releasesCheckedAt: row.releasesCheckedAt
        ? new Date(row.releasesCheckedAt).toISOString()
        : null,
      advisoriesCheckedAt: row.advisoriesCheckedAt
        ? new Date(row.advisoriesCheckedAt).toISOString()
        : null,
      releasesStale: row.releasesStale,
      advisoriesStale: row.advisoriesStale,
      errorCode: row.errorCode,
      consecutiveFailures: row.consecutiveFailures,
    })),
    openIncidents: input.snapshot.openIncidents,
    pendingAlerts: pending,
    retryingAlerts: retrying,
    deadLetters,
    heartbeats: { stale: staleHeartbeats, missing: missingHeartbeats },
    delivery: {
      destinationsConfigured: destinations.configured,
      recentErrors: errors,
    },
  };
  return { status, httpStatus: status === "healthy" ? 200 : 503, body };
}

function runOf(snapshot: OperationalSnapshot, name: string) {
  const run = snapshot.runs.find((item) => item.name === name);
  return {
    startedAt: run?.startedAt ?? null,
    finishedAt: run?.finishedAt ?? null,
    successAt: run?.successAt ?? null,
    error: run?.error ?? null,
  };
}

function publicRun(run: {
  startedAt: number | null;
  finishedAt: number | null;
  successAt: number | null;
  error: string | null;
}) {
  return {
    lastStartedAt: run.startedAt ? new Date(run.startedAt).toISOString() : null,
    lastFinishedAt: run.finishedAt ? new Date(run.finishedAt).toISOString() : null,
    lastSuccessAt: run.successAt ? new Date(run.successAt).toISOString() : null,
    lastError: run.error,
  };
}

function destinationHealth(
  env: Env,
  projectIds: string[],
): {
  ready: boolean;
  configured: { nostr: boolean; telegram: boolean };
} {
  const alertsOn = readString(env, "ALERTS_ENABLED") !== "false";
  let nostr = true;
  const projects = [...new Set(projectIds)];
  for (const id of projects) {
    const project = PROJECTS[id];
    if (!project) {
      nostr = false;
      continue;
    }
    if (readString(env, project.senderSecret) === "" || !projectRecipient(env, id)) nostr = false;
  }
  if (readString(env, "BOOTSTRAP_RELAYS") === "") nostr = false;
  const telegram =
    readString(env, "TELEGRAM_BOT_TOKEN") !== "" && readString(env, "TELEGRAM_CHAT_IDS") !== "";
  return {
    ready: !alertsOn || nostr,
    configured: { nostr, telegram },
  };
}
