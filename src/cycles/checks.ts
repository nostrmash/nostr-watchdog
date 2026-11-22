import { runAlbyHubCheck } from "../checks/alby-hub";
import { runBtcpayCheck } from "../checks/btcpay";
import { evaluateHeartbeat } from "../checks/heartbeat";
import { runHttpJsonCheck } from "../checks/http-json";
import { networkFailure, unknownResult } from "../checks/result";
import { formatIncidentMessage } from "../alerts/format";
import { PROJECTS } from "../config/projects";
import { enabledMonitors } from "../config/monitors";
import { loadSettings, type Settings } from "../config/settings";
import type { Dependencies } from "../deps";
import { log, mapLimit, readString } from "../runtime";
import {
  acquireLease,
  commitCheck,
  lastChecks,
  loadMemory,
  markRun,
  pruneOperationalRows,
  readHeartbeat,
  releaseLease,
} from "../state/store";
import { transition } from "../state/transition";
import { telegramChat } from "../alerts/telegram";
import type { AlertDraft, CheckResult, MonitorDefinition, Notice } from "../types";
import { dispatchDue } from "./dispatch";

export async function runCheckCycle(env: Env, deps: Dependencies): Promise<void> {
  const settings = loadSettings(env);
  if (!settings.enabled) {
    log("info", "checks_skipped", { reason: "disabled" });
    await markRun(env.DB, "checks", deps.now(), deps.now(), "disabled");
    return;
  }
  const owner = crypto.randomUUID();
  const started = deps.now();
  const leased = await acquireLease(env.DB, "checks", owner, started + 50_000, started);
  if (!leased) {
    log("info", "checks_skipped", { reason: "lease" });
    await dispatchDue(env, deps, settings);
    return;
  }
  let cycleError: string | null = null;
  try {
    await markRun(env.DB, "checks", started, null, null);
    const previous = await lastChecks(env.DB);
    const due = enabledMonitors(env).filter((monitor) => {
      const last = previous.get(monitor.id);
      return (
        last === undefined || last === null || started - last >= monitor.intervalSeconds * 1000
      );
    });
    const settled = await mapLimit(due, settings.concurrency, async (monitor) => ({
      monitor,
      result: await probe(env, settings, monitor, deps),
    }));
    for (const item of settled) {
      if (item.status === "rejected") {
        log("error", "probe_rejected", { monitor: "unknown" });
        continue;
      }
      try {
        await applyProbe(env, settings, item.value.monitor, item.value.result, deps.now());
      } catch {
        cycleError = "monitor_commit_failed";
        log("error", "monitor_commit_failed", { monitor: item.value.monitor.id });
      }
    }
    try {
      await pruneOperationalRows(env.DB, deps.now());
    } catch {
      log("error", "retention_failed", {});
    }
  } catch {
    cycleError = "cycle_failed";
    log("error", "checks_failed", {});
  } finally {
    await releaseLease(env.DB, "checks", owner, deps.now());
  }
  try {
    await dispatchDue(env, deps, settings);
  } catch {
    cycleError = cycleError ?? "dispatch_failed";
    log("error", "dispatch_failed", {});
  }
  await markRun(
    env.DB,
    "checks",
    null,
    deps.now(),
    cycleError,
    cycleError === null ? deps.now() : null,
  );
}

async function probe(
  env: Env,
  settings: Settings,
  monitor: MonitorDefinition,
  deps: Dependencies,
): Promise<CheckResult> {
  try {
    if (monitor.kind === "http_json" && monitor.http) {
      return await runHttpJsonCheck({
        spec: monitor.http,
        url: readString(env, monitor.http.urlVar),
        privateNetwork: settings.privateNetwork,
        timeoutMs: settings.timeoutMs,
        fetch: deps.fetch,
      });
    }
    if (monitor.kind === "signed_heartbeat") {
      return evaluateHeartbeat({
        row: await readHeartbeat(env.DB, monitor.id),
        now: deps.now(),
        staleSeconds: settings.staleSeconds,
        progressSeconds: settings.progressSeconds,
      });
    }
    if (monitor.kind === "alby_hub") {
      return await runAlbyHubCheck({
        baseUrl: readString(env, "ALBY_BASE_URL"),
        routingProfile: readString(env, "ALBY_ROUTING_PROFILE"),
        hubName: readString(env, "ALBY_HUB_NAME"),
        hubRegion: readString(env, "ALBY_HUB_REGION"),
        token: readString(env, "ALBY_AUTH_TOKEN"),
        privateNetwork: settings.privateNetwork,
        timeoutMs: settings.timeoutMs,
        fetch: deps.fetch,
      });
    }
    if (monitor.kind === "btcpay") {
      return await runBtcpayCheck({
        baseUrl: readString(env, "BTCPAY_BASE_URL"),
        apiKey: readString(env, "BTCPAY_API_KEY"),
        privateNetwork: settings.privateNetwork,
        timeoutMs: settings.timeoutMs,
        fetch: deps.fetch,
      });
    }
    return unknownResult("This monitor kind is not implemented.");
  } catch (error) {
    return networkFailure(error, 0);
  }
}

async function applyProbe(
  env: Env,
  settings: Settings,
  monitor: MonitorDefinition,
  check: CheckResult,
  now: number,
): Promise<void> {
  const loaded = await loadMemory(env.DB, monitor.id);
  const next = transition({
    memory: loaded.memory,
    result: check,
    now,
    monitor: {
      failureThreshold: settings.failureThreshold ?? monitor.failureThreshold,
      recoveryThreshold: settings.recoveryThreshold ?? monitor.recoveryThreshold,
      severity: monitor.severity,
      incidentOnDegraded: monitor.incidentOnDegraded,
      unknownThreshold: settings.unknownThreshold || monitor.unknownThreshold,
    },
    reminderSeconds: settings.reminderSeconds,
    newIncidentId: `inc_${crypto.randomUUID()}`,
    newIntegrityIncidentId: `inc_${crypto.randomUUID()}`,
  });
  const alerts = next.notices.flatMap((item) =>
    incidentAlerts(
      env,
      settings,
      monitor,
      item,
      check.observedVersion ?? loaded.memory.observedVersion,
      now,
    ),
  );
  await commitCheck(env.DB, {
    monitorId: monitor.id,
    projectId: monitor.projectId,
    previousGeneration: loaded.generation,
    memory: next.memory,
    check,
    now,
    notices: next.notices,
    alerts,
  });
}

function incidentAlerts(
  env: Env,
  settings: Settings,
  monitor: MonitorDefinition,
  notice: Notice,
  observedVersion: string | null,
  now: number,
): AlertDraft[] {
  const project = PROJECTS[monitor.projectId];
  const text = formatIncidentMessage({
    projectName: project.displayName,
    displayName: monitor.displayName,
    severity: notice.severity,
    kind: notice.kind,
    event: notice.event,
    state: notice.monitorStatus,
    incidentId: notice.incidentId,
    occurredAt: notice.occurredAt,
    reason: notice.reason,
    observedVersion,
    runbookUrl: settings.runbookBase ? `${settings.runbookBase}${monitor.runbookPath}` : null,
  });
  const bucket =
    settings.reminderSeconds > 0 ? Math.floor(now / (settings.reminderSeconds * 1000)) : now;
  const suffix = notice.event === "remind" ? `remind:${bucket}` : notice.event;
  const drafts: AlertDraft[] = [draft(monitor, notice, "nostr", `${suffix}:nostr`, text)];
  const criticalEvent =
    notice.severity === "critical" &&
    (notice.event === "open" || notice.event === "remind" || notice.event === "close");
  if (
    criticalEvent &&
    settings.telegramMode === "dual" &&
    telegramChat(readString(env, "TELEGRAM_CHAT_IDS"), monitor.projectId)
  ) {
    drafts.push(draft(monitor, notice, "telegram", `${suffix}:telegram`, text));
  }
  return drafts;
}

function draft(
  monitor: MonitorDefinition,
  notice: Notice,
  destination: "nostr" | "telegram",
  suffix: string,
  text: string,
): AlertDraft {
  return {
    id: `alt_${crypto.randomUUID()}`,
    alertClass:
      notice.event === "close" ? "recovery" : notice.event === "remind" ? "reminder" : "outage",
    incidentId: notice.incidentId,
    monitorId: monitor.id,
    projectId: monitor.projectId,
    dedupeKey: `incident:${notice.incidentId}:${suffix}`,
    destination,
    severity: notice.severity,
    text,
  };
}
