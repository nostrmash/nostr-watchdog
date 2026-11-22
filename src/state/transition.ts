import type {
  IncidentKind,
  MonitorDefinition,
  MonitorMemory,
  MonitorStatus,
  Notice,
  Severity,
  TransitionResult,
} from "../types";
import type { CheckResult } from "../types";

const EMPTY: MonitorMemory = {
  status: "unknown",
  consecutiveSuccesses: 0,
  consecutiveFailures: 0,
  failureKind: null,
  openIncident: null,
  integrityIncident: null,
  consecutiveUnknowns: 0,
  unknownSince: null,
  lastUnknownReason: null,
  observedVersion: null,
};

export function emptyMemory(): MonitorMemory {
  return {
    ...EMPTY,
    openIncident: null,
    integrityIncident: null,
  };
}

export function transition(input: {
  memory: MonitorMemory;
  result: CheckResult;
  now: number;
  monitor: Pick<
    MonitorDefinition,
    | "failureThreshold"
    | "recoveryThreshold"
    | "severity"
    | "incidentOnDegraded"
    | "unknownThreshold"
  >;
  reminderSeconds: number;
  newIncidentId: string;
  newIntegrityIncidentId?: string;
}): TransitionResult {
  const memory: MonitorMemory = {
    ...input.memory,
    openIncident: input.memory.openIncident ? { ...input.memory.openIncident } : null,
    integrityIncident: input.memory.integrityIncident
      ? { ...input.memory.integrityIncident }
      : null,
    observedVersion: input.result.observedVersion ?? input.memory.observedVersion,
  };
  if (input.result.status === "unknown") return applyUnknown(memory, input);
  const notices: Notice[] = [];
  closeIntegrity(memory, notices, input.now, input.result.summary);
  memory.consecutiveUnknowns = 0;
  memory.unknownSince = null;
  memory.lastUnknownReason = null;
  if (input.result.status === "healthy") {
    memory.status = "healthy";
    memory.consecutiveSuccesses += 1;
    memory.consecutiveFailures = 0;
    memory.failureKind = null;
    if (memory.openIncident && memory.consecutiveSuccesses >= input.monitor.recoveryThreshold) {
      const incident = memory.openIncident;
      memory.openIncident = null;
      notices.push(
        notice(
          "close",
          incident.id,
          incident.kind,
          incident.severity,
          input.result.summary,
          input.now,
          "healthy",
        ),
      );
    }
    return done(memory, notices);
  }
  const kind = incidentKind(input.result.status, input.monitor.incidentOnDegraded);
  if (!kind) {
    memory.status = input.result.status;
    memory.consecutiveSuccesses = 0;
    return done(memory, notices);
  }
  if (memory.failureKind === input.result.status) memory.consecutiveFailures += 1;
  else memory.consecutiveFailures = 1;
  memory.failureKind = input.result.status;
  memory.consecutiveSuccesses = 0;
  memory.status = input.result.status;
  const threshold = input.result.status === "misconfigured" ? 1 : input.monitor.failureThreshold;
  if (!memory.openIncident && memory.consecutiveFailures >= threshold) {
    const severity = severityFor(input.result.status, input.monitor.severity);
    memory.openIncident = {
      id: input.newIncidentId,
      kind,
      severity,
      openedAt: input.now,
      reminderCount: 0,
      lastReminderAt: null,
      silencedUntil: null,
      ackedAt: null,
    };
    notices.push(
      notice(
        "open",
        input.newIncidentId,
        kind,
        severity,
        input.result.summary,
        input.now,
        input.result.status,
      ),
    );
    return done(memory, notices);
  }
  const open = memory.openIncident;
  if (
    open &&
    open.kind === "outage" &&
    open.severity === "critical" &&
    input.reminderSeconds > 0 &&
    open.ackedAt === null &&
    (open.silencedUntil === null || open.silencedUntil <= input.now) &&
    input.now - (open.lastReminderAt ?? open.openedAt) >= input.reminderSeconds * 1000
  ) {
    open.reminderCount += 1;
    open.lastReminderAt = input.now;
    notices.push(
      notice(
        "remind",
        open.id,
        open.kind,
        open.severity,
        input.result.summary,
        input.now,
        input.result.status,
      ),
    );
  }
  return done(memory, notices);
}

function applyUnknown(
  memory: MonitorMemory,
  input: {
    result: CheckResult;
    now: number;
    monitor: Pick<MonitorDefinition, "unknownThreshold">;
    newIncidentId: string;
    newIntegrityIncidentId?: string;
  },
): TransitionResult {
  memory.consecutiveUnknowns += 1;
  memory.unknownSince ??= input.now;
  memory.lastUnknownReason = input.result.summary;
  if (!memory.openIncident) memory.status = "unknown";
  const threshold = input.monitor.unknownThreshold;
  if (!memory.integrityIncident && memory.consecutiveUnknowns >= threshold) {
    const id = input.newIntegrityIncidentId ?? input.newIncidentId;
    memory.integrityIncident = {
      id,
      kind: "inconclusive",
      severity: "warning",
      openedAt: input.now,
      reminderCount: 0,
      lastReminderAt: null,
      silencedUntil: null,
      ackedAt: null,
    };
    const opened = notice(
      "open",
      id,
      "inconclusive",
      "warning",
      input.result.summary,
      input.now,
      memory.status,
    );
    return { memory, notice: opened, notices: [opened], changed: true };
  }
  return { memory, notice: null, notices: [], changed: true };
}

function closeIntegrity(
  memory: MonitorMemory,
  notices: Notice[],
  now: number,
  reason: string,
): void {
  if (!memory.integrityIncident) return;
  const incident = memory.integrityIncident;
  memory.integrityIncident = null;
  notices.push(
    notice(
      "close",
      incident.id,
      "inconclusive",
      incident.severity,
      `Monitoring produced a conclusive sample. ${reason}`,
      now,
      "healthy",
    ),
  );
}

function done(memory: MonitorMemory, notices: Notice[]): TransitionResult {
  return { memory, notice: primaryNotice(notices), notices, changed: true };
}

function primaryNotice(notices: Notice[]): Notice | null {
  return notices.find((item) => item.kind !== "inconclusive") ?? notices[0] ?? null;
}

function incidentKind(status: MonitorStatus, incidentOnDegraded: boolean): IncidentKind | null {
  if (status === "down") return "outage";
  if (status === "degraded") return incidentOnDegraded ? "degraded" : null;
  if (status === "misconfigured") return "misconfigured";
  return null;
}

function severityFor(status: MonitorStatus, monitorSeverity: Severity): Severity {
  if (status === "down") return monitorSeverity;
  return "warning";
}

function notice(
  event: Notice["event"],
  incidentId: string,
  kind: IncidentKind,
  severity: Severity,
  reason: string,
  occurredAt: number,
  monitorStatus: MonitorStatus,
): Notice {
  return { event, incidentId, kind, severity, reason, occurredAt, monitorStatus };
}
