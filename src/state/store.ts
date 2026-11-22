import type {
  AlertDraft,
  CheckResult,
  MonitorMemory,
  MonitorStatus,
  Notice,
  OpenIncident,
  OutboxRow,
} from "../types";
import { emptyMemory } from "./transition";

interface StateRow {
  monitor_id: string;
  project_id: string;
  status: string;
  consecutive_successes: number;
  consecutive_failures: number;
  failure_kind: string | null;
  observed_version: string | null;
  generation: number;
}

interface IncidentRow {
  id: string;
  kind: string;
  severity: string;
  opened_at: number;
  reminder_count: number;
  last_reminder_at: number | null;
  silenced_until: number | null;
  acked_at: number | null;
}

export async function loadMemory(
  db: D1Database,
  monitorId: string,
): Promise<{ memory: MonitorMemory; generation: number }> {
  const state = await db
    .prepare(
      "SELECT monitor_id, project_id, status, consecutive_successes, consecutive_failures, failure_kind, observed_version, generation FROM monitor_state WHERE monitor_id = ?",
    )
    .bind(monitorId)
    .first<StateRow>();
  const incident = await db
    .prepare(
      "SELECT id, kind, severity, opened_at, reminder_count, last_reminder_at, silenced_until, acked_at FROM incidents WHERE monitor_id = ? AND status = 'open'",
    )
    .bind(monitorId)
    .first<IncidentRow>();
  if (!state) return { memory: emptyMemory(), generation: 0 };
  const memory = emptyMemory();
  memory.status = asStatus(state.status);
  memory.consecutiveSuccesses = state.consecutive_successes;
  memory.consecutiveFailures = state.consecutive_failures;
  memory.failureKind = state.failure_kind ? asStatus(state.failure_kind) : null;
  memory.observedVersion = state.observed_version;
  memory.openIncident = incident ? toIncident(incident) : null;
  return { memory, generation: state.generation };
}

export async function commitCheck(
  db: D1Database,
  input: {
    monitorId: string;
    projectId: string;
    previousGeneration: number;
    memory: MonitorMemory;
    check: CheckResult;
    now: number;
    notice: Notice | null;
    alerts: AlertDraft[];
  },
): Promise<void> {
  const nextGeneration = input.previousGeneration + 1;
  const successAt = input.check.status === "healthy" ? input.now : null;
  const failureAt =
    input.check.status === "down" ||
    input.check.status === "degraded" ||
    input.check.status === "misconfigured"
      ? input.now
      : null;
  const statements: D1PreparedStatement[] = [
    db
      .prepare(
        `INSERT INTO monitor_state (
        monitor_id, project_id, status, consecutive_successes, consecutive_failures, failure_kind,
        last_check_at, last_success_at, last_failure_at, last_error_class, last_latency_ms, last_summary,
        observed_version, generation, updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT(monitor_id) DO UPDATE SET
        project_id = excluded.project_id,
        status = excluded.status,
        consecutive_successes = excluded.consecutive_successes,
        consecutive_failures = excluded.consecutive_failures,
        failure_kind = excluded.failure_kind,
        last_check_at = excluded.last_check_at,
        last_success_at = COALESCE(excluded.last_success_at, monitor_state.last_success_at),
        last_failure_at = COALESCE(excluded.last_failure_at, monitor_state.last_failure_at),
        last_error_class = excluded.last_error_class,
        last_latency_ms = excluded.last_latency_ms,
        last_summary = excluded.last_summary,
        observed_version = COALESCE(excluded.observed_version, monitor_state.observed_version),
        generation = monitor_state.generation + 1,
        updated_at = excluded.updated_at
      WHERE monitor_state.generation = ?`,
      )
      .bind(
        input.monitorId,
        input.projectId,
        input.memory.status,
        input.memory.consecutiveSuccesses,
        input.memory.consecutiveFailures,
        input.memory.failureKind,
        input.now,
        successAt,
        failureAt,
        input.check.errorClass,
        input.check.latencyMs,
        input.check.summary,
        input.memory.observedVersion,
        nextGeneration,
        input.now,
        input.previousGeneration,
      ),
  ];
  if (input.notice?.event === "open") {
    statements.push(
      db
        .prepare(
          `INSERT INTO incidents (
          id, monitor_id, project_id, status, kind, severity, opened_at, open_reason, reminder_count, updated_at
        )
        SELECT ?, ?, ?, 'open', ?, ?, ?, ?, 0, ?
        FROM monitor_state
        WHERE monitor_id = ? AND generation = ?
          AND NOT EXISTS (SELECT 1 FROM incidents WHERE monitor_id = ? AND status = 'open')`,
        )
        .bind(
          input.notice.incidentId,
          input.monitorId,
          input.projectId,
          input.notice.kind,
          input.notice.severity,
          input.notice.occurredAt,
          input.notice.reason,
          input.now,
          input.monitorId,
          nextGeneration,
          input.monitorId,
        ),
    );
  }
  if (input.notice?.event === "close") {
    statements.push(
      db
        .prepare(
          `UPDATE incidents SET status = 'closed', closed_at = ?, close_reason = ?, updated_at = ?
         WHERE id = ? AND status = 'open'
           AND EXISTS (SELECT 1 FROM monitor_state WHERE monitor_id = ? AND generation = ?)`,
        )
        .bind(
          input.now,
          input.notice.reason,
          input.now,
          input.notice.incidentId,
          input.monitorId,
          nextGeneration,
        ),
    );
  }
  if (input.notice?.event === "remind") {
    statements.push(
      db
        .prepare(
          `UPDATE incidents SET reminder_count = reminder_count + 1, last_reminder_at = ?, updated_at = ?
         WHERE id = ? AND status = 'open'
           AND EXISTS (SELECT 1 FROM monitor_state WHERE monitor_id = ? AND generation = ?)`,
        )
        .bind(input.now, input.now, input.notice.incidentId, input.monitorId, nextGeneration),
    );
  }
  for (const alert of input.alerts) {
    statements.push(
      db
        .prepare(
          `INSERT OR IGNORE INTO alert_outbox (
          id, alert_class, incident_id, monitor_id, project_id, dedupe_key, destination, severity,
          state, payload_text, attempt_count, next_attempt_at, created_at, updated_at
        )
        SELECT ?, ?, ?, ?, ?, ?, ?, ?, 'queued', ?, 0, ?, ?, ?
        FROM monitor_state WHERE monitor_id = ? AND generation = ?`,
        )
        .bind(
          alert.id,
          alert.alertClass,
          alert.incidentId,
          alert.monitorId,
          alert.projectId,
          alert.dedupeKey,
          alert.destination,
          alert.severity,
          alert.text,
          input.now,
          input.now,
          input.now,
          input.monitorId,
          nextGeneration,
        ),
    );
  }
  await db.batch(statements);
}

export async function acquireLease(
  db: D1Database,
  name: string,
  owner: string,
  until: number,
  now: number,
): Promise<boolean> {
  const result = await db
    .prepare(
      `INSERT INTO scheduler_leases (job_name, owner, lease_until) VALUES (?, ?, ?)
     ON CONFLICT(job_name) DO UPDATE SET owner = excluded.owner, lease_until = excluded.lease_until
     WHERE scheduler_leases.lease_until <= ?`,
    )
    .bind(name, owner, until, now)
    .run();
  return (result.meta.changes ?? 0) > 0;
}

export async function releaseLease(
  db: D1Database,
  name: string,
  owner: string,
  now: number,
): Promise<void> {
  await db
    .prepare("UPDATE scheduler_leases SET lease_until = ? WHERE job_name = ? AND owner = ?")
    .bind(now, name, owner)
    .run();
}

export async function markRun(
  db: D1Database,
  name: string,
  startedAt: number | null,
  finishedAt: number | null,
  error: string | null,
): Promise<void> {
  await db
    .prepare(
      `INSERT INTO scheduler_runs (job_name, last_started_at, last_finished_at, last_error) VALUES (?, ?, ?, ?)
     ON CONFLICT(job_name) DO UPDATE SET
       last_started_at = COALESCE(excluded.last_started_at, scheduler_runs.last_started_at),
       last_finished_at = COALESCE(excluded.last_finished_at, scheduler_runs.last_finished_at),
       last_error = excluded.last_error`,
    )
    .bind(name, startedAt, finishedAt, error)
    .run();
}

export async function lastChecks(db: D1Database): Promise<Map<string, number | null>> {
  const rows = await db
    .prepare("SELECT monitor_id, last_check_at FROM monitor_state")
    .all<{ monitor_id: string; last_check_at: number | null }>();
  return new Map(rows.results.map((row) => [row.monitor_id, row.last_check_at]));
}

export interface HeartbeatRecord {
  receivedAt: number;
  progressToken: string | null;
  progressChangedAt: number;
  idle: boolean;
  loopAt: number | null;
}

export async function readHeartbeat(
  db: D1Database,
  monitorId: string,
): Promise<HeartbeatRecord | null> {
  const row = await db
    .prepare(
      "SELECT received_at, progress_token, progress_changed_at, idle, loop_at FROM heartbeats WHERE monitor_id = ?",
    )
    .bind(monitorId)
    .first<{
      received_at: number;
      progress_token: string | null;
      progress_changed_at: number;
      idle: number;
      loop_at: number | null;
    }>();
  if (!row) return null;
  return {
    receivedAt: row.received_at,
    progressToken: row.progress_token,
    progressChangedAt: row.progress_changed_at,
    idle: row.idle === 1,
    loopAt: row.loop_at,
  };
}

export async function storeHeartbeat(
  db: D1Database,
  input: {
    monitorId: string;
    projectId: string;
    now: number;
    reportedAt: number;
    nonce: string;
    nonceExpiresAt: number;
    progress: string | null;
    idle: boolean;
    loopAt: number | null;
  },
): Promise<"ok" | "replay"> {
  const existing = await readHeartbeat(db, input.monitorId);
  const progressChangedAt =
    !existing || existing.progressToken !== input.progress ? input.now : existing.progressChangedAt;
  try {
    await db.batch([
      db.prepare("DELETE FROM heartbeat_nonces WHERE expires_at < ?").bind(input.now),
      db
        .prepare("INSERT INTO heartbeat_nonces (monitor_id, nonce, expires_at) VALUES (?, ?, ?)")
        .bind(input.monitorId, input.nonce, input.nonceExpiresAt),
      db
        .prepare(
          `INSERT INTO heartbeats (
          monitor_id, project_id, received_at, reported_at, progress_token, progress_changed_at, idle, loop_at, summary
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL)
        ON CONFLICT(monitor_id) DO UPDATE SET
          received_at = excluded.received_at,
          reported_at = excluded.reported_at,
          progress_token = excluded.progress_token,
          progress_changed_at = excluded.progress_changed_at,
          idle = excluded.idle,
          loop_at = excluded.loop_at`,
        )
        .bind(
          input.monitorId,
          input.projectId,
          input.now,
          input.reportedAt,
          input.progress,
          progressChangedAt,
          input.idle ? 1 : 0,
          input.loopAt,
        ),
    ]);
    return "ok";
  } catch {
    return "replay";
  }
}

export async function claimOutbox(
  db: D1Database,
  now: number,
  claimUntil: number,
): Promise<OutboxRow[]> {
  const rows = await db
    .prepare(
      `SELECT id, alert_class, incident_id, monitor_id, project_id, dedupe_key, destination, severity, state,
            payload_text, envelope_json, attempt_count, next_attempt_at, claim_until, last_error, created_at, updated_at
     FROM alert_outbox
     WHERE state IN ('queued', 'retrying') AND next_attempt_at <= ? AND (claim_until IS NULL OR claim_until < ?)
     ORDER BY created_at LIMIT 20`,
    )
    .bind(now, now)
    .all<OutboxRow>();
  const claimed: OutboxRow[] = [];
  for (const row of rows.results) {
    const result = await db
      .prepare(
        `UPDATE alert_outbox SET claim_until = ?, state = 'retrying', updated_at = ?
       WHERE id = ? AND state IN ('queued', 'retrying') AND (claim_until IS NULL OR claim_until < ?)`,
      )
      .bind(claimUntil, now, row.id, now)
      .run();
    if ((result.meta.changes ?? 0) > 0)
      claimed.push({ ...row, state: "retrying", claim_until: claimUntil });
  }
  return claimed;
}

export async function saveEnvelope(
  db: D1Database,
  id: string,
  envelope: string,
  now: number,
): Promise<void> {
  await db
    .prepare(
      "UPDATE alert_outbox SET envelope_json = ?, updated_at = ? WHERE id = ? AND envelope_json IS NULL",
    )
    .bind(envelope, now, id)
    .run();
}

export async function finishDelivery(
  db: D1Database,
  input: {
    id: string;
    state: "relay_accepted" | "retrying" | "failed";
    attemptCount: number;
    nextAttemptAt: number;
    error: string | null;
    now: number;
  },
): Promise<void> {
  await db
    .prepare(
      `UPDATE alert_outbox SET state = ?, attempt_count = ?, next_attempt_at = ?, last_error = ?, claim_until = NULL, updated_at = ? WHERE id = ?`,
    )
    .bind(input.state, input.attemptCount, input.nextAttemptAt, input.error, input.now, input.id)
    .run();
}

export async function insertAlert(db: D1Database, alert: AlertDraft, now: number): Promise<void> {
  await db
    .prepare(
      `INSERT OR IGNORE INTO alert_outbox (
      id, alert_class, incident_id, monitor_id, project_id, dedupe_key, destination, severity,
      state, payload_text, attempt_count, next_attempt_at, created_at, updated_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'queued', ?, 0, ?, ?, ?)`,
    )
    .bind(
      alert.id,
      alert.alertClass,
      alert.incidentId,
      alert.monitorId,
      alert.projectId,
      alert.dedupeKey,
      alert.destination,
      alert.severity,
      alert.text,
      now,
      now,
      now,
    )
    .run();
}

export async function countRecent(
  db: D1Database,
  dedupePrefix: string,
  since: number,
): Promise<number> {
  const row = await db
    .prepare(
      "SELECT COUNT(*) AS count FROM alert_outbox WHERE dedupe_key LIKE ? AND created_at >= ?",
    )
    .bind(`${dedupePrefix}%`, since)
    .first<{ count: number }>();
  return row?.count ?? 0;
}

export async function relayCache(
  db: D1Database,
  pubkey: string,
  now: number,
): Promise<{ relays: string[]; negative: boolean } | null> {
  const row = await db
    .prepare(
      "SELECT relays_json, negative FROM relay_list_cache WHERE pubkey = ? AND expires_at > ?",
    )
    .bind(pubkey, now)
    .first<{ relays_json: string; negative: number }>();
  if (!row) return null;
  try {
    const relays = JSON.parse(row.relays_json) as unknown;
    if (!Array.isArray(relays) || relays.some((item) => typeof item !== "string")) return null;
    return { relays, negative: row.negative === 1 };
  } catch {
    return null;
  }
}

export async function saveRelayCache(
  db: D1Database,
  pubkey: string,
  relays: string[],
  negative: boolean,
  now: number,
  expiresAt: number,
): Promise<void> {
  await db
    .prepare(
      `INSERT INTO relay_list_cache (pubkey, relays_json, fetched_at, expires_at, negative) VALUES (?, ?, ?, ?, ?)
     ON CONFLICT(pubkey) DO UPDATE SET relays_json = excluded.relays_json, fetched_at = excluded.fetched_at, expires_at = excluded.expires_at, negative = excluded.negative`,
    )
    .bind(pubkey, JSON.stringify(relays), now, expiresAt, negative ? 1 : 0)
    .run();
}

export interface UpstreamCacheRow {
  etag: string | null;
  payload: unknown;
  fetchedAt: number;
  rateLimitedUntil: number | null;
}

export async function readUpstream(db: D1Database, key: string): Promise<UpstreamCacheRow | null> {
  const row = await db
    .prepare(
      "SELECT etag, payload_json, fetched_at, rate_limited_until FROM upstream_cache WHERE source_key = ?",
    )
    .bind(key)
    .first<{
      etag: string | null;
      payload_json: string | null;
      fetched_at: number;
      rate_limited_until: number | null;
    }>();
  if (!row) return null;
  let payload: unknown = null;
  if (row.payload_json) {
    try {
      payload = JSON.parse(row.payload_json) as unknown;
    } catch {
      payload = null;
    }
  }
  return {
    etag: row.etag,
    payload,
    fetchedAt: row.fetched_at,
    rateLimitedUntil: row.rate_limited_until,
  };
}

export async function writeUpstream(
  db: D1Database,
  key: string,
  row: UpstreamCacheRow,
): Promise<void> {
  await db
    .prepare(
      `INSERT INTO upstream_cache (source_key, etag, payload_json, fetched_at, rate_limited_until) VALUES (?, ?, ?, ?, ?)
     ON CONFLICT(source_key) DO UPDATE SET etag = excluded.etag, payload_json = excluded.payload_json, fetched_at = excluded.fetched_at, rate_limited_until = excluded.rate_limited_until`,
    )
    .bind(
      key,
      row.etag,
      row.payload === null ? null : JSON.stringify(row.payload),
      row.fetchedAt,
      row.rateLimitedUntil,
    )
    .run();
}

export interface VersionRow {
  installed: string | null;
  latest: string | null;
  latestUrl: string | null;
  securityStatus: string;
  advisoryFingerprint: string | null;
  noticeFingerprint: string | null;
}

export async function readVersion(db: D1Database, monitorId: string): Promise<VersionRow | null> {
  const row = await db
    .prepare(
      "SELECT installed_version, latest_version, latest_url, security_status, advisory_fingerprint, notice_fingerprint FROM observed_versions WHERE monitor_id = ?",
    )
    .bind(monitorId)
    .first<{
      installed_version: string | null;
      latest_version: string | null;
      latest_url: string | null;
      security_status: string;
      advisory_fingerprint: string | null;
      notice_fingerprint: string | null;
    }>();
  if (!row) return null;
  return {
    installed: row.installed_version,
    latest: row.latest_version,
    latestUrl: row.latest_url,
    securityStatus: row.security_status,
    advisoryFingerprint: row.advisory_fingerprint,
    noticeFingerprint: row.notice_fingerprint,
  };
}

export async function writeVersion(
  db: D1Database,
  monitorId: string,
  row: VersionRow,
  now: number,
): Promise<void> {
  await db
    .prepare(
      `INSERT INTO observed_versions (
      monitor_id, installed_version, latest_version, latest_url, security_status, advisory_fingerprint, notice_fingerprint, updated_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(monitor_id) DO UPDATE SET
      installed_version = excluded.installed_version,
      latest_version = excluded.latest_version,
      latest_url = excluded.latest_url,
      security_status = excluded.security_status,
      advisory_fingerprint = excluded.advisory_fingerprint,
      notice_fingerprint = excluded.notice_fingerprint,
      updated_at = excluded.updated_at`,
    )
    .bind(
      monitorId,
      row.installed,
      row.latest,
      row.latestUrl,
      row.securityStatus,
      row.advisoryFingerprint,
      row.noticeFingerprint,
      now,
    )
    .run();
}

export async function installedVersion(db: D1Database, monitorId: string): Promise<string | null> {
  const row = await db
    .prepare("SELECT observed_version FROM monitor_state WHERE monitor_id = ?")
    .bind(monitorId)
    .first<{ observed_version: string | null }>();
  return row?.observed_version ?? null;
}

export async function statusSummary(
  db: D1Database,
): Promise<{
  openIncidents: number;
  deadLetters: number;
  lastCheck: number | null;
  lastUpdate: number | null;
}> {
  const open = await db
    .prepare("SELECT COUNT(*) AS count FROM incidents WHERE status = 'open'")
    .first<{ count: number }>();
  const dead = await db
    .prepare("SELECT COUNT(*) AS count FROM alert_outbox WHERE state = 'failed'")
    .first<{ count: number }>();
  const check = await db
    .prepare("SELECT last_finished_at FROM scheduler_runs WHERE job_name = 'checks'")
    .first<{ last_finished_at: number | null }>();
  const update = await db
    .prepare("SELECT last_finished_at FROM scheduler_runs WHERE job_name = 'updates'")
    .first<{ last_finished_at: number | null }>();
  return {
    openIncidents: open?.count ?? 0,
    deadLetters: dead?.count ?? 0,
    lastCheck: check?.last_finished_at ?? null,
    lastUpdate: update?.last_finished_at ?? null,
  };
}

export async function silenceIncident(
  db: D1Database,
  id: string,
  until: number,
  now: number,
): Promise<boolean> {
  const result = await db
    .prepare(
      "UPDATE incidents SET silenced_until = ?, updated_at = ? WHERE id = ? AND status = 'open'",
    )
    .bind(until, now, id)
    .run();
  return (result.meta.changes ?? 0) > 0;
}

export async function ackIncident(db: D1Database, id: string, now: number): Promise<boolean> {
  const result = await db
    .prepare("UPDATE incidents SET acked_at = ?, updated_at = ? WHERE id = ? AND status = 'open'")
    .bind(now, now, id)
    .run();
  return (result.meta.changes ?? 0) > 0;
}

export async function listOpenIncident(
  db: D1Database,
  id: string,
): Promise<{ id: string; monitorId: string; status: string } | null> {
  const row = await db
    .prepare("SELECT id, monitor_id, status FROM incidents WHERE id = ?")
    .bind(id)
    .first<{ id: string; monitor_id: string; status: string }>();
  if (!row) return null;
  return { id: row.id, monitorId: row.monitor_id, status: row.status };
}

function asStatus(value: string): MonitorStatus {
  if (
    value === "healthy" ||
    value === "degraded" ||
    value === "down" ||
    value === "unknown" ||
    value === "misconfigured"
  )
    return value;
  return "unknown";
}

function toIncident(row: IncidentRow): OpenIncident {
  const kind =
    row.kind === "outage" ||
    row.kind === "degraded" ||
    row.kind === "misconfigured" ||
    row.kind === "inconclusive"
      ? row.kind
      : "outage";
  const severity =
    row.severity === "info" || row.severity === "warning" || row.severity === "critical"
      ? row.severity
      : "warning";
  return {
    id: row.id,
    kind,
    severity,
    openedAt: row.opened_at,
    reminderCount: row.reminder_count,
    lastReminderAt: row.last_reminder_at,
    silencedUntil: row.silenced_until,
    ackedAt: row.acked_at,
  };
}
