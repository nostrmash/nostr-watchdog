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
  consecutive_unknowns: number;
  unknown_since: number | null;
  last_unknown_reason: string | null;
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
      `SELECT monitor_id, project_id, status, consecutive_successes, consecutive_failures, failure_kind,
              observed_version, generation, consecutive_unknowns, unknown_since, last_unknown_reason
       FROM monitor_state WHERE monitor_id = ?`,
    )
    .bind(monitorId)
    .first<StateRow>();
  const incidents = await db
    .prepare(
      "SELECT id, kind, severity, opened_at, reminder_count, last_reminder_at, silenced_until, acked_at FROM incidents WHERE monitor_id = ? AND status = 'open'",
    )
    .bind(monitorId)
    .all<IncidentRow>();
  if (!state) return { memory: emptyMemory(), generation: 0 };
  const memory = emptyMemory();
  memory.status = asStatus(state.status);
  memory.consecutiveSuccesses = state.consecutive_successes;
  memory.consecutiveFailures = state.consecutive_failures;
  memory.failureKind = state.failure_kind ? asStatus(state.failure_kind) : null;
  memory.observedVersion = state.observed_version;
  memory.consecutiveUnknowns = state.consecutive_unknowns;
  memory.unknownSince = state.unknown_since;
  memory.lastUnknownReason = state.last_unknown_reason;
  for (const row of incidents.results) {
    const incident = toIncident(row);
    if (incident.kind === "inconclusive") memory.integrityIncident = incident;
    else memory.openIncident = incident;
  }
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
    notices: Notice[];
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
        observed_version, generation, updated_at, consecutive_unknowns, unknown_since, last_unknown_reason
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
        updated_at = excluded.updated_at,
        consecutive_unknowns = excluded.consecutive_unknowns,
        unknown_since = excluded.unknown_since,
        last_unknown_reason = excluded.last_unknown_reason
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
        input.memory.consecutiveUnknowns,
        input.memory.unknownSince,
        input.memory.lastUnknownReason,
        input.previousGeneration,
      ),
  ];
  for (const item of input.notices) {
    if (item.event === "open") {
      statements.push(
        db
          .prepare(
            `INSERT INTO incidents (
            id, monitor_id, project_id, status, kind, severity, opened_at, open_reason, reminder_count, updated_at
          )
          SELECT ?, ?, ?, 'open', ?, ?, ?, ?, 0, ?
          FROM monitor_state
          WHERE monitor_id = ? AND generation = ?
            AND NOT EXISTS (
              SELECT 1 FROM incidents WHERE monitor_id = ? AND status = 'open' AND kind = ?
            )`,
          )
          .bind(
            item.incidentId,
            input.monitorId,
            input.projectId,
            item.kind,
            item.severity,
            item.occurredAt,
            item.reason,
            input.now,
            input.monitorId,
            nextGeneration,
            input.monitorId,
            item.kind,
          ),
      );
    }
    if (item.event === "close") {
      statements.push(
        db
          .prepare(
            `UPDATE incidents SET status = 'closed', closed_at = ?, close_reason = ?, updated_at = ?
           WHERE id = ? AND status = 'open'
             AND EXISTS (SELECT 1 FROM monitor_state WHERE monitor_id = ? AND generation = ?)`,
          )
          .bind(
            input.now,
            item.reason,
            input.now,
            item.incidentId,
            input.monitorId,
            nextGeneration,
          ),
      );
    }
    if (item.event === "remind") {
      statements.push(
        db
          .prepare(
            `UPDATE incidents SET reminder_count = reminder_count + 1, last_reminder_at = ?, updated_at = ?
           WHERE id = ? AND status = 'open'
             AND EXISTS (SELECT 1 FROM monitor_state WHERE monitor_id = ? AND generation = ?)`,
          )
          .bind(input.now, input.now, item.incidentId, input.monitorId, nextGeneration),
      );
    }
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
  successAt: number | null = null,
): Promise<void> {
  await db
    .prepare(
      `INSERT INTO scheduler_runs (
      job_name, last_started_at, last_finished_at, last_error, last_success_at
    ) VALUES (?, ?, ?, ?, ?)
     ON CONFLICT(job_name) DO UPDATE SET
       last_started_at = COALESCE(excluded.last_started_at, scheduler_runs.last_started_at),
       last_finished_at = COALESCE(excluded.last_finished_at, scheduler_runs.last_finished_at),
       last_error = excluded.last_error,
       last_success_at = COALESCE(excluded.last_success_at, scheduler_runs.last_success_at)`,
    )
    .bind(name, startedAt, finishedAt, error, successAt)
    .run();
}

export interface VendorCheckRow {
  monitorId: string;
  vendor: string;
  attemptedAt: number | null;
  succeededAt: number | null;
  releasesCheckedAt: number | null;
  advisoriesCheckedAt: number | null;
  releasesStale: boolean;
  advisoriesStale: boolean;
  errorCode: string | null;
  consecutiveFailures: number;
}

export async function readVendorCheck(
  db: D1Database,
  monitorId: string,
): Promise<VendorCheckRow | null> {
  const row = await db
    .prepare(
      `SELECT monitor_id, vendor, attempted_at, succeeded_at, releases_checked_at, advisories_checked_at,
        releases_stale, advisories_stale, error_code, consecutive_failures
       FROM vendor_checks WHERE monitor_id = ?`,
    )
    .bind(monitorId)
    .first<{
      monitor_id: string;
      vendor: string;
      attempted_at: number | null;
      succeeded_at: number | null;
      releases_checked_at: number | null;
      advisories_checked_at: number | null;
      releases_stale: number;
      advisories_stale: number;
      error_code: string | null;
      consecutive_failures: number;
    }>();
  return row ? vendorCheckFrom(row) : null;
}

export async function writeVendorCheck(
  db: D1Database,
  row: VendorCheckRow,
  now: number,
): Promise<void> {
  await db
    .prepare(
      `INSERT INTO vendor_checks (
      monitor_id, vendor, attempted_at, succeeded_at, releases_checked_at, advisories_checked_at,
      releases_stale, advisories_stale, error_code, consecutive_failures, updated_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(monitor_id) DO UPDATE SET
      vendor = excluded.vendor,
      attempted_at = COALESCE(excluded.attempted_at, vendor_checks.attempted_at),
      succeeded_at = COALESCE(excluded.succeeded_at, vendor_checks.succeeded_at),
      releases_checked_at = COALESCE(excluded.releases_checked_at, vendor_checks.releases_checked_at),
      advisories_checked_at = COALESCE(excluded.advisories_checked_at, vendor_checks.advisories_checked_at),
      releases_stale = excluded.releases_stale,
      advisories_stale = excluded.advisories_stale,
      error_code = excluded.error_code,
      consecutive_failures = excluded.consecutive_failures,
      updated_at = excluded.updated_at`,
    )
    .bind(
      row.monitorId,
      row.vendor,
      row.attemptedAt,
      row.succeededAt,
      row.releasesCheckedAt,
      row.advisoriesCheckedAt,
      row.releasesStale ? 1 : 0,
      row.advisoriesStale ? 1 : 0,
      row.errorCode,
      row.consecutiveFailures,
      now,
    )
    .run();
}

function vendorCheckFrom(row: {
  monitor_id: string;
  vendor: string;
  attempted_at: number | null;
  succeeded_at: number | null;
  releases_checked_at: number | null;
  advisories_checked_at: number | null;
  releases_stale: number;
  advisories_stale: number;
  error_code: string | null;
  consecutive_failures: number;
}): VendorCheckRow {
  return {
    monitorId: row.monitor_id,
    vendor: row.vendor,
    attemptedAt: row.attempted_at,
    succeededAt: row.succeeded_at,
    releasesCheckedAt: row.releases_checked_at,
    advisoriesCheckedAt: row.advisories_checked_at,
    releasesStale: row.releases_stale === 1,
    advisoriesStale: row.advisories_stale === 1,
    errorCode: row.error_code,
    consecutiveFailures: row.consecutive_failures,
  };
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
            payload_text, envelope_json, attempt_count, next_attempt_at, claim_until, claim_token,
            accepted_relays, failed_relays, last_error, created_at, updated_at
     FROM alert_outbox
     WHERE state IN ('queued', 'retrying') AND next_attempt_at <= ? AND (claim_until IS NULL OR claim_until < ?)
     ORDER BY created_at LIMIT 20`,
    )
    .bind(now, now)
    .all<OutboxRow>();
  const claimed: OutboxRow[] = [];
  for (const row of rows.results) {
    const token = crypto.randomUUID();
    const result = await db
      .prepare(
        `UPDATE alert_outbox SET claim_until = ?, claim_token = ?, state = 'retrying', updated_at = ?
       WHERE id = ? AND state IN ('queued', 'retrying') AND (claim_until IS NULL OR claim_until < ?)`,
      )
      .bind(claimUntil, token, now, row.id, now)
      .run();
    if ((result.meta.changes ?? 0) > 0) {
      claimed.push({ ...row, state: "retrying", claim_until: claimUntil, claim_token: token });
    }
  }
  return claimed;
}

export async function claimRow(
  db: D1Database,
  id: string,
  now: number,
  claimUntil: number,
): Promise<string | null> {
  const token = crypto.randomUUID();
  const result = await db
    .prepare(
      `UPDATE alert_outbox SET claim_until = ?, claim_token = ?, state = 'retrying', updated_at = ?
       WHERE id = ? AND state IN ('queued', 'retrying') AND (claim_until IS NULL OR claim_until < ?)`,
    )
    .bind(claimUntil, token, now, id, now)
    .run();
  return (result.meta.changes ?? 0) > 0 ? token : null;
}

export async function extendClaim(
  db: D1Database,
  id: string,
  token: string,
  claimUntil: number,
): Promise<boolean> {
  const result = await db
    .prepare(
      "UPDATE alert_outbox SET claim_until = ? WHERE id = ? AND claim_token = ? AND state = 'retrying'",
    )
    .bind(claimUntil, id, token)
    .run();
  return (result.meta.changes ?? 0) > 0;
}

export async function saveEnvelope(
  db: D1Database,
  id: string,
  token: string,
  envelope: string,
  now: number,
): Promise<"saved" | "exists" | "lost"> {
  const result = await db
    .prepare(
      `UPDATE alert_outbox SET envelope_json = ?, updated_at = ?
       WHERE id = ? AND claim_token = ? AND envelope_json IS NULL`,
    )
    .bind(envelope, now, id, token)
    .run();
  if ((result.meta.changes ?? 0) > 0) return "saved";
  const row = await db
    .prepare("SELECT envelope_json, claim_token FROM alert_outbox WHERE id = ?")
    .bind(id)
    .first<{ envelope_json: string | null; claim_token: string | null }>();
  if (row?.envelope_json) return "exists";
  return row?.claim_token === token ? "lost" : "lost";
}

export async function readEnvelope(db: D1Database, id: string): Promise<string | null> {
  const row = await db
    .prepare("SELECT envelope_json FROM alert_outbox WHERE id = ?")
    .bind(id)
    .first<{ envelope_json: string | null }>();
  return row?.envelope_json ?? null;
}

export async function finishDelivery(
  db: D1Database,
  input: {
    id: string;
    token: string;
    state: "relay_accepted" | "retrying" | "failed";
    attemptCount: number;
    nextAttemptAt: number;
    error: string | null;
    acceptedRelays: string[] | null;
    failedRelays: string[] | null;
    now: number;
  },
): Promise<boolean> {
  const result = await db
    .prepare(
      `UPDATE alert_outbox
       SET state = ?, attempt_count = ?, next_attempt_at = ?, last_error = ?,
           accepted_relays = ?, failed_relays = ?, claim_until = NULL, claim_token = NULL, updated_at = ?
       WHERE id = ? AND claim_token = ?`,
    )
    .bind(
      input.state,
      input.attemptCount,
      input.nextAttemptAt,
      input.error,
      input.acceptedRelays ? JSON.stringify(input.acceptedRelays) : null,
      input.failedRelays ? JSON.stringify(input.failedRelays) : null,
      input.now,
      input.id,
      input.token,
    )
    .run();
  return (result.meta.changes ?? 0) > 0;
}

export async function retryDeadLetter(db: D1Database, id: string, now: number): Promise<boolean> {
  const result = await db
    .prepare(
      `UPDATE alert_outbox
       SET state = 'queued', attempt_count = 0, next_attempt_at = ?, claim_until = NULL,
           claim_token = NULL, last_error = NULL, updated_at = ?
       WHERE id = ? AND state = 'failed'`,
    )
    .bind(now, now, id)
    .run();
  return (result.meta.changes ?? 0) > 0;
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

const ACCEPTED_RETENTION_MS = 14 * 86_400_000;
const DEAD_LETTER_RETENTION_MS = 30 * 86_400_000;
const CLOSED_INCIDENT_RETENTION_MS = 90 * 86_400_000;
const UPSTREAM_RETENTION_MS = 7 * 86_400_000;

export async function pruneOperationalRows(db: D1Database, now: number): Promise<void> {
  await db.batch([
    db.prepare("DELETE FROM heartbeat_nonces WHERE expires_at < ?").bind(now),
    db.prepare("DELETE FROM relay_list_cache WHERE expires_at < ?").bind(now),
    db
      .prepare("DELETE FROM alert_outbox WHERE state = 'relay_accepted' AND updated_at < ?")
      .bind(now - ACCEPTED_RETENTION_MS),
    db
      .prepare("DELETE FROM alert_outbox WHERE state = 'failed' AND updated_at < ?")
      .bind(now - DEAD_LETTER_RETENTION_MS),
    db
      .prepare(
        "DELETE FROM incidents WHERE status = 'closed' AND closed_at IS NOT NULL AND closed_at < ?",
      )
      .bind(now - CLOSED_INCIDENT_RETENTION_MS),
    db
      .prepare(
        "DELETE FROM upstream_cache WHERE fetched_at < ? AND (rate_limited_until IS NULL OR rate_limited_until < ?)",
      )
      .bind(now - UPSTREAM_RETENTION_MS, now),
  ]);
}

export interface OperationalSnapshot {
  states: Array<{ monitorId: string; status: string; lastCheckAt: number | null }>;
  openIncidents: number;
  outbox: Array<{ state: string; count: number }>;
  errors: Array<{ error: string; count: number }>;
  runs: Array<{
    name: string;
    startedAt: number | null;
    finishedAt: number | null;
    successAt?: number | null;
    error: string | null;
  }>;
  heartbeats: Array<{ monitorId: string; receivedAt: number }>;
  vendorChecks?: VendorCheckRow[];
}

export async function operationalSnapshot(db: D1Database): Promise<OperationalSnapshot> {
  const [states, open, outbox, errors, runs, heartbeats, vendorChecks] = await Promise.all([
    db
      .prepare("SELECT monitor_id, status, last_check_at FROM monitor_state")
      .all<{ monitor_id: string; status: string; last_check_at: number | null }>(),
    db
      .prepare("SELECT COUNT(*) AS count FROM incidents WHERE status = 'open'")
      .first<{ count: number }>(),
    db
      .prepare("SELECT state, COUNT(*) AS count FROM alert_outbox GROUP BY state")
      .all<{ state: string; count: number }>(),
    db
      .prepare(
        `SELECT last_error AS error, COUNT(*) AS count FROM alert_outbox
         WHERE state IN ('retrying', 'failed') AND last_error IS NOT NULL
         GROUP BY last_error`,
      )
      .all<{ error: string; count: number }>(),
    db
      .prepare(
        "SELECT job_name, last_started_at, last_finished_at, last_success_at, last_error FROM scheduler_runs",
      )
      .all<{
        job_name: string;
        last_started_at: number | null;
        last_finished_at: number | null;
        last_success_at: number | null;
        last_error: string | null;
      }>(),
    db
      .prepare("SELECT monitor_id, received_at FROM heartbeats")
      .all<{ monitor_id: string; received_at: number }>(),
    db
      .prepare(
        `SELECT monitor_id, vendor, attempted_at, succeeded_at, releases_checked_at, advisories_checked_at,
          releases_stale, advisories_stale, error_code, consecutive_failures
         FROM vendor_checks`,
      )
      .all<{
        monitor_id: string;
        vendor: string;
        attempted_at: number | null;
        succeeded_at: number | null;
        releases_checked_at: number | null;
        advisories_checked_at: number | null;
        releases_stale: number;
        advisories_stale: number;
        error_code: string | null;
        consecutive_failures: number;
      }>(),
  ]);
  return {
    states: states.results.map((row) => ({
      monitorId: row.monitor_id,
      status: row.status,
      lastCheckAt: row.last_check_at,
    })),
    openIncidents: open?.count ?? 0,
    outbox: outbox.results.map((row) => ({ state: row.state, count: row.count })),
    errors: errors.results.map((row) => ({ error: row.error, count: row.count })),
    runs: runs.results.map((row) => ({
      name: row.job_name,
      startedAt: row.last_started_at,
      finishedAt: row.last_finished_at,
      successAt: row.last_success_at,
      error: row.last_error,
    })),
    heartbeats: heartbeats.results.map((row) => ({
      monitorId: row.monitor_id,
      receivedAt: row.received_at,
    })),
    vendorChecks: vendorChecks.results.map((row) => vendorCheckFrom(row)),
  };
}

export async function listFailedAlerts(db: D1Database): Promise<
  Array<{
    id: string;
    monitorId: string;
    projectId: string;
    destination: string;
    attemptCount: number;
    lastError: string | null;
    createdAt: number;
    payloadText: string;
  }>
> {
  const rows = await db
    .prepare(
      `SELECT id, monitor_id, project_id, destination, attempt_count, last_error, created_at, payload_text
       FROM alert_outbox WHERE state = 'failed' ORDER BY updated_at DESC LIMIT 50`,
    )
    .all<{
      id: string;
      monitor_id: string;
      project_id: string;
      destination: string;
      attempt_count: number;
      last_error: string | null;
      created_at: number;
      payload_text: string;
    }>();
  return rows.results.map((row) => ({
    id: row.id,
    monitorId: row.monitor_id,
    projectId: row.project_id,
    destination: row.destination,
    attemptCount: row.attempt_count,
    lastError: row.last_error,
    createdAt: row.created_at,
    payloadText: row.payload_text.slice(0, 500),
  }));
}

export async function statusSummary(db: D1Database): Promise<{
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
