use std::path::Path;
use std::sync::{Arc, Mutex};

use rusqlite::{params, Connection, OptionalExtension};
use watchdog_core::domain::{
    AlertClass, AlertDraft, CheckResult, DeliveryState, Destination, IncidentKind, MonitorMemory,
    MonitorStatus, Notice, NoticeEvent, OpenIncident, Severity,
};
use watchdog_core::status::{
    ErrorCount, HeartbeatView, OutboxCount, RunView, StateView, StatusSnapshot, VendorView,
};

const ACCEPTED_RETENTION_MS: i64 = 14 * 86_400_000;
const DEAD_LETTER_RETENTION_MS: i64 = 30 * 86_400_000;
const CLOSED_INCIDENT_RETENTION_MS: i64 = 90 * 86_400_000;
const UPSTREAM_RETENTION_MS: i64 = 7 * 86_400_000;

use crate::model::{
    CommitOutcome, FailedAlert, HeartbeatStored, LoadedMemory, MarmotProjectRow, OutboxRow,
    StoreError, UpstreamRow, VersionRow,
};
use crate::OperationalStore;

impl From<rusqlite::Error> for StoreError {
    fn from(value: rusqlite::Error) -> Self {
        StoreError::Database(value.to_string())
    }
}

#[derive(Clone)]
pub struct SqliteStore {
    conn: Arc<Mutex<Connection>>,
}

impl SqliteStore {
    pub fn open(path: &Path) -> Result<Self, StoreError> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)
                    .map_err(|error| StoreError::Database(error.to_string()))?;
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))
                        .map_err(|error| StoreError::Database(error.to_string()))?;
                }
            }
        }
        if !path.exists() {
            let mut options = std::fs::OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            options
                .open(path)
                .map_err(|error| StoreError::Database(error.to_string()))?;
        }
        let conn = Connection::open(path)?;
        let store = Self {
            conn: Arc::new(Mutex::new(conn)),
        };
        store.migrate()?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
                .map_err(|error| StoreError::Database(error.to_string()))?;
        }
        Ok(store)
    }

    pub fn memory() -> Result<Self, StoreError> {
        let store = Self {
            conn: Arc::new(Mutex::new(Connection::open_in_memory()?)),
        };
        store.migrate()?;
        Ok(store)
    }

    fn migrate(&self) -> Result<(), StoreError> {
        let mut conn = self.lock()?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS schema_migrations (id TEXT PRIMARY KEY, applied_at INTEGER NOT NULL);",
        )?;
        for (id, sql) in crate::schema::MIGRATIONS {
            let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
            let exists: bool = tx
                .query_row(
                    "SELECT 1 FROM schema_migrations WHERE id = ?1",
                    params![id],
                    |_| Ok(true),
                )
                .optional()?
                .unwrap_or(false);
            if !exists {
                tx.execute_batch(sql)?;
                tx.execute(
                    "INSERT INTO schema_migrations (id, applied_at) VALUES (?1, ?2)",
                    params![id, 0],
                )?;
            }
            tx.commit()?;
        }
        Ok(())
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, Connection>, StoreError> {
        self.conn.lock().map_err(|_| StoreError::Poison)
    }

    pub fn load_memory(&self, monitor_id: &str) -> Result<LoadedMemory, StoreError> {
        let conn = self.lock()?;
        let state = conn
            .query_row(
                "SELECT status, consecutive_successes, consecutive_failures, failure_kind, observed_version, generation, consecutive_unknowns, unknown_since, last_unknown_reason FROM monitor_state WHERE monitor_id = ?1",
                params![monitor_id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, Option<String>>(3)?,
                        row.get::<_, Option<String>>(4)?,
                        row.get::<_, i64>(5)?,
                        row.get::<_, i64>(6)?,
                        row.get::<_, Option<i64>>(7)?,
                        row.get::<_, Option<String>>(8)?,
                    ))
                },
            )
            .optional()?;
        let Some((
            status,
            successes,
            failures,
            failure_kind,
            version,
            generation,
            unknowns,
            unknown_since,
            unknown_reason,
        )) = state
        else {
            return Ok(LoadedMemory {
                memory: MonitorMemory::empty(),
                generation: 0,
            });
        };
        let mut memory = MonitorMemory::empty();
        memory.status = MonitorStatus::parse(&status).ok_or(StoreError::Invalid)?;
        memory.consecutive_successes = successes;
        memory.consecutive_failures = failures;
        memory.failure_kind = failure_kind.as_deref().and_then(MonitorStatus::parse);
        memory.observed_version = version;
        memory.consecutive_unknowns = unknowns;
        memory.unknown_since = unknown_since;
        memory.last_unknown_reason = unknown_reason;
        let mut stmt = conn.prepare(
            "SELECT id, kind, severity, opened_at, reminder_count, last_reminder_at, silenced_until, acked_at FROM incidents WHERE monitor_id = ?1 AND status = 'open'",
        )?;
        let rows = stmt.query_map(params![monitor_id], |row| {
            Ok(OpenIncident {
                id: row.get(0)?,
                kind: IncidentKind::parse(&row.get::<_, String>(1)?)
                    .unwrap_or(IncidentKind::Outage),
                severity: Severity::parse(&row.get::<_, String>(2)?).unwrap_or(Severity::Warning),
                opened_at: row.get(3)?,
                reminder_count: row.get(4)?,
                last_reminder_at: row.get(5)?,
                silenced_until: row.get(6)?,
                acked_at: row.get(7)?,
            })
        })?;
        for incident in rows {
            let incident = incident?;
            if incident.kind == IncidentKind::Inconclusive {
                memory.integrity_incident = Some(incident);
            } else {
                memory.open_incident = Some(incident);
            }
        }
        Ok(LoadedMemory { memory, generation })
    }

    pub fn commit_check(
        &self,
        monitor_id: &str,
        project_id: &str,
        previous_generation: i64,
        memory: &MonitorMemory,
        check: &CheckResult,
        now: i64,
        notices: &[Notice],
        alerts: &[AlertDraft],
    ) -> Result<CommitOutcome, StoreError> {
        let conn = self.lock()?;
        let tx = conn.unchecked_transaction()?;
        let next_generation = previous_generation + 1;
        let commit_token = uuid::Uuid::new_v4().to_string();
        let success_at = (check.status == MonitorStatus::Healthy).then_some(now);
        let failure_at = matches!(
            check.status,
            MonitorStatus::Down | MonitorStatus::Degraded | MonitorStatus::Misconfigured
        )
        .then_some(now);
        let changed = tx.execute(
            "INSERT INTO monitor_state (
                monitor_id, project_id, status, consecutive_successes, consecutive_failures, failure_kind,
                last_check_at, last_success_at, last_failure_at, last_error_class, last_latency_ms, last_summary,
                observed_version, generation, updated_at, consecutive_unknowns, unknown_since, last_unknown_reason,
                commit_token
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19)
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
                last_unknown_reason = excluded.last_unknown_reason,
                commit_token = excluded.commit_token
            WHERE monitor_state.generation = ?20",
            params![
                monitor_id,
                project_id,
                memory.status.as_str(),
                memory.consecutive_successes,
                memory.consecutive_failures,
                memory.failure_kind.map(MonitorStatus::as_str),
                now,
                success_at,
                failure_at,
                check.error_class,
                check.latency_ms,
                check.summary,
                memory.observed_version,
                next_generation,
                now,
                memory.consecutive_unknowns,
                memory.unknown_since,
                memory.last_unknown_reason,
                commit_token,
                previous_generation,
            ],
        )?;
        if changed == 0 {
            tx.rollback()?;
            return Ok(CommitOutcome { committed: false });
        }
        for item in notices {
            match item.event {
                NoticeEvent::Open => {
                    tx.execute(
                        "INSERT INTO incidents (
                            id, monitor_id, project_id, status, kind, severity, opened_at, open_reason, reminder_count, updated_at
                        )
                        SELECT ?1, ?2, ?3, 'open', ?4, ?5, ?6, ?7, 0, ?8
                        FROM monitor_state
                        WHERE monitor_id = ?2 AND generation = ?9 AND commit_token = ?10
                          AND NOT EXISTS (
                            SELECT 1 FROM incidents WHERE monitor_id = ?2 AND status = 'open' AND kind = ?4
                          )",
                        params![
                            item.incident_id,
                            monitor_id,
                            project_id,
                            item.kind.as_str(),
                            item.severity.as_str(),
                            item.occurred_at,
                            item.reason,
                            now,
                            next_generation,
                            commit_token,
                        ],
                    )?;
                }
                NoticeEvent::Close => {
                    tx.execute(
                        "UPDATE incidents SET status = 'closed', closed_at = ?1, close_reason = ?2, updated_at = ?1
                         WHERE id = ?3 AND status = 'open'
                           AND EXISTS (SELECT 1 FROM monitor_state WHERE monitor_id = ?4 AND generation = ?5 AND commit_token = ?6)",
                        params![now, item.reason, item.incident_id, monitor_id, next_generation, commit_token],
                    )?;
                }
                NoticeEvent::Remind => {
                    tx.execute(
                        "UPDATE incidents SET reminder_count = reminder_count + 1, last_reminder_at = ?1, updated_at = ?1
                         WHERE id = ?2 AND status = 'open'
                           AND EXISTS (SELECT 1 FROM monitor_state WHERE monitor_id = ?3 AND generation = ?4 AND commit_token = ?5)",
                        params![now, item.incident_id, monitor_id, next_generation, commit_token],
                    )?;
                }
            }
        }
        for alert in alerts {
            tx.execute(
                "INSERT OR IGNORE INTO alert_outbox (
                    id, alert_class, incident_id, monitor_id, project_id, dedupe_key, destination, severity,
                    state, payload_text, attempt_count, next_attempt_at, created_at, updated_at
                )
                SELECT ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 'queued', ?9, 0, ?10, ?10, ?10
                FROM monitor_state WHERE monitor_id = ?4 AND generation = ?11 AND commit_token = ?12",
                params![
                    alert.id,
                    alert.alert_class.as_str(),
                    alert.incident_id,
                    alert.monitor_id,
                    alert.project_id,
                    alert.dedupe_key,
                    alert.destination.as_str(),
                    alert.severity.as_str(),
                    alert.text,
                    now,
                    next_generation,
                    commit_token,
                ],
            )?;
        }
        tx.commit()?;
        Ok(CommitOutcome { committed: true })
    }

    pub fn acquire_lease(
        &self,
        name: &str,
        owner: &str,
        until: i64,
        now: i64,
    ) -> Result<bool, StoreError> {
        let conn = self.lock()?;
        let changed = conn.execute(
            "INSERT INTO scheduler_leases (job_name, owner, lease_until) VALUES (?1, ?2, ?3)
             ON CONFLICT(job_name) DO UPDATE SET owner = excluded.owner, lease_until = excluded.lease_until
             WHERE scheduler_leases.lease_until <= ?4",
            params![name, owner, until, now],
        )?;
        Ok(changed > 0)
    }

    pub fn release_lease(&self, name: &str, owner: &str, now: i64) -> Result<(), StoreError> {
        self.lock()?.execute(
            "UPDATE scheduler_leases SET lease_until = ?1 WHERE job_name = ?2 AND owner = ?3",
            params![now, name, owner],
        )?;
        Ok(())
    }

    pub fn mark_run(
        &self,
        name: &str,
        started_at: Option<i64>,
        finished_at: Option<i64>,
        error: Option<&str>,
        success_at: Option<i64>,
    ) -> Result<(), StoreError> {
        self.lock()?.execute(
            "INSERT INTO scheduler_runs (job_name, last_started_at, last_finished_at, last_error, last_success_at)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(job_name) DO UPDATE SET
               last_started_at = COALESCE(excluded.last_started_at, scheduler_runs.last_started_at),
               last_finished_at = COALESCE(excluded.last_finished_at, scheduler_runs.last_finished_at),
               last_error = excluded.last_error,
               last_success_at = COALESCE(excluded.last_success_at, scheduler_runs.last_success_at)",
            params![name, started_at, finished_at, error, success_at],
        )?;
        Ok(())
    }

    pub fn last_checks(&self) -> Result<Vec<(String, Option<i64>)>, StoreError> {
        let conn = self.lock()?;
        let mut stmt = conn.prepare("SELECT monitor_id, last_check_at FROM monitor_state")?;
        let rows = stmt
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    pub fn read_heartbeat(&self, monitor_id: &str) -> Result<Option<HeartbeatStored>, StoreError> {
        let conn = self.lock()?;
        conn.query_row(
            "SELECT received_at, progress_token, progress_changed_at, idle, loop_at FROM heartbeats WHERE monitor_id = ?1",
            params![monitor_id],
            |row| {
                Ok(HeartbeatStored {
                    received_at: row.get(0)?,
                    progress_token: row.get(1)?,
                    progress_changed_at: row.get(2)?,
                    idle: row.get::<_, i64>(3)? == 1,
                    loop_at: row.get(4)?,
                })
            },
        )
        .optional()
        .map_err(StoreError::from)
    }

    pub fn store_heartbeat(
        &self,
        monitor_id: &str,
        project_id: &str,
        now: i64,
        reported_at: i64,
        nonce: &str,
        nonce_expires_at: i64,
        progress: Option<&str>,
        idle: bool,
        loop_at: Option<i64>,
    ) -> Result<bool, StoreError> {
        let conn = self.lock()?;
        let tx = conn.unchecked_transaction()?;
        tx.execute(
            "DELETE FROM heartbeat_nonces WHERE expires_at < ?1",
            params![now],
        )?;
        let inserted = tx.execute(
            "INSERT INTO heartbeat_nonces (monitor_id, nonce, expires_at) VALUES (?1, ?2, ?3)",
            params![monitor_id, nonce, nonce_expires_at],
        );
        if let Err(error) = inserted {
            tx.rollback()?;
            return if is_constraint(&error) {
                Ok(false)
            } else {
                Err(error.into())
            };
        }
        tx.execute(
            "INSERT INTO heartbeats (
                monitor_id, project_id, received_at, reported_at, progress_token, progress_changed_at, idle, loop_at, summary
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, NULL)
            ON CONFLICT(monitor_id) DO UPDATE SET
                received_at = excluded.received_at,
                reported_at = excluded.reported_at,
                progress_token = excluded.progress_token,
                progress_changed_at = CASE
                    WHEN heartbeats.progress_token IS excluded.progress_token THEN heartbeats.progress_changed_at
                    ELSE excluded.received_at
                END,
                idle = excluded.idle,
                loop_at = excluded.loop_at",
            params![
                monitor_id,
                project_id,
                now,
                reported_at,
                progress,
                now,
                i64::from(idle),
                loop_at,
            ],
        )?;
        tx.commit()?;
        Ok(true)
    }

    pub fn insert_alert(&self, alert: &AlertDraft, now: i64) -> Result<(), StoreError> {
        self.lock()?.execute(
            "INSERT OR IGNORE INTO alert_outbox (
                id, alert_class, incident_id, monitor_id, project_id, dedupe_key, destination, severity,
                state, payload_text, attempt_count, next_attempt_at, created_at, updated_at
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 'queued', ?9, 0, ?10, ?10, ?10)",
            params![
                alert.id,
                alert.alert_class.as_str(),
                alert.incident_id,
                alert.monitor_id,
                alert.project_id,
                alert.dedupe_key,
                alert.destination.as_str(),
                alert.severity.as_str(),
                alert.text,
                now,
            ],
        )?;
        Ok(())
    }

    pub fn insert_alert_if_allowed(
        &self,
        alert: &AlertDraft,
        now: i64,
        prefix: &str,
        since: i64,
        limit: i64,
    ) -> Result<bool, StoreError> {
        let pattern = format!("{prefix}%");
        let conn = self.lock()?;
        let changed = conn.execute(
            "INSERT INTO alert_outbox (
                id, alert_class, incident_id, monitor_id, project_id, dedupe_key, destination, severity,
                state, payload_text, attempt_count, next_attempt_at, created_at, updated_at
            )
            SELECT ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 'queued', ?9, 0, ?10, ?10, ?10
            WHERE (
                SELECT COUNT(*) FROM alert_outbox WHERE dedupe_key LIKE ?11 AND created_at >= ?12
            ) < ?13",
            params![
                alert.id,
                alert.alert_class.as_str(),
                alert.incident_id,
                alert.monitor_id,
                alert.project_id,
                alert.dedupe_key,
                alert.destination.as_str(),
                alert.severity.as_str(),
                alert.text,
                now,
                pattern,
                since,
                limit,
            ],
        )?;
        Ok(changed > 0)
    }

    pub fn count_recent(&self, prefix: &str, since: i64) -> Result<i64, StoreError> {
        let pattern = format!("{prefix}%");
        let count = self.lock()?.query_row(
            "SELECT COUNT(*) FROM alert_outbox WHERE dedupe_key LIKE ?1 AND created_at >= ?2",
            params![pattern, since],
            |row| row.get(0),
        )?;
        Ok(count)
    }

    pub fn claim_outbox(
        &self,
        now: i64,
        claim_until: i64,
        destination: Option<&str>,
        limit: i64,
    ) -> Result<Vec<OutboxRow>, StoreError> {
        let conn = self.lock()?;
        let mut stmt = conn.prepare(
            "SELECT id FROM alert_outbox
             WHERE state IN ('queued', 'retrying') AND next_attempt_at <= ?1
               AND (claim_until IS NULL OR claim_until < ?1)
               AND (?2 IS NULL OR destination = ?2)
             ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'warning' THEN 1 ELSE 2 END, created_at
             LIMIT ?3",
        )?;
        let ids: Vec<String> = stmt
            .query_map(params![now, destination, limit], |row| row.get(0))?
            .collect::<Result<Vec<_>, _>>()?;
        drop(stmt);
        let mut claimed = Vec::new();
        for id in ids {
            let token = uuid::Uuid::new_v4().to_string();
            let changed = conn.execute(
                "UPDATE alert_outbox SET claim_until = ?1, claim_token = ?2, state = 'retrying', updated_at = ?3
                 WHERE id = ?4 AND state IN ('queued', 'retrying') AND (claim_until IS NULL OR claim_until < ?3)",
                params![claim_until, token, now, id],
            )?;
            if changed > 0 {
                if let Some(mut row) = read_outbox(&conn, &id)? {
                    row.claim_token = Some(token);
                    row.claim_until = Some(claim_until);
                    row.state = DeliveryState::Retrying.as_str().to_string();
                    claimed.push(row);
                }
            }
        }
        Ok(claimed)
    }

    pub fn claim_row(
        &self,
        id: &str,
        now: i64,
        claim_until: i64,
    ) -> Result<Option<String>, StoreError> {
        let token = uuid::Uuid::new_v4().to_string();
        let changed = self.lock()?.execute(
            "UPDATE alert_outbox SET claim_until = ?1, claim_token = ?2, state = 'retrying', updated_at = ?3
             WHERE id = ?4 AND state IN ('queued', 'retrying') AND (claim_until IS NULL OR claim_until < ?3)",
            params![claim_until, token, now, id],
        )?;
        Ok(if changed > 0 { Some(token) } else { None })
    }

    pub fn extend_claim(
        &self,
        id: &str,
        token: &str,
        claim_until: i64,
        now: i64,
    ) -> Result<bool, StoreError> {
        let changed = self.lock()?.execute(
            "UPDATE alert_outbox SET claim_until = ?1
             WHERE id = ?2 AND claim_token = ?3 AND state = 'retrying'
               AND claim_until IS NOT NULL AND claim_until >= ?4",
            params![claim_until, id, token, now],
        )?;
        Ok(changed > 0)
    }

    pub fn outbox_state(&self, id: &str) -> Result<Option<String>, StoreError> {
        self.lock()?
            .query_row(
                "SELECT state FROM alert_outbox WHERE id = ?1",
                params![id],
                |row| row.get(0),
            )
            .optional()
            .map_err(StoreError::from)
    }

    pub fn save_envelope(
        &self,
        id: &str,
        token: &str,
        envelope: &str,
        now: i64,
    ) -> Result<&'static str, StoreError> {
        let conn = self.lock()?;
        let changed = conn.execute(
            "UPDATE alert_outbox SET envelope_json = ?1, updated_at = ?2
             WHERE id = ?3 AND claim_token = ?4 AND envelope_json IS NULL",
            params![envelope, now, id, token],
        )?;
        if changed > 0 {
            return Ok("saved");
        }
        let existing: Option<Option<String>> = conn
            .query_row(
                "SELECT envelope_json FROM alert_outbox WHERE id = ?1",
                params![id],
                |row| row.get(0),
            )
            .optional()?;
        Ok(if existing.flatten().is_some() {
            "exists"
        } else {
            "lost"
        })
    }

    pub fn read_envelope(&self, id: &str) -> Result<Option<String>, StoreError> {
        self.lock()?
            .query_row(
                "SELECT envelope_json FROM alert_outbox WHERE id = ?1",
                params![id],
                |row| row.get(0),
            )
            .optional()
            .map(|value| value.flatten())
            .map_err(StoreError::from)
    }

    pub fn finish_delivery(
        &self,
        id: &str,
        token: &str,
        state: DeliveryState,
        attempt_count: i64,
        next_attempt_at: i64,
        error: Option<&str>,
        accepted_relays: Option<&str>,
        failed_relays: Option<&str>,
        message_phase: Option<&str>,
        push_phase: Option<&str>,
        message_event_id: Option<&str>,
        push_envelope: Option<&str>,
        now: i64,
    ) -> Result<bool, StoreError> {
        let changed = self.lock()?.execute(
            "UPDATE alert_outbox
             SET state = ?1, attempt_count = ?2, next_attempt_at = ?3, last_error = ?4,
                 accepted_relays = ?5, failed_relays = ?6, claim_until = NULL, claim_token = NULL,
                 message_phase = COALESCE(?7, message_phase), push_phase = COALESCE(?8, push_phase),
                 message_event_id = COALESCE(?9, message_event_id),
                 push_envelope_json = COALESCE(?10, push_envelope_json), updated_at = ?11
             WHERE id = ?12 AND claim_token = ?13 AND claim_until IS NOT NULL AND claim_until >= ?11",
            params![
                state.as_str(),
                attempt_count,
                next_attempt_at,
                error,
                accepted_relays,
                failed_relays,
                message_phase,
                push_phase,
                message_event_id,
                push_envelope,
                now,
                id,
                token,
            ],
        )?;
        Ok(changed > 0)
    }

    pub fn retry_dead_letter(&self, id: &str, now: i64) -> Result<bool, StoreError> {
        let changed = self.lock()?.execute(
            "UPDATE alert_outbox
             SET state = 'queued', attempt_count = 0, next_attempt_at = ?1, claim_until = NULL,
                 claim_token = NULL, last_error = NULL, updated_at = ?1
             WHERE id = ?2 AND state = 'failed'",
            params![now, id],
        )?;
        Ok(changed > 0)
    }

    pub fn ack_incident(&self, id: &str, now: i64) -> Result<bool, StoreError> {
        let changed = self.lock()?.execute(
            "UPDATE incidents SET acked_at = ?1, updated_at = ?1 WHERE id = ?2 AND status = 'open'",
            params![now, id],
        )?;
        Ok(changed > 0)
    }

    pub fn silence_incident(&self, id: &str, until: i64, now: i64) -> Result<bool, StoreError> {
        let changed = self.lock()?.execute(
            "UPDATE incidents SET silenced_until = ?1, updated_at = ?2 WHERE id = ?3 AND status = 'open'",
            params![until, now, id],
        )?;
        Ok(changed > 0)
    }

    pub fn open_incident_status(&self, id: &str) -> Result<Option<(String, String)>, StoreError> {
        self.lock()?
            .query_row(
                "SELECT monitor_id, status FROM incidents WHERE id = ?1",
                params![id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(StoreError::from)
    }

    pub fn list_failed(&self) -> Result<Vec<FailedAlert>, StoreError> {
        let conn = self.lock()?;
        let mut stmt = conn.prepare(
            "SELECT id, monitor_id, destination, last_error FROM alert_outbox WHERE state = 'failed' ORDER BY updated_at DESC LIMIT 50",
        )?;
        let rows = stmt
            .query_map([], |row| {
                Ok(FailedAlert {
                    id: row.get(0)?,
                    monitor_id: row.get(1)?,
                    destination: row.get(2)?,
                    last_error: row.get(3)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    pub fn save_relay_cache(
        &self,
        pubkey: &str,
        relays_json: &str,
        negative: bool,
        fetched_at: i64,
        expires_at: i64,
    ) -> Result<(), StoreError> {
        self.lock()?.execute(
            "INSERT INTO relay_list_cache (pubkey, relays_json, fetched_at, expires_at, negative)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(pubkey) DO UPDATE SET
               relays_json = excluded.relays_json,
               fetched_at = excluded.fetched_at,
               expires_at = excluded.expires_at,
               negative = excluded.negative",
            params![
                pubkey,
                relays_json,
                fetched_at,
                expires_at,
                i64::from(negative)
            ],
        )?;
        Ok(())
    }

    pub fn relay_cache(
        &self,
        pubkey: &str,
        now: i64,
    ) -> Result<Option<(String, bool)>, StoreError> {
        self.lock()?
            .query_row(
                "SELECT relays_json, negative FROM relay_list_cache WHERE pubkey = ?1 AND expires_at > ?2",
                params![pubkey, now],
                |row| Ok((row.get(0)?, row.get::<_, i64>(1)? == 1)),
            )
            .optional()
            .map_err(StoreError::from)
    }

    pub fn remembered_inbox(&self, pubkey: &str) -> Result<Vec<String>, StoreError> {
        let json: Option<String> = self
            .lock()?
            .query_row(
                "SELECT relays_json FROM relay_list_cache WHERE pubkey = ?1 AND negative = 0",
                params![pubkey],
                |row| row.get(0),
            )
            .optional()?;
        let Some(json) = json else {
            return Ok(Vec::new());
        };
        Ok(serde_json::from_str(&json).unwrap_or_default())
    }

    pub fn prune(&self, now: i64) -> Result<(), StoreError> {
        let conn = self.lock()?;
        conn.execute(
            "DELETE FROM heartbeat_nonces WHERE expires_at < ?1",
            params![now],
        )?;
        conn.execute(
            "DELETE FROM relay_list_cache WHERE negative = 1 AND expires_at < ?1",
            params![now],
        )?;
        conn.execute(
            "DELETE FROM alert_outbox WHERE state = 'relay_accepted' AND updated_at < ?1",
            params![now - ACCEPTED_RETENTION_MS],
        )?;
        conn.execute(
            "DELETE FROM alert_outbox WHERE state = 'failed' AND updated_at < ?1",
            params![now - DEAD_LETTER_RETENTION_MS],
        )?;
        conn.execute(
            "DELETE FROM incidents WHERE status = 'closed' AND closed_at IS NOT NULL AND closed_at < ?1",
            params![now - CLOSED_INCIDENT_RETENTION_MS],
        )?;
        conn.execute(
            "DELETE FROM upstream_cache WHERE fetched_at < ?1 AND (rate_limited_until IS NULL OR rate_limited_until < ?2)",
            params![now - UPSTREAM_RETENTION_MS, now],
        )?;
        Ok(())
    }

    pub fn snapshot(&self) -> Result<StatusSnapshot, StoreError> {
        let conn = self.lock()?;
        let mut states = Vec::new();
        let mut stmt =
            conn.prepare("SELECT monitor_id, status, last_check_at FROM monitor_state")?;
        for row in stmt.query_map([], |row| {
            Ok(StateView {
                monitor_id: row.get(0)?,
                status: row.get(1)?,
                last_check_at: row.get(2)?,
            })
        })? {
            states.push(row?);
        }
        drop(stmt);
        let mut open_incident_monitor_ids = Vec::new();
        let mut stmt = conn.prepare("SELECT monitor_id FROM incidents WHERE status = 'open'")?;
        for row in stmt.query_map([], |row| row.get::<_, String>(0))? {
            open_incident_monitor_ids.push(row?);
        }
        drop(stmt);
        let mut outbox_by_monitor = Vec::new();
        let mut stmt = conn.prepare(
            "SELECT monitor_id, state, COUNT(*) FROM alert_outbox GROUP BY monitor_id, state",
        )?;
        for row in stmt.query_map([], |row| {
            Ok(OutboxCount {
                monitor_id: row.get(0)?,
                state: row.get(1)?,
                count: row.get(2)?,
            })
        })? {
            outbox_by_monitor.push(row?);
        }
        drop(stmt);
        let mut errors_by_monitor = Vec::new();
        let mut stmt = conn.prepare(
            "SELECT monitor_id, last_error, COUNT(*) FROM alert_outbox
             WHERE state IN ('retrying', 'failed') AND last_error IS NOT NULL
             GROUP BY monitor_id, last_error",
        )?;
        for row in stmt.query_map([], |row| {
            Ok(ErrorCount {
                monitor_id: row.get(0)?,
                error: row.get(1)?,
                count: row.get(2)?,
            })
        })? {
            errors_by_monitor.push(row?);
        }
        drop(stmt);
        let mut runs = Vec::new();
        let mut stmt = conn.prepare(
            "SELECT job_name, last_started_at, last_finished_at, last_success_at, last_error FROM scheduler_runs",
        )?;
        for row in stmt.query_map([], |row| {
            Ok(RunView {
                name: row.get(0)?,
                started_at: row.get(1)?,
                finished_at: row.get(2)?,
                success_at: row.get(3)?,
                error: row.get(4)?,
            })
        })? {
            runs.push(row?);
        }
        drop(stmt);
        let mut heartbeats = Vec::new();
        let mut stmt = conn.prepare("SELECT monitor_id, received_at FROM heartbeats")?;
        for row in stmt.query_map([], |row| {
            Ok(HeartbeatView {
                monitor_id: row.get(0)?,
                received_at: row.get(1)?,
            })
        })? {
            heartbeats.push(row?);
        }
        drop(stmt);
        let mut vendor_checks = Vec::new();
        let mut stmt = conn.prepare(
            "SELECT monitor_id, vendor, attempted_at, succeeded_at, partial_succeeded_at, releases_checked_at,
                    advisories_checked_at, releases_stale, advisories_stale, releases_state, advisories_state,
                    coverage, error_code, consecutive_failures, releases_failures, advisories_failures
             FROM vendor_checks",
        )?;
        for row in stmt.query_map([], |row| {
            Ok(VendorView {
                monitor_id: row.get(0)?,
                vendor: row.get(1)?,
                attempted_at: row.get(2)?,
                succeeded_at: row.get(3)?,
                partial_succeeded_at: row.get(4)?,
                releases_checked_at: row.get(5)?,
                advisories_checked_at: row.get(6)?,
                releases_stale: row.get::<_, i64>(7)? == 1,
                advisories_stale: row.get::<_, i64>(8)? == 1,
                releases_state: row.get(9)?,
                advisories_state: row.get(10)?,
                coverage: row.get(11)?,
                error_code: row.get(12)?,
                consecutive_failures: row.get(13)?,
                releases_failures: row.get(14)?,
                advisories_failures: row.get(15)?,
            })
        })? {
            vendor_checks.push(row?);
        }
        Ok(StatusSnapshot {
            states,
            heartbeats,
            runs,
            vendor_checks,
            outbox_by_monitor,
            open_incident_monitor_ids,
            errors_by_monitor,
        })
    }

    pub fn upsert_marmot_project(
        &self,
        row: &MarmotProjectRow,
        now: i64,
    ) -> Result<(), StoreError> {
        self.lock()?.execute(
            "INSERT INTO marmot_projects (
                project_id, pubkey, conversation_id, group_id_hex, peer_pubkey, last_sync_at,
                last_sync_error, key_package_published_at, engine_status, updated_at
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
            ON CONFLICT(project_id) DO UPDATE SET
                pubkey = excluded.pubkey,
                conversation_id = excluded.conversation_id,
                group_id_hex = excluded.group_id_hex,
                peer_pubkey = excluded.peer_pubkey,
                last_sync_at = excluded.last_sync_at,
                last_sync_error = excluded.last_sync_error,
                key_package_published_at = excluded.key_package_published_at,
                engine_status = excluded.engine_status,
                updated_at = excluded.updated_at",
            params![
                row.project_id,
                row.pubkey,
                row.conversation_id,
                row.group_id_hex,
                row.peer_pubkey,
                row.last_sync_at,
                row.last_sync_error,
                row.key_package_published_at,
                row.engine_status,
                now,
            ],
        )?;
        Ok(())
    }

    pub fn marmot_project(&self, project_id: &str) -> Result<Option<MarmotProjectRow>, StoreError> {
        self.lock()?
            .query_row(
                "SELECT project_id, pubkey, conversation_id, group_id_hex, peer_pubkey, last_sync_at, last_sync_error, key_package_published_at, engine_status FROM marmot_projects WHERE project_id = ?1",
                params![project_id],
                |row| {
                    Ok(MarmotProjectRow {
                        project_id: row.get(0)?,
                        pubkey: row.get(1)?,
                        conversation_id: row.get(2)?,
                        group_id_hex: row.get(3)?,
                        peer_pubkey: row.get(4)?,
                        last_sync_at: row.get(5)?,
                        last_sync_error: row.get(6)?,
                        key_package_published_at: row.get(7)?,
                        engine_status: row.get(8)?,
                    })
                },
            )
            .optional()
            .map_err(StoreError::from)
    }

    pub fn read_outbox_row(&self, id: &str) -> Result<Option<OutboxRow>, StoreError> {
        let conn = self.lock()?;
        read_outbox(&conn, id)
    }

    pub fn installed_version(&self, monitor_id: &str) -> Result<Option<String>, StoreError> {
        self.lock()?
            .query_row(
                "SELECT observed_version FROM monitor_state WHERE monitor_id = ?1",
                params![monitor_id],
                |row| row.get(0),
            )
            .optional()
            .map(|value| value.flatten())
            .map_err(StoreError::from)
    }

    pub fn read_version(&self, monitor_id: &str) -> Result<Option<VersionRow>, StoreError> {
        self.lock()?
            .query_row(
                "SELECT installed_version, latest_version, latest_url, security_status, advisory_fingerprint, notice_fingerprint, security_reminded_at FROM observed_versions WHERE monitor_id = ?1",
                params![monitor_id],
                |row| {
                    Ok(VersionRow {
                        installed: row.get(0)?,
                        latest: row.get(1)?,
                        latest_url: row.get(2)?,
                        security_status: row.get(3)?,
                        advisory_fingerprint: row.get(4)?,
                        notice_fingerprint: row.get(5)?,
                        security_reminded_at: row.get(6)?,
                    })
                },
            )
            .optional()
            .map_err(StoreError::from)
    }

    pub fn write_version(
        &self,
        monitor_id: &str,
        row: &VersionRow,
        now: i64,
    ) -> Result<(), StoreError> {
        self.lock()?.execute(
            "INSERT INTO observed_versions (
                monitor_id, installed_version, latest_version, latest_url, security_status,
                advisory_fingerprint, notice_fingerprint, updated_at, security_reminded_at
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
            ON CONFLICT(monitor_id) DO UPDATE SET
                installed_version = excluded.installed_version,
                latest_version = excluded.latest_version,
                latest_url = excluded.latest_url,
                security_status = excluded.security_status,
                advisory_fingerprint = excluded.advisory_fingerprint,
                notice_fingerprint = excluded.notice_fingerprint,
                updated_at = excluded.updated_at,
                security_reminded_at = excluded.security_reminded_at",
            params![
                monitor_id,
                row.installed,
                row.latest,
                row.latest_url,
                row.security_status,
                row.advisory_fingerprint,
                row.notice_fingerprint,
                now,
                row.security_reminded_at,
            ],
        )?;
        Ok(())
    }

    pub fn read_upstream(&self, key: &str) -> Result<Option<UpstreamRow>, StoreError> {
        self.lock()?
            .query_row(
                "SELECT etag, payload_json, fetched_at, rate_limited_until FROM upstream_cache WHERE source_key = ?1",
                params![key],
                |row| {
                    Ok(UpstreamRow {
                        etag: row.get(0)?,
                        payload_json: row.get(1)?,
                        fetched_at: row.get(2)?,
                        rate_limited_until: row.get(3)?,
                    })
                },
            )
            .optional()
            .map_err(StoreError::from)
    }

    pub fn write_upstream(&self, key: &str, row: &UpstreamRow) -> Result<(), StoreError> {
        self.lock()?.execute(
            "INSERT INTO upstream_cache (source_key, etag, payload_json, fetched_at, rate_limited_until)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(source_key) DO UPDATE SET
               etag = excluded.etag,
               payload_json = excluded.payload_json,
               fetched_at = excluded.fetched_at,
               rate_limited_until = excluded.rate_limited_until",
            params![key, row.etag, row.payload_json, row.fetched_at, row.rate_limited_until],
        )?;
        Ok(())
    }

    pub fn read_vendor(&self, monitor_id: &str) -> Result<Option<VendorView>, StoreError> {
        self.lock()?
            .query_row(
                "SELECT monitor_id, vendor, attempted_at, succeeded_at, partial_succeeded_at, releases_checked_at,
                        advisories_checked_at, releases_stale, advisories_stale, releases_state, advisories_state,
                        coverage, error_code, consecutive_failures, releases_failures, advisories_failures
                 FROM vendor_checks WHERE monitor_id = ?1",
                params![monitor_id],
                |row| {
                    Ok(VendorView {
                        monitor_id: row.get(0)?,
                        vendor: row.get(1)?,
                        attempted_at: row.get(2)?,
                        succeeded_at: row.get(3)?,
                        partial_succeeded_at: row.get(4)?,
                        releases_checked_at: row.get(5)?,
                        advisories_checked_at: row.get(6)?,
                        releases_stale: row.get::<_, i64>(7)? == 1,
                        advisories_stale: row.get::<_, i64>(8)? == 1,
                        releases_state: row.get(9)?,
                        advisories_state: row.get(10)?,
                        coverage: row.get(11)?,
                        error_code: row.get(12)?,
                        consecutive_failures: row.get(13)?,
                        releases_failures: row.get(14)?,
                        advisories_failures: row.get(15)?,
                    })
                },
            )
            .optional()
            .map_err(StoreError::from)
    }

    pub fn write_vendor(&self, row: &VendorView, now: i64) -> Result<(), StoreError> {
        self.lock()?.execute(
            "INSERT INTO vendor_checks (
                monitor_id, vendor, attempted_at, succeeded_at, partial_succeeded_at, releases_checked_at,
                advisories_checked_at, releases_stale, advisories_stale, releases_state, advisories_state,
                coverage, error_code, consecutive_failures, releases_failures, advisories_failures, updated_at
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17)
            ON CONFLICT(monitor_id) DO UPDATE SET
                vendor = excluded.vendor,
                attempted_at = COALESCE(excluded.attempted_at, vendor_checks.attempted_at),
                succeeded_at = COALESCE(excluded.succeeded_at, vendor_checks.succeeded_at),
                partial_succeeded_at = COALESCE(excluded.partial_succeeded_at, vendor_checks.partial_succeeded_at),
                releases_checked_at = COALESCE(excluded.releases_checked_at, vendor_checks.releases_checked_at),
                advisories_checked_at = COALESCE(excluded.advisories_checked_at, vendor_checks.advisories_checked_at),
                releases_stale = excluded.releases_stale,
                advisories_stale = excluded.advisories_stale,
                releases_state = excluded.releases_state,
                advisories_state = excluded.advisories_state,
                coverage = excluded.coverage,
                error_code = excluded.error_code,
                consecutive_failures = excluded.consecutive_failures,
                releases_failures = excluded.releases_failures,
                advisories_failures = excluded.advisories_failures,
                updated_at = excluded.updated_at",
            params![
                row.monitor_id,
                row.vendor,
                row.attempted_at,
                row.succeeded_at,
                row.partial_succeeded_at,
                row.releases_checked_at,
                row.advisories_checked_at,
                i64::from(row.releases_stale),
                i64::from(row.advisories_stale),
                row.releases_state,
                row.advisories_state,
                row.coverage,
                row.error_code,
                row.consecutive_failures,
                row.releases_failures,
                row.advisories_failures,
                now,
            ],
        )?;
        Ok(())
    }
}

fn read_outbox(conn: &Connection, id: &str) -> Result<Option<OutboxRow>, StoreError> {
    conn.query_row(
        "SELECT id, alert_class, incident_id, monitor_id, project_id, dedupe_key, destination, severity, state,
                payload_text, envelope_json, attempt_count, next_attempt_at, claim_until, claim_token,
                accepted_relays, failed_relays, last_error, created_at, updated_at,
                message_phase, push_phase, push_envelope_json, message_event_id
         FROM alert_outbox WHERE id = ?1",
        params![id],
        |row| {
            Ok(OutboxRow {
                id: row.get(0)?,
                alert_class: row.get(1)?,
                incident_id: row.get(2)?,
                monitor_id: row.get(3)?,
                project_id: row.get(4)?,
                dedupe_key: row.get(5)?,
                destination: row.get(6)?,
                severity: row.get(7)?,
                state: row.get(8)?,
                payload_text: row.get(9)?,
                envelope_json: row.get(10)?,
                attempt_count: row.get(11)?,
                next_attempt_at: row.get(12)?,
                claim_until: row.get(13)?,
                claim_token: row.get(14)?,
                accepted_relays: row.get(15)?,
                failed_relays: row.get(16)?,
                last_error: row.get(17)?,
                created_at: row.get(18)?,
                updated_at: row.get(19)?,
                message_phase: row.get(20)?,
                push_phase: row.get(21)?,
                push_envelope_json: row.get(22)?,
                message_event_id: row.get(23)?,
            })
        },
    )
    .optional()
    .map_err(StoreError::from)
}

#[allow(dead_code)]
fn _enum_markers(class: AlertClass, destination: Destination) -> (&'static str, &'static str) {
    (class.as_str(), destination.as_str())
}

impl OperationalStore for SqliteStore {
    async fn load_memory(&self, monitor_id: &str) -> Result<LoadedMemory, StoreError> {
        SqliteStore::load_memory(self, monitor_id)
    }
    async fn commit_check(
        &self,
        monitor_id: &str,
        project_id: &str,
        previous_generation: i64,
        memory: &watchdog_core::domain::MonitorMemory,
        check: &watchdog_core::domain::CheckResult,
        now: i64,
        notices: &[watchdog_core::domain::Notice],
        alerts: &[watchdog_core::domain::AlertDraft],
    ) -> Result<CommitOutcome, StoreError> {
        SqliteStore::commit_check(
            self,
            monitor_id,
            project_id,
            previous_generation,
            memory,
            check,
            now,
            notices,
            alerts,
        )
    }
    async fn acquire_lease(
        &self,
        name: &str,
        owner: &str,
        until: i64,
        now: i64,
    ) -> Result<bool, StoreError> {
        SqliteStore::acquire_lease(self, name, owner, until, now)
    }
    async fn release_lease(&self, name: &str, owner: &str, now: i64) -> Result<(), StoreError> {
        SqliteStore::release_lease(self, name, owner, now)
    }
    async fn mark_run(
        &self,
        name: &str,
        started_at: Option<i64>,
        finished_at: Option<i64>,
        error: Option<&str>,
        success_at: Option<i64>,
    ) -> Result<(), StoreError> {
        SqliteStore::mark_run(self, name, started_at, finished_at, error, success_at)
    }
    async fn last_checks(&self) -> Result<Vec<(String, Option<i64>)>, StoreError> {
        SqliteStore::last_checks(self)
    }
    async fn read_heartbeat(
        &self,
        monitor_id: &str,
    ) -> Result<Option<HeartbeatStored>, StoreError> {
        SqliteStore::read_heartbeat(self, monitor_id)
    }
    async fn store_heartbeat(
        &self,
        monitor_id: &str,
        project_id: &str,
        now: i64,
        reported_at: i64,
        nonce: &str,
        nonce_expires_at: i64,
        progress: Option<&str>,
        idle: bool,
        loop_at: Option<i64>,
    ) -> Result<bool, StoreError> {
        SqliteStore::store_heartbeat(
            self,
            monitor_id,
            project_id,
            now,
            reported_at,
            nonce,
            nonce_expires_at,
            progress,
            idle,
            loop_at,
        )
    }
    async fn insert_alert(
        &self,
        alert: &watchdog_core::domain::AlertDraft,
        now: i64,
    ) -> Result<(), StoreError> {
        SqliteStore::insert_alert(self, alert, now)
    }
    async fn insert_alert_if_allowed(
        &self,
        alert: &watchdog_core::domain::AlertDraft,
        now: i64,
        prefix: &str,
        since: i64,
        limit: i64,
    ) -> Result<bool, StoreError> {
        SqliteStore::insert_alert_if_allowed(self, alert, now, prefix, since, limit)
    }
    async fn count_recent(&self, prefix: &str, since: i64) -> Result<i64, StoreError> {
        SqliteStore::count_recent(self, prefix, since)
    }
    async fn claim_outbox(
        &self,
        now: i64,
        claim_until: i64,
        destination: Option<&str>,
        limit: i64,
    ) -> Result<Vec<OutboxRow>, StoreError> {
        SqliteStore::claim_outbox(self, now, claim_until, destination, limit)
    }
    async fn extend_claim(
        &self,
        id: &str,
        token: &str,
        claim_until: i64,
        now: i64,
    ) -> Result<bool, StoreError> {
        SqliteStore::extend_claim(self, id, token, claim_until, now)
    }
    async fn outbox_state(&self, id: &str) -> Result<Option<String>, StoreError> {
        SqliteStore::outbox_state(self, id)
    }
    async fn save_envelope(
        &self,
        id: &str,
        token: &str,
        envelope: &str,
        now: i64,
    ) -> Result<&'static str, StoreError> {
        SqliteStore::save_envelope(self, id, token, envelope, now)
    }
    async fn read_envelope(&self, id: &str) -> Result<Option<String>, StoreError> {
        SqliteStore::read_envelope(self, id)
    }
    async fn finish_delivery(
        &self,
        id: &str,
        token: &str,
        state: watchdog_core::domain::DeliveryState,
        attempt_count: i64,
        next_attempt_at: i64,
        error: Option<&str>,
        accepted_relays: Option<&str>,
        failed_relays: Option<&str>,
        message_phase: Option<&str>,
        push_phase: Option<&str>,
        message_event_id: Option<&str>,
        push_envelope: Option<&str>,
        now: i64,
    ) -> Result<bool, StoreError> {
        SqliteStore::finish_delivery(
            self,
            id,
            token,
            state,
            attempt_count,
            next_attempt_at,
            error,
            accepted_relays,
            failed_relays,
            message_phase,
            push_phase,
            message_event_id,
            push_envelope,
            now,
        )
    }
    async fn retry_dead_letter(&self, id: &str, now: i64) -> Result<bool, StoreError> {
        SqliteStore::retry_dead_letter(self, id, now)
    }
    async fn ack_incident(&self, id: &str, now: i64) -> Result<bool, StoreError> {
        SqliteStore::ack_incident(self, id, now)
    }
    async fn silence_incident(&self, id: &str, until: i64, now: i64) -> Result<bool, StoreError> {
        SqliteStore::silence_incident(self, id, until, now)
    }
    async fn open_incident_status(&self, id: &str) -> Result<Option<(String, String)>, StoreError> {
        SqliteStore::open_incident_status(self, id)
    }
    async fn list_failed(&self) -> Result<Vec<FailedAlert>, StoreError> {
        SqliteStore::list_failed(self)
    }
    async fn save_relay_cache(
        &self,
        pubkey: &str,
        relays_json: &str,
        negative: bool,
        fetched_at: i64,
        expires_at: i64,
    ) -> Result<(), StoreError> {
        SqliteStore::save_relay_cache(self, pubkey, relays_json, negative, fetched_at, expires_at)
    }
    async fn relay_cache(
        &self,
        pubkey: &str,
        now: i64,
    ) -> Result<Option<(String, bool)>, StoreError> {
        SqliteStore::relay_cache(self, pubkey, now)
    }
    async fn remembered_inbox(&self, pubkey: &str) -> Result<Vec<String>, StoreError> {
        SqliteStore::remembered_inbox(self, pubkey)
    }
    async fn prune(&self, now: i64) -> Result<(), StoreError> {
        SqliteStore::prune(self, now)
    }
    async fn snapshot(&self) -> Result<watchdog_core::status::StatusSnapshot, StoreError> {
        SqliteStore::snapshot(self)
    }
    async fn upsert_marmot_project(
        &self,
        row: &MarmotProjectRow,
        now: i64,
    ) -> Result<(), StoreError> {
        SqliteStore::upsert_marmot_project(self, row, now)
    }
    async fn marmot_project(
        &self,
        project_id: &str,
    ) -> Result<Option<MarmotProjectRow>, StoreError> {
        SqliteStore::marmot_project(self, project_id)
    }
    async fn installed_version(&self, monitor_id: &str) -> Result<Option<String>, StoreError> {
        SqliteStore::installed_version(self, monitor_id)
    }
    async fn read_version(&self, monitor_id: &str) -> Result<Option<VersionRow>, StoreError> {
        SqliteStore::read_version(self, monitor_id)
    }
    async fn write_version(
        &self,
        monitor_id: &str,
        row: &VersionRow,
        now: i64,
    ) -> Result<(), StoreError> {
        SqliteStore::write_version(self, monitor_id, row, now)
    }
    async fn read_upstream(&self, key: &str) -> Result<Option<UpstreamRow>, StoreError> {
        SqliteStore::read_upstream(self, key)
    }
    async fn write_upstream(&self, key: &str, row: &UpstreamRow) -> Result<(), StoreError> {
        SqliteStore::write_upstream(self, key, row)
    }
    async fn read_vendor(
        &self,
        monitor_id: &str,
    ) -> Result<Option<watchdog_core::status::VendorView>, StoreError> {
        SqliteStore::read_vendor(self, monitor_id)
    }
    async fn write_vendor(
        &self,
        row: &watchdog_core::status::VendorView,
        now: i64,
    ) -> Result<(), StoreError> {
        SqliteStore::write_vendor(self, row, now)
    }
}

fn is_constraint(error: &rusqlite::Error) -> bool {
    matches!(
        error,
        rusqlite::Error::SqliteFailure(err, _)
            if err.code == rusqlite::ErrorCode::ConstraintViolation
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use watchdog_core::domain::{check_result, MonitorStatus};
    use watchdog_core::transition::{transition, TransitionInput};

    #[test]
    fn two_failures_open_one_incident_and_a_lost_generation_does_not_duplicate_it() {
        let store = SqliteStore::memory().unwrap();
        let mut loaded = store.load_memory("sfs-web").unwrap();
        for now in [1_i64, 2] {
            let result = check_result(
                MonitorStatus::Down,
                Some("http_status"),
                "down",
                Some(10),
                None,
            );
            let next = transition(TransitionInput {
                memory: &loaded.memory,
                result: &result,
                now,
                failure_threshold: 2,
                recovery_threshold: 2,
                severity: Severity::Critical,
                incident_on_degraded: false,
                unknown_threshold: 5,
                reminder_seconds: 0,
                new_incident_id: "inc_one",
                new_integrity_incident_id: "inc_integrity",
            });
            let alerts = next
                .notices
                .iter()
                .map(|notice| AlertDraft {
                    id: format!("alt_{now}"),
                    alert_class: AlertClass::Outage,
                    incident_id: Some(notice.incident_id.clone()),
                    monitor_id: "sfs-web".to_string(),
                    project_id: "smartflowsocial".to_string(),
                    dedupe_key: format!("incident:{}:open:nostr", notice.incident_id),
                    destination: Destination::Nostr,
                    severity: notice.severity,
                    text: "alert".to_string(),
                })
                .collect::<Vec<_>>();
            let outcome = store
                .commit_check(
                    "sfs-web",
                    "smartflowsocial",
                    loaded.generation,
                    &next.memory,
                    &result,
                    now,
                    &next.notices,
                    &alerts,
                )
                .unwrap();
            assert!(outcome.committed);
            loaded = store.load_memory("sfs-web").unwrap();
        }
        assert_eq!(loaded.memory.open_incident.as_ref().unwrap().id, "inc_one");
        let stale = store
            .commit_check(
                "sfs-web",
                "smartflowsocial",
                0,
                &loaded.memory,
                &check_result(MonitorStatus::Down, Some("http_status"), "down", None, None),
                3,
                &[],
                &[],
            )
            .unwrap();
        assert!(!stale.committed);
        let again = store.load_memory("sfs-web").unwrap();
        assert_eq!(again.generation, loaded.generation);
    }

    #[test]
    fn claim_fence_rejects_a_stale_token_and_heartbeat_nonce_replays() {
        let store = SqliteStore::memory().unwrap();
        store
            .insert_alert(
                &AlertDraft {
                    id: "alt_1".to_string(),
                    alert_class: AlertClass::Test,
                    incident_id: None,
                    monitor_id: "test".to_string(),
                    project_id: "nostrmash".to_string(),
                    dedupe_key: "test:1".to_string(),
                    destination: Destination::Nostr,
                    severity: Severity::Info,
                    text: "hello".to_string(),
                },
                10,
            )
            .unwrap();
        let claimed = store.claim_outbox(10, 100, None, 4).unwrap();
        assert_eq!(claimed.len(), 1);
        let token = claimed[0].claim_token.clone().unwrap();
        assert!(!store.extend_claim("alt_1", "other", 200, 10).unwrap());
        assert!(store.extend_claim("alt_1", &token, 200, 10).unwrap());
        assert!(!store.extend_claim("alt_1", &token, 400, 250).unwrap());
        assert!(store
            .finish_delivery(
                "alt_1",
                &token,
                DeliveryState::RelayAccepted,
                1,
                10,
                None,
                Some("[\"wss://relay.example\"]"),
                None,
                None,
                None,
                None,
                None,
                20,
            )
            .unwrap());
        assert!(!store
            .finish_delivery(
                "alt_1",
                &token,
                DeliveryState::Failed,
                2,
                10,
                Some("delivery_failed"),
                None,
                None,
                None,
                None,
                None,
                None,
                30,
            )
            .unwrap());
        assert!(store
            .store_heartbeat(
                "sfs-worker",
                "smartflowsocial",
                50,
                50,
                "nonce-value-123456",
                80,
                Some("cursor"),
                false,
                Some(50)
            )
            .unwrap());
        assert!(!store
            .store_heartbeat(
                "sfs-worker",
                "smartflowsocial",
                51,
                51,
                "nonce-value-123456",
                80,
                Some("cursor"),
                false,
                Some(51)
            )
            .unwrap());
    }

    fn migrated() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE schema_migrations (id TEXT PRIMARY KEY, applied_at INTEGER NOT NULL);",
        )
        .unwrap();
        for (id, sql) in crate::schema::MIGRATIONS {
            conn.execute_batch(sql).unwrap();
            conn.execute(
                "INSERT INTO schema_migrations (id, applied_at) VALUES (?1, 0)",
                params![id],
            )
            .unwrap();
        }
        conn
    }

    fn seed_generation(conn: &Connection, generation: i64) {
        conn.execute(
            "INSERT INTO monitor_state (
                monitor_id, project_id, status, generation, updated_at, commit_token,
                consecutive_successes, consecutive_failures, consecutive_unknowns
            ) VALUES ('sfs-web', 'smartflowsocial', 'healthy', ?1, 1, 'seed', 0, 0, 0)",
            params![generation],
        )
        .unwrap();
    }

    /// D1 runs every statement in a batch even when an earlier statement changes
    /// zero rows. The commit token, not the generation number alone, has to stop
    /// the loser. This uses SQLite's own engine, which is the engine inside D1.
    #[test]
    fn stale_writer_batch_cannot_close_an_incident_or_insert_an_alert() {
        let conn = migrated();
        seed_generation(&conn, 10);
        conn.execute(
            "INSERT INTO incidents (
                id, monitor_id, project_id, status, kind, severity, opened_at, open_reason, reminder_count, updated_at
            ) VALUES ('inc_open', 'sfs-web', 'smartflowsocial', 'open', 'outage', 'critical', 1, 'down', 0, 1)",
            [],
        )
        .unwrap();
        let winner = conn
            .execute(
                "UPDATE monitor_state SET generation = 11, status = 'down', commit_token = 'winner', updated_at = 2
                 WHERE monitor_id = 'sfs-web' AND generation = 10",
                [],
            )
            .unwrap();
        assert_eq!(winner, 1);
        let loser_state = conn
            .execute(
                "UPDATE monitor_state SET generation = generation + 1, status = 'healthy', commit_token = 'loser', updated_at = 3
                 WHERE monitor_id = 'sfs-web' AND generation = 10",
                [],
            )
            .unwrap();
        assert_eq!(loser_state, 0);
        let unfenced_alert = conn
            .execute(
                "INSERT INTO alert_outbox (
                    id, alert_class, monitor_id, project_id, dedupe_key, destination, severity,
                    state, payload_text, attempt_count, next_attempt_at, created_at, updated_at
                )
                SELECT 'alt_unfenced', 'recovery', 'sfs-web', 'smartflowsocial', 'unfenced', 'nostr', 'critical',
                    'queued', 'recovered', 0, 3, 3, 3
                FROM monitor_state WHERE monitor_id = 'sfs-web' AND generation = 11",
                [],
            )
            .unwrap();
        assert_eq!(
            unfenced_alert, 1,
            "generation alone does not fence a later statement"
        );
        conn.execute("DELETE FROM alert_outbox WHERE id = 'alt_unfenced'", [])
            .unwrap();
        let fenced_close = conn
            .execute(
                "UPDATE incidents SET status = 'closed', closed_at = 3, close_reason = 'stale', updated_at = 3
                 WHERE id = 'inc_open' AND status = 'open' AND EXISTS (
                    SELECT 1 FROM monitor_state WHERE monitor_id = 'sfs-web' AND generation = 11 AND commit_token = 'loser'
                 )",
                [],
            )
            .unwrap();
        let fenced_alert = conn
            .execute(
                "INSERT INTO alert_outbox (
                    id, alert_class, monitor_id, project_id, dedupe_key, destination, severity,
                    state, payload_text, attempt_count, next_attempt_at, created_at, updated_at
                )
                SELECT 'alt_loser', 'recovery', 'sfs-web', 'smartflowsocial', 'loser', 'nostr', 'critical',
                    'queued', 'recovered', 0, 3, 3, 3
                FROM monitor_state WHERE monitor_id = 'sfs-web' AND generation = 11 AND commit_token = 'loser'",
                [],
            )
            .unwrap();
        assert_eq!(fenced_close, 0);
        assert_eq!(fenced_alert, 0);
        let status: String = conn
            .query_row(
                "SELECT status FROM incidents WHERE id = 'inc_open'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let alerts: i64 = conn
            .query_row("SELECT COUNT(*) FROM alert_outbox", [], |row| row.get(0))
            .unwrap();
        let token: String = conn
            .query_row(
                "SELECT commit_token FROM monitor_state WHERE monitor_id = 'sfs-web'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(status, "open");
        assert_eq!(alerts, 0);
        assert_eq!(token, "winner");
    }
}
