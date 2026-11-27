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
    ClaimOwnership, CommitOutcome, FailedAlert, HeartbeatStored, HeartbeatWrite, LoadedMemory,
    MarmotProjectRow, OnboardReceipt, OutboxRow, RetryMode, StoreError, UpstreamRow, VersionRow,
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
        validate_open_schema(&conn)?;
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
            "SELECT id, kind, severity, opened_at, reminder_count, last_reminder_at, silenced_until, acked_at, decision_generation FROM incidents WHERE monitor_id = ?1 AND status = 'open'",
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
                decision_generation: row.get(8)?,
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
                           AND decision_generation = ?3 AND reminder_count = ?4
                           AND acked_at IS NULL
                           AND (silenced_until IS NULL OR silenced_until <= ?5)
                           AND EXISTS (SELECT 1 FROM monitor_state WHERE monitor_id = ?6 AND generation = ?7 AND commit_token = ?8)",
                        params![
                            now,
                            item.incident_id,
                            item.decision_generation,
                            item.reminder_count,
                            now,
                            monitor_id,
                            next_generation,
                            commit_token,
                        ],
                    )?;
                }
            }
        }
        for alert in alerts {
            let remind = notices.iter().find(|notice| {
                notice.event == NoticeEvent::Remind
                    && alert.incident_id.as_deref() == Some(notice.incident_id.as_str())
                    && alert.alert_class == AlertClass::Reminder
            });
            let (is_reminder, decision, count_after, incident_id) = match remind {
                Some(notice) => (
                    1_i64,
                    notice.decision_generation,
                    notice.reminder_count + 1,
                    notice.incident_id.as_str(),
                ),
                None => (0, 0, 0, ""),
            };
            tx.execute(
                "INSERT OR IGNORE INTO alert_outbox (
                    id, alert_class, incident_id, monitor_id, project_id, dedupe_key, destination, severity,
                    state, payload_text, attempt_count, next_attempt_at, created_at, updated_at, logical_id
                )
                SELECT ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 'queued', ?9, 0, ?10, ?10, ?10, ?11
                FROM monitor_state WHERE monitor_id = ?4 AND generation = ?12 AND commit_token = ?13
                  AND (
                    ?14 = 0 OR EXISTS (
                      SELECT 1 FROM incidents WHERE id = ?15 AND status = 'open'
                        AND decision_generation = ?16 AND reminder_count = ?17
                        AND last_reminder_at = ?10 AND acked_at IS NULL
                    )
                  )",
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
                    logical_notification_id(&alert.dedupe_key),
                    next_generation,
                    commit_token,
                    is_reminder,
                    incident_id,
                    decision,
                    count_after,
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

    pub fn renew_lease(
        &self,
        name: &str,
        owner: &str,
        until: i64,
        now: i64,
    ) -> Result<bool, StoreError> {
        let changed = self.lock()?.execute(
            "UPDATE scheduler_leases
             SET lease_until = CASE WHEN ?1 > lease_until THEN ?1 ELSE lease_until END
             WHERE job_name = ?2 AND owner = ?3 AND lease_until >= ?4",
            params![until, name, owner, now],
        )?;
        Ok(changed > 0)
    }

    pub fn mark_run(
        &self,
        name: &str,
        owner: &str,
        started_at: Option<i64>,
        finished_at: Option<i64>,
        error: Option<&str>,
        success_at: Option<i64>,
    ) -> Result<(), StoreError> {
        self.lock()?.execute(
            "INSERT INTO scheduler_runs (
                job_name, last_started_at, last_finished_at, last_error, last_success_at, run_owner
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT(job_name) DO UPDATE SET
               last_started_at = excluded.last_started_at,
               last_finished_at = excluded.last_finished_at,
               last_error = excluded.last_error,
               last_success_at = CASE
                 WHEN excluded.last_error IS NULL THEN excluded.last_success_at
                 ELSE scheduler_runs.last_success_at
               END,
               run_owner = excluded.run_owner
             WHERE scheduler_runs.last_started_at IS NULL
                OR excluded.last_started_at > scheduler_runs.last_started_at
                OR (
                  excluded.last_started_at = scheduler_runs.last_started_at
                  AND excluded.run_owner = scheduler_runs.run_owner
                  AND COALESCE(excluded.last_finished_at, 0) >= COALESCE(scheduler_runs.last_finished_at, 0)
                )",
            params![name, started_at, finished_at, error, success_at, owner],
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
    ) -> Result<HeartbeatWrite, StoreError> {
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
                Ok(HeartbeatWrite::Replay)
            } else {
                Err(error.into())
            };
        }
        let changed = tx.execute(
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
                loop_at = excluded.loop_at
            WHERE excluded.reported_at > heartbeats.reported_at",
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
        Ok(if changed == 0 {
            HeartbeatWrite::Stale
        } else {
            HeartbeatWrite::Stored
        })
    }

    pub fn insert_alert(&self, alert: &AlertDraft, now: i64) -> Result<(), StoreError> {
        self.lock()?.execute(
            "INSERT OR IGNORE INTO alert_outbox (
                id, alert_class, incident_id, monitor_id, project_id, dedupe_key, destination, severity,
                state, payload_text, attempt_count, next_attempt_at, created_at, updated_at, logical_id
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 'queued', ?9, 0, ?10, ?10, ?10, ?11)",
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
                logical_notification_id(&alert.dedupe_key),
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
                state, payload_text, attempt_count, next_attempt_at, created_at, updated_at, logical_id
            )
            SELECT ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 'queued', ?9, 0, ?10, ?10, ?10, ?14
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
                logical_notification_id(&alert.dedupe_key),
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
        kind: &str,
        oldest: i64,
        runtime_id: &str,
    ) -> Result<Vec<OutboxRow>, StoreError> {
        let conn = self.lock()?;
        let mut stmt = conn.prepare(
            "SELECT id FROM alert_outbox
             WHERE state IN ('queued', 'retrying') AND next_attempt_at <= ?1
               AND settled_at IS NULL
               AND (claim_until IS NULL OR claim_until < ?1)
               AND (?2 IS NULL OR destination = ?2)
               AND (
                 ((?3 = 'delivery' OR ?3 = 'delivery-critical' OR ?3 = 'delivery-other')
                    AND NOT (
                      destination = 'marmot'
                      AND COALESCE(message_state, '') IN ('relay_accepted', 'accepted', 'accepted_pending')
                      AND COALESCE(push_state, 'unknown') IN ('unknown', 'pending', 'unobservable', 'not_attempted', 'token_unavailable', 'prepared', 'publication_attempted', '')
                    )
                    AND (?3 != 'delivery-critical' OR severity = 'critical')
                    AND (?3 != 'delivery-other' OR severity != 'critical'))
                 OR (?3 = 'push'
                    AND destination = 'marmot'
                    AND COALESCE(message_state, '') IN ('relay_accepted', 'accepted', 'accepted_pending')
                    AND COALESCE(push_state, 'unknown') IN ('unknown', 'pending', 'unobservable', 'not_attempted', 'token_unavailable', 'prepared', 'publication_attempted', '')
                    AND (auth_push_publications IS NULL OR auth_push_publications < 2)
                    AND (auth_push_reconciles IS NULL OR auth_push_reconciles < 2)
                    AND (auth_token_waits IS NULL OR auth_token_waits < 2)
                    AND COALESCE(operation_started_at, created_at) >= ?4)
               )
             ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'warning' THEN 1 ELSE 2 END, created_at
             LIMIT ?5",
        )?;
        let ids: Vec<String> = stmt
            .query_map(params![now, destination, kind, oldest, limit], |row| {
                row.get(0)
            })?
            .collect::<Result<Vec<_>, _>>()?;
        drop(stmt);
        let mut claimed = Vec::new();
        for id in ids {
            let token = uuid::Uuid::new_v4().to_string();
            let changed = conn.execute(
                "UPDATE alert_outbox SET claim_until = ?1, claim_token = ?2, claim_owner = ?3, state = 'retrying', updated_at = ?4
                 WHERE id = ?5 AND state IN ('queued', 'retrying') AND settled_at IS NULL
                   AND (claim_until IS NULL OR claim_until < ?4)",
                params![claim_until, token, runtime_id, now, id],
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
               AND claim_until IS NOT NULL AND claim_until >= ?4
               AND ?1 > ?4 AND ?1 <= ?4 + 300000",
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
             WHERE id = ?3 AND claim_token = ?4 AND envelope_json IS NULL
               AND claim_until IS NOT NULL AND claim_until >= ?2",
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
                 message_phase = CASE
                   WHEN ?7 IS NULL THEN message_phase
                   WHEN COALESCE(message_state, '') IN ('relay_accepted', 'accepted')
                     AND ?7 IN ('not_submitted', 'completion_unknown', 'prepared', 'not_published') THEN message_phase
                   ELSE ?7 END,
                 push_phase = CASE
                   WHEN ?8 IS NULL THEN push_phase
                   WHEN COALESCE(push_state, '') = 'relay_accepted'
                     AND ?8 IN ('not_attempted', 'unknown', 'not_submitted', 'prepared') THEN push_phase
                   ELSE ?8 END,
                 message_event_id = COALESCE(?9, message_event_id),
                 push_envelope_json = COALESCE(?10, push_envelope_json), updated_at = ?11,
                 message_state = CASE
                   WHEN ?7 IS NULL THEN message_state
                   WHEN ?7 IN ('relay_accepted', 'message_accepted', 'accepted', 'published') THEN 'relay_accepted'
                   WHEN ?7 = 'accepted_pending' THEN 'accepted_pending'
                   WHEN ?7 = 'completion_unknown' THEN 'completion_unknown'
                   WHEN ?7 IN ('message_prepared', 'prepared') THEN 'prepared'
                   WHEN COALESCE(message_state, '') IN ('relay_accepted', 'accepted')
                     AND ?7 IN ('not_submitted', 'completion_unknown', 'prepared', 'not_published') THEN message_state
                   WHEN ?7 = 'not_submitted' THEN 'not_submitted'
                   WHEN ?7 IN ('rejected', 'failed') THEN 'rejected'
                   ELSE message_state END,
                 push_state = CASE
                   WHEN ?8 IS NULL THEN push_state
                   WHEN ?8 IN ('relay_accepted', 'push_trigger_accepted') THEN 'relay_accepted'
                   WHEN ?8 IN ('token_unavailable', 'push_token_unavailable') THEN 'token_unavailable'
                   WHEN ?8 IN ('unobservable', 'push_unobservable') THEN 'unobservable'
                   WHEN ?8 IN ('prepared', 'push_trigger_prepared') THEN 'prepared'
                   WHEN ?8 = 'pending' THEN 'pending'
                   WHEN ?8 IN ('expired', 'push_expired') THEN 'expired'
                   WHEN ?8 IN ('unknown', 'not_required', 'not_attempted', 'publication_attempted', 'rejected', 'terminal_failure') THEN ?8
                   ELSE push_state END,
                 claim_owner = NULL,
                 operation_started_at = COALESCE(operation_started_at, created_at),
                 message_updated_at = CASE WHEN ?7 IS NOT NULL THEN ?11 ELSE message_updated_at END,
                 push_updated_at = CASE WHEN ?8 IS NOT NULL THEN ?11 ELSE push_updated_at END,
                 terminal_reason = COALESCE(?4, terminal_reason)
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

    pub fn retry_dead_letter(&self, id: &str, now: i64) -> Result<RetryMode, StoreError> {
        let conn = self.lock()?;
        let existing: Option<(String, Option<String>, Option<String>)> = conn
            .query_row(
                "SELECT destination, envelope_json, message_state FROM alert_outbox WHERE id = ?1 AND state = 'failed'",
                params![id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?;
        let Some((destination, envelope, message_state)) = existing else {
            return Ok(RetryMode::Missing);
        };
        let mode = match destination.as_str() {
            "marmot" => RetryMode::Reconcile,
            "telegram" => RetryMode::SameOperation,
            "nostr" if envelope.is_some() => RetryMode::SameOperation,
            "nostr" => RetryMode::NewSubmission,
            _ if envelope.is_some() => RetryMode::SameOperation,
            _ => RetryMode::NewSubmission,
        };
        let _ = message_state;
        conn.execute(
            "UPDATE alert_outbox
             SET state = 'queued', next_attempt_at = ?1, claim_until = NULL, claim_token = NULL,
                 claim_owner = NULL, settled_at = NULL, updated_at = ?1,
                 attempt_count = CASE
                   WHEN destination = 'nostr' AND envelope_json IS NULL THEN 0
                   ELSE attempt_count END,
                 submission_generation = CASE
                   WHEN destination = 'nostr' AND envelope_json IS NULL THEN submission_generation + 1
                   ELSE submission_generation END
             WHERE id = ?2 AND state = 'failed'",
            params![now, id],
        )?;
        Ok(mode)
    }

    pub fn ack_incident(&self, id: &str, now: i64) -> Result<bool, StoreError> {
        let changed = self.lock()?.execute(
            "UPDATE incidents SET acked_at = ?1, updated_at = ?1, decision_generation = decision_generation + 1
             WHERE id = ?2 AND status = 'open' AND acked_at IS NULL",
            params![now, id],
        )?;
        Ok(changed > 0)
    }

    pub fn silence_incident(&self, id: &str, until: i64, now: i64) -> Result<bool, StoreError> {
        let changed = self.lock()?.execute(
            "UPDATE incidents SET silenced_until = ?1, updated_at = ?2, decision_generation = decision_generation + 1
             WHERE id = ?3 AND status = 'open' AND (silenced_until IS NULL OR silenced_until < ?1)",
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
                generation: 0,
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
                "SELECT installed_version, latest_version, latest_url, security_status, advisory_fingerprint, notice_fingerprint, security_reminded_at, generation FROM observed_versions WHERE monitor_id = ?1",
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
                        generation: row.get(7)?,
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
                        coverage, error_code, consecutive_failures, releases_failures, advisories_failures, generation
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
                        generation: row.get(16)?,
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

    pub fn finish_with_fallback(
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
        logical_id: Option<&str>,
        fallback: Option<&AlertDraft>,
        now: i64,
    ) -> Result<bool, StoreError> {
        self.finish_owned(
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
            logical_id,
            fallback,
            &watchdog_core::delivery::AuthoritativeCounters::unknown(),
            None,
            now,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn finish_owned(
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
        logical_id: Option<&str>,
        fallback: Option<&AlertDraft>,
        counters: &watchdog_core::delivery::AuthoritativeCounters,
        projection: Option<&str>,
        now: i64,
    ) -> Result<bool, StoreError> {
        let completion = uuid::Uuid::new_v4().to_string();
        let conn = self.lock()?;
        let tx = conn.unchecked_transaction()?;
        let changed = tx.execute(
            "UPDATE alert_outbox
             SET state = ?1, attempt_count = ?2, next_attempt_at = ?3, last_error = ?4,
                 accepted_relays = ?5, failed_relays = ?6, claim_until = NULL, claim_token = NULL,
                 message_phase = CASE
                   WHEN ?7 IS NULL THEN message_phase
                   WHEN COALESCE(message_state, '') IN ('relay_accepted', 'accepted')
                     AND ?7 IN ('not_submitted', 'completion_unknown', 'prepared', 'not_published') THEN message_phase
                   ELSE ?7 END,
                 push_phase = CASE
                   WHEN ?8 IS NULL THEN push_phase
                   WHEN COALESCE(push_state, '') = 'relay_accepted'
                     AND ?8 IN ('not_attempted', 'unknown', 'not_submitted', 'prepared') THEN push_phase
                   ELSE ?8 END,
                 message_event_id = COALESCE(?9, message_event_id),
                 push_envelope_json = COALESCE(?10, push_envelope_json), updated_at = ?11,
                 logical_id = COALESCE(logical_id, ?12),
                 message_state = CASE
                   WHEN ?7 IS NULL THEN message_state
                   WHEN ?7 IN ('relay_accepted', 'message_accepted', 'accepted', 'published') THEN 'relay_accepted'
                   WHEN ?7 = 'accepted_pending' THEN 'accepted_pending'
                   WHEN ?7 = 'completion_unknown' THEN 'completion_unknown'
                   WHEN ?7 IN ('message_prepared', 'prepared') THEN 'prepared'
                   WHEN COALESCE(message_state, '') IN ('relay_accepted', 'accepted')
                     AND ?7 IN ('not_submitted', 'completion_unknown', 'prepared', 'not_published') THEN message_state
                   WHEN ?7 = 'not_submitted' THEN 'not_submitted'
                   WHEN ?7 IN ('rejected', 'failed') THEN 'rejected'
                   ELSE message_state END,
                 push_state = CASE
                   WHEN ?8 IS NULL THEN push_state
                   WHEN ?8 IN ('relay_accepted', 'push_trigger_accepted') THEN 'relay_accepted'
                   WHEN ?8 = 'unknown' THEN 'unknown'
                   WHEN ?8 = 'not_required' THEN 'not_required'
                   WHEN COALESCE(push_state, '') = 'relay_accepted'
                     AND ?8 IN ('not_attempted', 'unknown', 'not_submitted', 'prepared') THEN push_state
                   WHEN ?8 = 'not_attempted' THEN 'not_attempted'
                   WHEN ?8 IN ('token_unavailable', 'push_token_unavailable') THEN 'token_unavailable'
                   WHEN ?8 IN ('prepared', 'push_trigger_prepared') THEN 'prepared'
                   WHEN ?8 = 'pending' THEN 'pending'
                   WHEN ?8 = 'publication_attempted' THEN 'publication_attempted'
                   WHEN ?8 = 'rejected' THEN 'rejected'
                   WHEN ?8 IN ('expired', 'push_expired') THEN 'expired'
                   WHEN ?8 IN ('unobservable', 'push_unobservable') THEN 'unobservable'
                   WHEN ?8 = 'terminal_failure' THEN 'terminal_failure'
                   ELSE push_state END,
                 claim_owner = NULL,
                 completion_token = ?15,
                 operation_started_at = COALESCE(operation_started_at, json_extract(?23, '$.startedAtMs'), created_at),
                 started_at_ms = COALESCE(started_at_ms, created_at),
                 push_event_id = COALESCE(json_extract(?23, '$.pushEventId'), push_event_id),
                 evidence = COALESCE(json_extract(?23, '$.evidence'), evidence),
                 transport_disposition = COALESCE(json_extract(?23, '$.disposition'), transport_disposition),
                 transport_updated_at = COALESCE(json_extract(?23, '$.updatedAtMs'), transport_updated_at),
                 message_phase_started_at = CASE
                   WHEN ?7 IS NOT NULL AND COALESCE(message_phase, '') != ?7 THEN ?11
                   ELSE message_phase_started_at END,
                 push_phase_started_at = CASE
                   WHEN ?8 IS NOT NULL AND COALESCE(push_phase, '') != ?8 THEN ?11
                   ELSE push_phase_started_at END,
                 auth_message_submissions = CASE
                   WHEN ?16 IS NULL THEN auth_message_submissions
                   WHEN auth_message_submissions IS NULL OR ?16 > auth_message_submissions THEN ?16
                   ELSE auth_message_submissions END,
                 auth_message_publications = CASE
                   WHEN ?17 IS NULL THEN auth_message_publications
                   WHEN auth_message_publications IS NULL OR ?17 > auth_message_publications THEN ?17
                   ELSE auth_message_publications END,
                 auth_message_reconciles = CASE
                   WHEN ?18 IS NULL THEN auth_message_reconciles
                   WHEN auth_message_reconciles IS NULL OR ?18 > auth_message_reconciles THEN ?18
                   ELSE auth_message_reconciles END,
                 auth_ambiguous_reconciles = CASE
                   WHEN ?19 IS NULL THEN auth_ambiguous_reconciles
                   WHEN auth_ambiguous_reconciles IS NULL OR ?19 > auth_ambiguous_reconciles THEN ?19
                   ELSE auth_ambiguous_reconciles END,
                 auth_token_waits = CASE
                   WHEN ?20 IS NULL THEN auth_token_waits
                   WHEN auth_token_waits IS NULL OR ?20 > auth_token_waits THEN ?20
                   ELSE auth_token_waits END,
                 auth_push_publications = CASE
                   WHEN ?21 IS NULL THEN auth_push_publications
                   WHEN auth_push_publications IS NULL OR ?21 > auth_push_publications THEN ?21
                   ELSE auth_push_publications END,
                 auth_push_reconciles = CASE
                   WHEN ?22 IS NULL THEN auth_push_reconciles
                   WHEN auth_push_reconciles IS NULL OR ?22 > auth_push_reconciles THEN ?22
                   ELSE auth_push_reconciles END,
                 settled_at = CASE WHEN ?1 IN ('relay_accepted', 'failed') THEN ?11 ELSE NULL END,
                 preserve_message = CASE
                   WHEN ?7 IN ('relay_accepted', 'accepted_pending') THEN 1
                   ELSE preserve_message END,
                 operation_id = COALESCE(operation_id, CASE WHEN destination = 'marmot' THEN id ELSE NULL END),
                 message_updated_at = CASE WHEN ?7 IS NOT NULL THEN ?11 ELSE message_updated_at END,
                 push_updated_at = CASE WHEN ?8 IS NOT NULL THEN ?11 ELSE push_updated_at END,
                 terminal_reason = COALESCE(?4, terminal_reason)
             WHERE id = ?13 AND claim_token = ?14 AND claim_until IS NOT NULL AND claim_until >= ?11",
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
                logical_id,
                id,
                token,
                completion,
                counters.message_submissions,
                counters.message_publications,
                counters.message_reconciles,
                counters.ambiguous_reconciles,
                counters.token_waits,
                counters.push_publications,
                counters.push_reconciles,
                projection,
            ],
        )?;
        if changed == 0 {
            tx.rollback()?;
            return Ok(false);
        }
        if let Some(alert) = fallback {
            let logical = logical_notification_id(&alert.dedupe_key);
            let inserted = tx.execute(
                "INSERT OR IGNORE INTO alert_outbox (
                    id, alert_class, incident_id, monitor_id, project_id, dedupe_key, destination, severity,
                    state, payload_text, attempt_count, next_attempt_at, created_at, updated_at, logical_id
                 )
                 SELECT ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 'queued', ?9, 0, ?10, ?10, ?10, ?11
                 FROM alert_outbox AS finished
                 WHERE finished.id = ?12 AND finished.completion_token = ?13
                   AND NOT EXISTS (
                     SELECT 1 FROM alert_outbox
                     WHERE destination = 'telegram' AND logical_id = ?11 AND id != ?1
                   )",
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
                    logical,
                    id,
                    completion,
                ],
            )?;
            if inserted == 0 {
                let existing: i64 = tx.query_row(
                    "SELECT COUNT(*) FROM alert_outbox WHERE destination = 'telegram' AND logical_id = ?1",
                    params![logical],
                    |row| row.get(0),
                )?;
                if existing == 0 {
                    tx.rollback()?;
                    return Ok(false);
                }
            }
        }
        tx.commit()?;
        Ok(true)
    }

    pub fn claim_ownership(
        &self,
        id: &str,
        token: &str,
        now: i64,
    ) -> Result<ClaimOwnership, StoreError> {
        let row = self.lock()?.query_row(
            "SELECT claim_token, claim_until FROM alert_outbox WHERE id = ?1",
            params![id],
            |row| {
                Ok((
                    row.get::<_, Option<String>>(0)?,
                    row.get::<_, Option<i64>>(1)?,
                ))
            },
        );
        match row {
            Ok((Some(stored), Some(until))) if stored == token && until >= now => {
                Ok(ClaimOwnership::Active { until })
            }
            Ok((Some(stored), _)) if stored == token => Ok(ClaimOwnership::Expired),
            Ok((None, _)) => Ok(ClaimOwnership::Lost),
            Ok(_) => Ok(ClaimOwnership::Lost),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(ClaimOwnership::Missing),
            Err(error) => Err(error.into()),
        }
    }

    pub fn release_open_claims(&self, runtime_id: &str, now: i64) -> Result<usize, StoreError> {
        if runtime_id.is_empty() {
            return Ok(0);
        }
        Ok(self.lock()?.execute(
            "UPDATE alert_outbox
             SET claim_until = NULL, claim_token = NULL, claim_owner = NULL, state = 'retrying', updated_at = ?1
             WHERE state = 'retrying' AND claim_owner = ?2",
            params![now, runtime_id],
        )?)
    }

    pub fn settle_expired(&self, now: i64) -> Result<usize, StoreError> {
        let ids = self.settlement_ids(now)?;
        let mut settled = 0;
        for id in ids {
            if self.settle_one(&id, now, None)? {
                settled += 1;
            }
        }
        Ok(settled)
    }

    pub fn settlement_ids(&self, now: i64) -> Result<Vec<String>, StoreError> {
        let sql = format!(
            "SELECT id FROM alert_outbox WHERE {} ORDER BY created_at LIMIT 16",
            crate::schema::SETTLEMENT_PREDICATE
        );
        let conn = self.lock()?;
        let mut stmt = conn.prepare(&sql)?;
        let rows = stmt.query_map(params![now], |row| row.get(0))?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(StoreError::from)
    }

    pub fn settle_one(
        &self,
        id: &str,
        now: i64,
        fallback: Option<&AlertDraft>,
    ) -> Result<bool, StoreError> {
        let completion = uuid::Uuid::new_v4().to_string();
        let sql = format!(
            "UPDATE alert_outbox
             SET state = CASE
                   WHEN COALESCE(message_state, '') IN ('relay_accepted', 'accepted') THEN 'relay_accepted'
                   ELSE 'failed' END,
                 settled_at = ?1,
                 terminal_reason = COALESCE(terminal_reason, 'reconciliation_window'),
                 push_state = CASE
                   WHEN COALESCE(push_state, '') IN ('publication_attempted', 'prepared', 'pending', 'unknown', 'not_attempted')
                     THEN 'unobservable'
                   ELSE push_state END,
                 claim_token = NULL,
                 claim_until = NULL,
                 claim_owner = NULL,
                 completion_token = ?3,
                 operation_started_at = COALESCE(operation_started_at, created_at),
                 updated_at = ?1
             WHERE id = ?2 AND {predicate}",
            predicate = crate::schema::SETTLEMENT_PREDICATE
        );
        let conn = self.lock()?;
        let tx = conn.unchecked_transaction()?;
        let changed = tx.execute(&sql, params![now, id, completion])?;
        if changed == 0 {
            tx.rollback()?;
            return Ok(false);
        }
        if let Some(alert) = fallback {
            let logical = logical_notification_id(&alert.dedupe_key);
            let inserted = tx.execute(
                "INSERT OR IGNORE INTO alert_outbox (
                    id, alert_class, incident_id, monitor_id, project_id, dedupe_key, destination, severity,
                    state, payload_text, attempt_count, next_attempt_at, created_at, updated_at, logical_id
                 )
                 SELECT ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 'queued', ?9, 0, ?10, ?10, ?10, ?11
                 FROM alert_outbox AS finished
                 WHERE finished.id = ?12 AND finished.completion_token = ?13
                   AND NOT EXISTS (
                     SELECT 1 FROM alert_outbox
                     WHERE destination = 'telegram' AND logical_id = ?11 AND id != ?1
                   )",
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
                    logical,
                    id,
                    completion,
                ],
            )?;
            if inserted == 0 {
                let existing: i64 = tx.query_row(
                    "SELECT COUNT(*) FROM alert_outbox WHERE destination = 'telegram' AND logical_id = ?1",
                    params![logical],
                    |row| row.get(0),
                )?;
                if existing == 0 {
                    tx.rollback()?;
                    return Ok(false);
                }
            }
        }
        tx.commit()?;
        Ok(true)
    }

    pub fn expedite_destination(&self, destination: &str, now: i64) -> Result<usize, StoreError> {
        Ok(self.lock()?.execute(
            "UPDATE alert_outbox SET next_attempt_at = ?1, updated_at = ?1
             WHERE destination = ?2 AND state IN ('queued', 'retrying')
               AND (claim_until IS NULL OR claim_until < ?1)
               AND next_attempt_at > ?1",
            params![now, destination],
        )?)
    }

    pub fn acknowledge_alert(&self, id: &str, now: i64) -> Result<bool, StoreError> {
        Ok(self.lock()?.execute(
            "UPDATE alert_outbox SET operator_ack_at = ?1, updated_at = ?1
             WHERE id = ?2 AND operator_ack_at IS NULL",
            params![now, id],
        )? > 0)
    }

    pub fn count_delivery_pressure(&self, now: i64) -> Result<(i64, i64), StoreError> {
        let pending = self.lock()?.query_row(
            "SELECT COUNT(*) FROM alert_outbox WHERE state = 'retrying' AND next_attempt_at <= ?1",
            params![now],
            |row| row.get(0),
        )?;
        let recent = self.lock()?.query_row(
            "SELECT COUNT(*) FROM alert_outbox WHERE state = 'retrying' AND updated_at >= ?1",
            params![now - 86_400_000],
            |row| row.get(0),
        )?;
        Ok((pending, recent))
    }

    pub fn record_onboarding(
        &self,
        project_id: &str,
        operation_id: &str,
        replace: bool,
        now: i64,
    ) -> Result<Option<OnboardReceipt>, StoreError> {
        self.lock()?.execute(
            "INSERT INTO marmot_projects (
                project_id, engine_status, updated_at, onboard_idempotency_key, onboard_requested_at
             ) VALUES (?1, 'onboard_requested', ?2, ?3, ?2)
             ON CONFLICT(project_id) DO UPDATE SET
               onboard_idempotency_key = excluded.onboard_idempotency_key,
               onboard_requested_at = excluded.onboard_requested_at,
               engine_status = 'onboard_requested',
               updated_at = excluded.updated_at
             WHERE marmot_projects.onboard_idempotency_key IS NULL
                OR marmot_projects.onboard_idempotency_key = excluded.onboard_idempotency_key
                OR ?4 = 1",
            params![project_id, now, operation_id, i64::from(replace)],
        )?;
        self.lock()?.execute(
            "INSERT OR IGNORE INTO marmot_onboard_history (
                project_id, operation_id, replace_requested, requested_at, engine_status
             ) VALUES (?1, ?2, ?3, ?4, 'onboard_requested')",
            params![project_id, operation_id, i64::from(replace), now],
        )?;
        self.lock()?
            .query_row(
                "SELECT engine_status, onboard_idempotency_key FROM marmot_projects WHERE project_id = ?1",
                params![project_id],
                |row| {
                    Ok(OnboardReceipt {
                        engine_status: row.get(0)?,
                        idempotency_key: row.get::<_, Option<String>>(1)?.unwrap_or_default(),
                    })
                },
            )
            .optional()
            .map_err(StoreError::from)
    }

    pub fn commit_vendor_cycle(
        &self,
        monitor_id: &str,
        version_generation: Option<i64>,
        version: Option<&VersionRow>,
        vendor_generation: i64,
        vendor: &VendorView,
        alerts: &[AlertDraft],
        now: i64,
    ) -> Result<CommitOutcome, StoreError> {
        let conn = self.lock()?;
        let tx = conn.unchecked_transaction()?;
        let token = uuid::Uuid::new_v4().to_string();
        if let (Some(generation), Some(version)) = (version_generation, version) {
            let changed = tx.execute(
                "INSERT INTO observed_versions (
                    monitor_id, installed_version, latest_version, latest_url, security_status,
                    advisory_fingerprint, notice_fingerprint, updated_at, security_reminded_at,
                    generation, commit_token
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
                 ON CONFLICT(monitor_id) DO UPDATE SET
                    installed_version = excluded.installed_version,
                    latest_version = excluded.latest_version,
                    latest_url = excluded.latest_url,
                    security_status = excluded.security_status,
                    advisory_fingerprint = excluded.advisory_fingerprint,
                    notice_fingerprint = excluded.notice_fingerprint,
                    updated_at = excluded.updated_at,
                    security_reminded_at = excluded.security_reminded_at,
                    generation = excluded.generation,
                    commit_token = excluded.commit_token
                 WHERE observed_versions.generation = ?12",
                params![
                    monitor_id,
                    version.installed,
                    version.latest,
                    version.latest_url,
                    version.security_status,
                    version.advisory_fingerprint,
                    version.notice_fingerprint,
                    now,
                    version.security_reminded_at,
                    generation + 1,
                    token,
                    generation,
                ],
            )?;
            if changed == 0 {
                tx.rollback()?;
                return Ok(CommitOutcome { committed: false });
            }
        }
        let vendor_changed = tx.execute(
            "INSERT INTO vendor_checks (
                monitor_id, vendor, attempted_at, succeeded_at, partial_succeeded_at, releases_checked_at,
                advisories_checked_at, releases_stale, advisories_stale, releases_state, advisories_state,
                coverage, error_code, consecutive_failures, releases_failures, advisories_failures, updated_at,
                generation, commit_token
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19)
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
                updated_at = excluded.updated_at,
                generation = excluded.generation,
                commit_token = excluded.commit_token
             WHERE vendor_checks.generation = ?20",
            params![
                vendor.monitor_id,
                vendor.vendor,
                vendor.attempted_at,
                vendor.succeeded_at,
                vendor.partial_succeeded_at,
                vendor.releases_checked_at,
                vendor.advisories_checked_at,
                i64::from(vendor.releases_stale),
                i64::from(vendor.advisories_stale),
                vendor.releases_state,
                vendor.advisories_state,
                vendor.coverage,
                vendor.error_code,
                vendor.consecutive_failures,
                vendor.releases_failures,
                vendor.advisories_failures,
                now,
                vendor_generation + 1,
                token,
                vendor_generation,
            ],
        )?;
        if vendor_changed == 0 {
            tx.rollback()?;
            return Ok(CommitOutcome { committed: false });
        }
        for alert in alerts {
            tx.execute(
                "INSERT OR IGNORE INTO alert_outbox (
                    id, alert_class, incident_id, monitor_id, project_id, dedupe_key, destination, severity,
                    state, payload_text, attempt_count, next_attempt_at, created_at, updated_at, logical_id
                 )
                 SELECT ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 'queued', ?9, 0, ?10, ?10, ?10, ?11
                 FROM vendor_checks WHERE monitor_id = ?4 AND generation = ?12 AND commit_token = ?13",
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
                    logical_notification_id(&alert.dedupe_key),
                    vendor_generation + 1,
                    token,
                ],
            )?;
        }
        tx.commit()?;
        Ok(CommitOutcome { committed: true })
    }
}

fn read_outbox(conn: &Connection, id: &str) -> Result<Option<OutboxRow>, StoreError> {
    conn.query_row(
        "SELECT id, alert_class, incident_id, monitor_id, project_id, dedupe_key, destination, severity, state,
                payload_text, envelope_json, attempt_count, next_attempt_at, claim_until, claim_token,
                accepted_relays, failed_relays, last_error, created_at, updated_at,
                message_phase, push_phase, push_envelope_json, message_event_id,
                message_state, push_state, message_attempts, push_attempts, message_updated_at,
                push_updated_at, terminal_reason, operator_ack_at, logical_id, submission_generation,
                message_reconcile_attempts, unknown_attempts, token_wait_attempts,
                push_publication_attempts, unobservable_attempts, started_at_ms, preserve_message,
                settled_at, operation_id, claim_owner, operation_started_at,
                message_phase_started_at, push_phase_started_at,
                auth_message_submissions, auth_message_publications, auth_message_reconciles,
                auth_ambiguous_reconciles, auth_token_waits, auth_push_publications,
                auth_push_reconciles, push_event_id, evidence, transport_disposition,
                transport_updated_at
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
                message_state: row.get(24)?,
                push_state: row.get(25)?,
                message_attempts: row.get(26)?,
                push_attempts: row.get(27)?,
                message_updated_at: row.get(28)?,
                push_updated_at: row.get(29)?,
                terminal_reason: row.get(30)?,
                operator_ack_at: row.get(31)?,
                logical_id: row.get(32)?,
                submission_generation: row.get(33)?,
                message_reconcile_attempts: row.get(34)?,
                unknown_attempts: row.get(35)?,
                token_wait_attempts: row.get(36)?,
                push_publication_attempts: row.get(37)?,
                unobservable_attempts: row.get(38)?,
                started_at_ms: row.get(39)?,
                preserve_message: row.get::<_, i64>(40)? == 1,
                settled_at: row.get(41)?,
                operation_id: row.get(42)?,
                claim_owner: row.get(43)?,
                operation_started_at: row.get(44)?,
                message_phase_started_at: row.get(45)?,
                push_phase_started_at: row.get(46)?,
                auth_message_submissions: row.get(47)?,
                auth_message_publications: row.get(48)?,
                auth_message_reconciles: row.get(49)?,
                auth_ambiguous_reconciles: row.get(50)?,
                auth_token_waits: row.get(51)?,
                auth_push_publications: row.get(52)?,
                auth_push_reconciles: row.get(53)?,
                push_event_id: row.get(54)?,
                evidence: row.get(55)?,
                transport_disposition: row.get(56)?,
                transport_updated_at: row.get(57)?,
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
    async fn renew_lease(
        &self,
        name: &str,
        owner: &str,
        until: i64,
        now: i64,
    ) -> Result<bool, StoreError> {
        SqliteStore::renew_lease(self, name, owner, until, now)
    }
    async fn mark_run(
        &self,
        name: &str,
        owner: &str,
        started_at: Option<i64>,
        finished_at: Option<i64>,
        error: Option<&str>,
        success_at: Option<i64>,
    ) -> Result<(), StoreError> {
        SqliteStore::mark_run(
            self,
            name,
            owner,
            started_at,
            finished_at,
            error,
            success_at,
        )
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
    ) -> Result<HeartbeatWrite, StoreError> {
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
        kind: &str,
        oldest: i64,
        runtime_id: &str,
    ) -> Result<Vec<OutboxRow>, StoreError> {
        SqliteStore::claim_outbox(
            self,
            now,
            claim_until,
            destination,
            limit,
            kind,
            oldest,
            runtime_id,
        )
    }
    async fn claim_ownership(
        &self,
        id: &str,
        token: &str,
        now: i64,
    ) -> Result<ClaimOwnership, StoreError> {
        SqliteStore::claim_ownership(self, id, token, now)
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
    async fn finish_with_fallback(
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
        logical_id: Option<&str>,
        fallback: Option<&watchdog_core::domain::AlertDraft>,
        counters: &watchdog_core::delivery::AuthoritativeCounters,
        projection: Option<&str>,
        now: i64,
    ) -> Result<bool, StoreError> {
        SqliteStore::finish_owned(
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
            logical_id,
            fallback,
            counters,
            projection,
            now,
        )
    }
    async fn retry_dead_letter(&self, id: &str, now: i64) -> Result<RetryMode, StoreError> {
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
    async fn commit_vendor_cycle(
        &self,
        monitor_id: &str,
        version_generation: Option<i64>,
        version: Option<&VersionRow>,
        vendor_generation: i64,
        vendor: &watchdog_core::status::VendorView,
        alerts: &[watchdog_core::domain::AlertDraft],
        now: i64,
    ) -> Result<CommitOutcome, StoreError> {
        SqliteStore::commit_vendor_cycle(
            self,
            monitor_id,
            version_generation,
            version,
            vendor_generation,
            vendor,
            alerts,
            now,
        )
    }
    async fn read_alert(&self, id: &str) -> Result<Option<OutboxRow>, StoreError> {
        SqliteStore::read_outbox_row(self, id)
    }
    async fn acknowledge_alert(&self, id: &str, now: i64) -> Result<bool, StoreError> {
        SqliteStore::acknowledge_alert(self, id, now)
    }
    async fn release_open_claims(&self, runtime_id: &str, now: i64) -> Result<usize, StoreError> {
        SqliteStore::release_open_claims(self, runtime_id, now)
    }
    async fn settle_expired(&self, now: i64) -> Result<usize, StoreError> {
        SqliteStore::settle_expired(self, now)
    }
    async fn settlement_ids(&self, now: i64) -> Result<Vec<String>, StoreError> {
        SqliteStore::settlement_ids(self, now)
    }
    async fn settle_one(
        &self,
        id: &str,
        now: i64,
        fallback: Option<&watchdog_core::domain::AlertDraft>,
    ) -> Result<bool, StoreError> {
        SqliteStore::settle_one(self, id, now, fallback)
    }
    async fn expedite_destination(&self, destination: &str, now: i64) -> Result<usize, StoreError> {
        SqliteStore::expedite_destination(self, destination, now)
    }
    async fn record_onboarding(
        &self,
        project_id: &str,
        operation_id: &str,
        replace: bool,
        now: i64,
    ) -> Result<Option<OnboardReceipt>, StoreError> {
        SqliteStore::record_onboarding(self, project_id, operation_id, replace, now)
    }
    async fn count_delivery_pressure(&self, now: i64) -> Result<(i64, i64), StoreError> {
        SqliteStore::count_delivery_pressure(self, now)
    }
}

fn logical_notification_id(dedupe_key: &str) -> String {
    watchdog_core::settings::logical_notification_key(dedupe_key).to_string()
}

fn validate_open_schema(conn: &Connection) -> Result<(), StoreError> {
    let mut missing = Vec::new();
    for table in crate::schema::REQUIRED_TABLES {
        let present: bool = conn
            .query_row(
                "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1",
                params![table],
                |_| Ok(true),
            )
            .optional()?
            .unwrap_or(false);
        if !present {
            missing.push((*table).to_string());
        }
    }
    for (table, column) in crate::schema::REQUIRED_COLUMNS {
        let mut stmt = conn.prepare(&format!("PRAGMA table_info({table})"))?;
        let names = stmt
            .query_map([], |row| row.get::<_, String>(1))?
            .collect::<Result<Vec<_>, _>>()?;
        if !names.iter().any(|name| name == column) {
            missing.push(format!("{table}.{column}"));
        }
    }
    for index in crate::schema::REQUIRED_INDEXES {
        let present: bool = conn
            .query_row(
                "SELECT 1 FROM sqlite_master WHERE type = 'index' AND name = ?1",
                params![index],
                |_| Ok(true),
            )
            .optional()?
            .unwrap_or(false);
        if !present {
            missing.push(format!("index:{index}"));
        }
    }
    let mut stmt = conn.prepare("SELECT id FROM schema_migrations")?;
    let applied = stmt
        .query_map([], |row| row.get::<_, String>(0))?
        .collect::<Result<Vec<_>, _>>()?;
    crate::schema::schema_status(&applied, &missing)
        .map_err(|error| StoreError::Database(error.to_string()))
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
        let claimed = store
            .claim_outbox(10, 100, None, 4, "delivery", 0, "test")
            .unwrap();
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
        assert_eq!(
            store
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
                .unwrap(),
            HeartbeatWrite::Stored
        );
        assert_eq!(
            store
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
                .unwrap(),
            HeartbeatWrite::Replay
        );
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

    #[test]
    fn older_heartbeats_do_not_regress_progress_and_replays_stay_distinct() {
        let store = SqliteStore::memory().unwrap();
        let stored = store
            .store_heartbeat(
                "sfs-web",
                "smartflowsocial",
                2_000,
                1_500,
                "nonce-new",
                9_000,
                Some("token-b"),
                false,
                None,
            )
            .unwrap();
        assert_eq!(stored, HeartbeatWrite::Stored);
        let older = store
            .store_heartbeat(
                "sfs-web",
                "smartflowsocial",
                2_100,
                1_000,
                "nonce-old",
                9_000,
                Some("token-a"),
                true,
                None,
            )
            .unwrap();
        assert_eq!(older, HeartbeatWrite::Stale);
        let equal = store
            .store_heartbeat(
                "sfs-web",
                "smartflowsocial",
                2_200,
                1_500,
                "nonce-equal",
                9_000,
                Some("token-c"),
                false,
                None,
            )
            .unwrap();
        assert_eq!(equal, HeartbeatWrite::Stale);
        let replay = store
            .store_heartbeat(
                "sfs-web",
                "smartflowsocial",
                2_300,
                1_800,
                "nonce-new",
                9_000,
                Some("token-d"),
                false,
                None,
            )
            .unwrap();
        assert_eq!(replay, HeartbeatWrite::Replay);
        let token: String = store
            .lock()
            .unwrap()
            .query_row(
                "SELECT progress_token FROM heartbeats WHERE monitor_id = 'sfs-web'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(token, "token-b");
    }

    #[test]
    fn an_expired_claim_cannot_be_renewed_by_the_same_token() {
        let store = SqliteStore::memory().unwrap();
        store
            .insert_alert(
                &AlertDraft {
                    id: "alt_claim".to_string(),
                    alert_class: AlertClass::Outage,
                    incident_id: None,
                    monitor_id: "sfs-web".to_string(),
                    project_id: "smartflowsocial".to_string(),
                    dedupe_key: "claim".to_string(),
                    destination: Destination::Nostr,
                    severity: Severity::Critical,
                    text: "down".to_string(),
                },
                1_000,
            )
            .unwrap();
        let claimed = store
            .claim_outbox(1_000, 1_500, Some("nostr"), 1, "delivery", 0, "test")
            .unwrap();
        let token = claimed[0].claim_token.clone().unwrap();
        assert!(!store
            .extend_claim("alt_claim", &token, 2_200, 2_000)
            .unwrap());
        assert!(matches!(
            store.claim_ownership("alt_claim", &token, 2_000).unwrap(),
            ClaimOwnership::Expired
        ));
    }

    fn draft(id: &str, destination: Destination, dedupe: &str) -> AlertDraft {
        AlertDraft {
            id: id.to_string(),
            alert_class: AlertClass::Outage,
            incident_id: Some("inc".to_string()),
            monitor_id: "sfs-web".to_string(),
            project_id: "smartflowsocial".to_string(),
            dedupe_key: dedupe.to_string(),
            destination,
            severity: Severity::Critical,
            text: "down".to_string(),
        }
    }

    #[test]
    fn fallback_is_created_only_by_the_winning_claim_and_is_not_duplicated() {
        let store = SqliteStore::memory().unwrap();
        store
            .insert_alert(
                &draft("alt_m", Destination::Marmot, "incident:inc:open:marmot"),
                10,
            )
            .unwrap();
        let claimed = store
            .claim_outbox(10, 100, Some("marmot"), 1, "delivery", 0, "runtime-a")
            .unwrap();
        let token = claimed[0].claim_token.clone().unwrap();
        let fallback = draft(
            "alt_t",
            Destination::Telegram,
            "incident:inc:fallback:telegram",
        );
        assert!(!store
            .finish_with_fallback(
                "alt_m",
                "stale",
                DeliveryState::Failed,
                1,
                10,
                Some("lost"),
                None,
                None,
                Some("rejected"),
                Some("unobservable"),
                None,
                None,
                Some("logical"),
                Some(&fallback),
                20,
            )
            .unwrap());
        assert!(store.read_outbox_row("alt_t").unwrap().is_none());
        assert!(store
            .finish_with_fallback(
                "alt_m",
                &token,
                DeliveryState::Failed,
                1,
                10,
                Some("rejected"),
                None,
                None,
                Some("rejected"),
                Some("unobservable"),
                None,
                None,
                Some("logical"),
                Some(&fallback),
                20,
            )
            .unwrap());
        assert!(store.read_outbox_row("alt_t").unwrap().is_some());
        let again = draft("alt_t2", Destination::Telegram, "incident:inc:fallback");
        store
            .insert_alert(
                &draft("alt_m2", Destination::Marmot, "incident:inc:open:marmot:2"),
                30,
            )
            .unwrap();
        let second = store
            .claim_outbox(30, 100, Some("marmot"), 1, "delivery", 0, "runtime-a")
            .unwrap();
        assert!(store
            .finish_with_fallback(
                "alt_m2",
                &second[0].claim_token.clone().unwrap(),
                DeliveryState::Failed,
                1,
                30,
                Some("rejected"),
                None,
                None,
                Some("rejected"),
                Some("unobservable"),
                None,
                None,
                Some("logical-2"),
                Some(&again),
                40,
            )
            .unwrap());
        let logical = store
            .lock()
            .unwrap()
            .query_row(
                "SELECT logical_id FROM alert_outbox WHERE id = 'alt_t'",
                [],
                |row| row.get::<_, String>(0),
            )
            .unwrap();
        let count: i64 = store
            .lock()
            .unwrap()
            .query_row(
                "SELECT COUNT(*) FROM alert_outbox WHERE destination = 'telegram' AND logical_id = ?1",
                params![logical],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 1);
        assert!(store.read_outbox_row("alt_t2").unwrap().is_none());
    }

    #[test]
    fn a_repeated_phase_does_not_increment_and_unknown_is_not_rejected() {
        let store = SqliteStore::memory().unwrap();
        store
            .insert_alert(&draft("alt_p", Destination::Marmot, "phase"), 10)
            .unwrap();
        let claimed = store
            .claim_outbox(10, 200, Some("marmot"), 1, "delivery", 0, "runtime-a")
            .unwrap();
        let token = claimed[0].claim_token.clone().unwrap();
        assert!(store
            .finish_with_fallback(
                "alt_p",
                &token,
                DeliveryState::Retrying,
                1,
                10,
                None,
                None,
                None,
                Some("relay_accepted"),
                Some("publication_attempted"),
                Some("event-1"),
                None,
                None,
                None,
                20,
            )
            .unwrap());
        store
            .lock()
            .unwrap()
            .execute(
                "UPDATE alert_outbox SET state = 'retrying', claim_token = 'again', claim_until = 300, updated_at = 30 WHERE id = 'alt_p'",
                [],
            )
            .unwrap();
        assert!(store
            .finish_with_fallback(
                "alt_p",
                "again",
                DeliveryState::Retrying,
                1,
                30,
                None,
                None,
                None,
                Some("relay_accepted"),
                Some("unobservable"),
                Some("event-1"),
                None,
                None,
                None,
                40,
            )
            .unwrap());
        let row = store.read_outbox_row("alt_p").unwrap().unwrap();
        assert_eq!(row.message_state.as_deref(), Some("relay_accepted"));
        assert_eq!(row.push_state.as_deref(), Some("unobservable"));
        assert_eq!(row.message_attempts, 0);
        assert_eq!(row.auth_message_submissions, None);
        assert_eq!(row.push_publication_attempts, 0);
        assert_eq!(row.unobservable_attempts, 0);
        assert!(row.preserve_message);
        store
            .lock()
            .unwrap()
            .execute(
                "UPDATE alert_outbox SET state = 'retrying', claim_token = 'bad', claim_until = 500 WHERE id = 'alt_p'",
                [],
            )
            .unwrap();
        assert!(store
            .finish_with_fallback(
                "alt_p",
                "bad",
                DeliveryState::Failed,
                2,
                50,
                Some("unknown"),
                None,
                None,
                Some("not-a-message-state"),
                Some("not-a-push-state"),
                None,
                None,
                None,
                None,
                60,
            )
            .unwrap());
        let row = store.read_outbox_row("alt_p").unwrap().unwrap();
        assert_eq!(row.message_state.as_deref(), Some("relay_accepted"));
        assert_eq!(row.push_state.as_deref(), Some("unobservable"));
    }

    #[test]
    fn retries_follow_the_transport_and_shutdown_releases_only_this_runtime() {
        let store = SqliteStore::memory().unwrap();
        store
            .insert_alert(&draft("nip", Destination::Nostr, "nip"), 10)
            .unwrap();
        store
            .lock()
            .unwrap()
            .execute(
                "UPDATE alert_outbox SET state = 'failed', envelope_json = '{\"id\":\"evt\"}', message_state = 'relay_accepted' WHERE id = 'nip'",
                [],
            )
            .unwrap();
        assert_eq!(
            store.retry_dead_letter("nip", 20).unwrap(),
            RetryMode::SameOperation
        );
        let row = store.read_outbox_row("nip").unwrap().unwrap();
        assert_eq!(row.message_state.as_deref(), Some("relay_accepted"));
        assert_eq!(row.submission_generation, 0);
        store
            .insert_alert(&draft("marmot", Destination::Marmot, "marmot"), 10)
            .unwrap();
        store
            .lock()
            .unwrap()
            .execute(
                "UPDATE alert_outbox SET state = 'failed', message_state = 'accepted_pending', operation_id = 'marmot' WHERE id = 'marmot'",
                [],
            )
            .unwrap();
        assert_eq!(
            store.retry_dead_letter("marmot", 20).unwrap(),
            RetryMode::Reconcile
        );
        let row = store.read_outbox_row("marmot").unwrap().unwrap();
        assert_eq!(row.message_state.as_deref(), Some("accepted_pending"));
        store
            .insert_alert(&draft("bare", Destination::Nostr, "bare"), 10)
            .unwrap();
        store
            .lock()
            .unwrap()
            .execute(
                "UPDATE alert_outbox SET state = 'failed' WHERE id = 'bare'",
                [],
            )
            .unwrap();
        assert_eq!(
            store.retry_dead_letter("bare", 20).unwrap(),
            RetryMode::NewSubmission
        );
        assert_eq!(
            store
                .read_outbox_row("bare")
                .unwrap()
                .unwrap()
                .submission_generation,
            1
        );
        store
            .insert_alert(&draft("owned", Destination::Telegram, "owned"), 10)
            .unwrap();
        store
            .claim_outbox(10, 1_000, Some("telegram"), 1, "delivery", 0, "runtime-a")
            .unwrap();
        store
            .insert_alert(&draft("other", Destination::Telegram, "other"), 10)
            .unwrap();
        store
            .claim_outbox(10, 1_000, Some("telegram"), 1, "delivery", 0, "runtime-b")
            .unwrap();
        assert_eq!(store.release_open_claims("runtime-a", 20).unwrap(), 1);
        let other = store.read_outbox_row("other").unwrap().unwrap();
        assert_eq!(other.claim_owner.as_deref(), Some("runtime-b"));
        assert!(other.claim_token.is_some());
        assert_eq!(store.release_open_claims("", 20).unwrap(), 0);
    }

    #[test]
    fn an_acknowledged_incident_does_not_accept_a_stale_reminder() {
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
                    id: format!("open_{now}"),
                    alert_class: AlertClass::Outage,
                    incident_id: Some(notice.incident_id.clone()),
                    monitor_id: "sfs-web".to_string(),
                    project_id: "smartflowsocial".to_string(),
                    dedupe_key: format!("incident:{}:open:nostr", notice.incident_id),
                    destination: Destination::Nostr,
                    severity: notice.severity,
                    text: "down".to_string(),
                })
                .collect::<Vec<_>>();
            assert!(
                store
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
                    .unwrap()
                    .committed
            );
            loaded = store.load_memory("sfs-web").unwrap();
        }
        let incident = loaded.memory.open_incident.clone().unwrap();
        let remind = Notice {
            event: NoticeEvent::Remind,
            incident_id: incident.id.clone(),
            kind: IncidentKind::Outage,
            severity: Severity::Critical,
            reason: "still down".to_string(),
            occurred_at: 100,
            monitor_status: MonitorStatus::Down,
            decision_generation: incident.decision_generation,
            reminder_count: incident.reminder_count,
        };
        let reminder = AlertDraft {
            id: "remind_1".to_string(),
            alert_class: AlertClass::Reminder,
            incident_id: Some(incident.id.clone()),
            monitor_id: "sfs-web".to_string(),
            project_id: "smartflowsocial".to_string(),
            dedupe_key: "incident:inc_one:reminder:1".to_string(),
            destination: Destination::Nostr,
            severity: Severity::Critical,
            text: "still down".to_string(),
        };
        let result = check_result(
            MonitorStatus::Down,
            Some("http_status"),
            "down",
            Some(10),
            None,
        );
        assert!(
            store
                .commit_check(
                    "sfs-web",
                    "smartflowsocial",
                    loaded.generation,
                    &loaded.memory,
                    &result,
                    100,
                    &[remind.clone()],
                    &[reminder.clone()],
                )
                .unwrap()
                .committed
        );
        assert!(store.read_outbox_row("remind_1").unwrap().is_some());
        loaded = store.load_memory("sfs-web").unwrap();
        assert!(store.ack_incident(&incident.id, 110).unwrap());
        let stale = reminder_after_ack(&store, &loaded, &incident.id);
        assert!(!stale);
        assert!(store.read_outbox_row("remind_stale").unwrap().is_none());
    }

    fn reminder_after_ack(store: &SqliteStore, loaded: &LoadedMemory, incident_id: &str) -> bool {
        let incident = loaded.memory.open_incident.clone().unwrap();
        let remind = Notice {
            event: NoticeEvent::Remind,
            incident_id: incident_id.to_string(),
            kind: IncidentKind::Outage,
            severity: Severity::Critical,
            reason: "stale".to_string(),
            occurred_at: 120,
            monitor_status: MonitorStatus::Down,
            decision_generation: incident.decision_generation,
            reminder_count: incident.reminder_count,
        };
        let reminder = AlertDraft {
            id: "remind_stale".to_string(),
            alert_class: AlertClass::Reminder,
            incident_id: Some(incident_id.to_string()),
            monitor_id: "sfs-web".to_string(),
            project_id: "smartflowsocial".to_string(),
            dedupe_key: "incident:inc_one:reminder:stale".to_string(),
            destination: Destination::Nostr,
            severity: Severity::Critical,
            text: "stale".to_string(),
        };
        let result = check_result(
            MonitorStatus::Down,
            Some("http_status"),
            "down",
            Some(10),
            None,
        );
        store
            .commit_check(
                "sfs-web",
                "smartflowsocial",
                loaded.generation,
                &loaded.memory,
                &result,
                120,
                &[remind],
                &[reminder],
            )
            .unwrap()
            .committed
            && store.read_outbox_row("remind_stale").unwrap().is_some()
    }

    #[test]
    fn typescript_history_upgrades_without_inventing_acceptance() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE schema_migrations (id TEXT PRIMARY KEY, applied_at INTEGER NOT NULL);",
        )
        .unwrap();
        for (id, sql) in crate::schema::MIGRATIONS.iter().take(5) {
            conn.execute_batch(sql).unwrap();
            conn.execute(
                "INSERT INTO schema_migrations (id, applied_at) VALUES (?1, 0)",
                params![id],
            )
            .unwrap();
        }
        conn.execute(
            "INSERT INTO alert_outbox (
                id, alert_class, monitor_id, project_id, dedupe_key, destination, severity,
                state, payload_text, next_attempt_at, created_at, updated_at
             ) VALUES ('legacy', 'outage', 'sfs-web', 'smartflowsocial', 'legacy', 'marmot',
                       'critical', 'failed', 'down', 1, 1, 1)",
            [],
        )
        .unwrap();
        for (id, sql) in crate::schema::MIGRATIONS.iter().skip(5) {
            conn.execute_batch(sql).unwrap();
            conn.execute(
                "INSERT INTO schema_migrations (id, applied_at) VALUES (?1, 0)",
                params![id],
            )
            .unwrap();
        }
        let state: Option<String> = conn
            .query_row(
                "SELECT message_state FROM alert_outbox WHERE id = 'legacy'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(state, None);
        let push: Option<String> = conn
            .query_row(
                "SELECT push_state FROM alert_outbox WHERE id = 'legacy'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(push, None);
        let attempts: i64 = conn
            .query_row(
                "SELECT message_attempts FROM alert_outbox WHERE id = 'legacy'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(attempts, 0);
        let submissions: Option<i64> = conn
            .query_row(
                "SELECT auth_message_submissions FROM alert_outbox WHERE id = 'legacy'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(submissions, None);
        let started: Option<i64> = conn
            .query_row(
                "SELECT operation_started_at FROM alert_outbox WHERE id = 'legacy'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(started, None);
        assert!(validate_open_schema(&conn).is_ok());
    }

    #[test]
    fn an_equal_timestamp_loser_cannot_insert_a_fallback_and_a_failed_insert_rolls_back() {
        let store = SqliteStore::memory().unwrap();
        store
            .insert_alert(
                &draft("alt_eq", Destination::Marmot, "incident:eq:open:marmot"),
                10,
            )
            .unwrap();
        let claimed = store
            .claim_outbox(10, 100, Some("marmot"), 1, "delivery", 0, "runtime-a")
            .unwrap();
        let token = claimed[0].claim_token.clone().unwrap();
        let fallback = draft(
            "alt_eq_tg",
            Destination::Telegram,
            "incident:eq:fallback:telegram",
        );
        let now = 50;
        assert!(store
            .finish_with_fallback(
                "alt_eq",
                &token,
                DeliveryState::Failed,
                1,
                now,
                Some("rejected"),
                None,
                None,
                Some("rejected"),
                Some("unobservable"),
                None,
                None,
                Some("logical-eq"),
                Some(&fallback),
                now,
            )
            .unwrap());
        let winner_token: String = store
            .lock()
            .unwrap()
            .query_row(
                "SELECT completion_token FROM alert_outbox WHERE id = 'alt_eq'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(!winner_token.is_empty());
        let loser = draft(
            "alt_eq_loser",
            Destination::Telegram,
            "incident:eq:loser:telegram",
        );
        assert!(!store
            .finish_with_fallback(
                "alt_eq",
                "other-token",
                DeliveryState::Failed,
                1,
                now,
                Some("rejected"),
                None,
                None,
                Some("rejected"),
                Some("unobservable"),
                None,
                None,
                Some("logical-eq"),
                Some(&loser),
                now,
            )
            .unwrap());
        let telegram: i64 = store
            .lock()
            .unwrap()
            .query_row(
                "SELECT COUNT(*) FROM alert_outbox WHERE destination = 'telegram'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(telegram, 1);
        let still: String = store
            .lock()
            .unwrap()
            .query_row(
                "SELECT completion_token FROM alert_outbox WHERE id = 'alt_eq'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(still, winner_token);

        store
            .insert_alert(
                &draft(
                    "alt_block",
                    Destination::Marmot,
                    "incident:block:open:marmot",
                ),
                10,
            )
            .unwrap();
        store
            .insert_alert(
                &draft(
                    "alt_block_taken",
                    Destination::Nostr,
                    "blocked:fallback:telegram",
                ),
                10,
            )
            .unwrap();
        let claimed = store
            .claim_outbox(10, 100, Some("marmot"), 1, "delivery", 0, "runtime-a")
            .unwrap();
        let token = claimed[0].claim_token.clone().unwrap();
        let blocked = draft(
            "alt_block_tg",
            Destination::Telegram,
            "blocked:fallback:telegram",
        );
        assert!(!store
            .finish_with_fallback(
                "alt_block",
                &token,
                DeliveryState::Failed,
                1,
                80,
                Some("rejected"),
                None,
                None,
                Some("rejected"),
                None,
                None,
                None,
                Some("logical-block"),
                Some(&blocked),
                80,
            )
            .unwrap());
        let row = store.read_outbox_row("alt_block").unwrap().unwrap();
        assert_eq!(row.state, "retrying");
        assert!(row.claim_token.is_some());
        assert!(store.read_outbox_row("alt_block_tg").unwrap().is_none());
    }

    #[test]
    fn settlement_uses_the_original_age_and_creates_one_fallback() {
        let store = SqliteStore::memory().unwrap();
        store
            .insert_alert(
                &draft("alt_age", Destination::Marmot, "incident:age:open:marmot"),
                1_000,
            )
            .unwrap();
        store
            .lock()
            .unwrap()
            .execute(
                "UPDATE alert_outbox
                 SET state = 'retrying', message_state = 'completion_unknown', updated_at = 900000
                 WHERE id = 'alt_age'",
                [],
            )
            .unwrap();
        let now = 1_000 + 900_000 + 1;
        assert!(store.settlement_ids(now - 1).unwrap().is_empty());
        let ids = store.settlement_ids(now).unwrap();
        assert_eq!(ids, vec!["alt_age".to_string()]);
        let fallback = draft(
            "alt_age_tg",
            Destination::Telegram,
            "incident:age:fallback:telegram",
        );
        assert!(store.settle_one("alt_age", now, Some(&fallback)).unwrap());
        let row = store.read_outbox_row("alt_age").unwrap().unwrap();
        assert_eq!(row.state, "failed");
        assert_eq!(row.message_state.as_deref(), Some("completion_unknown"));
        assert!(row.claim_token.is_none());
        assert!(row.settled_at.is_some());
        assert_eq!(row.operation_started_at, Some(1_000));
        assert!(store.read_outbox_row("alt_age_tg").unwrap().is_some());
        assert!(!store.settle_one("alt_age", now, Some(&fallback)).unwrap());
        let telegram: i64 = store
            .lock()
            .unwrap()
            .query_row(
                "SELECT COUNT(*) FROM alert_outbox WHERE destination = 'telegram' AND logical_id = 'incident:age:fallback'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(telegram, 1);

        store
            .insert_alert(
                &draft(
                    "alt_young",
                    Destination::Marmot,
                    "incident:young:open:marmot",
                ),
                now,
            )
            .unwrap();
        store
            .lock()
            .unwrap()
            .execute(
                "UPDATE alert_outbox SET state = 'retrying', updated_at = 1 WHERE id = 'alt_young'",
                [],
            )
            .unwrap();
        assert!(!store
            .settlement_ids(now)
            .unwrap()
            .contains(&"alt_young".to_string()));
    }

    #[test]
    fn supplied_counters_are_monotonic_and_onboarding_history_is_append_only() {
        let store = SqliteStore::memory().unwrap();
        store
            .insert_alert(&draft("alt_count", Destination::Marmot, "count"), 10)
            .unwrap();
        let claimed = store
            .claim_outbox(10, 100, Some("marmot"), 1, "delivery", 0, "runtime-a")
            .unwrap();
        let token = claimed[0].claim_token.clone().unwrap();
        let mut counters = watchdog_core::delivery::AuthoritativeCounters::unknown();
        counters.ambiguous_reconciles = Some(3);
        assert!(store
            .finish_owned(
                "alt_count",
                &token,
                DeliveryState::Retrying,
                0,
                20,
                None,
                None,
                None,
                Some("completion_unknown"),
                None,
                None,
                None,
                None,
                None,
                &counters,
                None,
                20,
            )
            .unwrap());
        store
            .lock()
            .unwrap()
            .execute(
                "UPDATE alert_outbox SET state = 'retrying', claim_token = 'again', claim_until = 400 WHERE id = 'alt_count'",
                [],
            )
            .unwrap();
        counters.ambiguous_reconciles = Some(2);
        assert!(store
            .finish_owned(
                "alt_count",
                "again",
                DeliveryState::Retrying,
                0,
                30,
                None,
                None,
                None,
                Some("completion_unknown"),
                None,
                None,
                None,
                None,
                None,
                &counters,
                None,
                30,
            )
            .unwrap());
        let row = store.read_outbox_row("alt_count").unwrap().unwrap();
        assert_eq!(row.auth_ambiguous_reconciles, Some(3));
        assert_eq!(row.message_attempts, 0);
        assert_eq!(row.operation_started_at, Some(10));

        let first = store
            .record_onboarding("smartflowsocial", "op-1", false, 10)
            .unwrap()
            .unwrap();
        assert_eq!(first.idempotency_key, "op-1");
        let second = store
            .record_onboarding("smartflowsocial", "op-2", true, 20)
            .unwrap()
            .unwrap();
        assert_eq!(second.idempotency_key, "op-2");
        let history: i64 = store
            .lock()
            .unwrap()
            .query_row(
                "SELECT COUNT(*) FROM marmot_onboard_history WHERE project_id = 'smartflowsocial'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(history, 2);
        let original: i64 = store
            .lock()
            .unwrap()
            .query_row(
                "SELECT requested_at FROM marmot_onboard_history WHERE operation_id = 'op-1'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(original, 10);
    }

    #[test]
    fn accepted_message_evidence_survives_a_later_incomplete_response() {
        let store = SqliteStore::memory().unwrap();
        store
            .insert_alert(
                &draft("alt_m", Destination::Marmot, "incident:keep:marmot"),
                10,
            )
            .unwrap();
        let claimed = store
            .claim_outbox(10, 100, Some("marmot"), 1, "delivery", 0, "runtime-a")
            .unwrap();
        let token = claimed[0].claim_token.clone().unwrap();
        let projection = r#"{"pushEventId":"push-1","evidence":"relay_acknowledgement","disposition":"reconcile","startedAtMs":10,"updatedAtMs":20}"#;
        assert!(store
            .finish_owned(
                "alt_m",
                &token,
                DeliveryState::Retrying,
                0,
                30,
                None,
                None,
                None,
                Some("relay_accepted"),
                Some("unobservable"),
                Some("event-1"),
                None,
                Some("incident:keep"),
                None,
                &watchdog_core::delivery::AuthoritativeCounters {
                    message_submissions: Some(1),
                    message_publications: None,
                    message_reconciles: None,
                    ambiguous_reconciles: None,
                    token_waits: None,
                    push_publications: None,
                    push_reconciles: Some(1),
                },
                Some(projection),
                20,
            )
            .unwrap());
        let claimed = store
            .claim_outbox(40, 200, Some("marmot"), 1, "push", 0, "runtime-b")
            .unwrap();
        assert_eq!(claimed.len(), 1);
        let token = claimed[0].claim_token.clone().unwrap();
        let later = r#"{"startedAtMs":999,"updatedAtMs":50}"#;
        assert!(store
            .finish_owned(
                "alt_m",
                &token,
                DeliveryState::Retrying,
                0,
                60,
                Some("marmot_timeout"),
                None,
                None,
                Some("not_submitted"),
                Some("not_attempted"),
                None,
                None,
                Some("incident:keep"),
                None,
                &watchdog_core::delivery::AuthoritativeCounters::unknown(),
                Some(later),
                50,
            )
            .unwrap());
        let row = store.read_outbox_row("alt_m").unwrap().unwrap();
        assert_eq!(row.message_state.as_deref(), Some("relay_accepted"));
        assert_eq!(row.message_event_id.as_deref(), Some("event-1"));
        assert_eq!(row.push_event_id.as_deref(), Some("push-1"));
        assert_eq!(row.evidence.as_deref(), Some("relay_acknowledgement"));
        assert_eq!(row.operation_started_at, Some(10));
        assert_eq!(row.transport_updated_at, Some(50));
        assert_eq!(row.auth_message_submissions, Some(1));
        assert_eq!(row.auth_push_reconciles, Some(1));
    }

    #[test]
    fn an_interrupted_migration_does_not_leave_the_new_columns() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE schema_migrations (id TEXT PRIMARY KEY, applied_at INTEGER NOT NULL);",
        )
        .unwrap();
        let (last_id, last_sql) = crate::schema::MIGRATIONS.last().copied().unwrap();
        for (id, sql) in crate::schema::MIGRATIONS
            .iter()
            .filter(|(id, _)| *id != last_id)
        {
            conn.execute_batch(sql).unwrap();
            conn.execute(
                "INSERT INTO schema_migrations (id, applied_at) VALUES (?1, 0)",
                params![id],
            )
            .unwrap();
        }
        let tx = conn.unchecked_transaction().unwrap();
        tx.execute_batch(last_sql).unwrap();
        tx.rollback().unwrap();
        let missing = conn
            .prepare("SELECT push_event_id FROM alert_outbox")
            .is_err();
        assert!(missing);
        let tx = conn.unchecked_transaction().unwrap();
        tx.execute_batch(last_sql).unwrap();
        tx.execute(
            "INSERT INTO schema_migrations (id, applied_at) VALUES (?1, 0)",
            params![last_id],
        )
        .unwrap();
        tx.commit().unwrap();
        assert!(validate_open_schema(&conn).is_ok());
    }
}
