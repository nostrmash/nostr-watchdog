//! D1 adapter for the shared operational store.
//!
//! Batches are the atomic boundary D1 actually provides. A generation mismatch
//! makes the state update match zero rows, and the incident and outbox
//! statements are conditional on that new generation, so a lost race writes
//! nothing.

use serde_json::Value;
use wasm_bindgen::JsValue;
use watchdog_core::domain::{
    AlertDraft, CheckResult, DeliveryState, IncidentKind, MonitorMemory, MonitorStatus, Notice,
    NoticeEvent, OpenIncident, Severity,
};
use watchdog_core::status::{
    ErrorCount, HeartbeatView, OutboxCount, RunView, StateView, StatusSnapshot, VendorView,
};
use watchdog_store::{
    CommitOutcome, FailedAlert, HeartbeatStored, LoadedMemory, MarmotProjectRow, OperationalStore,
    OutboxRow, StoreError, UpstreamRow, VersionRow,
};
use worker::{D1Database, D1PreparedStatement};

pub struct D1Store<'a> {
    db: &'a D1Database,
}

impl<'a> D1Store<'a> {
    pub fn new(db: &'a D1Database) -> Self {
        Self { db }
    }

    fn prepare(&self, sql: &str, binds: &[JsValue]) -> Result<D1PreparedStatement, StoreError> {
        self.db
            .prepare(sql)
            .bind(binds)
            .map_err(|error| StoreError::Database(error.to_string()))
    }

    async fn run(&self, sql: &str, binds: &[JsValue]) -> Result<usize, StoreError> {
        let result = self
            .prepare(sql, binds)?
            .run()
            .await
            .map_err(|error| StoreError::Database(error.to_string()))?;
        Ok(result
            .meta()
            .ok()
            .flatten()
            .and_then(|meta| meta.changes)
            .unwrap_or(0))
    }

    async fn first(&self, sql: &str, binds: &[JsValue]) -> Result<Option<Value>, StoreError> {
        self.prepare(sql, binds)?
            .first(None)
            .await
            .map_err(|error| StoreError::Database(error.to_string()))
    }

    async fn all(&self, sql: &str, binds: &[JsValue]) -> Result<Vec<Value>, StoreError> {
        let result = self
            .prepare(sql, binds)?
            .all()
            .await
            .map_err(|error| StoreError::Database(error.to_string()))?;
        result
            .results()
            .map_err(|error| StoreError::Database(error.to_string()))
    }
}

fn text(value: &str) -> JsValue {
    JsValue::from_str(value)
}

fn number(value: i64) -> JsValue {
    JsValue::from_f64(value as f64)
}

fn optional_text(value: Option<&str>) -> JsValue {
    value.map(JsValue::from_str).unwrap_or(JsValue::NULL)
}

fn optional_number(value: Option<i64>) -> JsValue {
    value.map(number).unwrap_or(JsValue::NULL)
}

fn as_i64(value: &Value) -> i64 {
    value.as_f64().unwrap_or(0.0) as i64
}

fn as_opt_i64(value: &Value) -> Option<i64> {
    value.as_f64().map(|number| number as i64)
}

fn as_text(value: &Value) -> String {
    value.as_str().unwrap_or_default().to_string()
}

impl OperationalStore for D1Store<'_> {
    async fn load_memory(&self, monitor_id: &str) -> Result<LoadedMemory, StoreError> {
        let Some(row) = self
            .first(
                "SELECT status, consecutive_successes, consecutive_failures, failure_kind, observed_version, generation, consecutive_unknowns, unknown_since, last_unknown_reason FROM monitor_state WHERE monitor_id = ?1",
                &[text(monitor_id)],
            )
            .await?
        else {
            return Ok(LoadedMemory {
                memory: MonitorMemory::empty(),
                generation: 0,
            });
        };
        let mut memory = MonitorMemory::empty();
        memory.status =
            MonitorStatus::parse(&as_text(&row["status"])).ok_or(StoreError::Invalid)?;
        memory.consecutive_successes = as_i64(&row["consecutive_successes"]);
        memory.consecutive_failures = as_i64(&row["consecutive_failures"]);
        memory.failure_kind = row["failure_kind"].as_str().and_then(MonitorStatus::parse);
        memory.observed_version = row["observed_version"].as_str().map(str::to_string);
        memory.consecutive_unknowns = as_i64(&row["consecutive_unknowns"]);
        memory.unknown_since = as_opt_i64(&row["unknown_since"]);
        memory.last_unknown_reason = row["last_unknown_reason"].as_str().map(str::to_string);
        let incidents = self
            .all(
                "SELECT id, kind, severity, opened_at, reminder_count, last_reminder_at, silenced_until, acked_at FROM incidents WHERE monitor_id = ?1 AND status = 'open'",
                &[text(monitor_id)],
            )
            .await?;
        for incident in incidents {
            let open = OpenIncident {
                id: as_text(&incident["id"]),
                kind: IncidentKind::parse(&as_text(&incident["kind"]))
                    .unwrap_or(IncidentKind::Outage),
                severity: Severity::parse(&as_text(&incident["severity"]))
                    .unwrap_or(Severity::Warning),
                opened_at: as_i64(&incident["opened_at"]),
                reminder_count: as_i64(&incident["reminder_count"]),
                last_reminder_at: as_opt_i64(&incident["last_reminder_at"]),
                silenced_until: as_opt_i64(&incident["silenced_until"]),
                acked_at: as_opt_i64(&incident["acked_at"]),
            };
            if open.kind == IncidentKind::Inconclusive {
                memory.integrity_incident = Some(open);
            } else {
                memory.open_incident = Some(open);
            }
        }
        Ok(LoadedMemory {
            memory,
            generation: as_i64(&row["generation"]),
        })
    }

    async fn commit_check(
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
        let next_generation = previous_generation + 1;
        let commit_token = uuid::Uuid::new_v4().to_string();
        let success_at = (check.status == MonitorStatus::Healthy).then_some(now);
        let failure_at = matches!(
            check.status,
            MonitorStatus::Down | MonitorStatus::Degraded | MonitorStatus::Misconfigured
        )
        .then_some(now);
        let state = self.prepare(
            "INSERT INTO monitor_state (
                monitor_id, project_id, status, consecutive_successes, consecutive_failures, failure_kind,
                last_check_at, last_success_at, last_failure_at, last_error_class, last_latency_ms, last_summary,
                observed_version, generation, updated_at, consecutive_unknowns, unknown_since, last_unknown_reason,
                commit_token
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19)
            ON CONFLICT(monitor_id) DO UPDATE SET
                project_id = excluded.project_id, status = excluded.status,
                consecutive_successes = excluded.consecutive_successes,
                consecutive_failures = excluded.consecutive_failures,
                failure_kind = excluded.failure_kind, last_check_at = excluded.last_check_at,
                last_success_at = COALESCE(excluded.last_success_at, monitor_state.last_success_at),
                last_failure_at = COALESCE(excluded.last_failure_at, monitor_state.last_failure_at),
                last_error_class = excluded.last_error_class, last_latency_ms = excluded.last_latency_ms,
                last_summary = excluded.last_summary,
                observed_version = COALESCE(excluded.observed_version, monitor_state.observed_version),
                generation = monitor_state.generation + 1, updated_at = excluded.updated_at,
                consecutive_unknowns = excluded.consecutive_unknowns,
                unknown_since = excluded.unknown_since, last_unknown_reason = excluded.last_unknown_reason,
                commit_token = excluded.commit_token
            WHERE monitor_state.generation = ?20",
            &[
                text(monitor_id),
                text(project_id),
                text(memory.status.as_str()),
                number(memory.consecutive_successes),
                number(memory.consecutive_failures),
                optional_text(memory.failure_kind.map(MonitorStatus::as_str)),
                number(now),
                optional_number(success_at),
                optional_number(failure_at),
                optional_text(check.error_class.as_deref()),
                optional_number(check.latency_ms),
                text(&check.summary),
                optional_text(memory.observed_version.as_deref()),
                number(next_generation),
                number(now),
                number(memory.consecutive_unknowns),
                optional_number(memory.unknown_since),
                optional_text(memory.last_unknown_reason.as_deref()),
                text(&commit_token),
                number(previous_generation),
            ],
        )?;
        let mut statements = vec![state];
        for item in notices {
            let statement = match item.event {
                NoticeEvent::Open => self.prepare(
                    "INSERT INTO incidents (id, monitor_id, project_id, status, kind, severity, opened_at, open_reason, reminder_count, updated_at)
                     SELECT ?1, ?2, ?3, 'open', ?4, ?5, ?6, ?7, 0, ?8 FROM monitor_state
                     WHERE monitor_id = ?2 AND generation = ?9 AND commit_token = ?10 AND NOT EXISTS (
                        SELECT 1 FROM incidents WHERE monitor_id = ?2 AND status = 'open' AND kind = ?4
                     )",
                    &[
                        text(&item.incident_id),
                        text(monitor_id),
                        text(project_id),
                        text(item.kind.as_str()),
                        text(item.severity.as_str()),
                        number(item.occurred_at),
                        text(&item.reason),
                        number(now),
                        number(next_generation),
                        text(&commit_token),
                    ],
                )?,
                NoticeEvent::Close => self.prepare(
                    "UPDATE incidents SET status = 'closed', closed_at = ?1, close_reason = ?2, updated_at = ?1
                     WHERE id = ?3 AND status = 'open' AND EXISTS (
                        SELECT 1 FROM monitor_state WHERE monitor_id = ?4 AND generation = ?5 AND commit_token = ?6
                     )",
                    &[
                        number(now),
                        text(&item.reason),
                        text(&item.incident_id),
                        text(monitor_id),
                        number(next_generation),
                        text(&commit_token),
                    ],
                )?,
                NoticeEvent::Remind => self.prepare(
                    "UPDATE incidents SET reminder_count = reminder_count + 1, last_reminder_at = ?1, updated_at = ?1
                     WHERE id = ?2 AND status = 'open' AND EXISTS (
                        SELECT 1 FROM monitor_state WHERE monitor_id = ?3 AND generation = ?4 AND commit_token = ?5
                     )",
                    &[
                        number(now),
                        text(&item.incident_id),
                        text(monitor_id),
                        number(next_generation),
                        text(&commit_token),
                    ],
                )?,
            };
            statements.push(statement);
        }
        for alert in alerts {
            statements.push(self.prepare(
                "INSERT OR IGNORE INTO alert_outbox (
                    id, alert_class, incident_id, monitor_id, project_id, dedupe_key, destination, severity,
                    state, payload_text, attempt_count, next_attempt_at, created_at, updated_at
                 ) SELECT ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 'queued', ?9, 0, ?10, ?10, ?10
                 FROM monitor_state WHERE monitor_id = ?4 AND generation = ?11 AND commit_token = ?12",
                &[
                    text(&alert.id),
                    text(alert.alert_class.as_str()),
                    optional_text(alert.incident_id.as_deref()),
                    text(&alert.monitor_id),
                    text(&alert.project_id),
                    text(&alert.dedupe_key),
                    text(alert.destination.as_str()),
                    text(alert.severity.as_str()),
                    text(&alert.text),
                    number(now),
                    number(next_generation),
                    text(&commit_token),
                ],
            )?);
        }
        let results = self
            .db
            .batch(statements)
            .await
            .map_err(|error| StoreError::Database(error.to_string()))?;
        let changed = results
            .first()
            .and_then(|result| result.meta().ok().flatten())
            .and_then(|meta| meta.changes)
            .unwrap_or(0);
        Ok(CommitOutcome {
            committed: changed > 0,
        })
    }

    async fn acquire_lease(
        &self,
        name: &str,
        owner: &str,
        until: i64,
        now: i64,
    ) -> Result<bool, StoreError> {
        let changed = self
            .run(
                "INSERT INTO scheduler_leases (job_name, owner, lease_until) VALUES (?1, ?2, ?3)
                 ON CONFLICT(job_name) DO UPDATE SET owner = excluded.owner, lease_until = excluded.lease_until
                 WHERE scheduler_leases.lease_until <= ?4",
                &[text(name), text(owner), number(until), number(now)],
            )
            .await?;
        Ok(changed > 0)
    }

    async fn release_lease(&self, name: &str, owner: &str, now: i64) -> Result<(), StoreError> {
        self.run(
            "UPDATE scheduler_leases SET lease_until = ?1 WHERE job_name = ?2 AND owner = ?3",
            &[number(now), text(name), text(owner)],
        )
        .await?;
        Ok(())
    }

    async fn mark_run(
        &self,
        name: &str,
        started_at: Option<i64>,
        finished_at: Option<i64>,
        error: Option<&str>,
        success_at: Option<i64>,
    ) -> Result<(), StoreError> {
        self.run(
            "INSERT INTO scheduler_runs (job_name, last_started_at, last_finished_at, last_error, last_success_at)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(job_name) DO UPDATE SET
               last_started_at = COALESCE(excluded.last_started_at, scheduler_runs.last_started_at),
               last_finished_at = COALESCE(excluded.last_finished_at, scheduler_runs.last_finished_at),
               last_error = excluded.last_error,
               last_success_at = COALESCE(excluded.last_success_at, scheduler_runs.last_success_at)",
            &[
                text(name),
                optional_number(started_at),
                optional_number(finished_at),
                optional_text(error),
                optional_number(success_at),
            ],
        )
        .await?;
        Ok(())
    }

    async fn last_checks(&self) -> Result<Vec<(String, Option<i64>)>, StoreError> {
        let rows = self
            .all("SELECT monitor_id, last_check_at FROM monitor_state", &[])
            .await?;
        Ok(rows
            .into_iter()
            .map(|row| {
                (
                    as_text(&row["monitor_id"]),
                    as_opt_i64(&row["last_check_at"]),
                )
            })
            .collect())
    }

    async fn read_heartbeat(
        &self,
        monitor_id: &str,
    ) -> Result<Option<HeartbeatStored>, StoreError> {
        let Some(row) = self
            .first(
                "SELECT received_at, progress_token, progress_changed_at, idle, loop_at FROM heartbeats WHERE monitor_id = ?1",
                &[text(monitor_id)],
            )
            .await?
        else {
            return Ok(None);
        };
        Ok(Some(HeartbeatStored {
            received_at: as_i64(&row["received_at"]),
            progress_token: row["progress_token"].as_str().map(str::to_string),
            progress_changed_at: as_i64(&row["progress_changed_at"]),
            idle: as_i64(&row["idle"]) == 1,
            loop_at: as_opt_i64(&row["loop_at"]),
        }))
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
        let statements = vec![
            self.prepare(
                "DELETE FROM heartbeat_nonces WHERE expires_at < ?1",
                &[number(now)],
            )?,
            self.prepare(
                "INSERT INTO heartbeat_nonces (monitor_id, nonce, expires_at) VALUES (?1, ?2, ?3)",
                &[text(monitor_id), text(nonce), number(nonce_expires_at)],
            )?,
            self.prepare(
                "INSERT INTO heartbeats (monitor_id, project_id, received_at, reported_at, progress_token, progress_changed_at, idle, loop_at, summary)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, NULL)
                 ON CONFLICT(monitor_id) DO UPDATE SET received_at = excluded.received_at, reported_at = excluded.reported_at,
                   progress_token = excluded.progress_token,
                   progress_changed_at = CASE
                     WHEN heartbeats.progress_token IS excluded.progress_token THEN heartbeats.progress_changed_at
                     ELSE excluded.received_at
                   END,
                   idle = excluded.idle, loop_at = excluded.loop_at",
                &[
                    text(monitor_id),
                    text(project_id),
                    number(now),
                    number(reported_at),
                    optional_text(progress),
                    number(now),
                    number(i64::from(idle)),
                    optional_number(loop_at),
                ],
            )?,
        ];
        match self.db.batch(statements).await {
            Ok(_) => Ok(true),
            Err(error) => {
                let text = error.to_string();
                if text.to_ascii_lowercase().contains("unique") {
                    Ok(false)
                } else {
                    Err(StoreError::Database(text))
                }
            }
        }
    }

    async fn insert_alert(&self, alert: &AlertDraft, now: i64) -> Result<(), StoreError> {
        self.run(
            "INSERT OR IGNORE INTO alert_outbox (
                id, alert_class, incident_id, monitor_id, project_id, dedupe_key, destination, severity,
                state, payload_text, attempt_count, next_attempt_at, created_at, updated_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 'queued', ?9, 0, ?10, ?10, ?10)",
            &[
                text(&alert.id),
                text(alert.alert_class.as_str()),
                optional_text(alert.incident_id.as_deref()),
                text(&alert.monitor_id),
                text(&alert.project_id),
                text(&alert.dedupe_key),
                text(alert.destination.as_str()),
                text(alert.severity.as_str()),
                text(&alert.text),
                number(now),
            ],
        )
        .await?;
        Ok(())
    }

    async fn insert_alert_if_allowed(
        &self,
        alert: &AlertDraft,
        now: i64,
        prefix: &str,
        since: i64,
        limit: i64,
    ) -> Result<bool, StoreError> {
        let pattern = format!("{prefix}%");
        let changed = self
            .run(
                "INSERT INTO alert_outbox (
                    id, alert_class, incident_id, monitor_id, project_id, dedupe_key, destination, severity,
                    state, payload_text, attempt_count, next_attempt_at, created_at, updated_at
                 )
                 SELECT ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 'queued', ?9, 0, ?10, ?10, ?10
                 WHERE (
                    SELECT COUNT(*) FROM alert_outbox WHERE dedupe_key LIKE ?11 AND created_at >= ?12
                 ) < ?13",
                &[
                    text(&alert.id),
                    text(alert.alert_class.as_str()),
                    optional_text(alert.incident_id.as_deref()),
                    text(&alert.monitor_id),
                    text(&alert.project_id),
                    text(&alert.dedupe_key),
                    text(alert.destination.as_str()),
                    text(alert.severity.as_str()),
                    text(&alert.text),
                    number(now),
                    text(&pattern),
                    number(since),
                    number(limit),
                ],
            )
            .await?;
        Ok(changed > 0)
    }

    async fn count_recent(&self, prefix: &str, since: i64) -> Result<i64, StoreError> {
        let pattern = format!("{prefix}%");
        Ok(self
            .first(
                "SELECT COUNT(*) AS n FROM alert_outbox WHERE dedupe_key LIKE ?1 AND created_at >= ?2",
                &[text(&pattern), number(since)],
            )
            .await?
            .map(|row| as_i64(&row["n"]))
            .unwrap_or(0))
    }

    async fn claim_outbox(
        &self,
        now: i64,
        claim_until: i64,
        destination: Option<&str>,
        limit: i64,
    ) -> Result<Vec<OutboxRow>, StoreError> {
        let ids = self
            .all(
                "SELECT id FROM alert_outbox
                 WHERE state IN ('queued', 'retrying') AND next_attempt_at <= ?1
                   AND (claim_until IS NULL OR claim_until < ?1)
                   AND (?2 IS NULL OR destination = ?2)
                 ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'warning' THEN 1 ELSE 2 END, created_at
                 LIMIT ?3",
                &[
                    number(now),
                    optional_text(destination),
                    number(limit),
                ],
            )
            .await?;
        let mut claimed = Vec::new();
        for id in ids {
            let id = as_text(&id["id"]);
            let token = uuid::Uuid::new_v4().to_string();
            let changed = self
                .run(
                    "UPDATE alert_outbox SET claim_until = ?1, claim_token = ?2, state = 'retrying', updated_at = ?3
                     WHERE id = ?4 AND state IN ('queued', 'retrying') AND (claim_until IS NULL OR claim_until < ?3)",
                    &[number(claim_until), text(&token), number(now), text(&id)],
                )
                .await?;
            if changed > 0 {
                if let Some(mut row) = self.read_outbox(&id).await? {
                    row.claim_token = Some(token);
                    row.claim_until = Some(claim_until);
                    row.state = DeliveryState::Retrying.as_str().to_string();
                    claimed.push(row);
                }
            }
        }
        Ok(claimed)
    }

    async fn extend_claim(
        &self,
        id: &str,
        token: &str,
        claim_until: i64,
        now: i64,
    ) -> Result<bool, StoreError> {
        Ok(self
            .run(
                "UPDATE alert_outbox SET claim_until = ?1
                 WHERE id = ?2 AND claim_token = ?3 AND state = 'retrying'
                   AND claim_until IS NOT NULL AND claim_until >= ?4",
                &[number(claim_until), text(id), text(token), number(now)],
            )
            .await?
            > 0)
    }

    async fn outbox_state(&self, id: &str) -> Result<Option<String>, StoreError> {
        Ok(self
            .first("SELECT state FROM alert_outbox WHERE id = ?1", &[text(id)])
            .await?
            .map(|row| as_text(&row["state"])))
    }

    async fn save_envelope(
        &self,
        id: &str,
        token: &str,
        envelope: &str,
        now: i64,
    ) -> Result<&'static str, StoreError> {
        let changed = self
            .run(
                "UPDATE alert_outbox SET envelope_json = ?1, updated_at = ?2
                 WHERE id = ?3 AND claim_token = ?4 AND envelope_json IS NULL",
                &[text(envelope), number(now), text(id), text(token)],
            )
            .await?;
        if changed > 0 {
            return Ok("saved");
        }
        if self.read_envelope(id).await?.is_some() {
            Ok("exists")
        } else {
            Ok("lost")
        }
    }

    async fn read_envelope(&self, id: &str) -> Result<Option<String>, StoreError> {
        Ok(self
            .first(
                "SELECT envelope_json FROM alert_outbox WHERE id = ?1",
                &[text(id)],
            )
            .await?
            .and_then(|row| row["envelope_json"].as_str().map(str::to_string)))
    }

    async fn finish_delivery(
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
        Ok(self
            .run(
                "UPDATE alert_outbox SET state = ?1, attempt_count = ?2, next_attempt_at = ?3, last_error = ?4,
                    accepted_relays = ?5, failed_relays = ?6, claim_until = NULL, claim_token = NULL,
                    message_phase = COALESCE(?7, message_phase), push_phase = COALESCE(?8, push_phase),
                    message_event_id = COALESCE(?9, message_event_id),
                    push_envelope_json = COALESCE(?10, push_envelope_json), updated_at = ?11
                 WHERE id = ?12 AND claim_token = ?13 AND claim_until IS NOT NULL AND claim_until >= ?11",
                &[
                    text(state.as_str()),
                    number(attempt_count),
                    number(next_attempt_at),
                    optional_text(error),
                    optional_text(accepted_relays),
                    optional_text(failed_relays),
                    optional_text(message_phase),
                    optional_text(push_phase),
                    optional_text(message_event_id),
                    optional_text(push_envelope),
                    number(now),
                    text(id),
                    text(token),
                ],
            )
            .await?
            > 0)
    }

    async fn retry_dead_letter(&self, id: &str, now: i64) -> Result<bool, StoreError> {
        Ok(self
            .run(
                "UPDATE alert_outbox SET state = 'queued', attempt_count = 0, next_attempt_at = ?1,
                    claim_until = NULL, claim_token = NULL, last_error = NULL, updated_at = ?1
                 WHERE id = ?2 AND state = 'failed'",
                &[number(now), text(id)],
            )
            .await?
            > 0)
    }

    async fn ack_incident(&self, id: &str, now: i64) -> Result<bool, StoreError> {
        Ok(self
            .run(
                "UPDATE incidents SET acked_at = ?1, updated_at = ?1 WHERE id = ?2 AND status = 'open'",
                &[number(now), text(id)],
            )
            .await?
            > 0)
    }

    async fn silence_incident(&self, id: &str, until: i64, now: i64) -> Result<bool, StoreError> {
        Ok(self
            .run(
                "UPDATE incidents SET silenced_until = ?1, updated_at = ?2 WHERE id = ?3 AND status = 'open'",
                &[number(until), number(now), text(id)],
            )
            .await?
            > 0)
    }

    async fn open_incident_status(&self, id: &str) -> Result<Option<(String, String)>, StoreError> {
        Ok(self
            .first(
                "SELECT monitor_id, status FROM incidents WHERE id = ?1",
                &[text(id)],
            )
            .await?
            .map(|row| (as_text(&row["monitor_id"]), as_text(&row["status"]))))
    }

    async fn list_failed(&self) -> Result<Vec<FailedAlert>, StoreError> {
        let rows = self
            .all(
                "SELECT id, monitor_id, destination, last_error FROM alert_outbox WHERE state = 'failed' ORDER BY updated_at DESC LIMIT 50",
                &[],
            )
            .await?;
        Ok(rows
            .into_iter()
            .map(|row| FailedAlert {
                id: as_text(&row["id"]),
                monitor_id: as_text(&row["monitor_id"]),
                destination: as_text(&row["destination"]),
                last_error: row["last_error"].as_str().map(str::to_string),
            })
            .collect())
    }

    async fn save_relay_cache(
        &self,
        pubkey: &str,
        relays_json: &str,
        negative: bool,
        fetched_at: i64,
        expires_at: i64,
    ) -> Result<(), StoreError> {
        self.run(
            "INSERT INTO relay_list_cache (pubkey, relays_json, fetched_at, expires_at, negative)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(pubkey) DO UPDATE SET relays_json = excluded.relays_json, fetched_at = excluded.fetched_at,
               expires_at = excluded.expires_at, negative = excluded.negative",
            &[
                text(pubkey),
                text(relays_json),
                number(fetched_at),
                number(expires_at),
                number(i64::from(negative)),
            ],
        )
        .await?;
        Ok(())
    }

    async fn relay_cache(
        &self,
        pubkey: &str,
        now: i64,
    ) -> Result<Option<(String, bool)>, StoreError> {
        Ok(self
            .first(
                "SELECT relays_json, negative FROM relay_list_cache WHERE pubkey = ?1 AND expires_at > ?2",
                &[text(pubkey), number(now)],
            )
            .await?
            .map(|row| (as_text(&row["relays_json"]), as_i64(&row["negative"]) == 1)))
    }

    async fn remembered_inbox(&self, pubkey: &str) -> Result<Vec<String>, StoreError> {
        let Some(row) = self
            .first(
                "SELECT relays_json FROM relay_list_cache WHERE pubkey = ?1 AND negative = 0",
                &[text(pubkey)],
            )
            .await?
        else {
            return Ok(Vec::new());
        };
        Ok(serde_json::from_str(&as_text(&row["relays_json"])).unwrap_or_default())
    }

    async fn prune(&self, now: i64) -> Result<(), StoreError> {
        for (sql, cutoff) in [
            (
                "DELETE FROM alert_outbox WHERE state = 'relay_accepted' AND updated_at < ?1",
                now - 14 * 86_400_000,
            ),
            (
                "DELETE FROM alert_outbox WHERE state = 'failed' AND updated_at < ?1",
                now - 30 * 86_400_000,
            ),
            (
                "DELETE FROM incidents WHERE status = 'closed' AND updated_at < ?1",
                now - 90 * 86_400_000,
            ),
            (
                "DELETE FROM upstream_cache WHERE fetched_at < ?1",
                now - 7 * 86_400_000,
            ),
        ] {
            self.run(sql, &[number(cutoff)]).await?;
        }
        Ok(())
    }

    async fn snapshot(&self) -> Result<StatusSnapshot, StoreError> {
        let states = self
            .all(
                "SELECT monitor_id, status, last_check_at FROM monitor_state",
                &[],
            )
            .await?
            .into_iter()
            .map(|row| StateView {
                monitor_id: as_text(&row["monitor_id"]),
                status: as_text(&row["status"]),
                last_check_at: as_opt_i64(&row["last_check_at"]),
            })
            .collect();
        let heartbeats = self
            .all("SELECT monitor_id, received_at FROM heartbeats", &[])
            .await?
            .into_iter()
            .map(|row| HeartbeatView {
                monitor_id: as_text(&row["monitor_id"]),
                received_at: as_i64(&row["received_at"]),
            })
            .collect();
        let runs = self
            .all(
                "SELECT job_name, last_started_at, last_finished_at, last_success_at, last_error FROM scheduler_runs",
                &[],
            )
            .await?
            .into_iter()
            .map(|row| RunView {
                name: as_text(&row["job_name"]),
                started_at: as_opt_i64(&row["last_started_at"]),
                finished_at: as_opt_i64(&row["last_finished_at"]),
                success_at: as_opt_i64(&row["last_success_at"]),
                error: row["last_error"].as_str().map(str::to_string),
            })
            .collect();
        let outbox_by_monitor = self
            .all(
                "SELECT monitor_id, state, COUNT(*) AS n FROM alert_outbox GROUP BY monitor_id, state",
                &[],
            )
            .await?
            .into_iter()
            .map(|row| OutboxCount {
                monitor_id: as_text(&row["monitor_id"]),
                state: as_text(&row["state"]),
                count: as_i64(&row["n"]),
            })
            .collect();
        let open_incident_monitor_ids = self
            .all(
                "SELECT DISTINCT monitor_id FROM incidents WHERE status = 'open'",
                &[],
            )
            .await?
            .into_iter()
            .map(|row| as_text(&row["monitor_id"]))
            .collect();
        Ok(StatusSnapshot {
            states,
            heartbeats,
            runs,
            vendor_checks: Vec::new(),
            outbox_by_monitor,
            open_incident_monitor_ids,
            errors_by_monitor: Vec::<ErrorCount>::new(),
        })
    }

    async fn upsert_marmot_project(
        &self,
        row: &MarmotProjectRow,
        now: i64,
    ) -> Result<(), StoreError> {
        self.run(
            "INSERT INTO marmot_projects (project_id, pubkey, conversation_id, group_id_hex, peer_pubkey, last_sync_at, last_sync_error, key_package_published_at, engine_status, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
             ON CONFLICT(project_id) DO UPDATE SET pubkey = excluded.pubkey, conversation_id = excluded.conversation_id,
               group_id_hex = excluded.group_id_hex, peer_pubkey = excluded.peer_pubkey, last_sync_at = excluded.last_sync_at,
               last_sync_error = excluded.last_sync_error, key_package_published_at = excluded.key_package_published_at,
               engine_status = excluded.engine_status, updated_at = excluded.updated_at",
            &[
                text(&row.project_id),
                optional_text(row.pubkey.as_deref()),
                optional_text(row.conversation_id.as_deref()),
                optional_text(row.group_id_hex.as_deref()),
                optional_text(row.peer_pubkey.as_deref()),
                optional_number(row.last_sync_at),
                optional_text(row.last_sync_error.as_deref()),
                optional_number(row.key_package_published_at),
                text(&row.engine_status),
                number(now),
            ],
        )
        .await?;
        Ok(())
    }

    async fn marmot_project(
        &self,
        project_id: &str,
    ) -> Result<Option<MarmotProjectRow>, StoreError> {
        Ok(self
            .first(
                "SELECT * FROM marmot_projects WHERE project_id = ?1",
                &[text(project_id)],
            )
            .await?
            .map(|row| MarmotProjectRow {
                project_id: as_text(&row["project_id"]),
                pubkey: row["pubkey"].as_str().map(str::to_string),
                conversation_id: row["conversation_id"].as_str().map(str::to_string),
                group_id_hex: row["group_id_hex"].as_str().map(str::to_string),
                peer_pubkey: row["peer_pubkey"].as_str().map(str::to_string),
                last_sync_at: as_opt_i64(&row["last_sync_at"]),
                last_sync_error: row["last_sync_error"].as_str().map(str::to_string),
                key_package_published_at: as_opt_i64(&row["key_package_published_at"]),
                engine_status: as_text(&row["engine_status"]),
            }))
    }

    async fn installed_version(&self, monitor_id: &str) -> Result<Option<String>, StoreError> {
        Ok(self
            .first(
                "SELECT installed_version FROM observed_versions WHERE monitor_id = ?1",
                &[text(monitor_id)],
            )
            .await?
            .and_then(|row| row["installed_version"].as_str().map(str::to_string)))
    }

    async fn read_version(&self, monitor_id: &str) -> Result<Option<VersionRow>, StoreError> {
        Ok(self
            .first(
                "SELECT * FROM observed_versions WHERE monitor_id = ?1",
                &[text(monitor_id)],
            )
            .await?
            .map(|row| VersionRow {
                installed: row["installed_version"].as_str().map(str::to_string),
                latest: row["latest_version"].as_str().map(str::to_string),
                latest_url: row["latest_url"].as_str().map(str::to_string),
                security_status: as_text(&row["security_status"]),
                advisory_fingerprint: row["advisory_fingerprint"].as_str().map(str::to_string),
                notice_fingerprint: row["notice_fingerprint"].as_str().map(str::to_string),
                security_reminded_at: as_opt_i64(&row["security_reminded_at"]),
            }))
    }

    async fn write_version(
        &self,
        monitor_id: &str,
        row: &VersionRow,
        now: i64,
    ) -> Result<(), StoreError> {
        self.run(
            "INSERT INTO observed_versions (monitor_id, installed_version, latest_version, latest_url, security_status, advisory_fingerprint, notice_fingerprint, updated_at, security_reminded_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
             ON CONFLICT(monitor_id) DO UPDATE SET installed_version = excluded.installed_version, latest_version = excluded.latest_version,
               latest_url = excluded.latest_url, security_status = excluded.security_status, advisory_fingerprint = excluded.advisory_fingerprint,
               notice_fingerprint = excluded.notice_fingerprint, updated_at = excluded.updated_at, security_reminded_at = excluded.security_reminded_at",
            &[
                text(monitor_id),
                optional_text(row.installed.as_deref()),
                optional_text(row.latest.as_deref()),
                optional_text(row.latest_url.as_deref()),
                text(&row.security_status),
                optional_text(row.advisory_fingerprint.as_deref()),
                optional_text(row.notice_fingerprint.as_deref()),
                number(now),
                optional_number(row.security_reminded_at),
            ],
        )
        .await?;
        Ok(())
    }

    async fn read_upstream(&self, key: &str) -> Result<Option<UpstreamRow>, StoreError> {
        Ok(self
            .first(
                "SELECT * FROM upstream_cache WHERE source_key = ?1",
                &[text(key)],
            )
            .await?
            .map(|row| UpstreamRow {
                etag: row["etag"].as_str().map(str::to_string),
                payload_json: row["payload_json"].as_str().map(str::to_string),
                fetched_at: as_i64(&row["fetched_at"]),
                rate_limited_until: as_opt_i64(&row["rate_limited_until"]),
            }))
    }

    async fn write_upstream(&self, key: &str, row: &UpstreamRow) -> Result<(), StoreError> {
        self.run(
            "INSERT INTO upstream_cache (source_key, etag, payload_json, fetched_at, rate_limited_until)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(source_key) DO UPDATE SET etag = excluded.etag, payload_json = excluded.payload_json,
               fetched_at = excluded.fetched_at, rate_limited_until = excluded.rate_limited_until",
            &[
                text(key),
                optional_text(row.etag.as_deref()),
                optional_text(row.payload_json.as_deref()),
                number(row.fetched_at),
                optional_number(row.rate_limited_until),
            ],
        )
        .await?;
        Ok(())
    }

    async fn read_vendor(&self, monitor_id: &str) -> Result<Option<VendorView>, StoreError> {
        Ok(self
            .first(
                "SELECT * FROM vendor_checks WHERE monitor_id = ?1",
                &[text(monitor_id)],
            )
            .await?
            .map(|row| VendorView {
                monitor_id: as_text(&row["monitor_id"]),
                vendor: as_text(&row["vendor"]),
                attempted_at: as_opt_i64(&row["attempted_at"]),
                succeeded_at: as_opt_i64(&row["succeeded_at"]),
                partial_succeeded_at: as_opt_i64(&row["partial_succeeded_at"]),
                releases_checked_at: as_opt_i64(&row["releases_checked_at"]),
                advisories_checked_at: as_opt_i64(&row["advisories_checked_at"]),
                releases_stale: as_i64(&row["releases_stale"]) == 1,
                advisories_stale: as_i64(&row["advisories_stale"]) == 1,
                releases_state: as_text(&row["releases_state"]),
                advisories_state: as_text(&row["advisories_state"]),
                coverage: as_text(&row["coverage"]),
                error_code: row["error_code"].as_str().map(str::to_string),
                consecutive_failures: as_i64(&row["consecutive_failures"]),
                releases_failures: as_i64(&row["releases_failures"]),
                advisories_failures: as_i64(&row["advisories_failures"]),
            }))
    }

    async fn write_vendor(&self, row: &VendorView, now: i64) -> Result<(), StoreError> {
        self.run(
            "INSERT INTO vendor_checks (
                monitor_id, vendor, attempted_at, succeeded_at, partial_succeeded_at, releases_checked_at,
                advisories_checked_at, releases_stale, advisories_stale, releases_state, advisories_state,
                coverage, error_code, consecutive_failures, releases_failures, advisories_failures, updated_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17)
             ON CONFLICT(monitor_id) DO UPDATE SET vendor = excluded.vendor,
               attempted_at = COALESCE(excluded.attempted_at, vendor_checks.attempted_at),
               succeeded_at = COALESCE(excluded.succeeded_at, vendor_checks.succeeded_at),
               partial_succeeded_at = COALESCE(excluded.partial_succeeded_at, vendor_checks.partial_succeeded_at),
               releases_checked_at = COALESCE(excluded.releases_checked_at, vendor_checks.releases_checked_at),
               advisories_checked_at = COALESCE(excluded.advisories_checked_at, vendor_checks.advisories_checked_at),
               releases_stale = excluded.releases_stale, advisories_stale = excluded.advisories_stale,
               releases_state = excluded.releases_state, advisories_state = excluded.advisories_state,
               coverage = excluded.coverage, error_code = excluded.error_code,
               consecutive_failures = excluded.consecutive_failures, releases_failures = excluded.releases_failures,
               advisories_failures = excluded.advisories_failures, updated_at = excluded.updated_at",
            &[
                text(&row.monitor_id),
                text(&row.vendor),
                optional_number(row.attempted_at),
                optional_number(row.succeeded_at),
                optional_number(row.partial_succeeded_at),
                optional_number(row.releases_checked_at),
                optional_number(row.advisories_checked_at),
                number(i64::from(row.releases_stale)),
                number(i64::from(row.advisories_stale)),
                text(&row.releases_state),
                text(&row.advisories_state),
                text(&row.coverage),
                optional_text(row.error_code.as_deref()),
                number(row.consecutive_failures),
                number(row.releases_failures),
                number(row.advisories_failures),
                number(now),
            ],
        )
        .await?;
        Ok(())
    }
}

/// Applies the shared migration list. Ordinary requests only validate the
/// schema. Local setup and tests call this; production uses Wrangler.
#[allow(dead_code)]
pub async fn migrate(db: &D1Database) -> Result<(), StoreError> {
    db.exec("CREATE TABLE IF NOT EXISTS schema_migrations (id TEXT PRIMARY KEY, applied_at INTEGER NOT NULL);")
        .await
        .map_err(|error| StoreError::Database(error.to_string()))?;
    for (id, sql) in watchdog_store::MIGRATIONS {
        let present = db
            .prepare("SELECT id FROM schema_migrations WHERE id = ?1")
            .bind(&[JsValue::from_str(id)])
            .map_err(|error| StoreError::Database(error.to_string()))?
            .first::<Value>(None)
            .await
            .map_err(|error| StoreError::Database(error.to_string()))?
            .is_some();
        if present {
            continue;
        }
        db.exec(sql)
            .await
            .map_err(|error| StoreError::Database(error.to_string()))?;
        db.prepare("INSERT INTO schema_migrations (id, applied_at) VALUES (?1, 0)")
            .bind(&[JsValue::from_str(id)])
            .map_err(|error| StoreError::Database(error.to_string()))?
            .run()
            .await
            .map_err(|error| StoreError::Database(error.to_string()))?;
    }
    Ok(())
}

pub async fn schema_ready(db: &D1Database) -> Result<(), StoreError> {
    let store = D1Store::new(db);
    // Native open writes schema_migrations. Wrangler writes d1_migrations and
    // does not create the native ledger. Either list is accepted. Names in
    // the Wrangler ledger include the `.sql` suffix.
    let applied = match store.all("SELECT id FROM schema_migrations", &[]).await {
        Ok(rows) if !rows.is_empty() => rows
            .into_iter()
            .map(|row| as_text(&row["id"]))
            .collect::<Vec<_>>(),
        _ => {
            let rows = store
                .all("SELECT name FROM d1_migrations", &[])
                .await
                .map_err(|_| StoreError::Database("schema_not_ready".to_string()))?;
            rows.into_iter()
                .map(|row| {
                    as_text(&row["name"])
                        .trim_end_matches(".sql")
                        .to_string()
                })
                .collect::<Vec<_>>()
        }
    };
    let commit_token_column = store
        .first("SELECT commit_token FROM monitor_state LIMIT 1", &[])
        .await
        .is_ok();
    match watchdog_store::schema_status(&applied, commit_token_column) {
        Ok(()) => Ok(()),
        Err(error) => Err(StoreError::Database(error.to_string())),
    }
}

impl D1Store<'_> {
    async fn read_outbox(&self, id: &str) -> Result<Option<OutboxRow>, StoreError> {
        Ok(self
            .first("SELECT * FROM alert_outbox WHERE id = ?1", &[text(id)])
            .await?
            .map(outbox_row))
    }
}

fn outbox_row(row: Value) -> OutboxRow {
    OutboxRow {
        id: as_text(&row["id"]),
        alert_class: as_text(&row["alert_class"]),
        incident_id: row["incident_id"].as_str().map(str::to_string),
        monitor_id: as_text(&row["monitor_id"]),
        project_id: as_text(&row["project_id"]),
        dedupe_key: as_text(&row["dedupe_key"]),
        destination: as_text(&row["destination"]),
        severity: as_text(&row["severity"]),
        state: as_text(&row["state"]),
        payload_text: as_text(&row["payload_text"]),
        attempt_count: as_i64(&row["attempt_count"]),
        next_attempt_at: as_i64(&row["next_attempt_at"]),
        claim_until: as_opt_i64(&row["claim_until"]),
        claim_token: row["claim_token"].as_str().map(str::to_string),
        last_error: row["last_error"].as_str().map(str::to_string),
        envelope_json: row["envelope_json"].as_str().map(str::to_string),
        accepted_relays: row["accepted_relays"].as_str().map(str::to_string),
        failed_relays: row["failed_relays"].as_str().map(str::to_string),
        created_at: as_i64(&row["created_at"]),
        updated_at: as_i64(&row["updated_at"]),
        message_phase: row["message_phase"].as_str().map(str::to_string),
        push_phase: row["push_phase"].as_str().map(str::to_string),
        push_envelope_json: row["push_envelope_json"].as_str().map(str::to_string),
        message_event_id: row["message_event_id"].as_str().map(str::to_string),
    }
}
