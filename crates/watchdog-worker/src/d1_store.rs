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

    pub(crate) async fn complete_onboarding(
        &self,
        project: &str,
        operation: &str,
        account: &str,
        recipient: &str,
        now: i64,
    ) -> Result<bool, StoreError> {
        let updated = self
            .run(
                "UPDATE marmot_projects SET
                    pubkey = ?3, peer_pubkey = ?4, engine_status = 'account_initialized',
                    conversation_id = CASE WHEN pubkey = ?3 AND peer_pubkey = ?4 THEN conversation_id END,
                    group_id_hex = CASE WHEN pubkey = ?3 AND peer_pubkey = ?4 THEN group_id_hex END,
                    updated_at = MAX(updated_at, ?5)
                 WHERE project_id = ?1 AND onboard_idempotency_key = ?2",
                &[text(project), text(operation), text(account), text(recipient), number(now)],
            )
            .await?;
        if updated == 0 {
            return Ok(false);
        }
        self.run(
            "UPDATE marmot_onboard_history SET engine_status = 'account_initialized'
             WHERE project_id = ?1 AND operation_id = ?2",
            &[text(project), text(operation)],
        )
        .await?;
        Ok(true)
    }

    pub(crate) async fn record_marmot_sync(
        &self,
        project: &str,
        sender: &str,
        recipient: &str,
        now: i64,
    ) -> Result<(), StoreError> {
        self.run(
            "UPDATE marmot_projects SET last_sync_at = MAX(COALESCE(last_sync_at, 0), ?4),
               last_sync_error = NULL, updated_at = MAX(updated_at, ?4)
             WHERE project_id = ?1 AND pubkey = ?2 AND peer_pubkey = ?3",
            &[text(project), text(sender), text(recipient), number(now)],
        )
        .await?;
        Ok(())
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

fn finish_statement_error(error: worker::Error) -> Result<bool, StoreError> {
    let message = error.to_string();
    if ["NULL", "constraint", "Constraint", "UNIQUE"]
        .iter()
        .any(|part| message.contains(part))
    {
        return Ok(false);
    }
    Err(StoreError::Database(message))
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
                "SELECT id, kind, severity, opened_at, reminder_count, last_reminder_at, silenced_until, acked_at, decision_generation FROM incidents WHERE monitor_id = ?1 AND status = 'open'",
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
                decision_generation: as_i64(&incident["decision_generation"]),
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
                     WHERE id = ?2 AND status = 'open'
                       AND decision_generation = ?3 AND reminder_count = ?4
                       AND acked_at IS NULL
                       AND (silenced_until IS NULL OR silenced_until <= ?1)
                       AND EXISTS (
                        SELECT 1 FROM monitor_state WHERE monitor_id = ?5 AND generation = ?6 AND commit_token = ?7
                     )",
                    &[
                        number(now),
                        text(&item.incident_id),
                        number(item.decision_generation),
                        number(item.reminder_count),
                        text(monitor_id),
                        number(next_generation),
                        text(&commit_token),
                    ],
                )?,
            };
            statements.push(statement);
        }
        for alert in alerts {
            let remind = notices.iter().find(|notice| {
                notice.event == NoticeEvent::Remind
                    && alert.incident_id.as_deref() == Some(notice.incident_id.as_str())
                    && alert.alert_class == watchdog_core::domain::AlertClass::Reminder
            });
            let (is_reminder, decision, count_after, incident_id) = match remind {
                Some(notice) => (
                    1_i64,
                    notice.decision_generation,
                    notice.reminder_count + 1,
                    notice.incident_id.clone(),
                ),
                None => (0, 0, 0, String::new()),
            };
            statements.push(self.prepare(
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
                    text(watchdog_core::settings::logical_notification_key(&alert.dedupe_key)),
                    number(next_generation),
                    text(&commit_token),
                    number(is_reminder),
                    text(&incident_id),
                    number(decision),
                    number(count_after),
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

    async fn renew_lease(
        &self,
        name: &str,
        owner: &str,
        until: i64,
        now: i64,
    ) -> Result<bool, StoreError> {
        Ok(self
            .run(
                "UPDATE scheduler_leases
                 SET lease_until = CASE WHEN ?1 > lease_until THEN ?1 ELSE lease_until END
                 WHERE job_name = ?2 AND owner = ?3 AND lease_until >= ?4",
                &[number(until), text(name), text(owner), number(now)],
            )
            .await?
            > 0)
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
        self.run(
            "INSERT INTO scheduler_runs (
                job_name, last_started_at, last_finished_at, last_error, last_success_at, run_owner
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT(job_name) DO UPDATE SET
               last_started_at = excluded.last_started_at,
               last_finished_at = excluded.last_finished_at,
               last_error = excluded.last_error,
               last_success_at = CASE
                 WHEN excluded.last_error IS NULL AND excluded.last_success_at IS NOT NULL
                   THEN excluded.last_success_at
                 ELSE scheduler_runs.last_success_at END,
               run_owner = excluded.run_owner
             WHERE scheduler_runs.last_started_at IS NULL
                OR excluded.last_started_at > scheduler_runs.last_started_at
                OR (
                  excluded.last_started_at = scheduler_runs.last_started_at
                  AND excluded.run_owner = scheduler_runs.run_owner
                  AND COALESCE(excluded.last_finished_at, 0) >= COALESCE(scheduler_runs.last_finished_at, 0)
                )",
            &[
                text(name),
                optional_number(started_at),
                optional_number(finished_at),
                optional_text(error),
                optional_number(success_at),
                text(owner),
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
    ) -> Result<watchdog_store::HeartbeatWrite, StoreError> {
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
                   idle = excluded.idle, loop_at = excluded.loop_at
                 WHERE excluded.reported_at > heartbeats.reported_at",
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
            Ok(results) => {
                let changed = results
                    .get(2)
                    .and_then(|result| result.meta().ok().flatten())
                    .and_then(|meta| meta.changes)
                    .unwrap_or(0);
                Ok(if changed == 0 {
                    watchdog_store::HeartbeatWrite::Stale
                } else {
                    watchdog_store::HeartbeatWrite::Stored
                })
            }
            Err(error) => {
                let text = error.to_string();
                if text.to_ascii_lowercase().contains("unique") {
                    Ok(watchdog_store::HeartbeatWrite::Replay)
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
        kind: &str,
        oldest: i64,
        runtime_id: &str,
    ) -> Result<Vec<OutboxRow>, StoreError> {
        let ids = self
            .all(
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
                          AND (transport_disposition = 'reconcile' OR (transport_disposition IS NULL AND COALESCE(push_state, 'unknown') IN ('unknown', 'pending', 'unobservable', 'not_attempted', 'token_unavailable', 'prepared', 'publication_attempted', '')))
                        )
                        AND (?3 != 'delivery-critical' OR severity = 'critical')
                        AND (?3 != 'delivery-other' OR severity != 'critical'))
                     OR (?3 = 'push'
                        AND destination = 'marmot'
                        AND COALESCE(message_state, '') IN ('relay_accepted', 'accepted', 'accepted_pending')
                        AND (transport_disposition = 'reconcile' OR (transport_disposition IS NULL AND COALESCE(push_state, 'unknown') IN ('unknown', 'pending', 'unobservable', 'not_attempted', 'token_unavailable', 'prepared', 'publication_attempted', '')))
                        AND COALESCE(operation_started_at, created_at) >= ?4)
                   )
                 ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'warning' THEN 1 ELSE 2 END, created_at
                 LIMIT ?5",
                &[
                    number(now),
                    optional_text(destination),
                    text(kind),
                    number(oldest),
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
                    "UPDATE alert_outbox SET claim_until = ?1, claim_token = ?2, claim_owner = ?3, state = 'retrying', updated_at = ?4
                     WHERE id = ?5 AND state IN ('queued', 'retrying') AND settled_at IS NULL
                       AND (claim_until IS NULL OR claim_until < ?4)",
                    &[
                        number(claim_until),
                        text(&token),
                        text(runtime_id),
                        number(now),
                        text(&id),
                    ],
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
                   AND claim_until IS NOT NULL AND claim_until >= ?4
                   AND ?1 > ?4 AND ?1 <= ?4 + 300000",
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
                 WHERE id = ?3 AND claim_token = ?4 AND envelope_json IS NULL
                   AND claim_until IS NOT NULL AND claim_until >= ?2",
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
                    accepted_relays = ?5, failed_relays = ?6, claim_until = NULL, claim_token = NULL, claim_owner = NULL,
                    message_phase = CASE
                      WHEN ?7 IS NULL THEN message_phase
                      WHEN COALESCE(message_state, message_phase, '') IN ('relay_accepted', 'accepted', 'message_accepted', 'published')
                        AND ?7 NOT IN ('relay_accepted', 'accepted', 'message_accepted', 'published') THEN message_phase
                      ELSE ?7 END,
                    push_phase = CASE
                      WHEN ?8 IS NULL THEN push_phase
                      WHEN COALESCE(push_state, '') = 'relay_accepted'
                        AND ?8 IN ('not_attempted', 'unknown', 'not_submitted', 'prepared') THEN push_phase
                      ELSE ?8 END,
                    message_event_id = COALESCE(message_event_id, ?9),
                    push_envelope_json = COALESCE(?10, push_envelope_json), updated_at = ?11
                 WHERE id = ?12 AND claim_token = ?13 AND claim_until IS NOT NULL AND claim_until >= ?11
                   AND (?9 IS NULL OR message_event_id IS NULL OR message_event_id = ?9)",
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

    async fn retry_dead_letter(
        &self,
        id: &str,
        now: i64,
    ) -> Result<watchdog_store::RetryMode, StoreError> {
        let existing = self
            .first(
                "SELECT destination, envelope_json, message_state FROM alert_outbox WHERE id = ?1 AND state = 'failed'",
                &[text(id)],
            )
            .await?;
        let Some(row) = existing else {
            return Ok(watchdog_store::RetryMode::Missing);
        };
        let destination = as_text(&row["destination"]);
        let envelope = row["envelope_json"].as_str().is_some();
        let mode = match destination.as_str() {
            "marmot" => watchdog_store::RetryMode::Reconcile,
            "telegram" => watchdog_store::RetryMode::SameOperation,
            "nostr" if envelope => watchdog_store::RetryMode::SameOperation,
            "nostr" => watchdog_store::RetryMode::NewSubmission,
            _ if envelope => watchdog_store::RetryMode::SameOperation,
            _ => watchdog_store::RetryMode::NewSubmission,
        };
        self.run(
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
            &[number(now), text(id)],
        )
        .await?;
        Ok(mode)
    }

    async fn ack_incident(&self, id: &str, now: i64) -> Result<bool, StoreError> {
        Ok(self
            .run(
                "UPDATE incidents SET acked_at = ?1, updated_at = ?1, decision_generation = decision_generation + 1 WHERE id = ?2 AND status = 'open' AND acked_at IS NULL",
                &[number(now), text(id)],
            )
            .await?
            > 0)
    }

    async fn silence_incident(&self, id: &str, until: i64, now: i64) -> Result<bool, StoreError> {
        Ok(self
            .run(
                "UPDATE incidents SET silenced_until = ?1, updated_at = ?2, decision_generation = decision_generation + 1 WHERE id = ?3 AND status = 'open' AND (silenced_until IS NULL OR silenced_until < ?1)",
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
                generation: as_i64(&row["generation"]),
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
                generation: as_i64(&row["generation"]),
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

    async fn claim_ownership(
        &self,
        id: &str,
        token: &str,
        now: i64,
    ) -> Result<watchdog_store::ClaimOwnership, StoreError> {
        let Some(row) = self
            .first(
                "SELECT claim_token, claim_until FROM alert_outbox WHERE id = ?1",
                &[text(id)],
            )
            .await?
        else {
            return Ok(watchdog_store::ClaimOwnership::Missing);
        };
        match (row["claim_token"].as_str(), as_opt_i64(&row["claim_until"])) {
            (Some(stored), Some(until)) if stored == token && until >= now => {
                Ok(watchdog_store::ClaimOwnership::Active { until })
            }
            (Some(stored), _) if stored == token => Ok(watchdog_store::ClaimOwnership::Expired),
            _ => Ok(watchdog_store::ClaimOwnership::Lost),
        }
    }

    async fn finish_with_fallback(
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
        let require_fallback = i64::from(fallback.is_some());
        let fallback_logical = fallback
            .as_ref()
            .map(|alert| {
                watchdog_core::settings::logical_notification_key(&alert.dedupe_key).to_string()
            })
            .unwrap_or_default();
        let update = self.prepare(
            "UPDATE alert_outbox
             SET state = ?1, attempt_count = ?2, next_attempt_at = ?3, last_error = ?4,
                 accepted_relays = ?5, failed_relays = ?6, claim_until = NULL, claim_token = NULL,
                 message_phase = CASE
                   WHEN ?7 IS NULL THEN message_phase
                   WHEN COALESCE(message_state, message_phase, '') IN ('relay_accepted', 'accepted', 'message_accepted', 'published')
                     AND ?7 NOT IN ('relay_accepted', 'accepted', 'message_accepted', 'published') THEN message_phase
                   ELSE ?7 END,
                 push_phase = CASE
                   WHEN ?8 IS NULL THEN push_phase
                   WHEN COALESCE(push_state, '') = 'relay_accepted'
                     AND ?8 IN ('not_attempted', 'unknown', 'not_submitted', 'prepared') THEN push_phase
                   ELSE ?8 END,
                 message_event_id = COALESCE(message_event_id, ?9),
                 push_envelope_json = COALESCE(?10, push_envelope_json), updated_at = ?11,
                 logical_id = COALESCE(logical_id, ?12),
                 message_state = CASE
                   WHEN ?7 IS NULL THEN message_state
                   WHEN COALESCE(message_state, message_phase, '') IN ('relay_accepted', 'message_accepted', 'accepted', 'published')
                     OR ?7 IN ('relay_accepted', 'message_accepted', 'accepted', 'published') THEN 'relay_accepted'
                   WHEN ?7 = 'accepted_pending' THEN 'accepted_pending'
                   WHEN ?7 = 'completion_unknown' THEN 'completion_unknown'
                   WHEN ?7 IN ('message_prepared', 'prepared') THEN 'prepared'
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
                 operation_started_at = COALESCE(operation_started_at, json_extract(?25, '$.startedAtMs'), created_at),
                 started_at_ms = COALESCE(started_at_ms, created_at),
                 push_event_id = COALESCE(push_event_id, json_extract(?25, '$.pushEventId')),
                 evidence = COALESCE(json_extract(?25, '$.evidence'), evidence),
                 transport_disposition = COALESCE(json_extract(?25, '$.disposition'), transport_disposition),
                 transport_updated_at = CASE
                   WHEN transport_updated_at IS NULL THEN json_extract(?25, '$.updatedAtMs')
                   ELSE MAX(transport_updated_at, COALESCE(json_extract(?25, '$.updatedAtMs'), 0)) END,
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
             WHERE id = ?13 AND claim_token = ?14 AND claim_until IS NOT NULL AND claim_until >= ?11
               AND (?9 IS NULL OR message_event_id IS NULL OR message_event_id = ?9)
               AND (?23 = 0 OR EXISTS (
                 SELECT 1 FROM alert_outbox AS fallback_row
                 WHERE fallback_row.destination = 'telegram' AND fallback_row.logical_id = ?24
               ))",
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
                optional_text(logical_id),
                text(id),
                text(token),
                text(&completion),
                optional_number(counters.message_submissions),
                optional_number(counters.message_publications),
                optional_number(counters.message_reconciles),
                optional_number(counters.ambiguous_reconciles),
                optional_number(counters.token_waits),
                optional_number(counters.push_publications),
                optional_number(counters.push_reconciles),
                number(require_fallback),
                text(&fallback_logical),
                optional_text(projection),
            ],
        )?;
        if let Some(alert) = fallback {
            let logical =
                watchdog_core::settings::logical_notification_key(&alert.dedupe_key).to_string();
            let insert = self.prepare(
                "INSERT INTO alert_outbox (
                    id, alert_class, incident_id, monitor_id, project_id, dedupe_key, destination, severity,
                    state, payload_text, attempt_count, next_attempt_at, created_at, updated_at, logical_id
                 )
                 SELECT ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 'queued', ?9, 0, ?10, ?10, ?10, ?11
                 FROM alert_outbox AS live
                 WHERE live.id = ?12 AND live.claim_token = ?13
                   AND live.claim_until IS NOT NULL AND live.claim_until >= ?10
                   AND (?14 IS NULL OR live.message_event_id IS NULL OR live.message_event_id = ?14)
                   AND NOT EXISTS (
                     SELECT 1 FROM alert_outbox AS existing
                     WHERE existing.destination = 'telegram' AND existing.logical_id = ?11
                   )",
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
                    text(&logical),
                    text(id),
                    text(token),
                    optional_text(message_event_id),
                ],
            )?;
            // Durable fallback first. A later fenced update can safely resume
            // against the same logical Telegram row after interruption.
            if let Err(error) = insert.run().await {
                return finish_statement_error(error);
            }
        }
        if let Err(error) = update.run().await {
            return finish_statement_error(error);
        }
        let won = self
            .first(
                "SELECT 1 AS n FROM alert_outbox WHERE id = ?1 AND completion_token = ?2",
                &[text(id), text(&completion)],
            )
            .await?
            .is_some();
        Ok(won)
    }

    async fn commit_vendor_cycle(
        &self,
        monitor_id: &str,
        version_generation: Option<i64>,
        version: Option<&VersionRow>,
        vendor_generation: i64,
        vendor: &VendorView,
        alerts: &[AlertDraft],
        now: i64,
    ) -> Result<CommitOutcome, StoreError> {
        let token = uuid::Uuid::new_v4().to_string();
        let mut statements = Vec::new();
        let version_next = version_generation.map(|generation| generation + 1);
        if let (Some(generation), Some(version)) = (version_generation, version) {
            statements.push(self.prepare(
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
                &[
                    text(monitor_id),
                    optional_text(version.installed.as_deref()),
                    optional_text(version.latest.as_deref()),
                    optional_text(version.latest_url.as_deref()),
                    text(&version.security_status),
                    optional_text(version.advisory_fingerprint.as_deref()),
                    optional_text(version.notice_fingerprint.as_deref()),
                    number(now),
                    optional_number(version.security_reminded_at),
                    number(generation + 1),
                    text(&token),
                    number(generation),
                ],
            )?);
        }
        let vendor_index = statements.len();
        statements.push(self.prepare(
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
                 WHERE vendor_checks.generation = ?20
                   AND (?21 = 0 OR EXISTS (
                     SELECT 1 FROM observed_versions
                     WHERE monitor_id = ?1 AND generation = ?22 AND commit_token = ?19
                   ))",
                &[
                    text(&vendor.monitor_id),
                    text(&vendor.vendor),
                    optional_number(vendor.attempted_at),
                    optional_number(vendor.succeeded_at),
                    optional_number(vendor.partial_succeeded_at),
                    optional_number(vendor.releases_checked_at),
                    optional_number(vendor.advisories_checked_at),
                    number(i64::from(vendor.releases_stale)),
                    number(i64::from(vendor.advisories_stale)),
                    text(&vendor.releases_state),
                    text(&vendor.advisories_state),
                    text(&vendor.coverage),
                    optional_text(vendor.error_code.as_deref()),
                    number(vendor.consecutive_failures),
                    number(vendor.releases_failures),
                    number(vendor.advisories_failures),
                    number(now),
                    number(vendor_generation + 1),
                    text(&token),
                    number(vendor_generation),
                    number(i64::from(version_next.is_some())),
                    number(version_next.unwrap_or(0)),
                ],
            )?);
        if version_next.is_some() {
            statements.push(self.prepare(
                "INSERT INTO alert_outbox (
                    id, alert_class, monitor_id, project_id, dedupe_key, destination, severity,
                    state, payload_text, attempt_count, next_attempt_at, created_at, updated_at
                 )
                 SELECT NULL, 'fence', ?1, 'fence', 'fence-' || ?2, 'telegram', 'info',
                        'queued', '', 0, 0, 0, 0
                 WHERE EXISTS (
                   SELECT 1 FROM observed_versions
                   WHERE monitor_id = ?1 AND commit_token = ?2 AND generation = ?3
                 )
                 AND NOT EXISTS (
                   SELECT 1 FROM vendor_checks
                   WHERE monitor_id = ?1 AND commit_token = ?2 AND generation = ?4
                 )",
                &[
                    text(monitor_id),
                    text(&token),
                    number(version_next.unwrap_or(0)),
                    number(vendor_generation + 1),
                ],
            )?);
        }
        for alert in alerts {
            statements.push(self.prepare(
                "INSERT OR IGNORE INTO alert_outbox (
                    id, alert_class, incident_id, monitor_id, project_id, dedupe_key, destination, severity,
                    state, payload_text, attempt_count, next_attempt_at, created_at, updated_at, logical_id
                 )
                 SELECT ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 'queued', ?9, 0, ?10, ?10, ?10, ?11
                 FROM vendor_checks WHERE monitor_id = ?4 AND generation = ?12 AND commit_token = ?13",
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
                    text(watchdog_core::settings::logical_notification_key(&alert.dedupe_key)),
                    number(vendor_generation + 1),
                    text(&token),
                ],
            )?);
        }
        let results = match self.db.batch(statements).await {
            Ok(results) => results,
            Err(error) => {
                let message = error.to_string();
                if message.to_ascii_lowercase().contains("not null")
                    || message.to_ascii_lowercase().contains("constraint")
                {
                    return Ok(CommitOutcome { committed: false });
                }
                return Err(StoreError::Database(message));
            }
        };
        let changed = results
            .get(vendor_index)
            .and_then(|result| result.meta().ok().flatten())
            .and_then(|meta| meta.changes)
            .unwrap_or(0);
        Ok(CommitOutcome {
            committed: changed > 0,
        })
    }

    async fn read_alert(&self, id: &str) -> Result<Option<OutboxRow>, StoreError> {
        self.read_outbox(id).await
    }

    async fn acknowledge_alert(&self, id: &str, now: i64) -> Result<bool, StoreError> {
        Ok(self
            .run(
                "UPDATE alert_outbox SET operator_ack_at = ?1, updated_at = ?1 WHERE id = ?2 AND operator_ack_at IS NULL",
                &[number(now), text(id)],
            )
            .await?
            > 0)
    }

    async fn release_open_claims(&self, runtime_id: &str, now: i64) -> Result<usize, StoreError> {
        if runtime_id.is_empty() {
            return Ok(0);
        }
        self.run(
            "UPDATE alert_outbox SET claim_until = NULL, claim_token = NULL, claim_owner = NULL, state = 'retrying', updated_at = ?1
             WHERE state = 'retrying' AND claim_owner = ?2",
            &[number(now), text(runtime_id)],
        )
        .await
    }

    async fn settle_expired(&self, now: i64) -> Result<usize, StoreError> {
        let ids = self.settlement_ids(now).await?;
        let mut settled = 0;
        for id in ids {
            if self.settle_one(&id, now, None).await? {
                settled += 1;
            }
        }
        Ok(settled)
    }

    async fn settlement_ids(&self, now: i64) -> Result<Vec<String>, StoreError> {
        let sql = format!(
            "SELECT id FROM alert_outbox WHERE {} ORDER BY created_at LIMIT 16",
            watchdog_store::SETTLEMENT_PREDICATE
        );
        let rows = self.all(&sql, &[number(now)]).await?;
        Ok(rows
            .into_iter()
            .map(|row| as_text(&row["id"]))
            .filter(|id| !id.is_empty())
            .collect())
    }

    async fn settle_one(
        &self,
        id: &str,
        now: i64,
        fallback: Option<&AlertDraft>,
    ) -> Result<bool, StoreError> {
        let completion = uuid::Uuid::new_v4().to_string();
        let predicate = watchdog_store::SETTLEMENT_PREDICATE;
        let mut statements = Vec::new();
        let fallback_logical = fallback
            .as_ref()
            .map(|alert| {
                watchdog_core::settings::logical_notification_key(&alert.dedupe_key).to_string()
            })
            .unwrap_or_default();
        if let Some(alert) = fallback {
            let live_predicate = predicate.replace("?1", "?13");
            statements.push(self.prepare(
                &format!(
                    "INSERT INTO alert_outbox (
                        id, alert_class, incident_id, monitor_id, project_id, dedupe_key, destination, severity,
                        state, payload_text, attempt_count, next_attempt_at, created_at, updated_at, logical_id
                     )
                     SELECT ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 'queued', ?9, 0, ?10, ?10, ?10, ?11
                     FROM alert_outbox AS live
                     WHERE live.id = ?12 AND {live_predicate}
                       AND NOT EXISTS (
                         SELECT 1 FROM alert_outbox AS existing
                         WHERE existing.destination = 'telegram' AND existing.logical_id = ?11
                       )"
                ),
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
                    text(&fallback_logical),
                    text(id),
                    number(now),
                ],
            )?);
        }
        let fallback_gate = if fallback.is_some() {
            " AND EXISTS (
                SELECT 1 FROM alert_outbox AS fallback_row
                WHERE fallback_row.destination = 'telegram' AND fallback_row.logical_id = ?4
              )"
        } else {
            ""
        };
        let update_sql = format!(
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
             WHERE id = ?2 AND {predicate}{fallback_gate}"
        );
        let mut binds = vec![number(now), text(id), text(&completion)];
        if fallback.is_some() {
            binds.push(text(&fallback_logical));
        }
        statements.push(self.prepare(&update_sql, &binds)?);
        if let Err(error) = self.db.batch(statements).await {
            let message = error.to_string();
            if message.contains("NULL")
                || message.contains("constraint")
                || message.contains("Constraint")
                || message.contains("UNIQUE")
            {
                return Ok(false);
            }
            return Err(StoreError::Database(message));
        }
        let won = self
            .first(
                "SELECT 1 AS n FROM alert_outbox WHERE id = ?1 AND completion_token = ?2",
                &[text(id), text(&completion)],
            )
            .await?
            .is_some();
        Ok(won)
    }

    async fn expedite_destination(&self, destination: &str, now: i64) -> Result<usize, StoreError> {
        self.run(
            "UPDATE alert_outbox SET next_attempt_at = ?1, updated_at = ?1
             WHERE destination = ?2 AND state IN ('queued', 'retrying')
               AND (claim_until IS NULL OR claim_until < ?1) AND next_attempt_at > ?1",
            &[number(now), text(destination)],
        )
        .await
    }

    async fn record_onboarding(
        &self,
        project_id: &str,
        operation_id: &str,
        replace: bool,
        now: i64,
    ) -> Result<Option<watchdog_store::OnboardReceipt>, StoreError> {
        self.run(
            "INSERT INTO marmot_projects (
                project_id, engine_status, updated_at, onboard_idempotency_key, onboard_requested_at
             ) VALUES (?1, 'onboard_requested', ?2, ?3, ?2)
             ON CONFLICT(project_id) DO UPDATE SET
               onboard_idempotency_key = excluded.onboard_idempotency_key,
               onboard_requested_at = excluded.onboard_requested_at,
               engine_status = CASE
                 WHEN marmot_projects.onboard_idempotency_key = excluded.onboard_idempotency_key
                 THEN marmot_projects.engine_status ELSE 'onboard_requested' END,
               updated_at = excluded.updated_at
             WHERE marmot_projects.onboard_idempotency_key IS NULL
                OR marmot_projects.onboard_idempotency_key = excluded.onboard_idempotency_key
                OR ?4 = 1",
            &[
                text(project_id),
                number(now),
                text(operation_id),
                number(i64::from(replace)),
            ],
        )
        .await?;
        self.run(
            "INSERT OR IGNORE INTO marmot_onboard_history (
                project_id, operation_id, replace_requested, requested_at, engine_status
             ) VALUES (?1, ?2, ?3, ?4, 'onboard_requested')",
            &[
                text(project_id),
                text(operation_id),
                number(i64::from(replace)),
                number(now),
            ],
        )
        .await?;
        Ok(self
            .first(
                "SELECT engine_status, onboard_idempotency_key FROM marmot_projects WHERE project_id = ?1",
                &[text(project_id)],
            )
            .await?
            .map(|row| watchdog_store::OnboardReceipt {
                engine_status: as_text(&row["engine_status"]),
                idempotency_key: row["onboard_idempotency_key"]
                    .as_str()
                    .unwrap_or("")
                    .to_string(),
            }))
    }

    async fn count_delivery_pressure(&self, now: i64) -> Result<(i64, i64), StoreError> {
        let pending = self
            .first(
                "SELECT COUNT(*) AS n FROM alert_outbox WHERE state = 'retrying' AND next_attempt_at <= ?1",
                &[number(now)],
            )
            .await?
            .map(|row| as_i64(&row["n"]))
            .unwrap_or(0);
        let recent = self
            .first(
                "SELECT COUNT(*) AS n FROM alert_outbox WHERE state = 'retrying' AND updated_at >= ?1",
                &[number(now - 86_400_000)],
            )
            .await?
            .map(|row| as_i64(&row["n"]))
            .unwrap_or(0);
        Ok((pending, recent))
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
                .map(|row| as_text(&row["name"]).trim_end_matches(".sql").to_string())
                .collect::<Vec<_>>()
        }
    };
    let commit_token_column = store
        .first("SELECT commit_token FROM monitor_state LIMIT 1", &[])
        .await
        .is_ok();
    let mut missing = Vec::new();
    for (table, column) in watchdog_store::REQUIRED_COLUMNS {
        if store
            .first(&format!("SELECT {column} AS c FROM {table} LIMIT 1"), &[])
            .await
            .is_err()
        {
            missing.push(format!("{table}.{column}"));
        }
    }
    for index in watchdog_store::REQUIRED_INDEXES {
        let present = store
            .first(
                "SELECT 1 AS n FROM sqlite_master WHERE type = 'index' AND name = ?1",
                &[text(index)],
            )
            .await
            .ok()
            .flatten()
            .is_some();
        if !present {
            missing.push(format!("index:{index}"));
        }
    }
    let _ = commit_token_column;
    match watchdog_store::schema_status(&applied, &missing) {
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

pub async fn probe_completion_fence(store: &D1Store<'_>, now: i64) -> Result<Value, StoreError> {
    store
        .run("DELETE FROM alert_outbox WHERE id LIKE 'alt_fence%'", &[])
        .await?;
    let source = fence_alert("alt_fence_src", "fence:src:marmot", "marmot");
    let winner_fallback = fence_alert("alt_fence_win", "fence:win:telegram", "telegram");
    let loser_fallback = fence_alert("alt_fence_lose", "fence:lose:telegram", "telegram");
    OperationalStore::insert_alert(store, &source, now).await?;
    store
        .run(
            "UPDATE alert_outbox
             SET state = 'retrying', claim_token = 'fence-winner', claim_owner = 'worker',
                 claim_until = ?1
             WHERE id = 'alt_fence_src'",
            &[number(now + 60_000)],
        )
        .await?;
    let unknown = watchdog_core::delivery::AuthoritativeCounters::unknown();
    let winner = OperationalStore::finish_with_fallback(
        store,
        "alt_fence_src",
        "fence-winner",
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
        Some("fence:src"),
        Some(&winner_fallback),
        &unknown,
        None,
        now,
    )
    .await?;
    let loser = OperationalStore::finish_with_fallback(
        store,
        "alt_fence_src",
        "fence-loser",
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
        Some("fence:src"),
        Some(&loser_fallback),
        &unknown,
        None,
        now,
    )
    .await?;
    let telegram = store
        .first(
            "SELECT COUNT(*) AS n FROM alert_outbox WHERE id LIKE 'alt_fence%' AND destination = 'telegram'",
            &[],
        )
        .await?
        .map(|row| as_i64(&row["n"]))
        .unwrap_or(0);

    let blocked = fence_alert("alt_fence_block", "fence:block:marmot", "marmot");
    let taken = fence_alert("alt_fence_taken", "fence:block:fallback:telegram", "nostr");
    let blocked_fallback = fence_alert(
        "alt_fence_blocked_tg",
        "fence:block:fallback:telegram",
        "telegram",
    );
    OperationalStore::insert_alert(store, &blocked, now).await?;
    OperationalStore::insert_alert(store, &taken, now).await?;
    store
        .run(
            "UPDATE alert_outbox
             SET state = 'retrying', claim_token = 'fence-block', claim_owner = 'worker',
                 claim_until = ?1
             WHERE id = 'alt_fence_block'",
            &[number(now + 60_000)],
        )
        .await?;
    let rolled_back = !OperationalStore::finish_with_fallback(
        store,
        "alt_fence_block",
        "fence-block",
        DeliveryState::Failed,
        1,
        now,
        Some("rejected"),
        None,
        None,
        Some("rejected"),
        None,
        None,
        None,
        Some("fence:block"),
        Some(&blocked_fallback),
        &unknown,
        None,
        now,
    )
    .await?;
    let preserved = store
        .first(
            "SELECT claim_token, state FROM alert_outbox WHERE id = 'alt_fence_block'",
            &[],
        )
        .await?;
    let rollback_preserved = preserved.as_ref().is_some_and(|row| {
        row["claim_token"].as_str() == Some("fence-block")
            && row["state"].as_str() == Some("retrying")
    });

    let interrupted = fence_alert("alt_fence_retry", "fence:retry:marmot", "marmot");
    let retry_fallback = fence_alert(
        "alt_fence_retry_tg",
        "fence:retry:fallback:telegram",
        "telegram",
    );
    OperationalStore::insert_alert(store, &interrupted, now).await?;
    store
        .run(
            "UPDATE alert_outbox SET state = 'retrying', claim_token = 'fence-retry',
         claim_until = ?1, message_state = 'relay_accepted', message_phase = 'relay_accepted',
         message_event_id = 'accepted-event' WHERE id = 'alt_fence_retry'",
            &[number(now + 60_000)],
        )
        .await?;
    store.run(
        "CREATE TRIGGER fixture_abort_completion BEFORE UPDATE OF completion_token ON alert_outbox
         WHEN NEW.id = 'alt_fence_retry'
         BEGIN SELECT RAISE(ABORT, 'fixture completion constraint'); END",
        &[],
    ).await?;
    let complete_retry = || {
        OperationalStore::finish_with_fallback(
            store,
            "alt_fence_retry",
            "fence-retry",
            DeliveryState::Retrying,
            0,
            now + 15_000,
            Some("marmot_timeout"),
            None,
            None,
            Some("accepted_pending"),
            Some("unobservable"),
            Some("accepted-event"),
            None,
            Some("fence:retry"),
            Some(&retry_fallback),
            &unknown,
            None,
            now,
        )
    };
    let update_interrupted = complete_retry().await;
    store
        .run("DROP TRIGGER fixture_abort_completion", &[])
        .await?;
    let update_interrupted = !update_interrupted?;
    let fallback_persisted = store.read_alert(&retry_fallback.id).await?.is_some();
    let retry_won = complete_retry().await?;
    let retry_row = store.read_alert("alt_fence_retry").await?;
    let retry_preserved = retry_row.is_some_and(|row| {
        row.message_state.as_deref() == Some("relay_accepted")
            && row.message_event_id.as_deref() == Some("accepted-event")
            && row.claim_token.is_none()
    });
    let retry_fallback_count = store
        .first(
            "SELECT COUNT(*) AS n FROM alert_outbox WHERE destination = 'telegram'
         AND logical_id = 'fence:retry:fallback'",
            &[],
        )
        .await?
        .map(|row| as_i64(&row["n"]))
        .unwrap_or(0);

    let aged = fence_alert("alt_fence_age", "fence:age:marmot", "marmot");
    let aged_fallback = fence_alert(
        "alt_fence_age_tg",
        "fence:age:fallback:telegram",
        "telegram",
    );
    let aged_again = fence_alert(
        "alt_fence_age_tg2",
        "fence:age:fallback:telegram",
        "telegram",
    );
    OperationalStore::insert_alert(store, &aged, now).await?;
    store
        .run(
            "UPDATE alert_outbox
             SET created_at = ?1, state = 'retrying', claim_token = NULL, claim_until = NULL,
                 claim_owner = NULL, message_state = 'completion_unknown'
             WHERE id = 'alt_fence_age'",
            &[number(now - 86_400_001)],
        )
        .await?;
    let settled =
        OperationalStore::settle_one(store, "alt_fence_age", now, Some(&aged_fallback)).await?;
    let settled_again =
        OperationalStore::settle_one(store, "alt_fence_age", now, Some(&aged_again)).await?;
    let settlement_telegram = store
        .first(
            "SELECT COUNT(*) AS n FROM alert_outbox
             WHERE destination = 'telegram' AND logical_id = 'fence:age:fallback'",
            &[],
        )
        .await?
        .map(|row| as_i64(&row["n"]))
        .unwrap_or(0);
    let settled_row = store
        .first(
            "SELECT state, settled_at, claim_token FROM alert_outbox WHERE id = 'alt_fence_age'",
            &[],
        )
        .await?;
    let settlement_preserved = settled_row.as_ref().is_some_and(|row| {
        row["state"].as_str() == Some("failed")
            && row["settled_at"].as_f64().is_some()
            && row["claim_token"].is_null()
    });

    let stuck = fence_alert("alt_fence_stuck", "fence:stuck:marmot", "marmot");
    let occupied = fence_alert(
        "alt_fence_occupied",
        "fence:stuck:fallback:telegram",
        "nostr",
    );
    let stuck_fallback = fence_alert(
        "alt_fence_stuck_tg",
        "fence:stuck:fallback:telegram",
        "telegram",
    );
    OperationalStore::insert_alert(store, &stuck, now).await?;
    OperationalStore::insert_alert(store, &occupied, now).await?;
    store
        .run(
            "UPDATE alert_outbox
             SET created_at = ?1, state = 'retrying', claim_token = NULL, claim_until = NULL,
                 claim_owner = NULL
             WHERE id = 'alt_fence_stuck'",
            &[number(now - 86_400_001)],
        )
        .await?;
    let settlement_blocked =
        !OperationalStore::settle_one(store, "alt_fence_stuck", now, Some(&stuck_fallback)).await?;
    let stuck_row = store
        .first(
            "SELECT state, settled_at FROM alert_outbox WHERE id = 'alt_fence_stuck'",
            &[],
        )
        .await?;
    let settlement_blocked_preserved = stuck_row.as_ref().is_some_and(|row| {
        row["state"].as_str() == Some("retrying") && row["settled_at"].is_null()
    });

    Ok(serde_json::json!({
        "winner": winner,
        "loser": loser,
        "telegramRows": telegram,
        "rolledBack": rolled_back,
        "rollbackPreserved": rollback_preserved,
        "updateInterrupted": update_interrupted,
        "fallbackPersisted": fallback_persisted,
        "retryWon": retry_won,
        "retryPreserved": retry_preserved,
        "retryFallbackCount": retry_fallback_count,
        "settled": settled,
        "settledAgain": settled_again,
        "settlementTelegram": settlement_telegram,
        "settlementPreserved": settlement_preserved,
        "settlementBlocked": settlement_blocked,
        "settlementBlockedPreserved": settlement_blocked_preserved,
    }))
}

fn fence_alert(id: &str, dedupe: &str, destination: &str) -> AlertDraft {
    AlertDraft {
        id: id.to_string(),
        alert_class: watchdog_core::domain::AlertClass::Outage,
        incident_id: None,
        monitor_id: "sfs-web".to_string(),
        project_id: "smartflowsocial".to_string(),
        dedupe_key: dedupe.to_string(),
        destination: watchdog_core::domain::Destination::parse(destination)
            .unwrap_or(watchdog_core::domain::Destination::Marmot),
        severity: watchdog_core::domain::Severity::Critical,
        text: "fence".to_string(),
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
        message_state: row["message_state"].as_str().map(str::to_string),
        push_state: row["push_state"].as_str().map(str::to_string),
        message_attempts: as_i64(&row["message_attempts"]),
        push_attempts: as_i64(&row["push_attempts"]),
        message_updated_at: as_opt_i64(&row["message_updated_at"]),
        push_updated_at: as_opt_i64(&row["push_updated_at"]),
        terminal_reason: row["terminal_reason"].as_str().map(str::to_string),
        operator_ack_at: as_opt_i64(&row["operator_ack_at"]),
        logical_id: row["logical_id"].as_str().map(str::to_string),
        submission_generation: as_i64(&row["submission_generation"]),
        message_reconcile_attempts: as_i64(&row["message_reconcile_attempts"]),
        unknown_attempts: as_i64(&row["unknown_attempts"]),
        token_wait_attempts: as_i64(&row["token_wait_attempts"]),
        push_publication_attempts: as_i64(&row["push_publication_attempts"]),
        unobservable_attempts: as_i64(&row["unobservable_attempts"]),
        started_at_ms: as_opt_i64(&row["started_at_ms"]),
        preserve_message: as_i64(&row["preserve_message"]) == 1,
        settled_at: as_opt_i64(&row["settled_at"]),
        operation_id: row["operation_id"].as_str().map(str::to_string),
        claim_owner: row["claim_owner"].as_str().map(str::to_string),
        operation_started_at: as_opt_i64(&row["operation_started_at"]),
        message_phase_started_at: as_opt_i64(&row["message_phase_started_at"]),
        push_phase_started_at: as_opt_i64(&row["push_phase_started_at"]),
        auth_message_submissions: as_opt_i64(&row["auth_message_submissions"]),
        auth_message_publications: as_opt_i64(&row["auth_message_publications"]),
        auth_message_reconciles: as_opt_i64(&row["auth_message_reconciles"]),
        auth_ambiguous_reconciles: as_opt_i64(&row["auth_ambiguous_reconciles"]),
        auth_token_waits: as_opt_i64(&row["auth_token_waits"]),
        auth_push_publications: as_opt_i64(&row["auth_push_publications"]),
        auth_push_reconciles: as_opt_i64(&row["auth_push_reconciles"]),
        push_event_id: row["push_event_id"].as_str().map(str::to_string),
        evidence: row["evidence"].as_str().map(str::to_string),
        transport_disposition: row["transport_disposition"].as_str().map(str::to_string),
        transport_updated_at: as_opt_i64(&row["transport_updated_at"]),
    }
}
