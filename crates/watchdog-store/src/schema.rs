//! One migration list for native SQLite and Cloudflare D1.
//!
//! Runtime code validates this list. It does not apply it. Deployment applies
//! the files under `migrations/` with the Wrangler D1 migrator, or the native
//! process applies them inside a transaction when it opens a database.

pub const MIGRATIONS: &[(&str, &str)] = &[
    (
        "0001_init",
        include_str!("../../../migrations/0001_init.sql"),
    ),
    (
        "0002_hardening",
        include_str!("../../../migrations/0002_hardening.sql"),
    ),
    (
        "0003_vendor_checks",
        include_str!("../../../migrations/0003_vendor_checks.sql"),
    ),
    (
        "0004_vendor_source_state",
        include_str!("../../../migrations/0004_vendor_source_state.sql"),
    ),
    (
        "0005_source_failures",
        include_str!("../../../migrations/0005_source_failures.sql"),
    ),
    (
        "0006_marmot",
        include_str!("../../../migrations/0006_marmot.sql"),
    ),
    (
        "0007_marmot_push_identity",
        include_str!("../../../migrations/0007_marmot_push_identity.sql"),
    ),
    (
        "0008_commit_token",
        include_str!("../../../migrations/0008_commit_token.sql"),
    ),
    (
        "0009_operations",
        include_str!("../../../migrations/0009_operations.sql"),
    ),
    (
        "0010_lifecycle",
        include_str!("../../../migrations/0010_lifecycle.sql"),
    ),
    (
        "0011_delivery_fencing",
        include_str!("../../../migrations/0011_delivery_fencing.sql"),
    ),
];

pub const SCHEMA_VERSION: &str = "0011_delivery_fencing";

/// A row is due for terminal settlement when its immutable start is old enough
/// or a transport-supplied counter has reached its own budget. `updated_at`
/// is not an age. A null counter is not zero.
pub const SETTLEMENT_PREDICATE: &str = "\
state IN ('queued', 'retrying')
 AND settled_at IS NULL
 AND (claim_until IS NULL OR claim_until < ?1)
 AND (
   COALESCE(operation_started_at, created_at) < ?1 - 86400000
   OR (
     COALESCE(message_state, '') = 'completion_unknown'
     AND (
       (auth_ambiguous_reconciles IS NOT NULL AND auth_ambiguous_reconciles >= 4)
       OR COALESCE(operation_started_at, created_at) < ?1 - 900000
     )
   )
   OR (
     COALESCE(message_state, '') IN ('accepted_pending', 'prepared')
     AND (
       (auth_message_reconciles IS NOT NULL AND auth_message_reconciles >= 8)
       OR COALESCE(operation_started_at, created_at) < ?1 - 900000
     )
   )
   OR (
     COALESCE(message_state, '') IN ('relay_accepted', 'accepted')
     AND COALESCE(push_state, '') IN (
       'unknown', '', 'not_attempted', 'token_unavailable', 'unobservable',
       'publication_attempted', 'prepared', 'pending'
     )
     AND (
       (auth_push_publications IS NOT NULL AND auth_push_publications >= 2)
       OR (auth_push_reconciles IS NOT NULL AND auth_push_reconciles >= 2)
       OR (
         COALESCE(push_state, '') = 'token_unavailable'
         AND auth_token_waits IS NOT NULL AND auth_token_waits >= 2
       )
       OR COALESCE(operation_started_at, created_at) < ?1 - 900000
     )
   )
   OR COALESCE(push_state, '') IN ('rejected', 'terminal_failure', 'expired')
 )";

/// Columns the running binary selects. A ledger entry without the column is
/// not ready. A column without its ledger entry is not ready either.
pub const REQUIRED_COLUMNS: &[(&str, &str)] = &[
    ("monitor_state", "commit_token"),
    ("monitor_state", "generation"),
    ("monitor_state", "consecutive_unknowns"),
    ("alert_outbox", "claim_token"),
    ("alert_outbox", "message_state"),
    ("alert_outbox", "push_state"),
    ("alert_outbox", "message_attempts"),
    ("alert_outbox", "push_attempts"),
    ("alert_outbox", "logical_id"),
    ("alert_outbox", "submission_generation"),
    ("alert_outbox", "message_reconcile_attempts"),
    ("alert_outbox", "token_wait_attempts"),
    ("alert_outbox", "push_publication_attempts"),
    ("alert_outbox", "settled_at"),
    ("alert_outbox", "operation_id"),
    ("alert_outbox", "claim_owner"),
    ("alert_outbox", "terminal_reason"),
    ("alert_outbox", "completion_token"),
    ("alert_outbox", "operation_started_at"),
    ("alert_outbox", "message_phase_started_at"),
    ("alert_outbox", "push_phase_started_at"),
    ("alert_outbox", "auth_message_submissions"),
    ("alert_outbox", "auth_message_publications"),
    ("alert_outbox", "auth_message_reconciles"),
    ("alert_outbox", "auth_ambiguous_reconciles"),
    ("alert_outbox", "auth_token_waits"),
    ("alert_outbox", "auth_push_publications"),
    ("alert_outbox", "auth_push_reconciles"),
    ("incidents", "decision_generation"),
    ("incidents", "acked_at"),
    ("scheduler_runs", "run_owner"),
    ("scheduler_runs", "last_success_at"),
    ("observed_versions", "generation"),
    ("observed_versions", "security_reminded_at"),
    ("vendor_checks", "generation"),
    ("vendor_checks", "coverage"),
    ("heartbeats", "reported_at"),
    ("marmot_projects", "onboard_idempotency_key"),
    ("marmot_push_records", "group_id_hex"),
];

pub const REQUIRED_INDEXES: &[&str] = &[
    "incidents_one_open_kind",
    "incidents_project_status",
    "incidents_closed",
    "alert_outbox_due",
    "alert_outbox_state",
    "alert_outbox_logical",
    "alert_outbox_operation",
    "alert_outbox_owner",
    "alert_outbox_completion",
    "heartbeat_nonces_expiry",
    "relay_list_cache_expiry",
    "idx_marmot_push_records_group",
];

pub const REQUIRED_TABLES: &[&str] = &[
    "monitor_state",
    "incidents",
    "alert_outbox",
    "observed_versions",
    "upstream_cache",
    "heartbeats",
    "heartbeat_nonces",
    "relay_list_cache",
    "scheduler_leases",
    "scheduler_runs",
    "vendor_checks",
    "marmot_projects",
    "marmot_push_records",
    "schema_migrations",
    "marmot_onboard_history",
];

/// `applied` is the migration ledger. `missing` names absent tables, columns,
/// or indexes (`table.column` or `index:name`). An id this binary does not
/// know is a newer schema and is refused.
pub fn schema_status(applied: &[String], missing: &[String]) -> Result<(), &'static str> {
    if !missing.is_empty() {
        return Err("schema_not_ready");
    }
    for (id, _) in MIGRATIONS {
        if !applied.iter().any(|row| row == id) {
            return Err("schema_not_ready");
        }
    }
    for id in applied {
        if !MIGRATIONS.iter().any(|(known, _)| known == id) {
            return Err("schema_unsupported");
        }
    }
    Ok(())
}

pub fn column_name(table: &str, column: &str) -> String {
    format!("{table}.{column}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn all() -> Vec<String> {
        MIGRATIONS.iter().map(|(id, _)| (*id).to_string()).collect()
    }

    #[test]
    fn current_ledger_is_ready_and_drift_is_closed() {
        assert_eq!(schema_status(&all(), &[]), Ok(()));
        assert_eq!(
            schema_status(&all(), &["monitor_state.commit_token".to_string()]),
            Err("schema_not_ready")
        );
        let mut missing = all();
        missing.pop();
        assert_eq!(schema_status(&missing, &[]), Err("schema_not_ready"));
        let mut newer = all();
        newer.push("0010_future".to_string());
        assert_eq!(schema_status(&newer, &[]), Err("schema_unsupported"));
        assert_eq!(SCHEMA_VERSION, MIGRATIONS.last().unwrap().0);
        assert!(REQUIRED_TABLES.contains(&"alert_outbox"));
        assert!(REQUIRED_INDEXES.contains(&"alert_outbox_logical"));
        assert!(REQUIRED_COLUMNS
            .iter()
            .any(|(table, column)| *table == "alert_outbox" && *column == "message_state"));
    }
}
