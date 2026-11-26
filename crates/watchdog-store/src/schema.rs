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
];

pub const SCHEMA_VERSION: &str = "0008_commit_token";

/// `applied` is the migration ledger. `commit_token_column` is whether
/// `monitor_state.commit_token` can be selected. A ledger row without the
/// column, or a column without the ledger row, is not ready. An id this
/// binary does not know is a newer schema and is refused.
pub fn schema_status(applied: &[String], commit_token_column: bool) -> Result<(), &'static str> {
    if !commit_token_column {
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

#[cfg(test)]
mod tests {
    use super::*;

    fn all() -> Vec<String> {
        MIGRATIONS.iter().map(|(id, _)| (*id).to_string()).collect()
    }

    #[test]
    fn current_ledger_is_ready_and_drift_is_closed() {
        assert_eq!(schema_status(&all(), true), Ok(()));
        assert_eq!(schema_status(&all(), false), Err("schema_not_ready"));
        let mut missing = all();
        missing.pop();
        assert_eq!(schema_status(&missing, true), Err("schema_not_ready"));
        let mut newer = all();
        newer.push("0009_future".to_string());
        assert_eq!(schema_status(&newer, true), Err("schema_unsupported"));
        assert_eq!(SCHEMA_VERSION, MIGRATIONS.last().unwrap().0);
    }
}
