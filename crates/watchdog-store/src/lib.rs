//! Application state for both deployment targets.
//!
//! The schema is the existing D1 migration chain plus additive Marmot
//! metadata. MLS private keys are not stored here. Official MDK storage is a
//! separate database.

mod contract;
mod model;
mod schema;
#[cfg(feature = "sqlite")]
mod sqlite;

pub use contract::OperationalStore;
pub use model::{
    ClaimOwnership, CommitOutcome, FailedAlert, HeartbeatStored, HeartbeatWrite, LoadedMemory,
    MarmotDiagnostics, MarmotProjectRow, OnboardReceipt, OutboxRow, RetryMode, StoreError,
    UpstreamRow, VersionRow,
};
pub use schema::{schema_status, MIGRATIONS, REQUIRED_COLUMNS, REQUIRED_INDEXES, SCHEMA_VERSION};
#[cfg(feature = "sqlite")]
pub use sqlite::SqliteStore;
