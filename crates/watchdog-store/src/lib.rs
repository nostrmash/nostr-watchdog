//! Application state for both deployment targets.
#![allow(clippy::too_many_arguments, clippy::result_unit_err)]
//!
//! The schema is the existing D1 migration chain plus an additive Marmot
//! metadata migration. MLS private keys are not stored here. The official MDK
//! storage backend is separate and, today, native-only.

mod sqlite;

pub use sqlite::{
    CommitOutcome, FailedAlert, HeartbeatStored, LoadedMemory, MarmotProjectRow, OutboxRow,
    SqliteStore, StoreError, UpstreamRow, VersionRow,
};
