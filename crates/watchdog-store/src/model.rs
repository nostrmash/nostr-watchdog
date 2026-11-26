//! Persistence values shared by the native SQLite adapter and the Worker D1 adapter.

use thiserror::Error;
use watchdog_core::domain::MonitorMemory;

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("database error: {0}")]
    Database(String),
    #[error("database lock poisoned")]
    Poison,
    #[error("stored value is invalid")]
    Invalid,
}

#[derive(Clone, Debug)]
pub struct LoadedMemory {
    pub memory: MonitorMemory,
    pub generation: i64,
}

#[derive(Clone, Debug)]
pub struct CommitOutcome {
    pub committed: bool,
}

#[derive(Clone, Debug)]
pub struct FailedAlert {
    pub id: String,
    pub monitor_id: String,
    pub destination: String,
    pub last_error: Option<String>,
}

#[derive(Clone, Debug)]
pub struct OutboxRow {
    pub id: String,
    pub alert_class: String,
    pub incident_id: Option<String>,
    pub monitor_id: String,
    pub project_id: String,
    pub dedupe_key: String,
    pub destination: String,
    pub severity: String,
    pub state: String,
    pub payload_text: String,
    pub attempt_count: i64,
    pub next_attempt_at: i64,
    pub claim_until: Option<i64>,
    pub claim_token: Option<String>,
    pub last_error: Option<String>,
    pub envelope_json: Option<String>,
    pub accepted_relays: Option<String>,
    pub failed_relays: Option<String>,
    pub created_at: i64,
    pub updated_at: i64,
    pub message_phase: Option<String>,
    pub push_phase: Option<String>,
    pub push_envelope_json: Option<String>,
    pub message_event_id: Option<String>,
}

#[derive(Clone, Debug)]
pub struct HeartbeatStored {
    pub received_at: i64,
    pub progress_token: Option<String>,
    pub progress_changed_at: i64,
    pub idle: bool,
    pub loop_at: Option<i64>,
}

#[derive(Clone, Debug)]
pub struct VersionRow {
    pub installed: Option<String>,
    pub latest: Option<String>,
    pub latest_url: Option<String>,
    pub security_status: String,
    pub advisory_fingerprint: Option<String>,
    pub notice_fingerprint: Option<String>,
    pub security_reminded_at: Option<i64>,
}

#[derive(Clone, Debug)]
pub struct UpstreamRow {
    pub etag: Option<String>,
    pub payload_json: Option<String>,
    pub fetched_at: i64,
    pub rate_limited_until: Option<i64>,
}

#[derive(Clone, Debug)]
pub struct MarmotProjectRow {
    pub project_id: String,
    pub pubkey: Option<String>,
    pub conversation_id: Option<String>,
    pub group_id_hex: Option<String>,
    pub peer_pubkey: Option<String>,
    pub last_sync_at: Option<i64>,
    pub last_sync_error: Option<String>,
    pub key_package_published_at: Option<i64>,
    pub engine_status: String,
}
