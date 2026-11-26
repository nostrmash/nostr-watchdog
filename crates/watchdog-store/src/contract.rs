//! Domain persistence operations. Adapters implement this for SQLite and D1.
//!
//! Methods are not `Send`. The Worker runtime is single-threaded, and forcing
//! `Send` would reject D1 futures. The native process runs these calls on a
//! current-thread local task.

use watchdog_core::domain::{AlertDraft, CheckResult, DeliveryState, MonitorMemory, Notice};
use watchdog_core::status::{StatusSnapshot, VendorView};

use crate::model::{
    ClaimOwnership, CommitOutcome, FailedAlert, HeartbeatStored, HeartbeatWrite, LoadedMemory,
    MarmotProjectRow, OnboardReceipt, OutboxRow, RetryMode, StoreError, UpstreamRow, VersionRow,
};

pub trait OperationalStore {
    async fn load_memory(&self, monitor_id: &str) -> Result<LoadedMemory, StoreError>;
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
    ) -> Result<CommitOutcome, StoreError>;
    async fn acquire_lease(
        &self,
        name: &str,
        owner: &str,
        until: i64,
        now: i64,
    ) -> Result<bool, StoreError>;
    async fn release_lease(&self, name: &str, owner: &str, now: i64) -> Result<(), StoreError>;
    async fn renew_lease(
        &self,
        name: &str,
        owner: &str,
        until: i64,
        now: i64,
    ) -> Result<bool, StoreError>;
    async fn mark_run(
        &self,
        name: &str,
        owner: &str,
        started_at: Option<i64>,
        finished_at: Option<i64>,
        error: Option<&str>,
        success_at: Option<i64>,
    ) -> Result<(), StoreError>;
    async fn last_checks(&self) -> Result<Vec<(String, Option<i64>)>, StoreError>;
    async fn read_heartbeat(&self, monitor_id: &str)
        -> Result<Option<HeartbeatStored>, StoreError>;
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
    ) -> Result<HeartbeatWrite, StoreError>;
    async fn insert_alert(&self, alert: &AlertDraft, now: i64) -> Result<(), StoreError>;
    async fn insert_alert_if_allowed(
        &self,
        alert: &AlertDraft,
        now: i64,
        prefix: &str,
        since: i64,
        limit: i64,
    ) -> Result<bool, StoreError>;
    async fn count_recent(&self, prefix: &str, since: i64) -> Result<i64, StoreError>;
    async fn claim_outbox(
        &self,
        now: i64,
        claim_until: i64,
        destination: Option<&str>,
        limit: i64,
        kind: &str,
        oldest: i64,
        runtime_id: &str,
    ) -> Result<Vec<OutboxRow>, StoreError>;
    async fn extend_claim(
        &self,
        id: &str,
        token: &str,
        claim_until: i64,
        now: i64,
    ) -> Result<bool, StoreError>;
    async fn claim_ownership(
        &self,
        id: &str,
        token: &str,
        now: i64,
    ) -> Result<ClaimOwnership, StoreError>;
    async fn outbox_state(&self, id: &str) -> Result<Option<String>, StoreError>;
    async fn save_envelope(
        &self,
        id: &str,
        token: &str,
        envelope: &str,
        now: i64,
    ) -> Result<&'static str, StoreError>;
    async fn read_envelope(&self, id: &str) -> Result<Option<String>, StoreError>;
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
    ) -> Result<bool, StoreError>;
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
        now: i64,
    ) -> Result<bool, StoreError>;
    async fn retry_dead_letter(&self, id: &str, now: i64) -> Result<RetryMode, StoreError>;
    async fn ack_incident(&self, id: &str, now: i64) -> Result<bool, StoreError>;
    async fn silence_incident(&self, id: &str, until: i64, now: i64) -> Result<bool, StoreError>;
    async fn open_incident_status(&self, id: &str) -> Result<Option<(String, String)>, StoreError>;
    async fn list_failed(&self) -> Result<Vec<FailedAlert>, StoreError>;
    async fn save_relay_cache(
        &self,
        pubkey: &str,
        relays_json: &str,
        negative: bool,
        fetched_at: i64,
        expires_at: i64,
    ) -> Result<(), StoreError>;
    async fn relay_cache(
        &self,
        pubkey: &str,
        now: i64,
    ) -> Result<Option<(String, bool)>, StoreError>;
    async fn remembered_inbox(&self, pubkey: &str) -> Result<Vec<String>, StoreError>;
    async fn prune(&self, now: i64) -> Result<(), StoreError>;
    async fn snapshot(&self) -> Result<StatusSnapshot, StoreError>;
    async fn upsert_marmot_project(
        &self,
        row: &MarmotProjectRow,
        now: i64,
    ) -> Result<(), StoreError>;
    async fn marmot_project(
        &self,
        project_id: &str,
    ) -> Result<Option<MarmotProjectRow>, StoreError>;
    async fn installed_version(&self, monitor_id: &str) -> Result<Option<String>, StoreError>;
    async fn read_version(&self, monitor_id: &str) -> Result<Option<VersionRow>, StoreError>;
    async fn write_version(
        &self,
        monitor_id: &str,
        row: &VersionRow,
        now: i64,
    ) -> Result<(), StoreError>;
    async fn read_upstream(&self, key: &str) -> Result<Option<UpstreamRow>, StoreError>;
    async fn write_upstream(&self, key: &str, row: &UpstreamRow) -> Result<(), StoreError>;
    async fn read_vendor(&self, monitor_id: &str) -> Result<Option<VendorView>, StoreError>;
    async fn write_vendor(&self, row: &VendorView, now: i64) -> Result<(), StoreError>;
    async fn commit_vendor_cycle(
        &self,
        monitor_id: &str,
        version_generation: Option<i64>,
        version: Option<&VersionRow>,
        vendor_generation: i64,
        vendor: &VendorView,
        alerts: &[AlertDraft],
        now: i64,
    ) -> Result<CommitOutcome, StoreError>;
    async fn read_alert(&self, id: &str) -> Result<Option<OutboxRow>, StoreError>;
    async fn acknowledge_alert(&self, id: &str, now: i64) -> Result<bool, StoreError>;
    async fn release_open_claims(&self, runtime_id: &str, now: i64) -> Result<usize, StoreError>;
    async fn settle_expired(&self, now: i64) -> Result<usize, StoreError>;
    async fn expedite_destination(&self, destination: &str, now: i64) -> Result<usize, StoreError>;
    async fn record_onboarding(
        &self,
        project_id: &str,
        operation_id: &str,
        replace: bool,
        now: i64,
    ) -> Result<Option<OnboardReceipt>, StoreError>;
    async fn count_delivery_pressure(&self, now: i64) -> Result<(i64, i64), StoreError>;
}
