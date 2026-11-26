use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MonitorStatus {
    Healthy,
    Degraded,
    Down,
    Unknown,
    Misconfigured,
}

impl MonitorStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Healthy => "healthy",
            Self::Degraded => "degraded",
            Self::Down => "down",
            Self::Unknown => "unknown",
            Self::Misconfigured => "misconfigured",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        Some(match value {
            "healthy" => Self::Healthy,
            "degraded" => Self::Degraded,
            "down" => Self::Down,
            "unknown" => Self::Unknown,
            "misconfigured" => Self::Misconfigured,
            _ => return None,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Info,
    Warning,
    Critical,
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Warning => "warning",
            Self::Critical => "critical",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        Some(match value {
            "info" => Self::Info,
            "warning" => Self::Warning,
            "critical" => Self::Critical,
            _ => return None,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IncidentKind {
    Outage,
    Degraded,
    Misconfigured,
    Inconclusive,
}

impl IncidentKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Outage => "outage",
            Self::Degraded => "degraded",
            Self::Misconfigured => "misconfigured",
            Self::Inconclusive => "inconclusive",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        Some(match value {
            "outage" => Self::Outage,
            "degraded" => Self::Degraded,
            "misconfigured" => Self::Misconfigured,
            "inconclusive" => Self::Inconclusive,
            _ => return None,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Destination {
    Nostr,
    Telegram,
    Marmot,
}

impl Destination {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Nostr => "nostr",
            Self::Telegram => "telegram",
            Self::Marmot => "marmot",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        Some(match value {
            "nostr" => Self::Nostr,
            "telegram" => Self::Telegram,
            "marmot" => Self::Marmot,
            _ => return None,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AlertClass {
    Outage,
    Recovery,
    Reminder,
    Update,
    Security,
    Integrity,
    Test,
}

impl AlertClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Outage => "outage",
            Self::Recovery => "recovery",
            Self::Reminder => "reminder",
            Self::Update => "update",
            Self::Security => "security",
            Self::Integrity => "integrity",
            Self::Test => "test",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        Some(match value {
            "outage" => Self::Outage,
            "recovery" => Self::Recovery,
            "reminder" => Self::Reminder,
            "update" => Self::Update,
            "security" => Self::Security,
            "integrity" => Self::Integrity,
            "test" => Self::Test,
            _ => return None,
        })
    }
}

/// Publication state of one outbox row.
///
/// `RelayAccepted` means at least one relay accepted the prepared event.
/// It does not mean a phone displayed a notification.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeliveryState {
    Queued,
    RelayAccepted,
    Retrying,
    Failed,
}

impl DeliveryState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::RelayAccepted => "relay_accepted",
            Self::Retrying => "retrying",
            Self::Failed => "failed",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        Some(match value {
            "queued" => Self::Queued,
            "relay_accepted" => Self::RelayAccepted,
            "retrying" => Self::Retrying,
            "failed" => Self::Failed,
            _ => return None,
        })
    }
}

/// Marmot-specific progress, stored beside the shared outbox state.
/// Message publication and push-trigger publication are independent.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MarmotPhase {
    MessagePrepared,
    MessageAccepted,
    PushTokenUnavailable,
    PushTriggerPrepared,
    PushTriggerAccepted,
}

impl MarmotPhase {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MessagePrepared => "message_prepared",
            Self::MessageAccepted => "message_accepted",
            Self::PushTokenUnavailable => "push_token_unavailable",
            Self::PushTriggerPrepared => "push_trigger_prepared",
            Self::PushTriggerAccepted => "push_trigger_accepted",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        Some(match value {
            "message_prepared" => Self::MessagePrepared,
            "message_accepted" => Self::MessageAccepted,
            "push_token_unavailable" => Self::PushTokenUnavailable,
            "push_trigger_prepared" => Self::PushTriggerPrepared,
            "push_trigger_accepted" => Self::PushTriggerAccepted,
            _ => return None,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CheckKind {
    HttpJson,
    SignedHeartbeat,
    AlbyHub,
    Btcpay,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VendorId {
    AlbyHub,
    BtcpayServer,
}

impl VendorId {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AlbyHub => "getAlby/hub",
            Self::BtcpayServer => "btcpayserver/btcpayserver",
        }
    }

    pub fn github(self) -> (&'static str, &'static str) {
        match self {
            Self::AlbyHub => ("getAlby", "hub"),
            Self::BtcpayServer => ("btcpayserver", "btcpayserver"),
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct CheckResult {
    pub status: MonitorStatus,
    pub error_class: Option<String>,
    pub summary: String,
    pub latency_ms: Option<i64>,
    pub observed_version: Option<String>,
}

pub fn check_result(
    status: MonitorStatus,
    error_class: Option<&str>,
    summary: impl Into<String>,
    latency_ms: Option<i64>,
    observed_version: Option<String>,
) -> CheckResult {
    CheckResult {
        status,
        error_class: error_class.map(str::to_string),
        summary: summary.into(),
        latency_ms,
        observed_version,
    }
}

pub fn misconfigured(summary: impl Into<String>, latency_ms: Option<i64>) -> CheckResult {
    check_result(
        MonitorStatus::Misconfigured,
        Some("misconfigured"),
        summary,
        latency_ms,
        None,
    )
}

pub fn unknown_result(
    summary: impl Into<String>,
    error_class: &str,
    latency_ms: Option<i64>,
) -> CheckResult {
    check_result(
        MonitorStatus::Unknown,
        Some(error_class),
        summary,
        latency_ms,
        None,
    )
}

pub fn network_failure(message: &str, name: &str, latency_ms: i64) -> CheckResult {
    let message = message.to_ascii_lowercase();
    let (class, summary) = if name == "AbortError"
        || name == "TimeoutError"
        || message.contains("timeout")
        || message.contains("aborted")
    {
        ("timeout", "The probe timed out.")
    } else if message.contains("cert") || message.contains("tls") || message.contains("ssl") {
        ("tls", "The probe failed TLS validation.")
    } else if message.contains("dns")
        || message.contains("enotfound")
        || message.contains("getaddrinfo")
    {
        ("dns", "The probe could not resolve the host.")
    } else {
        ("network", "The probe could not connect.")
    };
    check_result(
        MonitorStatus::Down,
        Some(class),
        summary,
        Some(latency_ms),
        None,
    )
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OpenIncident {
    pub id: String,
    pub kind: IncidentKind,
    pub severity: Severity,
    pub opened_at: i64,
    pub reminder_count: i64,
    pub last_reminder_at: Option<i64>,
    pub silenced_until: Option<i64>,
    pub acked_at: Option<i64>,
    /// Advances on acknowledgement and silence. A reminder commit must match
    /// the value observed before the probe.
    pub decision_generation: i64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MonitorMemory {
    pub status: MonitorStatus,
    pub consecutive_successes: i64,
    pub consecutive_failures: i64,
    pub failure_kind: Option<MonitorStatus>,
    pub open_incident: Option<OpenIncident>,
    pub integrity_incident: Option<OpenIncident>,
    pub consecutive_unknowns: i64,
    pub unknown_since: Option<i64>,
    pub last_unknown_reason: Option<String>,
    pub observed_version: Option<String>,
}

impl MonitorMemory {
    pub fn empty() -> Self {
        Self {
            status: MonitorStatus::Unknown,
            consecutive_successes: 0,
            consecutive_failures: 0,
            failure_kind: None,
            open_incident: None,
            integrity_incident: None,
            consecutive_unknowns: 0,
            unknown_since: None,
            last_unknown_reason: None,
            observed_version: None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NoticeEvent {
    Open,
    Close,
    Remind,
}

impl NoticeEvent {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Close => "close",
            Self::Remind => "remind",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Notice {
    pub event: NoticeEvent,
    pub incident_id: String,
    pub kind: IncidentKind,
    pub severity: Severity,
    pub reason: String,
    pub occurred_at: i64,
    pub monitor_status: MonitorStatus,
    /// Incident decision generation observed before this notice was computed.
    pub decision_generation: i64,
    /// Reminder count observed before this notice incremented it.
    pub reminder_count: i64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransitionResult {
    pub memory: MonitorMemory,
    pub notice: Option<Notice>,
    pub notices: Vec<Notice>,
    pub changed: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AlertDraft {
    pub id: String,
    pub alert_class: AlertClass,
    pub incident_id: Option<String>,
    pub monitor_id: String,
    pub project_id: String,
    pub dedupe_key: String,
    pub destination: Destination,
    pub severity: Severity,
    pub text: String,
}

#[derive(Clone, Debug)]
pub struct JsonPredicate {
    pub pointer: &'static str,
    pub equals: serde_json::Value,
}

#[derive(Clone, Debug)]
pub struct HttpStatusMap {
    pub pointer: &'static str,
    pub healthy: &'static str,
    pub degraded: Option<&'static str>,
    pub down: Option<&'static str>,
    pub misconfigured: Option<&'static str>,
}

#[derive(Clone, Debug)]
pub struct HttpCheckSpec {
    pub url_var: &'static str,
    pub expected_path: &'static str,
    pub expected_statuses: Vec<u16>,
    pub predicates: Vec<JsonPredicate>,
    pub max_bytes: usize,
    pub bearer_secret: Option<&'static str>,
    pub status_from_body: Option<HttpStatusMap>,
}

#[derive(Clone, Debug)]
pub struct MonitorDefinition {
    pub id: &'static str,
    pub project_id: &'static str,
    pub kind: CheckKind,
    pub display_name: &'static str,
    pub enable_var: &'static str,
    pub interval_seconds: i64,
    pub failure_threshold: i64,
    pub recovery_threshold: i64,
    pub unknown_threshold: i64,
    pub severity: Severity,
    pub incident_on_degraded: bool,
    pub runbook_path: &'static str,
    pub http: Option<HttpCheckSpec>,
    pub version_vendor: Option<VendorId>,
}

#[derive(Clone, Debug)]
pub struct ProjectDefinition {
    pub id: &'static str,
    pub display_name: &'static str,
    pub contact_name: &'static str,
    pub sender_secret: &'static str,
}

pub fn clamp_i64(value: i64, min: i64, max: i64) -> i64 {
    value.clamp(min, max)
}

pub fn backoff_ms(attempt: i64) -> i64 {
    let shift = attempt.saturating_sub(1).clamp(0, 16);
    (30_000_i64).saturating_mul(1_i64 << shift).min(3_600_000)
}

pub fn next_delivery_state(attempt: i64, terminal: bool) -> DeliveryState {
    if terminal || attempt >= 8 {
        DeliveryState::Failed
    } else {
        DeliveryState::Retrying
    }
}
