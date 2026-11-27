use serde_json::{json, Value};

use crate::domain::{
    CheckKind, HttpCheckSpec, HttpStatusMap, JsonPredicate, MonitorDefinition, ProjectDefinition,
    Severity, VendorId,
};

const COMMON_INTERVAL: i64 = 60;
const COMMON_FAILURE: i64 = 2;
const COMMON_RECOVERY: i64 = 2;
const COMMON_UNKNOWN: i64 = 5;

pub static PROJECTS: &[ProjectDefinition] = &[
    ProjectDefinition {
        id: "smartflowsocial",
        display_name: "SmartFlowSocial",
        contact_name: "SmartFlowSocial Watchdog",
        sender_secret: "SFS_BOT_NSEC",
    },
    ProjectDefinition {
        id: "nostrmash",
        display_name: "NostrMash",
        contact_name: "NostrMash Watchdog",
        sender_secret: "NOSTRMASH_BOT_NSEC",
    },
];

fn predicate(pointer: &'static str, equals: Value) -> JsonPredicate {
    JsonPredicate { pointer, equals }
}

pub fn monitors() -> Vec<MonitorDefinition> {
    vec![
        http(
            "sfs-web",
            "smartflowsocial",
            "SmartFlowSocial app readiness",
            "ENABLE_SFS_WEB",
            Severity::Critical,
            false,
            "/smartflowsocial/web",
            "SFS_WEB_READY_URL",
            "/healthcheck",
            &[200],
            &[predicate("/status", json!("ok"))],
            16_384,
            None,
            None,
        ),
        heartbeat(
            "sfs-worker",
            "smartflowsocial",
            "SmartFlowSocial worker loop",
            "ENABLE_SFS_WORKER",
            "/smartflowsocial/worker",
        ),
        http(
            "sfs-blossom",
            "smartflowsocial",
            "Blossom gateway readiness",
            "ENABLE_SFS_BLOSSOM",
            Severity::Critical,
            false,
            "/smartflowsocial/blossom",
            "SFS_BLOSSOM_READY_URL",
            "/ready",
            &[200],
            &[predicate("/status", json!("ready"))],
            16_384,
            None,
            None,
        ),
        http(
            "sfs-blastr",
            "smartflowsocial",
            "Blastr readiness",
            "ENABLE_SFS_BLASTR",
            Severity::Warning,
            false,
            "/smartflowsocial/blastr",
            "SFS_BLASTR_READY_URL",
            "/ready",
            &[200],
            &[predicate("/status", json!("ok"))],
            16_384,
            None,
            None,
        ),
        MonitorDefinition {
            id: "sfs-alby-hub",
            project_id: "smartflowsocial",
            kind: CheckKind::AlbyHub,
            display_name: "Alby Hub",
            enable_var: "ENABLE_SFS_ALBY",
            interval_seconds: COMMON_INTERVAL,
            failure_threshold: COMMON_FAILURE,
            recovery_threshold: COMMON_RECOVERY,
            unknown_threshold: COMMON_UNKNOWN,
            severity: Severity::Critical,
            incident_on_degraded: true,
            runbook_path: "/smartflowsocial/alby-hub",
            http: None,
            version_vendor: Some(VendorId::AlbyHub),
        },
        MonitorDefinition {
            id: "sfs-btcpay",
            project_id: "smartflowsocial",
            kind: CheckKind::Btcpay,
            display_name: "BTCPay Server",
            enable_var: "ENABLE_SFS_BTCPAY",
            interval_seconds: COMMON_INTERVAL,
            failure_threshold: COMMON_FAILURE,
            recovery_threshold: COMMON_RECOVERY,
            unknown_threshold: COMMON_UNKNOWN,
            severity: Severity::Critical,
            incident_on_degraded: true,
            runbook_path: "/smartflowsocial/btcpay",
            http: None,
            version_vendor: Some(VendorId::BtcpayServer),
        },
        http(
            "nostrmash-api",
            "nostrmash",
            "NostrMash API readiness",
            "ENABLE_NOSTRMASH_API",
            Severity::Critical,
            false,
            "/nostrmash/api",
            "NOSTRMASH_API_READY_URL",
            "/ready",
            &[200],
            &[predicate("/status", json!("ready"))],
            8_192,
            None,
            None,
        ),
        heartbeat(
            "nostrmash-ingestor",
            "nostrmash",
            "NostrMash ingestor loop",
            "ENABLE_NOSTRMASH_INGESTOR",
            "/nostrmash/ingestor",
        ),
        heartbeat(
            "nostrmash-worker",
            "nostrmash",
            "NostrMash worker loop",
            "ENABLE_NOSTRMASH_WORKER",
            "/nostrmash/worker",
        ),
        http(
            "nostrmash-read-gateway",
            "nostrmash",
            "Nostr read gateway",
            "ENABLE_NOSTRMASH_READ_GATEWAY",
            Severity::Warning,
            false,
            "/nostrmash/read-gateway",
            "NOSTRMASH_READ_GATEWAY_URL",
            "/health",
            &[200],
            &[predicate("/status", json!("ok"))],
            8_192,
            None,
            None,
        ),
        http(
            "nostrmash-publish-gateway",
            "nostrmash",
            "Nostr publish gateway",
            "ENABLE_NOSTRMASH_PUBLISH_GATEWAY",
            Severity::Warning,
            false,
            "/nostrmash/publish-gateway",
            "NOSTRMASH_PUBLISH_GATEWAY_URL",
            "/health",
            &[200],
            &[predicate("/status", json!("ok"))],
            8_192,
            None,
            None,
        ),
        http(
            "nostrmash-read-gateway-deep",
            "nostrmash",
            "Nostr read gateway upstream probe",
            "ENABLE_NOSTRMASH_READ_GATEWAY_DEEP",
            Severity::Warning,
            false,
            "/nostrmash/read-gateway",
            "NOSTRMASH_READ_GATEWAY_DEEP_URL",
            "/health/deep",
            &[200, 503],
            &[],
            8_192,
            Some("READ_GATEWAY_HEALTH_TOKEN"),
            Some(HttpStatusMap {
                pointer: "/status",
                healthy: "ok",
                degraded: None,
                down: Some("down"),
                misconfigured: Some("misconfigured"),
            }),
        ),
        http(
            "nostrmash-publish-gateway-deep",
            "nostrmash",
            "Nostr publish gateway relay probe",
            "ENABLE_NOSTRMASH_PUBLISH_GATEWAY_DEEP",
            Severity::Warning,
            true,
            "/nostrmash/publish-gateway",
            "NOSTRMASH_PUBLISH_GATEWAY_DEEP_URL",
            "/health/deep",
            &[200, 503],
            &[],
            8_192,
            Some("PUBLISH_GATEWAY_HEALTH_TOKEN"),
            Some(HttpStatusMap {
                pointer: "/status",
                healthy: "healthy",
                degraded: Some("degraded"),
                down: Some("down"),
                misconfigured: Some("misconfigured"),
            }),
        ),
    ]
}

fn heartbeat(
    id: &'static str,
    project_id: &'static str,
    display_name: &'static str,
    enable_var: &'static str,
    runbook_path: &'static str,
) -> MonitorDefinition {
    MonitorDefinition {
        id,
        project_id,
        kind: CheckKind::SignedHeartbeat,
        display_name,
        enable_var,
        interval_seconds: COMMON_INTERVAL,
        failure_threshold: COMMON_FAILURE,
        recovery_threshold: COMMON_RECOVERY,
        unknown_threshold: COMMON_UNKNOWN,
        severity: Severity::Critical,
        incident_on_degraded: true,
        runbook_path,
        http: None,
        version_vendor: None,
    }
}

fn http(
    id: &'static str,
    project_id: &'static str,
    display_name: &'static str,
    enable_var: &'static str,
    severity: Severity,
    incident_on_degraded: bool,
    runbook_path: &'static str,
    url_var: &'static str,
    expected_path: &'static str,
    expected_statuses: &[u16],
    predicates: &[JsonPredicate],
    max_bytes: usize,
    bearer_secret: Option<&'static str>,
    status_from_body: Option<HttpStatusMap>,
) -> MonitorDefinition {
    MonitorDefinition {
        id,
        project_id,
        kind: CheckKind::HttpJson,
        display_name,
        enable_var,
        interval_seconds: COMMON_INTERVAL,
        failure_threshold: COMMON_FAILURE,
        recovery_threshold: COMMON_RECOVERY,
        unknown_threshold: COMMON_UNKNOWN,
        severity,
        incident_on_degraded,
        runbook_path,
        http: Some(HttpCheckSpec {
            url_var,
            expected_path,
            expected_statuses: expected_statuses.to_vec(),
            predicates: predicates.to_vec(),
            max_bytes,
            bearer_secret,
            status_from_body,
        }),
        version_vendor: None,
    }
}

pub fn project_by_id(id: &str) -> Option<&'static ProjectDefinition> {
    PROJECTS.iter().find(|project| project.id == id)
}

pub fn monitor_by_id(id: &str) -> Option<MonitorDefinition> {
    monitors().into_iter().find(|monitor| monitor.id == id)
}

pub fn enabled_monitors(get: impl Fn(&str) -> String) -> Vec<MonitorDefinition> {
    monitors()
        .into_iter()
        .filter(|monitor| get(monitor.enable_var) == "true")
        .collect()
}

pub fn project_recipient(raw_map: &str, admin: &str, project_id: &str) -> Option<String> {
    let raw = raw_map.trim();
    if !raw.is_empty() && raw != "{}" {
        let parsed: serde_json::Value = serde_json::from_str(raw).ok()?;
        let value = parsed.get(project_id)?.as_str()?.trim();
        if value.is_empty() {
            return None;
        }
        return Some(value.to_string());
    }
    let admin = admin.trim();
    if admin.is_empty() {
        None
    } else {
        Some(admin.to_string())
    }
}

pub fn telegram_chat(raw: &str, project_id: &str) -> Option<String> {
    if raw.trim().is_empty() {
        return None;
    }
    let parsed: serde_json::Value = serde_json::from_str(raw).ok()?;
    let value = parsed.get(project_id)?.as_str()?;
    if value.chars().all(|ch| ch.is_ascii_digit() || ch == '-')
        && value.chars().any(|ch| ch.is_ascii_digit())
    {
        Some(value.to_string())
    } else {
        None
    }
}

pub fn known_project(id: &str) -> bool {
    project_by_id(id).is_some()
}
