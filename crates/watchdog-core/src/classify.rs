use serde_json::Value;

use crate::domain::{check_result, CheckResult, MonitorStatus};
use crate::redact::safe_version;

const KNOWN_ALARMS: &[&str] = &[
    "alby_service",
    "node_not_ready",
    "channels_offline",
    "nostr_relay_offline",
    "vss_no_subscription",
];

#[derive(Clone, Debug)]
pub struct AlbyInfo {
    pub version: String,
    pub running: bool,
    pub unlocked: bool,
    pub startup_error: bool,
}

pub fn classify_alby(
    info: &AlbyInfo,
    alarms: &[String],
    node_ready: bool,
    latency_ms: i64,
) -> CheckResult {
    let version = safe_version(Some(&info.version));
    for alarm in alarms {
        if !KNOWN_ALARMS.contains(&alarm.as_str()) {
            return check_result(
                MonitorStatus::Unknown,
                Some("schema"),
                "The Alby Hub returned an unrecognized health alarm.",
                Some(latency_ms),
                version,
            );
        }
    }
    let base = |status, class: Option<&str>, summary: &str| {
        check_result(status, class, summary, Some(latency_ms), version.clone())
    };
    if !info.running {
        return base(
            MonitorStatus::Degraded,
            Some("node_not_ready"),
            "The Alby Hub API is up and the node is not running.",
        );
    }
    if !info.unlocked {
        return base(
            MonitorStatus::Degraded,
            Some("locked"),
            "The Alby Hub API is up and the hub is locked, so the Lightning node is not usable.",
        );
    }
    if alarms.iter().any(|alarm| alarm == "node_not_ready") || !node_ready {
        return base(
            MonitorStatus::Degraded,
            Some("node_not_ready"),
            "The Alby Hub is up and the Lightning node is not ready.",
        );
    }
    if alarms.iter().any(|alarm| alarm == "alby_service") {
        return base(
            MonitorStatus::Degraded,
            Some("health_alarm"),
            "The Alby Hub reported an Alby service alarm.",
        );
    }
    if alarms.iter().any(|alarm| alarm == "channels_offline") {
        return base(
            MonitorStatus::Degraded,
            Some("channels_offline"),
            "The Alby Hub reported offline channels.",
        );
    }
    if alarms.iter().any(|alarm| alarm == "nostr_relay_offline") {
        return base(
            MonitorStatus::Degraded,
            Some("relay_offline"),
            "The Alby Hub reported an offline Nostr relay.",
        );
    }
    if alarms.iter().any(|alarm| alarm == "vss_no_subscription") {
        return base(
            MonitorStatus::Degraded,
            Some("subscription"),
            "The Alby Hub reported that VSS has no subscription.",
        );
    }
    if info.startup_error {
        return base(
            MonitorStatus::Degraded,
            Some("startup"),
            "The Alby Hub recorded a startup error.",
        );
    }
    base(
        MonitorStatus::Healthy,
        None,
        "The Alby Hub info, health, and node status checks passed.",
    )
}

pub fn parse_alby_info(value: &Value) -> Option<AlbyInfo> {
    let object = value.as_object()?;
    Some(AlbyInfo {
        version: object.get("version")?.as_str()?.to_string(),
        running: object.get("running")?.as_bool()?,
        unlocked: object.get("unlocked")?.as_bool()?,
        startup_error: object.get("startupError")?.as_bool()?,
    })
}

pub fn parse_alarms(value: &Value) -> Result<Vec<String>, ()> {
    let alarms = value.get("alarms").ok_or(())?.as_array().ok_or(())?;
    let mut out = Vec::new();
    for alarm in alarms {
        out.push(alarm.as_str().ok_or(())?.to_string());
    }
    Ok(out)
}

pub fn parse_node_ready(value: &Value) -> Result<bool, ()> {
    value.get("node_ready").and_then(Value::as_bool).ok_or(())
}

#[derive(Clone, Debug)]
pub struct BtcpayInfo {
    pub version: Option<String>,
    pub fully_synched: Option<bool>,
    pub processor_unavailable: bool,
}

pub fn classify_btcpay(synchronized: bool, info: &BtcpayInfo, latency_ms: i64) -> CheckResult {
    let unsynced = !synchronized || info.fully_synched == Some(false);
    if info.processor_unavailable {
        return check_result(
            MonitorStatus::Degraded,
            Some("processor_unavailable"),
            if unsynced {
                "BTCPay is up, a payment processor is unavailable, and chain sync is incomplete."
            } else {
                "BTCPay is up and a payment processor is unavailable."
            },
            Some(latency_ms),
            info.version.clone(),
        );
    }
    if unsynced {
        return check_result(
            MonitorStatus::Degraded,
            Some("unsynchronized"),
            "BTCPay is up but not synchronized.",
            Some(latency_ms),
            info.version.clone(),
        );
    }
    check_result(
        MonitorStatus::Healthy,
        None,
        "BTCPay health and server info checks passed.",
        Some(latency_ms),
        info.version.clone(),
    )
}

pub fn parse_synchronized(value: &Value) -> Result<bool, ()> {
    value.get("synchronized").and_then(Value::as_bool).ok_or(())
}

pub fn parse_server_info(value: &Value) -> Option<BtcpayInfo> {
    let body = value.as_object()?;
    let version = body.get("version")?.as_str()?;
    if body
        .get("fullySynched")
        .is_some_and(|item| !item.is_boolean())
    {
        return None;
    }
    if body.get("syncStatus").is_some_and(|item| !item.is_array()) {
        return None;
    }
    let mut processor_unavailable = false;
    if let Some(entries) = body.get("syncStatus").and_then(Value::as_array) {
        for entry in entries {
            let entry = entry.as_object()?;
            match entry.get("available") {
                Some(Value::Bool(false)) => processor_unavailable = true,
                Some(Value::Bool(true)) | None => {}
                Some(_) => return None,
            }
        }
    }
    Some(BtcpayInfo {
        version: safe_version(Some(version)),
        fully_synched: body.get("fullySynched").and_then(Value::as_bool),
        processor_unavailable,
    })
}
