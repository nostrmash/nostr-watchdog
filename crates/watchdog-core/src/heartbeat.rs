use crate::domain::{check_result, CheckResult, MonitorStatus};

/// When two valid heartbeats report the same timestamp, the first committed
/// row wins. The later arrival consumes its nonce and does not change stored
/// progress, idle, or loop time. A strictly older `reported_at` is rejected
/// the same way. A strictly newer `reported_at` replaces the row. Progress
/// change time stays put when the progress token is unchanged and becomes the
/// receive time when the token changes.

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HeartbeatRow {
    pub received_at: i64,
    pub progress_token: Option<String>,
    pub progress_changed_at: i64,
    pub idle: bool,
    pub loop_at: Option<i64>,
}

pub fn evaluate_heartbeat(
    row: Option<&HeartbeatRow>,
    now: i64,
    stale_seconds: i64,
    progress_seconds: i64,
) -> CheckResult {
    let Some(row) = row else {
        return check_result(
            MonitorStatus::Down,
            Some("stale"),
            "No heartbeat has been received.",
            None,
            None,
        );
    };
    if now - row.received_at > stale_seconds.saturating_mul(1000) {
        return check_result(
            MonitorStatus::Down,
            Some("stale"),
            "The heartbeat is stale.",
            None,
            None,
        );
    }
    if let Some(loop_at) = row.loop_at {
        if now - loop_at > stale_seconds.saturating_mul(1000) {
            return check_result(
                MonitorStatus::Down,
                Some("stale"),
                "A heartbeat arrived, but the job loop timestamp is stale.",
                None,
                None,
            );
        }
    }
    if !row.idle && now - row.progress_changed_at > progress_seconds.saturating_mul(1000) {
        return check_result(
            MonitorStatus::Degraded,
            Some("not_progressing"),
            "The process is alive, but reported work has not progressed.",
            None,
            None,
        );
    }
    check_result(
        MonitorStatus::Healthy,
        None,
        if row.idle {
            "The heartbeat is fresh and the loop reported idle."
        } else {
            "The heartbeat is fresh and progress is current."
        },
        None,
        None,
    )
}

#[derive(Clone, Debug, PartialEq)]
pub struct HeartbeatPayload {
    pub progress: Option<String>,
    pub idle: Option<bool>,
    pub loop_at: Option<f64>,
}

pub fn parse_heartbeat(value: &serde_json::Value) -> Result<HeartbeatPayload, ()> {
    let object = value.as_object().ok_or(())?;
    let progress = match object.get("progress") {
        None => None,
        Some(serde_json::Value::String(text))
            if text.len() <= 128
                && text.chars().all(|ch| {
                    ch.is_ascii_alphanumeric() || matches!(ch, '_' | '.' | ':' | '-')
                }) =>
        {
            Some(text.clone())
        }
        Some(_) => return Err(()),
    };
    let idle = match object.get("idle") {
        None => None,
        Some(serde_json::Value::Bool(value)) => Some(*value),
        Some(_) => return Err(()),
    };
    let loop_at = match object.get("loopAt") {
        None => None,
        Some(serde_json::Value::Number(value)) => Some(value.as_f64().ok_or(())?),
        Some(_) => return Err(()),
    };
    Ok(HeartbeatPayload {
        progress,
        idle,
        loop_at,
    })
}
