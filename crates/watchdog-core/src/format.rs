use chrono::{DateTime, SecondsFormat, Utc};

use crate::domain::{IncidentKind, NoticeEvent, Severity};
use crate::redact::{safe_version, sanitize_text};

pub struct IncidentMessage<'a> {
    pub project_name: &'a str,
    pub display_name: &'a str,
    pub severity: Severity,
    pub kind: IncidentKind,
    pub event: NoticeEvent,
    pub state: &'a str,
    pub incident_id: &'a str,
    pub occurred_at: i64,
    pub reason: &'a str,
    pub observed_version: Option<&'a str>,
    pub runbook_url: Option<&'a str>,
}

pub fn format_unix_ms(ms: i64) -> String {
    DateTime::<Utc>::from_timestamp_millis(ms)
        .map(|time| time.to_rfc3339_opts(SecondsFormat::Millis, true))
        .unwrap_or_else(|| "invalid-time".to_string())
}

pub fn format_incident_message(input: IncidentMessage<'_>) -> String {
    let label = match input.event {
        NoticeEvent::Close => "recovery",
        NoticeEvent::Remind => "reminder",
        NoticeEvent::Open => input.kind.as_str(),
    };
    let mut lines = vec![
        format!(
            "[{}] {} {label}",
            input.project_name,
            input.severity.as_str().to_ascii_uppercase()
        ),
        format!("Service: {}", input.display_name),
        format!("State: {}", input.state),
        format!("Incident: {}", input.incident_id),
        format!("Time: {}", format_unix_ms(input.occurred_at)),
        format!("Reason: {}", sanitize_text(input.reason, 180)),
    ];
    if let Some(version) = safe_version(input.observed_version) {
        lines.push(format!("Observed version: {version}"));
    }
    if let Some(url) = input.runbook_url {
        lines.push(format!("Runbook: {url}"));
    }
    lines.push(
        "Relay acceptance does not confirm that a person or phone received this message."
            .to_string(),
    );
    lines.join("\n")
}

pub fn format_version_message(
    project_name: &str,
    display_name: &str,
    installed: &str,
    latest: &str,
    url: &str,
    occurred_at: i64,
) -> String {
    [
        format!("[{project_name}] INFO update_available"),
        format!("Service: {display_name}"),
        "State: update_available".to_string(),
        format!("Time: {}", format_unix_ms(occurred_at)),
        format!("Installed version: {installed}"),
        format!("Latest version: {latest}"),
        format!("Reference: {url}"),
        "No upgrade was performed.".to_string(),
    ]
    .join("\n")
}

pub fn format_security_message(
    project_name: &str,
    display_name: &str,
    severity: Severity,
    installed: Option<&str>,
    summary: &str,
    url: Option<&str>,
    occurred_at: i64,
    classification: Option<&str>,
) -> String {
    let state = classification.unwrap_or(if severity == Severity::Critical {
        "affected"
    } else {
        "review_recommended"
    });
    let mut lines = vec![
        format!(
            "[{project_name}] {} security_update",
            severity.as_str().to_ascii_uppercase()
        ),
        format!("Service: {display_name}"),
        format!("State: {state}"),
        format!("Time: {}", format_unix_ms(occurred_at)),
        format!("Reason: {}", sanitize_text(summary, 300)),
    ];
    if let Some(version) = safe_version(installed) {
        lines.push(format!("Installed version: {version}"));
    }
    if let Some(url) = url {
        lines.push(format!("Reference: {url}"));
    }
    lines.push(
        "No upgrade was performed. This is not a claim about unrelated vulnerabilities."
            .to_string(),
    );
    lines.join("\n")
}

pub fn format_test_message(project_name: &str, occurred_at: i64) -> String {
    [
        format!("[{project_name}] INFO test"),
        "State: test".to_string(),
        format!("Time: {}", format_unix_ms(occurred_at)),
        "Reason: Operator requested a test alert.".to_string(),
        "Relay acceptance does not confirm phone delivery.".to_string(),
    ]
    .join("\n")
}
