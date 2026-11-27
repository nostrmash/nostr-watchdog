use crate::domain::{
    CheckResult, IncidentKind, MonitorMemory, MonitorStatus, Notice, NoticeEvent, OpenIncident,
    Severity, TransitionResult,
};

pub struct TransitionInput<'a> {
    pub memory: &'a MonitorMemory,
    pub result: &'a CheckResult,
    pub now: i64,
    pub failure_threshold: i64,
    pub recovery_threshold: i64,
    pub severity: Severity,
    pub incident_on_degraded: bool,
    pub unknown_threshold: i64,
    pub reminder_seconds: i64,
    pub new_incident_id: &'a str,
    pub new_integrity_incident_id: &'a str,
}

pub fn transition(input: TransitionInput<'_>) -> TransitionResult {
    let mut memory = input.memory.clone();
    memory.observed_version = input
        .result
        .observed_version
        .clone()
        .or(memory.observed_version.clone());
    if input.result.status == MonitorStatus::Unknown {
        return apply_unknown(&mut memory, &input);
    }
    let mut notices = Vec::new();
    close_integrity(&mut memory, &mut notices, input.now, &input.result.summary);
    memory.consecutive_unknowns = 0;
    memory.unknown_since = None;
    memory.last_unknown_reason = None;
    if input.result.status == MonitorStatus::Healthy {
        memory.status = MonitorStatus::Healthy;
        memory.consecutive_successes += 1;
        memory.consecutive_failures = 0;
        memory.failure_kind = None;
        if memory.consecutive_successes >= input.recovery_threshold {
            if let Some(incident) = memory.open_incident.take() {
                notices.push(notice(
                    NoticeEvent::Close,
                    incident.id,
                    incident.kind,
                    incident.severity,
                    input.result.summary.clone(),
                    input.now,
                    MonitorStatus::Healthy,
                ));
            }
        }
        return done(memory, notices);
    }
    let kind = incident_kind(input.result.status, input.incident_on_degraded);
    let Some(kind) = kind else {
        memory.status = input.result.status;
        memory.consecutive_successes = 0;
        return done(memory, notices);
    };
    if memory.failure_kind == Some(input.result.status) {
        memory.consecutive_failures += 1;
    } else {
        memory.consecutive_failures = 1;
    }
    memory.failure_kind = Some(input.result.status);
    memory.consecutive_successes = 0;
    memory.status = input.result.status;
    let threshold = if input.result.status == MonitorStatus::Misconfigured {
        1
    } else {
        input.failure_threshold
    };
    if memory.open_incident.is_none() && memory.consecutive_failures >= threshold {
        let severity = severity_for(input.result.status, input.severity);
        memory.open_incident = Some(OpenIncident {
            id: input.new_incident_id.to_string(),
            kind,
            severity,
            opened_at: input.now,
            reminder_count: 0,
            last_reminder_at: None,
            silenced_until: None,
            acked_at: None,
            decision_generation: 0,
        });
        notices.push(notice(
            NoticeEvent::Open,
            input.new_incident_id.to_string(),
            kind,
            severity,
            input.result.summary.clone(),
            input.now,
            input.result.status,
        ));
        return done(memory, notices);
    }
    if let Some(open) = memory.open_incident.as_mut() {
        if open.kind == IncidentKind::Outage
            && open.severity == Severity::Critical
            && input.reminder_seconds > 0
            && open.acked_at.is_none()
            && open.silenced_until.is_none_or(|until| until <= input.now)
            && input.now - open.last_reminder_at.unwrap_or(open.opened_at)
                >= input.reminder_seconds.saturating_mul(1000)
        {
            let decision_generation = open.decision_generation;
            let reminder_count = open.reminder_count;
            open.reminder_count += 1;
            open.last_reminder_at = Some(input.now);
            let id = open.id.clone();
            let mut item = notice(
                NoticeEvent::Remind,
                id,
                IncidentKind::Outage,
                Severity::Critical,
                input.result.summary.clone(),
                input.now,
                input.result.status,
            );
            item.decision_generation = decision_generation;
            item.reminder_count = reminder_count;
            notices.push(item);
        }
    }
    done(memory, notices)
}

fn apply_unknown(memory: &mut MonitorMemory, input: &TransitionInput<'_>) -> TransitionResult {
    memory.consecutive_unknowns += 1;
    if memory.unknown_since.is_none() {
        memory.unknown_since = Some(input.now);
    }
    memory.last_unknown_reason = Some(input.result.summary.clone());
    if memory.open_incident.is_none() {
        memory.status = MonitorStatus::Unknown;
    }
    if memory.integrity_incident.is_none() && memory.consecutive_unknowns >= input.unknown_threshold
    {
        let id = if input.new_integrity_incident_id.is_empty() {
            input.new_incident_id
        } else {
            input.new_integrity_incident_id
        };
        memory.integrity_incident = Some(OpenIncident {
            id: id.to_string(),
            kind: IncidentKind::Inconclusive,
            severity: Severity::Warning,
            opened_at: input.now,
            reminder_count: 0,
            last_reminder_at: None,
            silenced_until: None,
            acked_at: None,
            decision_generation: 0,
        });
        let opened = notice(
            NoticeEvent::Open,
            id.to_string(),
            IncidentKind::Inconclusive,
            Severity::Warning,
            input.result.summary.clone(),
            input.now,
            memory.status,
        );
        return TransitionResult {
            memory: memory.clone(),
            notice: Some(opened.clone()),
            notices: vec![opened],
            changed: true,
        };
    }
    TransitionResult {
        memory: memory.clone(),
        notice: None,
        notices: Vec::new(),
        changed: true,
    }
}

fn close_integrity(memory: &mut MonitorMemory, notices: &mut Vec<Notice>, now: i64, reason: &str) {
    let Some(incident) = memory.integrity_incident.take() else {
        return;
    };
    notices.push(notice(
        NoticeEvent::Close,
        incident.id,
        IncidentKind::Inconclusive,
        incident.severity,
        format!("Monitoring produced a conclusive sample. {reason}"),
        now,
        MonitorStatus::Healthy,
    ));
}

fn done(memory: MonitorMemory, notices: Vec<Notice>) -> TransitionResult {
    let notice = primary_notice(&notices);
    TransitionResult {
        memory,
        notice,
        notices,
        changed: true,
    }
}

fn primary_notice(notices: &[Notice]) -> Option<Notice> {
    notices
        .iter()
        .find(|item| item.kind != IncidentKind::Inconclusive)
        .cloned()
        .or_else(|| notices.first().cloned())
}

fn incident_kind(status: MonitorStatus, incident_on_degraded: bool) -> Option<IncidentKind> {
    match status {
        MonitorStatus::Down => Some(IncidentKind::Outage),
        MonitorStatus::Degraded if incident_on_degraded => Some(IncidentKind::Degraded),
        MonitorStatus::Misconfigured => Some(IncidentKind::Misconfigured),
        _ => None,
    }
}

fn severity_for(status: MonitorStatus, monitor_severity: Severity) -> Severity {
    if status == MonitorStatus::Down {
        monitor_severity
    } else {
        Severity::Warning
    }
}

fn notice(
    event: NoticeEvent,
    incident_id: String,
    kind: IncidentKind,
    severity: Severity,
    reason: String,
    occurred_at: i64,
    monitor_status: MonitorStatus,
) -> Notice {
    Notice {
        event,
        incident_id,
        kind,
        severity,
        reason,
        occurred_at,
        monitor_status,
        decision_generation: 0,
        reminder_count: 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{check_result, MonitorStatus, Severity};
    use crate::format::format_incident_message;

    fn check(status: MonitorStatus) -> CheckResult {
        check_result(
            status,
            if status == MonitorStatus::Healthy {
                None
            } else {
                Some(status.as_str())
            },
            status.as_str(),
            Some(12),
            None,
        )
    }

    fn step(
        memory: &MonitorMemory,
        status: MonitorStatus,
        now: i64,
        reminder_seconds: i64,
    ) -> TransitionResult {
        transition(TransitionInput {
            memory,
            result: &check(status),
            now,
            failure_threshold: 2,
            recovery_threshold: 2,
            severity: Severity::Critical,
            incident_on_degraded: true,
            unknown_threshold: 3,
            reminder_seconds,
            new_incident_id: &format!("inc_{now}"),
            new_integrity_incident_id: &format!("inc_integrity_{now}"),
        })
    }

    #[test]
    fn opens_after_two_failures_and_closes_after_two_successes() {
        let mut memory = MonitorMemory::empty();
        memory = step(&memory, MonitorStatus::Down, 1, 0).memory;
        assert!(memory.open_incident.is_none());
        let opened = step(&memory, MonitorStatus::Down, 2, 0);
        assert_eq!(
            opened.notice.as_ref().map(|item| item.event),
            Some(NoticeEvent::Open)
        );
        memory = step(&opened.memory, MonitorStatus::Healthy, 3, 0).memory;
        assert!(memory.open_incident.is_some());
        let closed = step(&memory, MonitorStatus::Healthy, 4, 0);
        assert_eq!(
            closed.notice.as_ref().map(|item| item.event),
            Some(NoticeEvent::Close)
        );
        assert!(closed.memory.open_incident.is_none());
    }

    #[test]
    fn does_not_open_while_flapping_below_the_threshold() {
        let mut memory = MonitorMemory::empty();
        for (status, now) in [
            (MonitorStatus::Down, 1),
            (MonitorStatus::Healthy, 2),
            (MonitorStatus::Down, 3),
            (MonitorStatus::Healthy, 4),
        ] {
            memory = step(&memory, status, now, 0).memory;
        }
        assert!(memory.open_incident.is_none());
    }

    #[test]
    fn unknown_does_not_recover_or_count_as_success() {
        let opened = step(
            &step(&MonitorMemory::empty(), MonitorStatus::Down, 1, 0).memory,
            MonitorStatus::Down,
            2,
            0,
        );
        let unknown = step(&opened.memory, MonitorStatus::Unknown, 3, 0);
        assert_eq!(
            unknown
                .memory
                .open_incident
                .as_ref()
                .map(|item| item.id.as_str()),
            opened
                .memory
                .open_incident
                .as_ref()
                .map(|item| item.id.as_str())
        );
        assert_eq!(unknown.memory.consecutive_failures, 2);
        assert!(unknown.notice.is_none());
    }

    #[test]
    fn degraded_stays_warning_and_only_critical_outages_remind() {
        let opened = step(
            &step(&MonitorMemory::empty(), MonitorStatus::Degraded, 1, 0).memory,
            MonitorStatus::Degraded,
            2,
            0,
        );
        assert_eq!(
            opened.notice.as_ref().map(|item| item.severity),
            Some(Severity::Warning)
        );
        assert!(step(&opened.memory, MonitorStatus::Degraded, 10_000, 0)
            .notice
            .is_none());
        assert!(step(&opened.memory, MonitorStatus::Degraded, 10_000, 5)
            .notice
            .is_none());
        let critical = step(
            &step(&MonitorMemory::empty(), MonitorStatus::Down, 1, 0).memory,
            MonitorStatus::Down,
            2,
            0,
        );
        let reminder = step(&critical.memory, MonitorStatus::Down, 8_000, 5);
        assert_eq!(
            reminder.notice.as_ref().map(|item| item.event),
            Some(NoticeEvent::Remind)
        );
    }

    #[test]
    fn repeated_unknown_opens_integrity_without_closing_the_outage() {
        let mut current = step(
            &step(&MonitorMemory::empty(), MonitorStatus::Down, 1, 0).memory,
            MonitorStatus::Down,
            2,
            0,
        );
        current = step(&current.memory, MonitorStatus::Unknown, 3, 0);
        assert!(current.notice.is_none());
        current = step(&current.memory, MonitorStatus::Unknown, 4, 0);
        assert!(current.notice.is_none());
        current = step(&current.memory, MonitorStatus::Unknown, 5, 0);
        assert_eq!(
            current.notice.as_ref().map(|item| item.kind),
            Some(IncidentKind::Inconclusive)
        );
        assert_eq!(
            current.memory.open_incident.as_ref().map(|item| item.kind),
            Some(IncidentKind::Outage)
        );
        assert_eq!(current.memory.consecutive_failures, 2);
        assert!(step(&current.memory, MonitorStatus::Unknown, 6, 0)
            .notice
            .is_none());
        let resumed = step(&current.memory, MonitorStatus::Down, 7, 0);
        assert!(resumed.notices.iter().any(|item| {
            item.kind == IncidentKind::Inconclusive && item.event == NoticeEvent::Close
        }));
        assert_eq!(
            resumed.memory.open_incident.as_ref().map(|item| item.kind),
            Some(IncidentKind::Outage)
        );
    }

    #[test]
    fn alert_text_redacts_secrets_and_keeps_the_incident_id() {
        let text = format_incident_message(crate::format::IncidentMessage {
            project_name: "SmartFlowSocial",
            display_name: "App",
            severity: Severity::Critical,
            kind: IncidentKind::Outage,
            event: NoticeEvent::Open,
            state: "down",
            incident_id: "inc_00000000-0000-4000-8000-000000000001",
            occurred_at: 1_700_000_000_000,
            reason: "failed token=abc nsec1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq",
            observed_version: None,
            runbook_url: None,
        });
        assert!(!text.contains("nsec1"));
        assert!(!text.contains("token=abc"));
        assert!(text.contains("inc_00000000-0000-4000-8000-000000000001"));
    }

    #[test]
    fn skipped_is_not_represented_as_healthy() {
        let memory = MonitorMemory::empty();
        assert_eq!(memory.status, MonitorStatus::Unknown);
        assert_ne!(memory.status, MonitorStatus::Healthy);
    }
}
