//! Relay acknowledgement correlation and per-trigger publication records.
//!
//! An `OK` frame counts only when its event id is the id that was published.
//! A timeout is not a rejection. One accepted destination is enough, and a
//! later failure cannot erase that acceptance.

use serde_json::Value;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FrameClass {
    Unrelated,
    Accepted,
    Rejected { reason: String },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DestinationVerdict {
    Accepted,
    Rejected { reason: String },
    Ambiguous { reason: String },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DestinationReport {
    pub relay: String,
    pub verdict: DestinationVerdict,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublishAttempt {
    pub event_id: String,
    pub attempt_id: String,
    pub outcome: String,
    pub relay: String,
    pub reason: String,
    pub retryable: bool,
}

/// Classify one NIP-01 frame against the prepared event id.
pub fn classify_ok(frame: &Value, expected_id: &str) -> FrameClass {
    if frame.get(0).and_then(|item| item.as_str()) != Some("OK") {
        return FrameClass::Unrelated;
    }
    if frame.get(1).and_then(|item| item.as_str()) != Some(expected_id) {
        return FrameClass::Unrelated;
    }
    match frame.get(2).and_then(|item| item.as_bool()) {
        Some(true) => FrameClass::Accepted,
        Some(false) => FrameClass::Rejected {
            reason: sanitize_reason(
                frame.get(3).and_then(|item| item.as_str()).unwrap_or("relay_rejected"),
            ),
        },
        None => FrameClass::Unrelated,
    }
}

/// First correlated verdict in a frame list. Unrelated frames are skipped.
/// A later duplicate of the same verdict does not change the result.
pub fn first_correlated(frames: &[Value], expected_id: &str) -> Option<FrameClass> {
    for frame in frames {
        match classify_ok(frame, expected_id) {
            FrameClass::Unrelated => continue,
            other => return Some(other),
        }
    }
    None
}

pub fn sanitize_reason(raw: &str) -> String {
    let lower = raw.to_ascii_lowercase();
    if lower.contains("nsec")
        || lower.contains("token")
        || lower.contains("bearer")
        || lower.contains("secret")
        || lower.contains("priv")
    {
        return "relay_rejected".into();
    }
    let cleaned: String = raw
        .chars()
        .filter(|ch| ch.is_ascii() && !ch.is_control())
        .take(120)
        .collect();
    if cleaned.is_empty() {
        "relay_rejected".into()
    } else {
        cleaned
    }
}

/// Combine one attempt's per-relay verdicts.
///
/// Acceptance is the relay that returned the matching `OK`, which may be a
/// later destination. Mixed rejection and timeout stays unobservable.
pub fn aggregate_destinations(
    event_id: &str,
    attempt_id: &str,
    reports: &[DestinationReport],
) -> PublishAttempt {
    if let Some(accepted) = reports.iter().find(|report| {
        matches!(report.verdict, DestinationVerdict::Accepted)
    }) {
        return PublishAttempt {
            event_id: event_id.to_owned(),
            attempt_id: attempt_id.to_owned(),
            outcome: "relay_accepted".into(),
            relay: accepted.relay.clone(),
            reason: String::new(),
            retryable: false,
        };
    }
    let rejected: Vec<_> = reports
        .iter()
        .filter(|report| matches!(report.verdict, DestinationVerdict::Rejected { .. }))
        .collect();
    let ambiguous: Vec<_> = reports
        .iter()
        .filter(|report| matches!(report.verdict, DestinationVerdict::Ambiguous { .. }))
        .collect();
    if !reports.is_empty() && ambiguous.is_empty() && rejected.len() == reports.len() {
        let reason = match &rejected[0].verdict {
            DestinationVerdict::Rejected { reason } => reason.clone(),
            _ => "relay_rejected".into(),
        };
        return PublishAttempt {
            event_id: event_id.to_owned(),
            attempt_id: attempt_id.to_owned(),
            outcome: "rejected".into(),
            relay: rejected[0].relay.clone(),
            reason,
            retryable: false,
        };
    }
    let (relay, reason) = if let Some(report) = ambiguous.first() {
        let reason = match &report.verdict {
            DestinationVerdict::Ambiguous { reason } => reason.clone(),
            _ => "publication_timeout".into(),
        };
        (report.relay.clone(), reason)
    } else if let Some(report) = rejected.first() {
        (report.relay.clone(), "publication_ambiguous".into())
    } else {
        (String::new(), "publication_timeout".into())
    };
    PublishAttempt {
        event_id: event_id.to_owned(),
        attempt_id: attempt_id.to_owned(),
        outcome: "unobservable".into(),
        relay,
        reason,
        retryable: true,
    }
}

pub fn new_attempt_id() -> String {
    let mut bytes = [0u8; 8];
    let _ = getrandom::getrandom(&mut bytes);
    format!("{}-{}", crate::clock::unix_ms(), hex::encode(bytes))
}

/// One stored trigger the retry path may publish again.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TriggerJob {
    pub event: Value,
    pub relays: Vec<String>,
    pub server: String,
    pub fingerprints: Vec<String>,
}

/// Split a stored trigger envelope into jobs that are still authorized.
///
/// Accepted jobs are not returned. A job whose fingerprints are no longer all
/// authorized is marked `retired` and its signed event bytes are left unchanged.
pub fn revalidate_trigger_envelope(
    envelope: &Value,
    authorized: &std::collections::HashSet<String>,
) -> (Value, Vec<TriggerJob>, Vec<String>) {
    let Some(items) = envelope.as_array() else {
        return (envelope.clone(), Vec::new(), Vec::new());
    };
    let mut updated = Vec::new();
    let mut jobs = Vec::new();
    let mut uncovered = Vec::new();
    for item in items {
        let mut item = item.clone();
        let phase = item
            .get("phase")
            .and_then(|value| value.as_str())
            .unwrap_or("prepared");
        let fingerprints = item
            .get("fingerprints")
            .and_then(|value| value.as_array())
            .map(|values| {
                values
                    .iter()
                    .filter_map(|value| value.as_str().map(str::to_owned))
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        let event = item.get("event").cloned().unwrap_or(Value::Null);
        let relays = item
            .get("relays")
            .and_then(|value| value.as_array())
            .map(|values| {
                values
                    .iter()
                    .filter_map(|value| value.as_str().map(str::to_owned))
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        let server = item
            .get("server")
            .and_then(|value| value.as_str())
            .unwrap_or("")
            .to_owned();
        if phase == "relay_accepted" || phase == "retired" {
            updated.push(item);
            continue;
        }
        let still_authorized = !fingerprints.is_empty()
            && fingerprints
                .iter()
                .all(|fingerprint| authorized.contains(fingerprint));
        if still_authorized {
            if !relays.is_empty() {
                jobs.push(TriggerJob {
                    event,
                    relays,
                    server,
                    fingerprints,
                });
            }
            updated.push(item);
            continue;
        }
        for fingerprint in &fingerprints {
            if authorized.contains(fingerprint) {
                uncovered.push(fingerprint.clone());
            }
        }
        if let Some(map) = item.as_object_mut() {
            map.insert("phase".into(), Value::String("retired".into()));
        }
        updated.push(item);
    }
    (Value::Array(updated), jobs, uncovered)
}

pub fn split_count(len: usize, batch: usize) -> usize {
    if len == 0 || batch == 0 {
        0
    } else {
        len.div_ceil(batch)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn ok(id: &str, accepted: bool) -> Value {
        json!(["OK", id, accepted, ""])
    }

    #[test]
    fn unrelated_positive_ok_is_not_acceptance() {
        assert_eq!(
            classify_ok(&ok("other", true), "event-1"),
            FrameClass::Unrelated
        );
    }

    #[test]
    fn unrelated_negative_ok_is_not_rejection() {
        assert_eq!(
            classify_ok(&ok("other", false), "event-1"),
            FrameClass::Unrelated
        );
    }

    #[test]
    fn delayed_matching_ok_is_the_first_correlated_frame() {
        let frames = vec![
            ok("other", true),
            json!(["NOTICE", "waiting"]),
            ok("event-1", true),
        ];
        assert_eq!(
            first_correlated(&frames, "event-1"),
            Some(FrameClass::Accepted)
        );
    }

    #[test]
    fn duplicate_matching_acknowledgements_stay_one_acceptance() {
        let frames = vec![ok("event-1", true), ok("event-1", true)];
        assert_eq!(
            first_correlated(&frames, "event-1"),
            Some(FrameClass::Accepted)
        );
    }

    #[test]
    fn a_later_relay_is_the_accepting_destination() {
        let reports = vec![
            DestinationReport {
                relay: "wss://first.example".into(),
                verdict: DestinationVerdict::Rejected {
                    reason: "blocked".into(),
                },
            },
            DestinationReport {
                relay: "wss://second.example".into(),
                verdict: DestinationVerdict::Accepted,
            },
        ];
        let attempt = aggregate_destinations("event-1", "attempt-1", &reports);
        assert_eq!(attempt.outcome, "relay_accepted");
        assert_eq!(attempt.relay, "wss://second.example");
        assert!(!attempt.retryable);
    }

    #[test]
    fn explicit_rejection_is_not_a_timeout() {
        let reports = vec![DestinationReport {
            relay: "wss://relay.example".into(),
            verdict: DestinationVerdict::Rejected {
                reason: "invalid: id is malformed".into(),
            },
        }];
        let attempt = aggregate_destinations("event-1", "attempt-1", &reports);
        assert_eq!(attempt.outcome, "rejected");
        assert!(!attempt.retryable);
        assert_eq!(attempt.reason, "invalid: id is malformed");
    }

    #[test]
    fn timeout_is_unobservable_and_retryable() {
        let reports = vec![DestinationReport {
            relay: "wss://relay.example".into(),
            verdict: DestinationVerdict::Ambiguous {
                reason: "publication_timeout".into(),
            },
        }];
        let attempt = aggregate_destinations("event-1", "attempt-1", &reports);
        assert_eq!(attempt.outcome, "unobservable");
        assert_eq!(attempt.reason, "publication_timeout");
        assert!(attempt.retryable);
    }

    #[test]
    fn mixed_rejection_and_timeout_is_not_an_explicit_rejection() {
        let reports = vec![
            DestinationReport {
                relay: "wss://one.example".into(),
                verdict: DestinationVerdict::Rejected {
                    reason: "blocked".into(),
                },
            },
            DestinationReport {
                relay: "wss://two.example".into(),
                verdict: DestinationVerdict::Ambiguous {
                    reason: "publication_timeout".into(),
                },
            },
        ];
        let attempt = aggregate_destinations("event-1", "attempt-1", &reports);
        assert_eq!(attempt.outcome, "unobservable");
        assert!(attempt.retryable);
        assert_ne!(attempt.outcome, "rejected");
    }

    #[test]
    fn rejection_reasons_do_not_keep_secrets() {
        assert_eq!(
            sanitize_reason("invalid nsec1qqqq and token=abc"),
            "relay_rejected"
        );
    }

    #[test]
    fn a_revoked_batch_is_retired_without_editing_the_event() {
        let event = json!({"id": "trigger-1", "sig": "signed"});
        let envelope = json!([{
            "event": event,
            "relays": ["wss://inbox.example"],
            "server": "server",
            "fingerprints": ["sha256:aaa"],
            "phase": "unobservable"
        }]);
        let (updated, jobs, uncovered) =
            revalidate_trigger_envelope(&envelope, &std::collections::HashSet::new());
        assert!(jobs.is_empty());
        assert!(uncovered.is_empty());
        assert_eq!(updated[0]["phase"], "retired");
        assert_eq!(updated[0]["event"], event);
    }

    #[test]
    fn an_accepted_trigger_is_not_sent_again() {
        let envelope = json!([
            {
                "event": {"id": "kept"},
                "relays": ["wss://a.example"],
                "server": "s",
                "fingerprints": ["sha256:aaa"],
                "phase": "relay_accepted"
            },
            {
                "event": {"id": "retry"},
                "relays": ["wss://b.example"],
                "server": "s",
                "fingerprints": ["sha256:bbb"],
                "phase": "unobservable"
            }
        ]);
        let mut authorized = std::collections::HashSet::new();
        authorized.insert("sha256:aaa".into());
        authorized.insert("sha256:bbb".into());
        let (_updated, jobs, uncovered) = revalidate_trigger_envelope(&envelope, &authorized);
        assert!(uncovered.is_empty());
        assert_eq!(jobs.len(), 1);
        assert_eq!(jobs[0].event["id"], "retry");
    }

    #[test]
    fn nineteen_tokens_need_two_protocol_batches() {
        assert_eq!(split_count(19, 18), 2);
        assert_eq!(split_count(18, 18), 1);
        assert_eq!(split_count(0, 18), 0);
    }
}
