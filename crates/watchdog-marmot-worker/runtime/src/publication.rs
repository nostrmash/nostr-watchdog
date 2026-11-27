//! Relay acknowledgement correlation and per-trigger publication records.
//!
//! An `OK` frame counts only when its event id is the id that was published.
//! A timeout is not a rejection. One accepted destination is enough, and a
//! later failure cannot erase that acceptance.

use serde_json::Value;

use crate::push::CapabilityId;

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
    pub capabilities: Vec<CapabilityId>,
}

/// Split a stored trigger envelope into jobs whose exact capabilities remain authorized.
///
/// Accepted jobs are not returned. A job that does not match the current
/// authenticated record is marked `retired`. Its signed event bytes stay as stored.
pub fn revalidate_trigger_envelope(
    envelope: &Value,
    authorized: &[CapabilityId],
) -> (Value, Vec<TriggerJob>, Vec<CapabilityId>) {
    let Some(items) = envelope.as_array() else {
        return (envelope.clone(), Vec::new(), authorized.to_vec());
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
        let capabilities = item_capabilities(&item);
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
        let still_authorized = !capabilities.is_empty()
            && capabilities.iter().all(|capability| {
                capability.server_pubkey_hex == server && authorized.iter().any(|item| item == capability)
            });
        if still_authorized {
            if !relays.is_empty() {
                jobs.push(TriggerJob {
                    event,
                    relays,
                    server,
                    capabilities,
                });
            }
            updated.push(item);
            continue;
        }
        for capability in &capabilities {
            if authorized.iter().any(|item| item == capability) && !uncovered.iter().any(|item| item == capability)
            {
                uncovered.push(capability.clone());
            }
        }
        if let Some(map) = item.as_object_mut() {
            map.insert("phase".into(), Value::String("retired".into()));
        }
        updated.push(item);
    }
    for capability in authorized {
        if !capability_covered(&updated, capability) && !uncovered.iter().any(|item| item == capability) {
            uncovered.push(capability.clone());
        }
    }
    (Value::Array(updated), jobs, uncovered)
}

fn item_capabilities(item: &Value) -> Vec<CapabilityId> {
    item.get("capabilities")
        .and_then(|value| serde_json::from_value(value.clone()).ok())
        .unwrap_or_default()
}

fn capability_covered(items: &[Value], capability: &CapabilityId) -> bool {
    items.iter().any(|item| {
        let phase = item.get("phase").and_then(|value| value.as_str()).unwrap_or("");
        phase != "retired" && item_capabilities(item).iter().any(|item| item == capability)
    })
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
    use crate::push::CapabilityId;
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

    fn capability(server: &str, leaf: u32, owner_ts: i64, digest: &str) -> CapabilityId {
        CapabilityId {
            group_id_hex: "aa".into(),
            member_id_hex: "bb".into(),
            leaf_index: leaf,
            platform: "fcm".into(),
            server_pubkey_hex: server.into(),
            token_fingerprint: "sha256:abcdef0123456789abcdef01".into(),
            owner_ts,
            record_digest: digest.into(),
            ciphertext_sha256: digest.into(),
        }
    }

    fn envelope_for(event: Value, server: &str, capability: &CapabilityId, phase: &str) -> Value {
        json!([{
            "event": event,
            "relays": ["wss://inbox.example"],
            "server": server,
            "capabilities": [capability],
            "phase": phase
        }])
    }

    #[test]
    fn a_revoked_record_is_retired_without_editing_the_event() {
        let event = json!({"id": "trigger-1", "sig": "signed"});
        let stored = capability("server", 1, 10, "digest-old");
        let envelope = envelope_for(event.clone(), "server", &stored, "unobservable");
        let (updated, jobs, uncovered) = revalidate_trigger_envelope(&envelope, &[]);
        assert!(jobs.is_empty());
        assert!(uncovered.is_empty());
        assert_eq!(updated[0]["phase"], "retired");
        assert_eq!(updated[0]["event"], event);
    }

    #[test]
    fn the_same_fingerprint_on_another_server_leaf_or_group_does_not_authorize() {
        let event = json!({"id": "trigger-1", "sig": "signed"});
        let stored = capability("server-a", 1, 10, "digest-old");
        let envelope = envelope_for(event.clone(), "server-a", &stored, "prepared");
        let other_server = capability("server-b", 1, 10, "digest-old");
        let (updated, jobs, uncovered) = revalidate_trigger_envelope(&envelope, &[other_server.clone()]);
        assert!(jobs.is_empty());
        assert_eq!(updated[0]["phase"], "retired");
        assert_eq!(updated[0]["event"], event);
        assert_eq!(uncovered, vec![other_server]);

        let other_leaf = capability("server-a", 2, 10, "digest-old");
        let (updated, jobs, _) = revalidate_trigger_envelope(&envelope, &[other_leaf]);
        assert!(jobs.is_empty());
        assert_eq!(updated[0]["phase"], "retired");

        let mut other_group = capability("server-a", 1, 10, "digest-old");
        other_group.group_id_hex = "cc".into();
        let (updated, jobs, _) = revalidate_trigger_envelope(&envelope, &[other_group]);
        assert!(jobs.is_empty());
        assert_eq!(updated[0]["event"], event);
    }

    #[test]
    fn a_replacement_record_does_not_authorize_the_older_ciphertext() {
        let event = json!({"id": "trigger-1", "sig": "signed"});
        let stored = capability("server", 1, 10, "digest-old");
        let replacement = capability("server", 1, 11, "digest-new");
        let envelope = envelope_for(event.clone(), "server", &stored, "prepared");
        let (updated, jobs, uncovered) = revalidate_trigger_envelope(&envelope, &[replacement.clone()]);
        assert!(jobs.is_empty());
        assert_eq!(updated[0]["phase"], "retired");
        assert_eq!(updated[0]["event"]["sig"], "signed");
        assert_eq!(uncovered, vec![replacement]);
    }

    #[test]
    fn a_partial_batch_retires_the_signed_event_and_returns_the_valid_record() {
        let event = json!({"id": "trigger-1", "sig": "signed"});
        let kept = capability("server", 1, 10, "digest-a");
        let mut dropped = capability("server", 2, 10, "digest-b");
        dropped.token_fingerprint = "sha256:00112233445566778899aabb".into();
        let envelope = json!([{
            "event": event,
            "relays": ["wss://inbox.example"],
            "server": "server",
            "capabilities": [kept, dropped],
            "phase": "unobservable"
        }]);
        let (updated, jobs, uncovered) = revalidate_trigger_envelope(&envelope, &[kept.clone()]);
        assert!(jobs.is_empty());
        assert_eq!(updated[0]["phase"], "retired");
        assert_eq!(updated[0]["event"]["id"], "trigger-1");
        assert_eq!(uncovered, vec![kept]);
    }

    #[test]
    fn overlapping_fingerprints_stay_distinct_and_accepted_triggers_stay_accepted() {
        let first = capability("server", 1, 10, "digest-a");
        let mut second = capability("server", 2, 10, "digest-b");
        second.token_fingerprint = first.token_fingerprint.clone();
        let envelope = json!([
            {
                "event": {"id": "kept", "sig": "one"},
                "relays": ["wss://a.example"],
                "server": "server",
                "capabilities": [first],
                "phase": "relay_accepted"
            },
            {
                "event": {"id": "retry", "sig": "two"},
                "relays": ["wss://b.example"],
                "server": "server",
                "capabilities": [second],
                "phase": "unobservable"
            }
        ]);
        let (updated, jobs, uncovered) =
            revalidate_trigger_envelope(&envelope, &[first.clone(), second.clone()]);
        assert!(uncovered.is_empty());
        assert_eq!(jobs.len(), 1);
        assert_eq!(jobs[0].event["id"], "retry");
        assert_eq!(jobs[0].capabilities, vec![second]);
        assert_eq!(updated[0]["phase"], "relay_accepted");
        assert_eq!(updated[0]["event"]["sig"], "one");
    }

    #[test]
    fn a_fingerprint_list_without_a_record_identity_is_not_authorization() {
        let event = json!({"id": "trigger-1", "sig": "signed"});
        let envelope = json!([{
            "event": event,
            "relays": ["wss://inbox.example"],
            "server": "server",
            "fingerprints": ["sha256:abcdef0123456789abcdef01"],
            "phase": "prepared"
        }]);
        let current = capability("server", 1, 10, "digest");
        let (updated, jobs, uncovered) = revalidate_trigger_envelope(&envelope, &[current.clone()]);
        assert!(jobs.is_empty());
        assert_eq!(updated[0]["phase"], "retired");
        assert_eq!(updated[0]["event"]["sig"], "signed");
        assert_eq!(uncovered, vec![current]);
    }

    #[test]
    fn nineteen_tokens_need_two_protocol_batches() {
        assert_eq!(split_count(19, 18), 2);
        assert_eq!(split_count(18, 18), 1);
        assert_eq!(split_count(0, 18), 0);
    }
}
