//! Canonical application-message and push states.
//!
//! Native MDK and the Cloudflare Durable Object are authoritative for the
//! cryptographic operation. These types are the sanitized projection the
//! operational store and both transports share. Unknown names are rejected
//! by the parser instead of being stored as `rejected`.

use serde_json::{json, Value};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MessageState {
    NotSubmitted,
    Prepared,
    AcceptedPending,
    RelayAccepted,
    Rejected,
    CompletionUnknown,
}

impl MessageState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NotSubmitted => "not_submitted",
            Self::Prepared => "prepared",
            Self::AcceptedPending => "accepted_pending",
            Self::RelayAccepted => "relay_accepted",
            Self::Rejected => "rejected",
            Self::CompletionUnknown => "completion_unknown",
        }
    }

    /// Legacy aliases stay explicit. An unknown token returns `None`.
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "not_submitted" => Some(Self::NotSubmitted),
            "prepared" | "message_prepared" => Some(Self::Prepared),
            "accepted_pending" => Some(Self::AcceptedPending),
            "relay_accepted" | "message_accepted" | "accepted" | "published" => {
                Some(Self::RelayAccepted)
            }
            "rejected" | "failed" => Some(Self::Rejected),
            "completion_unknown" => Some(Self::CompletionUnknown),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PushState {
    Unknown,
    NotRequired,
    NotAttempted,
    TokenUnavailable,
    Prepared,
    Pending,
    PublicationAttempted,
    RelayAccepted,
    Rejected,
    Expired,
    Unobservable,
    TerminalFailure,
}

impl PushState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::NotRequired => "not_required",
            Self::NotAttempted => "not_attempted",
            Self::TokenUnavailable => "token_unavailable",
            Self::Prepared => "prepared",
            Self::Pending => "pending",
            Self::PublicationAttempted => "publication_attempted",
            Self::RelayAccepted => "relay_accepted",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
            Self::Unobservable => "unobservable",
            Self::TerminalFailure => "terminal_failure",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "unknown" => Some(Self::Unknown),
            "not_required" => Some(Self::NotRequired),
            "not_attempted" => Some(Self::NotAttempted),
            "token_unavailable" | "push_token_unavailable" => Some(Self::TokenUnavailable),
            "prepared" | "push_trigger_prepared" => Some(Self::Prepared),
            "pending" => Some(Self::Pending),
            "publication_attempted" => Some(Self::PublicationAttempted),
            "relay_accepted" | "push_trigger_accepted" => Some(Self::RelayAccepted),
            "rejected" => Some(Self::Rejected),
            "expired" | "push_expired" => Some(Self::Expired),
            "unobservable" | "push_unobservable" => Some(Self::Unobservable),
            "terminal_failure" => Some(Self::TerminalFailure),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EvidenceClass {
    None,
    RelayAcknowledgement,
    HelperJournal,
    TokenAvailabilityOnly,
    PublishErrorObserved,
    MdkDiscardsPublishResult,
    NotObserved,
}

impl EvidenceClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::RelayAcknowledgement => "relay_acknowledgement",
            Self::HelperJournal => "helper_journal",
            Self::TokenAvailabilityOnly => "token_availability_only",
            Self::PublishErrorObserved => "publish_error_observed",
            Self::MdkDiscardsPublishResult => "mdk_discards_publish_result",
            Self::NotObserved => "not_observed",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OperationDisposition {
    Settled,
    Reconcile,
}

impl OperationDisposition {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Settled => "settled",
            Self::Reconcile => "reconcile",
        }
    }
}

/// What one transport response is allowed to add to the counters.
///
/// A repeated phase adds nothing. A push reconciliation that restates an
/// already accepted message does not add an application-message submission.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PhaseDelta {
    pub message_state: Option<MessageState>,
    pub push_state: Option<PushState>,
    pub message_submissions: i64,
    pub message_reconciliations: i64,
    pub unknown_attempts: i64,
    pub token_waits: i64,
    pub push_publications: i64,
    pub push_reconciliations: i64,
    pub unobservable_attempts: i64,
    pub preserve_message: bool,
}

pub fn phase_delta(
    previous_message: Option<&str>,
    previous_push: Option<&str>,
    message_phase: Option<&str>,
    push_phase: Option<&str>,
) -> PhaseDelta {
    let message_state = message_phase.and_then(MessageState::parse);
    let push_state = push_phase.and_then(PushState::parse);
    let previous_message_state = previous_message.and_then(MessageState::parse);
    let previous_push_state = previous_push.and_then(PushState::parse);
    let message_changed = message_state.is_some() && message_state != previous_message_state;
    let push_changed = push_state.is_some() && push_state != previous_push_state;
    let submission = message_changed
        && matches!(
            previous_message_state,
            None | Some(MessageState::NotSubmitted) | Some(MessageState::Prepared)
        )
        && !matches!(message_state, Some(MessageState::NotSubmitted));
    let reconciliation = message_changed && !submission;
    let token_wait = push_changed && matches!(push_state, Some(PushState::TokenUnavailable));
    let publication = push_changed
        && matches!(
            push_state,
            Some(PushState::Prepared) | Some(PushState::PublicationAttempted)
        );
    let push_reconcile = push_changed && !token_wait && !publication;
    let unobservable = push_changed && matches!(push_state, Some(PushState::Unobservable));
    let unknown = message_changed && matches!(message_state, Some(MessageState::CompletionUnknown))
        || push_changed && matches!(push_state, Some(PushState::Unknown));
    PhaseDelta {
        message_state,
        push_state,
        message_submissions: i64::from(submission),
        message_reconciliations: i64::from(reconciliation),
        unknown_attempts: i64::from(unknown),
        token_waits: i64::from(token_wait),
        push_publications: i64::from(publication),
        push_reconciliations: i64::from(push_reconcile),
        unobservable_attempts: i64::from(unobservable),
        preserve_message: matches!(
            message_state.or(previous_message_state),
            Some(MessageState::RelayAccepted) | Some(MessageState::AcceptedPending)
        ),
    }
}

/// Recommended retry, clamped to the engine bounds. `None` means settle.
pub fn bounded_retry_ms(recommended_ms: Option<i64>, attempt: i64) -> Option<i64> {
    let fallback =
        15_000_i64.saturating_mul(1_i64.checked_shl(attempt.min(5) as u32).unwrap_or(32));
    let requested = recommended_ms.unwrap_or(fallback).clamp(15_000, 300_000);
    Some(requested)
}

pub fn operation_view(
    project_id: &str,
    operation_id: &str,
    message: Option<MessageState>,
    push: Option<PushState>,
    message_event_id: Option<&str>,
    error: Option<&str>,
    settled: bool,
    retry_at_ms: Option<i64>,
) -> Value {
    json!({
        "projectId": project_id,
        "operationId": operation_id,
        "messageState": message.map(MessageState::as_str),
        "messageEventId": message_event_id,
        "pushState": push.map(PushState::as_str),
        "pushEventId": Value::Null,
        "evidence": if message == Some(MessageState::RelayAccepted) {
            EvidenceClass::HelperJournal.as_str()
        } else {
            EvidenceClass::NotObserved.as_str()
        },
        "error": error,
        "disposition": if settled {
            OperationDisposition::Settled.as_str()
        } else {
            OperationDisposition::Reconcile.as_str()
        },
        "retryAtMs": retry_at_ms,
        "phoneDelivery": false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_phases_do_not_become_rejected_and_repeats_add_nothing() {
        assert_eq!(MessageState::parse("not-a-state"), None);
        assert_eq!(PushState::parse("nope"), None);
        let first = phase_delta(
            None,
            None,
            Some("relay_accepted"),
            Some("token_unavailable"),
        );
        assert_eq!(first.message_state, Some(MessageState::RelayAccepted));
        assert_eq!(first.message_submissions, 1);
        assert_eq!(first.token_waits, 1);
        assert!(first.preserve_message);
        let again = phase_delta(
            Some("relay_accepted"),
            Some("token_unavailable"),
            Some("message_accepted"),
            Some("push_token_unavailable"),
        );
        assert_eq!(again.message_submissions, 0);
        assert_eq!(again.message_reconciliations, 0);
        assert_eq!(again.token_waits, 0);
        assert_eq!(again.push_publications, 0);
    }

    #[test]
    fn a_push_update_does_not_count_as_a_new_message_submission() {
        let delta = phase_delta(
            Some("relay_accepted"),
            Some("publication_attempted"),
            Some("relay_accepted"),
            Some("unobservable"),
        );
        assert_eq!(delta.message_submissions, 0);
        assert_eq!(delta.message_reconciliations, 0);
        assert_eq!(delta.unobservable_attempts, 1);
        assert_eq!(delta.push_state, Some(PushState::Unobservable));
        assert!(delta.preserve_message);
    }

    #[test]
    fn legacy_aliases_map_onto_the_canonical_names() {
        assert_eq!(
            MessageState::parse("accepted"),
            Some(MessageState::RelayAccepted)
        );
        assert_eq!(
            PushState::parse("push_trigger_accepted"),
            Some(PushState::RelayAccepted)
        );
        assert_eq!(PushState::parse("push_expired"), Some(PushState::Expired));
    }
}
