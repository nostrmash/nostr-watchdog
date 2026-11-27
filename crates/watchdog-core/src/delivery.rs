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
    PartialPush,
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
            Self::PartialPush => "partial_push",
            Self::NotObserved => "not_observed",
        }
    }

    /// Unknown evidence labels stay `not_observed`. They do not change the
    /// message or push state.
    pub fn parse(value: &str) -> Self {
        match value {
            "none" => Self::None,
            "relay_acknowledgement" | "publication_recorded" | "stored_publication" => {
                Self::RelayAcknowledgement
            }
            "helper_journal" => Self::HelperJournal,
            "token_availability_only" | "token_lookup_failed" => Self::TokenAvailabilityOnly,
            "publish_error_observed" => Self::PublishErrorObserved,
            "mdk_discards_publish_result" | "no_correlated_push_evidence" => {
                Self::MdkDiscardsPublishResult
            }
            "partial_push" => Self::PartialPush,
            _ => Self::NotObserved,
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

/// Counters copied from a transport. `None` means the transport did not observe
/// that count. It is not zero, and it is not derived by counting phase strings.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AuthoritativeCounters {
    pub message_submissions: Option<i64>,
    pub message_publications: Option<i64>,
    pub message_reconciles: Option<i64>,
    pub ambiguous_reconciles: Option<i64>,
    pub token_waits: Option<i64>,
    pub push_publications: Option<i64>,
    pub push_reconciles: Option<i64>,
}

impl AuthoritativeCounters {
    pub fn unknown() -> Self {
        Self::default()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LifecycleDecision {
    /// Marmot cryptographic poll. Does not consume an ordinary delivery attempt.
    Reconcile {
        retry_ms: i64,
    },
    /// NIP-17 or Telegram attempt. Consumes one of the eight ordinary attempts.
    Retry {
        retry_ms: i64,
    },
    Accept,
    Fail,
}

/// The original TypeScript dispatcher failed a NIP-17 or Telegram row after
/// eight attempts. Backoff is `min(1h, 30s * 2^(attempt-1))`.
pub const ORDINARY_ATTEMPT_BUDGET: i64 = 8;

pub fn ordinary_backoff_ms(attempt: i64) -> i64 {
    let shift = attempt.saturating_sub(1).clamp(0, 16) as u32;
    30_000_i64
        .saturating_mul(1_i64.checked_shl(shift).unwrap_or(i64::MAX))
        .min(3_600_000)
}

/// Sanitized projection copied from a native helper or Durable Object response.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OperationResult {
    pub project_id: String,
    pub operation_id: String,
    pub message: Option<MessageState>,
    pub message_event_id: Option<String>,
    pub push: Option<PushState>,
    pub push_event_id: Option<String>,
    pub evidence: EvidenceClass,
    pub error: Option<String>,
    pub disposition: OperationDisposition,
    /// Native MDK cannot correlate a push publication. Further polls will not
    /// produce that evidence. A Cloudflare relay timeout leaves this false.
    pub permanent_push_uncertainty: bool,
    pub started_at_ms: Option<i64>,
    pub updated_at_ms: Option<i64>,
    pub retry_after_ms: Option<i64>,
    pub counters: AuthoritativeCounters,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransportOrigin {
    NativeHelper,
    CloudflareObject,
}

pub struct LifecycleInput<'a> {
    pub destination: &'a str,
    pub message_phase: Option<&'a str>,
    pub push_phase: Option<&'a str>,
    pub counters: AuthoritativeCounters,
    pub age_ms: i64,
    pub hold: bool,
    pub terminal: bool,
    pub accepted: bool,
    pub ordinary_attempts: i64,
    pub disposition: Option<OperationDisposition>,
    pub retry_after_ms: Option<i64>,
    pub permanent_push_uncertainty: bool,
}

pub struct InterpretedTransport {
    pub message: Option<MessageState>,
    pub push: Option<PushState>,
    pub incompatible: bool,
    pub decision: LifecycleDecision,
    pub counters: AuthoritativeCounters,
}

/// One boundary from a transport response to an operational decision.
/// Unknown names stay unknown and retry. They do not become `rejected`.
pub fn interpret(input: LifecycleInput<'_>) -> InterpretedTransport {
    let incompatible = input
        .message_phase
        .is_some_and(|value| MessageState::parse(value).is_none())
        || input
            .push_phase
            .is_some_and(|value| PushState::parse(value).is_none());
    if incompatible {
        return InterpretedTransport {
            message: None,
            push: None,
            incompatible: true,
            decision: LifecycleDecision::Reconcile { retry_ms: 60_000 },
            counters: AuthoritativeCounters::unknown(),
        };
    }
    let message = input.message_phase.and_then(MessageState::parse);
    let push = input.push_phase.and_then(PushState::parse);
    let decision = decide_lifecycle(&input, message, push);
    InterpretedTransport {
        message,
        push,
        incompatible: false,
        decision,
        counters: input.counters,
    }
}

fn decide_lifecycle(
    input: &LifecycleInput<'_>,
    message: Option<MessageState>,
    push: Option<PushState>,
) -> LifecycleDecision {
    let retry = |attempt: i64| LifecycleDecision::Reconcile {
        retry_ms: bounded_retry_ms(input.retry_after_ms, attempt).unwrap_or(15_000),
    };
    if input.age_ms >= 86_400_000 {
        return if message == Some(MessageState::RelayAccepted) {
            LifecycleDecision::Accept
        } else {
            LifecycleDecision::Fail
        };
    }
    if input.destination != "marmot" {
        if input.accepted {
            return LifecycleDecision::Accept;
        }
        if input.terminal {
            return LifecycleDecision::Fail;
        }
        let next = input.ordinary_attempts.saturating_add(1);
        if next >= ORDINARY_ATTEMPT_BUDGET {
            return LifecycleDecision::Fail;
        }
        return LifecycleDecision::Retry {
            retry_ms: ordinary_backoff_ms(next),
        };
    }
    if input.disposition == Some(OperationDisposition::Settled) {
        return if message == Some(MessageState::RelayAccepted) {
            LifecycleDecision::Accept
        } else {
            LifecycleDecision::Fail
        };
    }
    if message == Some(MessageState::RelayAccepted) {
        if input.permanent_push_uncertainty || input.age_ms >= 900_000 {
            return LifecycleDecision::Accept;
        }
        // The cryptographic authority owns target attempts. Its explicit
        // reconciliation decision takes priority over any aggregate push label.
        if input.disposition == Some(OperationDisposition::Reconcile) {
            return retry(input.counters.push_reconciles.unwrap_or(0));
        }
    }
    match message {
        Some(MessageState::Rejected) => return LifecycleDecision::Fail,
        Some(MessageState::CompletionUnknown) => {
            let attempts = input.counters.ambiguous_reconciles;
            if attempts.is_some_and(|count| count >= 4) || input.age_ms >= 900_000 {
                return LifecycleDecision::Fail;
            }
            return retry(attempts.unwrap_or(0));
        }
        Some(MessageState::AcceptedPending) | Some(MessageState::Prepared) => {
            let attempts = input
                .counters
                .message_reconciles
                .or(input.counters.message_submissions);
            if attempts.is_some_and(|count| count >= 8) || input.age_ms >= 900_000 {
                return LifecycleDecision::Fail;
            }
            return retry(attempts.unwrap_or(0));
        }
        Some(MessageState::RelayAccepted) => {}
        _ => {
            if input.terminal {
                return LifecycleDecision::Fail;
            }
            if input.accepted {
                return LifecycleDecision::Accept;
            }
            return retry(input.counters.message_submissions.unwrap_or(0));
        }
    }
    match push {
        Some(
            PushState::RelayAccepted
            | PushState::Rejected
            | PushState::Expired
            | PushState::TerminalFailure
            | PushState::NotRequired,
        ) => LifecycleDecision::Accept,
        _ => retry(input.counters.push_reconciles.unwrap_or(0)),
    }
}

fn json_i64(value: &Value, keys: &[&str]) -> Option<i64> {
    keys.iter().find_map(|key| {
        let item = value.get(*key)?;
        if item.is_null() {
            return None;
        }
        if let Some(number) = item.as_i64() {
            return Some(number);
        }
        item.as_u64().and_then(|number| i64::try_from(number).ok())
    })
}

/// A counter is an observed non-negative integer. A negative value, a
/// fractional value, or a number that does not fit in `i64` is not stored.
fn json_counter(value: &Value, keys: &[&str]) -> Option<i64> {
    json_i64(value, keys).filter(|number| *number >= 0)
}

fn json_str<'a>(value: &'a Value, keys: &[&str]) -> Option<&'a str> {
    keys.iter()
        .find_map(|key| value.get(*key).and_then(Value::as_str))
        .filter(|text| !text.is_empty())
}

/// A helper delay is a small relative number. A Unix millisecond timestamp is
/// not a delay and is ignored.
fn relative_delay(value: &Value) -> Option<i64> {
    let nested = value.get("operation").unwrap_or(&Value::Null);
    for source in [value, nested] {
        for key in [
            "retry_after_ms",
            "retryAfterMs",
            "reconcileAfterMs",
            "retryAtMs",
        ] {
            if let Some(millis) = json_i64(source, &[key]) {
                if (1..=300_000).contains(&millis) {
                    return Some(millis);
                }
            }
        }
    }
    None
}

fn disposition_of(value: &Value) -> OperationDisposition {
    let nested = value.get("operation").unwrap_or(&Value::Null);
    let label = json_str(value, &["disposition"]).or_else(|| json_str(nested, &["disposition"]));
    match label {
        Some("settled") => OperationDisposition::Settled,
        Some("reconcile") => OperationDisposition::Reconcile,
        _ if value["settled"] == true || (value["terminal"] == true && value["hold"] != true) => {
            OperationDisposition::Settled
        }
        _ => OperationDisposition::Reconcile,
    }
}

fn counters_from(value: &Value, origin: TransportOrigin) -> AuthoritativeCounters {
    match origin {
        TransportOrigin::NativeHelper => {
            let source = value
                .get("operation")
                .filter(|item| item.is_object())
                .unwrap_or(value);
            AuthoritativeCounters {
                message_submissions: json_counter(source, &["messageSubmissions"]),
                message_publications: json_counter(source, &["messagePublications"]),
                message_reconciles: json_counter(source, &["messageReconciles"]),
                ambiguous_reconciles: json_counter(source, &["ambiguousReconciles"]),
                token_waits: json_counter(source, &["tokenWaits"]),
                push_publications: json_counter(source, &["pushPublications"]),
                push_reconciles: json_counter(source, &["pushReconciles"]),
            }
        }
        TransportOrigin::CloudflareObject => AuthoritativeCounters {
            message_submissions: json_counter(value, &["messageAttempts"]),
            message_publications: json_counter(value, &["messagePublicationAttempts"]),
            message_reconciles: json_counter(value, &["messageReconcileAttempts"]),
            ambiguous_reconciles: json_counter(value, &["unknownAttempts"]),
            token_waits: json_counter(value, &["tokenWaitAttempts"]),
            push_publications: json_counter(value, &["pushPublicationAttempts"]),
            push_reconciles: json_counter(value, &["unobservableAttempts"]),
        },
    }
}

/// The Durable Object name and the request project are the same sender.
/// The character set is the one the transport accepts, so the value can be
/// placed in the query string without further encoding.
pub fn marmot_sender_url(project: &str) -> Option<String> {
    if (1..=128).contains(&project.len())
        && project
            .chars()
            .all(|item| item.is_ascii_alphanumeric() || matches!(item, '_' | ':' | '-'))
    {
        Some(format!(
            "https://marmot-sender.internal/marmot?sender={project}"
        ))
    } else {
        None
    }
}

/// A new alert is `deliver`. An operation the store has already admitted is
/// `reconcile`, which does not encrypt another application message.
pub fn marmot_transport_op(admitted: bool) -> &'static str {
    if admitted {
        "reconcile"
    } else {
        "deliver"
    }
}

pub fn marmot_operation_admitted(
    message_state: Option<&str>,
    message_event_id: Option<&str>,
    preserve_message: bool,
) -> bool {
    preserve_message
        || message_event_id.is_some()
        || matches!(
            message_state,
            Some(
                "relay_accepted"
                    | "accepted"
                    | "accepted_pending"
                    | "prepared"
                    | "completion_unknown"
                    | "rejected"
            )
        )
}

/// A response for another operation or project is not this alert's evidence.
pub fn transport_identity_matches(
    operation: &OperationResult,
    project: &str,
    operation_id: &str,
) -> bool {
    !operation_id.is_empty()
        && operation.operation_id == operation_id
        && operation.project_id == project
}

/// Sanitized fields the operational store keeps. This is not the transport body.
pub fn transport_projection(operation: &OperationResult) -> String {
    let text = json!({
        "operationId": operation.operation_id,
        "projectId": operation.project_id,
        "messageEventId": operation.message_event_id,
        "pushEventId": operation.push_event_id,
        "evidence": operation.evidence.as_str(),
        "disposition": operation.disposition.as_str(),
        "startedAtMs": operation.started_at_ms,
        "updatedAtMs": operation.updated_at_ms,
        "error": operation.error,
    })
    .to_string();
    if text.len() > 2_048 {
        text.chars().take(2_048).collect()
    } else {
        text
    }
}

/// One parser for both Marmot transports. Missing counters stay missing.
/// Unknown message or push names stay unknown.
pub fn operation_from_transport(value: &Value, origin: TransportOrigin) -> OperationResult {
    let nested = value.get("operation").unwrap_or(&Value::Null);
    let message_name = json_str(
        value,
        &[
            "message_state",
            "message_phase",
            "messageState",
            "messagePhase",
        ],
    )
    .or_else(|| json_str(nested, &["messageState", "messagePhase"]));
    let push_name = json_str(
        value,
        &["push_state", "push", "push_phase", "pushState", "pushPhase"],
    )
    .or_else(|| json_str(nested, &["pushState", "pushPhase"]));
    let message = message_name.and_then(MessageState::parse);
    let push = push_name.and_then(PushState::parse);
    let disposition = disposition_of(value);
    let evidence_name = json_str(value, &["push_evidence", "evidence"])
        .or_else(|| json_str(nested, &["evidence"]))
        .unwrap_or("not_observed");
    OperationResult {
        project_id: json_str(value, &["project", "projectId"])
            .or_else(|| json_str(nested, &["projectId"]))
            .unwrap_or_default()
            .to_string(),
        operation_id: json_str(value, &["operation_id", "operationId"])
            .or_else(|| json_str(nested, &["operationId"]))
            .unwrap_or_default()
            .to_string(),
        message,
        message_event_id: json_str(value, &["message_event_id", "messageEventId"])
            .or_else(|| json_str(nested, &["messageEventId"]))
            .map(str::to_string),
        push,
        push_event_id: json_str(value, &["push_event_id", "pushEventId"])
            .or_else(|| json_str(nested, &["pushEventId"]))
            .map(str::to_string),
        evidence: EvidenceClass::parse(evidence_name),
        error: json_str(value, &["error", "push_error"]).map(str::to_string),
        disposition,
        permanent_push_uncertainty: origin == TransportOrigin::NativeHelper
            && push == Some(PushState::Unobservable)
            && disposition == OperationDisposition::Settled,
        started_at_ms: json_i64(value, &["started_at_ms", "startedAtMs"])
            .or_else(|| json_i64(nested, &["startedAtMs"])),
        updated_at_ms: json_i64(value, &["updated_at_ms", "updatedAtMs"]),
        retry_after_ms: relative_delay(value),
        counters: counters_from(value, origin),
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
    fn unknown_transport_state_retries_and_age_settles_without_a_counter() {
        let young = interpret(LifecycleInput {
            destination: "marmot",
            message_phase: Some("completion_unknown"),
            push_phase: None,
            counters: AuthoritativeCounters::unknown(),
            age_ms: 1_000,
            hold: true,
            terminal: false,
            accepted: false,
            ordinary_attempts: 0,
            disposition: None,
            retry_after_ms: None,
            permanent_push_uncertainty: false,
        });
        assert!(!young.incompatible);
        assert!(matches!(
            young.decision,
            LifecycleDecision::Reconcile { .. }
        ));
        let aged = interpret(LifecycleInput {
            destination: "marmot",
            message_phase: Some("completion_unknown"),
            push_phase: None,
            counters: AuthoritativeCounters::unknown(),
            age_ms: 900_000,
            hold: true,
            terminal: false,
            accepted: false,
            ordinary_attempts: 0,
            disposition: None,
            retry_after_ms: None,
            permanent_push_uncertainty: false,
        });
        assert_eq!(aged.decision, LifecycleDecision::Fail);
        let unknown = interpret(LifecycleInput {
            destination: "marmot",
            message_phase: Some("not-a-state"),
            push_phase: Some("relay_accepted"),
            counters: AuthoritativeCounters::unknown(),
            age_ms: 1,
            hold: false,
            terminal: true,
            accepted: false,
            ordinary_attempts: 0,
            disposition: None,
            retry_after_ms: None,
            permanent_push_uncertainty: false,
        });
        assert!(unknown.incompatible);
        assert!(unknown.message.is_none());
        assert!(matches!(
            unknown.decision,
            LifecycleDecision::Reconcile { .. }
        ));
    }

    #[test]
    fn an_accepted_message_survives_push_failure_and_a_supplied_counter_is_not_invented() {
        let mut counters = AuthoritativeCounters::unknown();
        counters.token_waits = Some(1);
        let waiting = interpret(LifecycleInput {
            destination: "marmot",
            message_phase: Some("message_accepted"),
            push_phase: Some("push_token_unavailable"),
            counters,
            age_ms: 1_000,
            hold: true,
            terminal: false,
            accepted: true,
            ordinary_attempts: 0,
            disposition: None,
            retry_after_ms: Some(15_000),
            permanent_push_uncertainty: false,
        });
        assert_eq!(waiting.message, Some(MessageState::RelayAccepted));
        assert_eq!(waiting.push, Some(PushState::TokenUnavailable));
        assert!(matches!(
            waiting.decision,
            LifecycleDecision::Reconcile { .. }
        ));
        let rejected = interpret(LifecycleInput {
            destination: "marmot",
            message_phase: Some("relay_accepted"),
            push_phase: Some("rejected"),
            counters: AuthoritativeCounters::unknown(),
            age_ms: 1_000,
            hold: false,
            terminal: true,
            accepted: true,
            ordinary_attempts: 0,
            disposition: None,
            retry_after_ms: None,
            permanent_push_uncertainty: false,
        });
        assert_eq!(rejected.decision, LifecycleDecision::Accept);
        assert_eq!(rejected.message, Some(MessageState::RelayAccepted));
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

    fn marmot<'a>(
        message: &'a str,
        push: &'a str,
        counters: AuthoritativeCounters,
        disposition: Option<OperationDisposition>,
        permanent: bool,
    ) -> LifecycleInput<'a> {
        LifecycleInput {
            destination: "marmot",
            message_phase: Some(message),
            push_phase: Some(push),
            counters,
            age_ms: 1_000,
            hold: disposition == Some(OperationDisposition::Reconcile),
            terminal: disposition == Some(OperationDisposition::Settled),
            accepted: message == "relay_accepted",
            ordinary_attempts: 0,
            disposition,
            retry_after_ms: Some(15_000),
            permanent_push_uncertainty: permanent,
        }
    }

    #[test]
    fn native_permanent_uncertainty_settles_and_cloudflare_uncertainty_reconciles() {
        let mut native_counters = AuthoritativeCounters::unknown();
        native_counters.message_submissions = Some(1);
        native_counters.push_publications = None;
        let native = interpret(marmot(
            "relay_accepted",
            "unobservable",
            native_counters,
            Some(OperationDisposition::Settled),
            true,
        ));
        assert_eq!(native.decision, LifecycleDecision::Accept);
        assert_eq!(native.message, Some(MessageState::RelayAccepted));
        assert!(native.counters.push_publications.is_none());

        let mut cloud = AuthoritativeCounters::unknown();
        cloud.message_submissions = Some(1);
        cloud.push_publications = Some(1);
        let temporary = interpret(marmot(
            "relay_accepted",
            "unobservable",
            cloud,
            Some(OperationDisposition::Reconcile),
            false,
        ));
        assert!(matches!(
            temporary.decision,
            LifecycleDecision::Reconcile { retry_ms: 15_000 }
        ));
        assert_eq!(temporary.message, Some(MessageState::RelayAccepted));
    }

    #[test]
    fn ordinary_delivery_stops_at_eight_attempts() {
        let young = interpret(LifecycleInput {
            destination: "nostr",
            message_phase: None,
            push_phase: None,
            counters: AuthoritativeCounters::unknown(),
            age_ms: 1_000,
            hold: false,
            terminal: false,
            accepted: false,
            ordinary_attempts: 0,
            disposition: None,
            retry_after_ms: None,
            permanent_push_uncertainty: false,
        });
        assert_eq!(
            young.decision,
            LifecycleDecision::Retry { retry_ms: 30_000 }
        );
        let last = interpret(LifecycleInput {
            destination: "telegram",
            message_phase: None,
            push_phase: None,
            counters: AuthoritativeCounters::unknown(),
            age_ms: 1_000,
            hold: false,
            terminal: false,
            accepted: false,
            ordinary_attempts: 7,
            disposition: None,
            retry_after_ms: None,
            permanent_push_uncertainty: false,
        });
        assert_eq!(last.decision, LifecycleDecision::Fail);
    }

    #[test]
    fn a_delay_is_not_read_as_a_unix_timestamp_and_missing_counters_stay_missing() {
        let native = operation_from_transport(
            &json!({
                "operation_id": "alt_1",
                "project": "smartflowsocial",
                "message_state": "relay_accepted",
                "message_event_id": "abc",
                "push": "unobservable",
                "message_attempts": 4,
                "push_attempts": 9,
                "settled": true,
                "retryAtMs": 15_000,
                "operation": {
                    "messageSubmissions": 1,
                    "messagePublications": null,
                    "pushPublications": null,
                    "pushReconciles": 1,
                    "retryAtMs": 1_700_000_000_000_i64
                }
            }),
            TransportOrigin::NativeHelper,
        );
        assert_eq!(native.retry_after_ms, Some(15_000));
        assert!(native.permanent_push_uncertainty);
        assert_eq!(native.counters.message_submissions, Some(1));
        assert!(native.counters.message_publications.is_none());
        assert!(native.counters.push_publications.is_none());
        assert_eq!(native.counters.push_reconciles, Some(1));
        assert_eq!(native.disposition, OperationDisposition::Settled);

        let cloud = operation_from_transport(
            &json!({
                "operationId": "alt_1",
                "projectId": "smartflowsocial",
                "messagePhase": "relay_accepted",
                "pushPhase": "unobservable",
                "disposition": "reconcile",
                "reconcileAfterMs": 15_000,
                "messageAttempts": 1,
                "messagePublicationAttempts": 1,
                "pushAttempts": 9,
                "pushPublicationAttempts": 1,
                "unobservableAttempts": 0,
                "messagePublicationAttemptsNegative": -1
            }),
            TransportOrigin::CloudflareObject,
        );
        assert!(!cloud.permanent_push_uncertainty);
        assert_eq!(cloud.disposition, OperationDisposition::Reconcile);
        assert_eq!(cloud.counters.message_submissions, Some(1));
        assert_eq!(cloud.counters.message_publications, Some(1));
        assert_eq!(cloud.counters.push_publications, Some(1));
        assert_eq!(cloud.counters.push_reconciles, Some(0));
        assert!(cloud.counters.token_waits.is_none());
        let rejected = operation_from_transport(
            &json!({
                "operationId": "alt_1",
                "messageAttempts": -1,
                "pushPublicationAttempts": -3
            }),
            TransportOrigin::CloudflareObject,
        );
        assert!(rejected.counters.message_submissions.is_none());
        assert!(rejected.counters.push_publications.is_none());
        assert_eq!(
            operation_from_transport(
                &json!({"messagePhase": "not-a-state", "pushPhase": "rejected"}),
                TransportOrigin::CloudflareObject,
            )
            .message,
            None
        );
    }

    #[test]
    fn native_fixtures_use_nested_counters_and_ignore_legacy_attempt_fields() {
        let fixtures: Value =
            serde_json::from_str(include_str!("../../../docs/native-operation-fixtures.json"))
                .expect("fixtures");
        let permanent = operation_from_transport(
            &fixtures["permanentUnobservablePush"],
            TransportOrigin::NativeHelper,
        );
        assert!(permanent.permanent_push_uncertainty);
        assert_eq!(permanent.counters.message_submissions, Some(1));
        assert!(permanent.counters.message_publications.is_none());
        assert!(permanent.counters.push_publications.is_none());
        assert_eq!(permanent.counters.push_reconciles, Some(1));
        assert_eq!(
            interpret(LifecycleInput {
                destination: "marmot",
                message_phase: permanent.message.map(MessageState::as_str),
                push_phase: permanent.push.map(PushState::as_str),
                counters: permanent.counters,
                age_ms: 1_000,
                hold: false,
                terminal: false,
                accepted: true,
                ordinary_attempts: 0,
                disposition: Some(permanent.disposition),
                retry_after_ms: permanent.retry_after_ms,
                permanent_push_uncertainty: permanent.permanent_push_uncertainty,
            })
            .decision,
            LifecycleDecision::Accept
        );

        let pending = operation_from_transport(
            &fixtures["messagePublicationUncertain"],
            TransportOrigin::NativeHelper,
        );
        assert_eq!(pending.counters.message_submissions, Some(1));
        assert_eq!(pending.counters.message_reconciles, Some(1));
        assert!(pending.counters.message_publications.is_none());
        assert_eq!(pending.retry_after_ms, Some(15_000));

        let unknown = operation_from_transport(
            &fixtures["completionUnknown"],
            TransportOrigin::NativeHelper,
        );
        assert!(unknown.counters.message_submissions.is_none());
        assert_eq!(unknown.counters.ambiguous_reconciles, Some(1));
    }

    #[test]
    fn a_reconcile_disposition_does_not_settle_on_an_aggregate_push_label() {
        let decision = interpret(LifecycleInput {
            destination: "marmot",
            message_phase: Some("relay_accepted"),
            push_phase: Some("relay_accepted"),
            counters: AuthoritativeCounters {
                message_submissions: Some(1),
                message_publications: Some(1),
                message_reconciles: Some(0),
                ambiguous_reconciles: Some(0),
                token_waits: Some(0),
                push_publications: Some(5),
                push_reconciles: Some(4),
            },
            age_ms: 1_000,
            hold: true,
            terminal: false,
            accepted: true,
            ordinary_attempts: 0,
            disposition: Some(OperationDisposition::Reconcile),
            retry_after_ms: Some(15_000),
            permanent_push_uncertainty: false,
        });
        assert_eq!(
            decision.decision,
            LifecycleDecision::Reconcile { retry_ms: 15_000 }
        );
    }

    #[test]
    fn cloudflare_recorded_push_attempts_are_not_publication_attempts() {
        let value = json!({
            "ok": true,
            "operationId": "alert-1",
            "projectId": "smartflowsocial",
            "messagePhase": "relay_accepted",
            "pushPhase": "unobservable",
            "evidence": "partial_push",
            "disposition": "reconcile",
            "error": "publication_timeout",
            "retryAfterMs": 15000,
            "messageAttempts": 1,
            "messagePublicationAttempts": 1,
            "messageReconcileAttempts": 0,
            "unknownAttempts": 0,
            "tokenWaitAttempts": 0,
            "pushAttempts": 4,
            "pushPublicationAttempts": 1,
            "unobservableAttempts": 1
        });
        let operation = operation_from_transport(&value, TransportOrigin::CloudflareObject);
        assert_eq!(operation.evidence, EvidenceClass::PartialPush);
        assert_eq!(operation.counters.push_publications, Some(1));
        assert_eq!(operation.counters.push_reconciles, Some(1));
        assert_ne!(operation.counters.push_publications, Some(4));
        assert!(transport_identity_matches(
            &operation,
            "smartflowsocial",
            "alert-1"
        ));
        assert!(!transport_identity_matches(
            &operation,
            "nostrmash",
            "alert-1"
        ));
        assert_eq!(
            marmot_sender_url("smartflowsocial").as_deref(),
            Some("https://marmot-sender.internal/marmot?sender=smartflowsocial")
        );
        assert!(marmot_sender_url("bad project").is_none());
        assert_eq!(marmot_transport_op(false), "deliver");
        assert_eq!(marmot_transport_op(true), "reconcile");
        assert!(marmot_operation_admitted(
            Some("relay_accepted"),
            None,
            false
        ));
        assert!(!marmot_operation_admitted(None, None, false));
    }
}
