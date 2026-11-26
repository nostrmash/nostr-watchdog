//! Decisions for Marmot send, push, and conversation recovery.
//!
//! MDK's durable local-send status is authoritative whenever it exists.
//! A cached pending result must not become immutable, and an absent upstream
//! record after a submission has started is not permission to encrypt the
//! alert again. Push publication is a separate operation: its failure never
//! rewrites a published application message into an unpublished one.

/// Last message phase this process stored for one alert.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StoredSend {
    Submitting,
    Pending,
    Published,
    Rejected,
    CompletionUnknown,
}

/// What official MDK reports for the alert's client token.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UpstreamSend {
    Absent,
    Queued,
    EngineOwned,
    Published,
    AcceptedPending,
    CompletionUnknown,
    Rejected,
}

/// The next action for one alert. `ProjectUpstream` replaces the cache.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SendStep {
    ProjectUpstream,
    KeepStoredTerminal,
    CompletionUnknown,
    Submit,
    IdentityMismatch,
}

pub fn reconcile_send(
    stored: Option<StoredSend>,
    identity_matches: bool,
    upstream: UpstreamSend,
) -> SendStep {
    if stored.is_some() && !identity_matches {
        return SendStep::IdentityMismatch;
    }
    if upstream != UpstreamSend::Absent {
        return SendStep::ProjectUpstream;
    }
    match stored {
        None => SendStep::Submit,
        Some(StoredSend::Published | StoredSend::Rejected) => SendStep::KeepStoredTerminal,
        Some(StoredSend::Submitting | StoredSend::Pending | StoredSend::CompletionUnknown) => {
            SendStep::CompletionUnknown
        }
    }
}

/// Where a process died relative to the durable journal and MDK's record.
/// Recovery never chooses [`SendStep::Submit`] for an operation that already
/// passed the intent record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CrashPoint {
    IntentRecorded,
    SubmittedToMdk,
    PendingPublication,
    RelayAccepted,
    ResultPersisted,
    IpcTimeout,
    PushPublication,
}

pub fn recover_after_crash(point: CrashPoint, upstream: UpstreamSend) -> SendStep {
    let stored = match point {
        CrashPoint::IntentRecorded | CrashPoint::IpcTimeout => Some(StoredSend::Submitting),
        CrashPoint::SubmittedToMdk | CrashPoint::PendingPublication => Some(StoredSend::Submitting),
        CrashPoint::RelayAccepted => Some(StoredSend::Published),
        CrashPoint::ResultPersisted | CrashPoint::PushPublication => Some(StoredSend::Published),
    };
    let upstream = match (point, upstream) {
        (CrashPoint::RelayAccepted, UpstreamSend::Absent) => UpstreamSend::Published,
        (CrashPoint::PushPublication, UpstreamSend::Absent) => UpstreamSend::Published,
        (_, upstream) => upstream,
    };
    let step = reconcile_send(stored, true, upstream);
    if step == SendStep::Submit {
        SendStep::CompletionUnknown
    } else {
        step
    }
}

/// Result of asking MDK whether a direct conversation with the peer exists.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConversationLookup {
    /// The peer index is incomplete. This is not evidence that no group exists.
    NotReady,
    Reusable,
    /// A conversation exists but must not be treated as a fresh direct chat.
    NotReusable,
    None,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConversationStep {
    UseSaved,
    RetryIndex,
    UseExisting,
    NotReusable,
    Create,
}

/// `saved` is a group id already bound to this sender and recipient.
/// An unavailable index never selects [`ConversationStep::Create`].
pub fn reconcile_conversation(saved: Option<&str>, lookup: ConversationLookup) -> ConversationStep {
    let record = if saved.is_some_and(|group| !group.is_empty()) {
        ConversationRecord::Established
    } else {
        ConversationRecord::Absent
    };
    reconcile_conversation_record(record, lookup)
}

/// Local conversation journal, including a create that has not returned.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConversationRecord {
    Absent,
    /// A create was started. `empty_lookups` counts ready index misses.
    Intending { empty_lookups: i64, age_ms: i64 },
    Established,
}

/// Ready-index misses required before an intent may create a group.
pub const INTENT_READY_EMPTY_LOOKUPS: i64 = 2;
/// Minimum age of an intent before a ready index miss may create a group.
pub const INTENT_MIN_AGE_MS: i64 = 15_000;

/// An intent is reconciled. A ready index miss is not enough on its own:
/// the create may already have succeeded and not be visible yet.
pub fn reconcile_conversation_record(
    record: ConversationRecord,
    lookup: ConversationLookup,
) -> ConversationStep {
    match record {
        ConversationRecord::Established => ConversationStep::UseSaved,
        ConversationRecord::Absent => match lookup {
            ConversationLookup::NotReady => ConversationStep::RetryIndex,
            ConversationLookup::Reusable => ConversationStep::UseExisting,
            ConversationLookup::NotReusable => ConversationStep::NotReusable,
            ConversationLookup::None => ConversationStep::Create,
        },
        ConversationRecord::Intending {
            empty_lookups,
            age_ms,
        } => match lookup {
            ConversationLookup::Reusable => ConversationStep::UseExisting,
            ConversationLookup::NotReusable => ConversationStep::NotReusable,
            ConversationLookup::NotReady => ConversationStep::RetryIndex,
            ConversationLookup::None => {
                if empty_lookups >= INTENT_READY_EMPTY_LOOKUPS && age_ms >= INTENT_MIN_AGE_MS {
                    ConversationStep::Create
                } else {
                    ConversationStep::RetryIndex
                }
            }
        },
    }
}

/// How many times the engine's single outbox counter may retry a held Marmot
/// result. The helper uses the separate budgets below. This shared cap remains
/// so a caller that has not split its counters still stops.
pub const RECONCILE_BUDGET: i64 = 8;

/// Refreshes of a message MDK still owns.
pub const MESSAGE_ATTEMPT_BUDGET: i64 = 8;
/// Refreshes after the helper has already lost the upstream record.
pub const UNKNOWN_ATTEMPT_BUDGET: i64 = 4;
/// Observations of a push result the pinned runtime does not return.
pub const UNOBSERVABLE_ATTEMPT_BUDGET: i64 = 2;
/// One hold so a missing token can be recorded, then stop. A later token does
/// not republish the trigger for an already accepted message.
pub const TOKEN_WAIT_BUDGET: i64 = 2;
pub const PENDING_MAX_AGE_MS: i64 = 15 * 60 * 1000;
pub const OPERATION_MAX_AGE_MS: i64 = 24 * 60 * 60 * 1000;

pub fn reconcile_attempt(prior_attempts: i64) -> i64 {
    prior_attempts.saturating_add(1)
}

pub fn reconcile_exhausted(hold: bool, attempt: i64) -> bool {
    hold && attempt >= RECONCILE_BUDGET
}

/// Error code stored when the engine's shared counter reaches [`RECONCILE_BUDGET`].
/// A relay-accepted message stays relay-accepted; the code describes push or
/// publication uncertainty, not a missing ciphertext.
pub fn exhausted_push_error(message_phase: Option<&str>, push_phase: Option<&str>) -> &'static str {
    match message_phase {
        Some("relay_accepted") => match push_phase {
            Some("token_unavailable" | "recipient_push_token_unavailable") => {
                "recipient_push_token_unavailable"
            }
            Some("rejected" | "terminal_failure") => "push_terminal_failure",
            _ => "push_unobservable",
        },
        Some("accepted_pending") => "marmot_publish_unconfirmed",
        Some("completion_unknown") => "marmot_completion_unknown",
        _ => "marmot_reconcile_exhausted",
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PhaseAttempts {
    pub message: i64,
    pub unknown: i64,
    pub token_wait: i64,
    pub unobservable: i64,
    pub started_at_ms: i64,
}

impl Default for PhaseAttempts {
    fn default() -> Self {
        Self {
            message: 0,
            unknown: 0,
            token_wait: 0,
            unobservable: 0,
            started_at_ms: 0,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PhaseDecision {
    pub push_phase: &'static str,
    pub hold: bool,
    pub delay_ms: i64,
    pub preserve_message: bool,
    pub terminal: bool,
}

fn retry_delay(attempt: i64) -> i64 {
    let shift = attempt.saturating_sub(1).clamp(0, 4) as u32;
    15_000_i64.saturating_mul(1_i64 << shift).min(300_000)
}

fn aged_out(attempts: PhaseAttempts, now_ms: i64, limit_ms: i64) -> bool {
    attempts.started_at_ms > 0 && now_ms.saturating_sub(attempts.started_at_ms) >= limit_ms
}

/// Separate counters for the message and the push trigger.
///
/// `push_phase` is the raw observation for this check. A published message is
/// never turned back into an unpublished one because the trigger cannot be
/// confirmed. The pinned runtime does not return relay acceptance, rejection
/// of a successful publish, expiration, or a push operation id, so those states
/// are not produced here.
pub fn advance_phase(
    message_phase: &str,
    push_phase: &str,
    mut attempts: PhaseAttempts,
    now_ms: i64,
) -> (PhaseAttempts, PhaseDecision) {
    if attempts.started_at_ms == 0 {
        attempts.started_at_ms = now_ms;
    }
    let settled = |push_phase: &'static str, preserve_message: bool, terminal: bool| PhaseDecision {
        push_phase,
        hold: false,
        delay_ms: 0,
        preserve_message,
        terminal,
    };
    let hold = |push_phase: &'static str, attempt: i64| PhaseDecision {
        push_phase,
        hold: true,
        delay_ms: retry_delay(attempt),
        preserve_message: true,
        terminal: false,
    };
    let decision = match message_phase {
        "rejected" => settled("not_attempted", false, true),
        "relay_accepted" => match push_phase {
            "rejected" => settled("rejected", true, false),
            "terminal_failure" => settled("terminal_failure", true, false),
            "unobservable" => settled("unobservable", true, false),
            "token_unavailable" | "recipient_push_token_unavailable" => {
                if attempts.token_wait >= TOKEN_WAIT_BUDGET
                    || aged_out(attempts, now_ms, OPERATION_MAX_AGE_MS)
                {
                    settled("token_unavailable", true, false)
                } else {
                    attempts.token_wait = attempts.token_wait.saturating_add(1);
                    if attempts.token_wait >= TOKEN_WAIT_BUDGET
                        || aged_out(attempts, now_ms, OPERATION_MAX_AGE_MS)
                    {
                        settled("token_unavailable", true, false)
                    } else {
                        hold("token_unavailable", attempts.token_wait)
                    }
                }
            }
            "publication_attempted" | "prepared" | "push_disposition_unknown" | "not_attempted" => {
                if attempts.unobservable >= UNOBSERVABLE_ATTEMPT_BUDGET
                    || aged_out(attempts, now_ms, OPERATION_MAX_AGE_MS)
                {
                    settled("unobservable", true, false)
                } else {
                    attempts.unobservable = attempts.unobservable.saturating_add(1);
                    if attempts.unobservable >= UNOBSERVABLE_ATTEMPT_BUDGET
                        || aged_out(attempts, now_ms, OPERATION_MAX_AGE_MS)
                    {
                        settled("unobservable", true, false)
                    } else {
                        hold("publication_attempted", attempts.unobservable)
                    }
                }
            }
            other => {
                let _ = other;
                settled("unobservable", true, false)
            }
        },
        "accepted_pending" => {
            attempts.message = attempts.message.saturating_add(1);
            if attempts.message >= MESSAGE_ATTEMPT_BUDGET
                || aged_out(attempts, now_ms, PENDING_MAX_AGE_MS)
            {
                settled("not_attempted", true, true)
            } else {
                hold("not_attempted", attempts.message)
            }
        }
        _ => {
            attempts.unknown = attempts.unknown.saturating_add(1);
            if attempts.unknown >= UNKNOWN_ATTEMPT_BUDGET
                || aged_out(attempts, now_ms, PENDING_MAX_AGE_MS)
            {
                settled("not_attempted", true, true)
            } else {
                hold("not_attempted", attempts.unknown)
            }
        }
    };
    (attempts, decision)
}

/// What the helper can say about push from the current MDK API.
///
/// Relay acceptance is absent on purpose. `submit_text` publishes the trigger
/// and discards the event id and the relay acknowledgement.
pub fn classify_push(
    message_published: bool,
    active_recipient_tokens: i64,
    publish_error_observed: bool,
) -> (&'static str, &'static str) {
    if !message_published {
        return ("not_attempted", "not_attempted");
    }
    if publish_error_observed {
        return ("rejected", "publish_error_observed");
    }
    if active_recipient_tokens <= 0 {
        return ("token_unavailable", "token_availability_only");
    }
    (
        "publication_attempted",
        "mdk_discards_publish_result",
    )
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TokenObservation<'a> {
    pub member_id_hex: &'a str,
    pub active_leaf: bool,
    pub member_matches_active_leaf: bool,
}

/// Active tokens for the configured recipient only. Another member's token,
/// a stale leaf, and a record that does not match its leaf do not count.
/// Several active leaves of the recipient count as several devices.
pub fn active_recipient_tokens(tokens: &[TokenObservation<'_>], recipient: &str) -> i64 {
    tokens
        .iter()
        .filter(|token| {
            token.member_matches_active_leaf
                && token.active_leaf
                && token.member_id_hex.eq_ignore_ascii_case(recipient)
        })
        .count() as i64
}

/// Whether the operational cache may be used for this sender and recipient.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IdentityStep {
    UseCached,
    Import,
    /// An explicit onboard operation id must be reconciled. This is not a
    /// reason to import again on every alert.
    ExplicitOnboard,
    SenderMismatch,
    RecipientMismatch,
    /// A group id is saved without the recipient it was created for.
    RecipientUnbound,
    StorageMissing,
    DeviceInvalid,
    StorageReplaced,
    GroupUnavailable,
}

/// Evidence read from the helper's MDK home. Callers fail closed when the
/// cache names an account the storage no longer contains.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IdentityEvidence {
    pub account_in_storage: bool,
    pub device_can_sign: bool,
    pub storage_matches: bool,
    pub group_available: Option<bool>,
}

pub fn bind_identity(
    cached_sender: Option<&str>,
    expected_sender: Option<&str>,
    cached_peer: Option<&str>,
    cached_group: Option<&str>,
    recipient: &str,
    reonboard: bool,
) -> IdentityStep {
    bind_stored_identity(
        cached_sender,
        expected_sender,
        cached_peer,
        cached_group,
        recipient,
        reonboard,
        IdentityEvidence {
            account_in_storage: true,
            device_can_sign: true,
            storage_matches: true,
            group_available: None,
        },
    )
}

pub fn bind_stored_identity(
    cached_sender: Option<&str>,
    expected_sender: Option<&str>,
    cached_peer: Option<&str>,
    cached_group: Option<&str>,
    recipient: &str,
    explicit_onboard: bool,
    evidence: IdentityEvidence,
) -> IdentityStep {
    if let (Some(cached), Some(expected)) = (filled(cached_sender), filled(expected_sender)) {
        if !cached.eq_ignore_ascii_case(expected) && !explicit_onboard {
            return IdentityStep::SenderMismatch;
        }
    }
    if let Some(peer) = filled(cached_peer) {
        if !peer.eq_ignore_ascii_case(recipient) && !explicit_onboard {
            return IdentityStep::RecipientMismatch;
        }
    } else if filled(cached_group).is_some() && !explicit_onboard {
        return IdentityStep::RecipientUnbound;
    }
    if explicit_onboard {
        return IdentityStep::ExplicitOnboard;
    }
    if filled(cached_sender).is_some() {
        if !evidence.storage_matches {
            return IdentityStep::StorageReplaced;
        }
        if !evidence.account_in_storage {
            return IdentityStep::StorageMissing;
        }
        if !evidence.device_can_sign {
            return IdentityStep::DeviceInvalid;
        }
        if evidence.group_available == Some(false) {
            return IdentityStep::GroupUnavailable;
        }
        IdentityStep::UseCached
    } else {
        IdentityStep::Import
    }
}

/// A manual retry must not encrypt again when any durable record of the
/// operation exists, including a settled unknown completion.
pub fn dead_letter_may_resubmit(stored: Option<StoredSend>) -> bool {
    stored.is_none()
}

fn filled(value: Option<&str>) -> Option<&str> {
    value.filter(|item| !item.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pending_cache_follows_a_later_upstream_publication() {
        assert_eq!(
            reconcile_send(Some(StoredSend::Pending), true, UpstreamSend::Published),
            SendStep::ProjectUpstream
        );
    }

    #[test]
    fn pending_without_upstream_does_not_submit_again() {
        assert_eq!(
            reconcile_send(Some(StoredSend::Pending), true, UpstreamSend::Absent),
            SendStep::CompletionUnknown
        );
        assert_eq!(
            reconcile_send(Some(StoredSend::Submitting), true, UpstreamSend::Absent),
            SendStep::CompletionUnknown
        );
    }

    #[test]
    fn a_new_alert_submits_and_a_terminal_cache_is_kept_when_upstream_is_gone() {
        assert_eq!(
            reconcile_send(None, true, UpstreamSend::Absent),
            SendStep::Submit
        );
        assert_eq!(
            reconcile_send(Some(StoredSend::Published), true, UpstreamSend::Absent),
            SendStep::KeepStoredTerminal
        );
    }

    #[test]
    fn a_changed_payload_is_not_resubmitted() {
        assert_eq!(
            reconcile_send(Some(StoredSend::Pending), false, UpstreamSend::Absent),
            SendStep::IdentityMismatch
        );
    }

    #[test]
    fn crash_points_do_not_encrypt_again() {
        let points = [
            CrashPoint::IntentRecorded,
            CrashPoint::SubmittedToMdk,
            CrashPoint::PendingPublication,
            CrashPoint::RelayAccepted,
            CrashPoint::ResultPersisted,
            CrashPoint::IpcTimeout,
            CrashPoint::PushPublication,
        ];
        for point in points {
            for upstream in [
                UpstreamSend::Absent,
                UpstreamSend::Queued,
                UpstreamSend::Published,
                UpstreamSend::Rejected,
                UpstreamSend::CompletionUnknown,
            ] {
                assert_ne!(
                    recover_after_crash(point, upstream),
                    SendStep::Submit,
                    "{point:?} {upstream:?}"
                );
            }
        }
        assert_eq!(
            recover_after_crash(CrashPoint::PushPublication, UpstreamSend::Published),
            SendStep::ProjectUpstream
        );
        assert_eq!(
            recover_after_crash(CrashPoint::IpcTimeout, UpstreamSend::Absent),
            SendStep::CompletionUnknown
        );
        assert_eq!(
            recover_after_crash(CrashPoint::SubmittedToMdk, UpstreamSend::Rejected),
            SendStep::ProjectUpstream
        );
    }

    #[test]
    fn a_refused_commit_is_projected_and_not_encrypted_again() {
        assert_eq!(
            reconcile_send(Some(StoredSend::Submitting), true, UpstreamSend::Rejected),
            SendStep::ProjectUpstream
        );
        assert!(!dead_letter_may_resubmit(Some(StoredSend::Published)));
        assert!(!dead_letter_may_resubmit(Some(StoredSend::CompletionUnknown)));
        assert!(dead_letter_may_resubmit(None));
    }

    #[test]
    fn an_unready_conversation_index_does_not_create_a_group() {
        assert_eq!(
            reconcile_conversation(None, ConversationLookup::NotReady),
            ConversationStep::RetryIndex
        );
        assert_eq!(
            reconcile_conversation(Some("abc"), ConversationLookup::NotReady),
            ConversationStep::UseSaved
        );
        assert_eq!(
            reconcile_conversation(None, ConversationLookup::None),
            ConversationStep::Create
        );
        assert_eq!(
            reconcile_conversation(None, ConversationLookup::NotReusable),
            ConversationStep::NotReusable
        );
    }

    #[test]
    fn a_creation_intent_is_not_treated_as_proof_that_no_group_exists() {
        let fresh = ConversationRecord::Intending {
            empty_lookups: 0,
            age_ms: 0,
        };
        assert_eq!(
            reconcile_conversation_record(fresh, ConversationLookup::None),
            ConversationStep::RetryIndex
        );
        assert_eq!(
            reconcile_conversation_record(fresh, ConversationLookup::NotReady),
            ConversationStep::RetryIndex
        );
        assert_eq!(
            reconcile_conversation_record(fresh, ConversationLookup::Reusable),
            ConversationStep::UseExisting
        );
        let ready = ConversationRecord::Intending {
            empty_lookups: INTENT_READY_EMPTY_LOOKUPS,
            age_ms: INTENT_MIN_AGE_MS,
        };
        assert_eq!(
            reconcile_conversation_record(ready, ConversationLookup::None),
            ConversationStep::Create
        );
        assert_eq!(
            reconcile_conversation_record(ConversationRecord::Established, ConversationLookup::None),
            ConversationStep::UseSaved
        );
    }

    #[test]
    fn message_and_push_budgets_are_independent() {
        let started = PhaseAttempts {
            started_at_ms: 1_000,
            ..PhaseAttempts::default()
        };
        let (attempts, pending) = advance_phase("accepted_pending", "not_attempted", started, 2_000);
        assert!(pending.hold);
        assert!(pending.preserve_message);
        assert_eq!(attempts.message, 1);
        assert_eq!(attempts.unobservable, 0);

        let mut published = started;
        let (attempts, first) = advance_phase(
            "relay_accepted",
            "publication_attempted",
            published,
            2_000,
        );
        assert!(first.hold);
        assert_eq!(first.push_phase, "publication_attempted");
        assert!(first.preserve_message);
        published = attempts;
        let (attempts, second) = advance_phase(
            "relay_accepted",
            "publication_attempted",
            published,
            3_000,
        );
        assert!(!second.hold);
        assert_eq!(second.push_phase, "unobservable");
        assert!(second.preserve_message);
        assert!(!second.terminal);
        assert_eq!(attempts.message, 0);

        let rejected = advance_phase("relay_accepted", "rejected", started, 2_000).1;
        assert!(!rejected.hold);
        assert_eq!(rejected.push_phase, "rejected");
        assert!(rejected.preserve_message);

        let aged = PhaseAttempts {
            started_at_ms: 0,
            message: MESSAGE_ATTEMPT_BUDGET - 1,
            ..PhaseAttempts::default()
        };
        let (_, exhausted) = advance_phase("accepted_pending", "not_attempted", aged, 5_000);
        assert!(exhausted.terminal);
        assert!(exhausted.preserve_message);
        assert!(!exhausted.hold);
    }

    #[test]
    fn push_classification_uses_only_observed_evidence() {
        assert_eq!(
            classify_push(false, 2, false),
            ("not_attempted", "not_attempted")
        );
        assert_eq!(
            classify_push(true, 0, false),
            ("token_unavailable", "token_availability_only")
        );
        assert_eq!(
            classify_push(true, 2, false),
            ("publication_attempted", "mdk_discards_publish_result")
        );
        assert_eq!(
            classify_push(true, 2, true),
            ("rejected", "publish_error_observed")
        );
    }

    #[test]
    fn only_the_recipients_active_devices_count_as_push_targets() {
        let recipient = "bb";
        let tokens = [
            TokenObservation {
                member_id_hex: recipient,
                active_leaf: true,
                member_matches_active_leaf: true,
            },
            TokenObservation {
                member_id_hex: recipient,
                active_leaf: true,
                member_matches_active_leaf: true,
            },
            TokenObservation {
                member_id_hex: "cc",
                active_leaf: true,
                member_matches_active_leaf: true,
            },
            TokenObservation {
                member_id_hex: recipient,
                active_leaf: true,
                member_matches_active_leaf: false,
            },
            TokenObservation {
                member_id_hex: recipient,
                active_leaf: false,
                member_matches_active_leaf: true,
            },
        ];
        assert_eq!(active_recipient_tokens(&tokens, recipient), 2);
        assert_eq!(active_recipient_tokens(&tokens, "no-such"), 0);
    }

    #[test]
    fn reconciliation_stops_at_the_budget_with_an_explicit_push_outcome() {
        assert!(!reconcile_exhausted(true, RECONCILE_BUDGET - 1));
        assert!(reconcile_exhausted(true, RECONCILE_BUDGET));
        assert!(!reconcile_exhausted(false, RECONCILE_BUDGET));
        assert_eq!(
            exhausted_push_error(Some("relay_accepted"), Some("push_disposition_unknown")),
            "push_unobservable"
        );
        assert_eq!(
            exhausted_push_error(Some("relay_accepted"), Some("publication_attempted")),
            "push_unobservable"
        );
        assert_eq!(
            exhausted_push_error(
                Some("relay_accepted"),
                Some("recipient_push_token_unavailable")
            ),
            "recipient_push_token_unavailable"
        );
        assert_eq!(
            exhausted_push_error(Some("relay_accepted"), Some("rejected")),
            "push_terminal_failure"
        );
        assert_eq!(
            exhausted_push_error(Some("accepted_pending"), None),
            "marmot_publish_unconfirmed"
        );
        assert_eq!(
            exhausted_push_error(Some("completion_unknown"), None),
            "marmot_completion_unknown"
        );
    }

    #[test]
    fn cached_identities_fail_closed_until_explicit_reonboard() {
        assert_eq!(
            bind_identity(
                Some("aa"),
                Some("bb"),
                Some("cc"),
                Some("group"),
                "cc",
                false
            ),
            IdentityStep::SenderMismatch
        );
        assert_eq!(
            bind_identity(
                Some("aa"),
                Some("aa"),
                Some("cc"),
                Some("group"),
                "dd",
                false
            ),
            IdentityStep::RecipientMismatch
        );
        assert_eq!(
            bind_identity(Some("aa"), Some("aa"), None, Some("group"), "dd", false),
            IdentityStep::RecipientUnbound
        );
        assert_eq!(
            bind_identity(
                Some("aa"),
                Some("bb"),
                Some("cc"),
                Some("group"),
                "dd",
                true
            ),
            IdentityStep::ExplicitOnboard
        );
        assert_eq!(
            bind_identity(
                Some("aa"),
                Some("AA"),
                Some("cc"),
                Some("group"),
                "cc",
                false
            ),
            IdentityStep::UseCached
        );
    }

    #[test]
    fn missing_storage_device_or_group_does_not_silently_replace_the_conversation() {
        let broken = IdentityEvidence {
            account_in_storage: false,
            device_can_sign: false,
            storage_matches: false,
            group_available: Some(false),
        };
        assert_eq!(
            bind_stored_identity(
                Some("aa"),
                Some("aa"),
                Some("cc"),
                Some("group"),
                "cc",
                false,
                IdentityEvidence {
                    storage_matches: false,
                    ..broken
                }
            ),
            IdentityStep::StorageReplaced
        );
        assert_eq!(
            bind_stored_identity(
                Some("aa"),
                Some("aa"),
                Some("cc"),
                Some("group"),
                "cc",
                false,
                IdentityEvidence {
                    account_in_storage: false,
                    device_can_sign: true,
                    storage_matches: true,
                    group_available: Some(true),
                }
            ),
            IdentityStep::StorageMissing
        );
        assert_eq!(
            bind_stored_identity(
                Some("aa"),
                Some("aa"),
                Some("cc"),
                Some("group"),
                "cc",
                false,
                IdentityEvidence {
                    account_in_storage: true,
                    device_can_sign: false,
                    storage_matches: true,
                    group_available: Some(true),
                }
            ),
            IdentityStep::DeviceInvalid
        );
        assert_eq!(
            bind_stored_identity(
                Some("aa"),
                Some("aa"),
                Some("cc"),
                Some("group"),
                "cc",
                false,
                IdentityEvidence {
                    account_in_storage: true,
                    device_can_sign: true,
                    storage_matches: true,
                    group_available: Some(false),
                }
            ),
            IdentityStep::GroupUnavailable
        );
        assert_eq!(
            bind_stored_identity(None, Some("aa"), None, None, "cc", false, broken),
            IdentityStep::Import
        );
    }
}
