//! Decisions for Marmot send and conversation recovery.
//!
//! MDK's durable local-send status is authoritative whenever it exists.
//! A cached pending result must not become immutable, and an absent upstream
//! record after we have already started a submission is not permission to
//! encrypt the alert again.

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
    if saved.is_some_and(|group| !group.is_empty()) {
        return ConversationStep::UseSaved;
    }
    match lookup {
        ConversationLookup::NotReady => ConversationStep::RetryIndex,
        ConversationLookup::Reusable => ConversationStep::UseExisting,
        ConversationLookup::NotReusable => ConversationStep::NotReusable,
        ConversationLookup::None => ConversationStep::Create,
    }
}

/// How many times a nonterminal Marmot result may be reconciled before it
/// becomes an explicit terminal outcome. This does not mean the message was
/// unpublished, and it does not mean a phone displayed a notification.
pub const RECONCILE_BUDGET: i64 = 8;

pub fn reconcile_attempt(prior_attempts: i64) -> i64 {
    prior_attempts.saturating_add(1)
}

pub fn reconcile_exhausted(hold: bool, attempt: i64) -> bool {
    hold && attempt >= RECONCILE_BUDGET
}

/// Error code stored when reconciliation reaches [`RECONCILE_BUDGET`].
pub fn exhausted_push_error(message_phase: Option<&str>, push_phase: Option<&str>) -> &'static str {
    match message_phase {
        Some("relay_accepted") => match push_phase {
            Some("recipient_push_token_unavailable") => "recipient_push_token_unavailable",
            _ => "push_unobservable",
        },
        Some("accepted_pending") => "marmot_publish_unconfirmed",
        _ => "marmot_reconcile_exhausted",
    }
}

/// Whether the operational cache may be used for this sender and recipient.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IdentityStep {
    UseCached,
    Import,
    SenderMismatch,
    RecipientMismatch,
    /// A group id is saved without the recipient it was created for.
    RecipientUnbound,
}

pub fn bind_identity(
    cached_sender: Option<&str>,
    expected_sender: Option<&str>,
    cached_peer: Option<&str>,
    cached_group: Option<&str>,
    recipient: &str,
    reonboard: bool,
) -> IdentityStep {
    if reonboard {
        return IdentityStep::Import;
    }
    if let (Some(cached), Some(expected)) = (filled(cached_sender), filled(expected_sender)) {
        if !cached.eq_ignore_ascii_case(expected) {
            return IdentityStep::SenderMismatch;
        }
    }
    if let Some(peer) = filled(cached_peer) {
        if !peer.eq_ignore_ascii_case(recipient) {
            return IdentityStep::RecipientMismatch;
        }
    } else if filled(cached_group).is_some() {
        return IdentityStep::RecipientUnbound;
    }
    if filled(cached_sender).is_some() {
        IdentityStep::UseCached
    } else {
        IdentityStep::Import
    }
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
    fn reconciliation_stops_at_the_budget_with_an_explicit_push_outcome() {
        assert!(!reconcile_exhausted(true, RECONCILE_BUDGET - 1));
        assert!(reconcile_exhausted(true, RECONCILE_BUDGET));
        assert!(!reconcile_exhausted(false, RECONCILE_BUDGET));
        assert_eq!(
            exhausted_push_error(Some("relay_accepted"), Some("push_disposition_unknown")),
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
            exhausted_push_error(Some("accepted_pending"), None),
            "marmot_publish_unconfirmed"
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
            IdentityStep::Import
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
}
