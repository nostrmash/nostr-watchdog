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
}
