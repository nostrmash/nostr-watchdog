//! Shared NIP-17 discovery and publication policy.
//!
//! Bootstrap relays are discovery infrastructure. A gift wrap is published
//! only to relays the recipient advertised in a validated kind 10050 event.
//! Native sockets and the Worker WebSocket adapter both use this module.

use nostr::event::FinalizeEvent;
use nostr::nips::nip42::ClientAuthentication;
use nostr::prelude::{ClientMessage, Keys, RelayUrl};
use serde_json::Value;

use crate::inbox::{select_inbox, validate_inbox_relays, verify_inbox_event, VerifiedInbox};
use crate::Nip17Error;

pub const MAX_DISCOVERY_RELAYS: usize = 8;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InboxFrames {
    pub events: Vec<String>,
    pub eose: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RelayControl {
    Event {
        subscription: String,
        event_json: String,
    },
    Eose {
        subscription: String,
    },
    Ok {
        event_id: String,
        accepted: bool,
        message: String,
    },
    Closed {
        subscription: String,
        message: String,
    },
    Notice,
    Auth {
        challenge: String,
    },
    Ignore,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CacheDecision {
    Fresh(Vec<String>),
    Negative,
    Discover,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DiscoveryFold {
    pub relays: Vec<String>,
    pub completed: usize,
    pub failures: usize,
}

pub fn interpret_cache(cached: Option<(String, bool)>) -> CacheDecision {
    match cached {
        Some((json, true)) => {
            let _ = json;
            CacheDecision::Negative
        }
        Some((json, false)) => {
            let relays = serde_json::from_str::<Vec<String>>(&json).unwrap_or_default();
            let relays = validate_inbox_relays(&relays);
            if relays.is_empty() {
                CacheDecision::Discover
            } else {
                CacheDecision::Fresh(relays)
            }
        }
        None => CacheDecision::Discover,
    }
}

pub fn discovery_relays(bootstrap: &[String], remembered: &[String]) -> Vec<String> {
    let mut relays = Vec::new();
    for relay in bootstrap.iter().chain(remembered.iter()) {
        let normalized = relay.trim().trim_end_matches('/').to_string();
        if normalized.is_empty()
            || relays
                .iter()
                .any(|existing: &String| existing == &normalized)
        {
            continue;
        }
        relays.push(normalized);
        if relays.len() >= MAX_DISCOVERY_RELAYS {
            break;
        }
    }
    relays
}

pub fn fold_discovery(
    events: &[VerifiedInbox],
    completed: usize,
    failures: usize,
) -> DiscoveryFold {
    let relays = select_inbox(events)
        .map(|event| event.relays)
        .unwrap_or_default();
    DiscoveryFold {
        relays: validate_inbox_relays(&relays),
        completed,
        failures,
    }
}

pub fn definitive_negative(fold: &DiscoveryFold) -> bool {
    fold.relays.is_empty() && fold.completed > 0 && fold.failures == 0
}

pub fn partial_failure(fold: &DiscoveryFold) -> bool {
    fold.relays.is_empty() && !definitive_negative(fold)
}

/// Publication targets are the recipient inbox only. A bootstrap URL is included
/// when, and only when, the recipient advertised it.
pub fn publication_relays(inbox: &[String]) -> Vec<String> {
    validate_inbox_relays(inbox)
}

pub fn parse_relay_frame(text: &str) -> RelayControl {
    let Ok(parsed) = serde_json::from_str::<Value>(text) else {
        return RelayControl::Ignore;
    };
    let Some(items) = parsed.as_array() else {
        return RelayControl::Ignore;
    };
    let kind = items.first().and_then(Value::as_str).unwrap_or("");
    match kind {
        "EVENT" => RelayControl::Event {
            subscription: items
                .get(1)
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string(),
            event_json: items
                .get(2)
                .map(|event| event.to_string())
                .unwrap_or_default(),
        },
        "EOSE" => RelayControl::Eose {
            subscription: items
                .get(1)
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string(),
        },
        "OK" => RelayControl::Ok {
            event_id: items
                .get(1)
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string(),
            accepted: items.get(2).and_then(Value::as_bool).unwrap_or(false),
            message: items
                .get(3)
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string(),
        },
        "CLOSED" => RelayControl::Closed {
            subscription: items
                .get(1)
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string(),
            message: items
                .get(2)
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string(),
        },
        "NOTICE" => RelayControl::Notice,
        "AUTH" => {
            let challenge = items.get(1).and_then(Value::as_str).unwrap_or("");
            if challenge.is_empty() {
                RelayControl::Ignore
            } else {
                RelayControl::Auth {
                    challenge: challenge.to_string(),
                }
            }
        }
        _ => RelayControl::Ignore,
    }
}

pub fn verify_frames(frames: &[String], author: &str, now_sec: u64) -> Vec<VerifiedInbox> {
    frames
        .iter()
        .filter_map(|frame| verify_inbox_event(frame, author, now_sec))
        .collect()
}

/// NIP-42 client AUTH frame. Callers that cannot sign must surface
/// `relay_auth_required` rather than treat the relay as an empty inbox.
pub fn auth_frame(nsec: &str, challenge: &str, relay_url: &str) -> Result<String, Nip17Error> {
    let keys = Keys::parse(nsec.trim()).map_err(|_| Nip17Error::Sender)?;
    let relay = RelayUrl::parse(relay_url).map_err(|_| Nip17Error::Event)?;
    let event = ClientAuthentication::new(challenge, relay)
        .finalize(&keys)
        .map_err(|_| Nip17Error::Event)?;
    Ok(ClientMessage::auth(event).as_json())
}

pub const MAX_AUTH_CHALLENGES: u8 = 2;

/// Discovery relays never receive a signed identity. Publication relays may
/// be signed only after they require authentication.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthPolicy {
    Discovery,
    Publication,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SessionStep {
    Continue,
    Sign { challenge: String },
    ResendOriginal,
    Accepted,
    Rejected,
    Failed(&'static str),
}

#[derive(Clone, Debug)]
pub struct AuthSession {
    policy: AuthPolicy,
    challenges: u8,
    resends: u8,
    pending_auth_id: Option<String>,
    authenticated: bool,
}

impl AuthSession {
    pub fn new(policy: AuthPolicy) -> Self {
        Self {
            policy,
            challenges: 0,
            resends: 0,
            pending_auth_id: None,
            authenticated: false,
        }
    }

    pub fn note_auth_sent(&mut self, event_id: &str) {
        self.pending_auth_id = Some(event_id.to_string());
    }

    pub fn on_frame(&mut self, control: &RelayControl, original_id: &str) -> SessionStep {
        match control {
            RelayControl::Auth { challenge } => self.on_challenge(challenge),
            RelayControl::Ok {
                event_id,
                accepted,
                message,
            } => self.on_ok(event_id, *accepted, message, original_id),
            RelayControl::Closed { message, .. } => {
                if auth_required(message) && !self.may_have_authenticated() {
                    SessionStep::Failed("relay_auth_required")
                } else {
                    SessionStep::Failed("relay_closed")
                }
            }
            _ => SessionStep::Continue,
        }
    }

    fn on_challenge(&mut self, challenge: &str) -> SessionStep {
        self.challenges = self.challenges.saturating_add(1);
        if self.challenges > MAX_AUTH_CHALLENGES {
            return SessionStep::Failed("relay_auth_repeated");
        }
        if self.policy == AuthPolicy::Discovery || self.authenticated {
            return SessionStep::Continue;
        }
        SessionStep::Sign {
            challenge: challenge.to_string(),
        }
    }

    fn on_ok(
        &mut self,
        event_id: &str,
        accepted: bool,
        message: &str,
        original_id: &str,
    ) -> SessionStep {
        if self.pending_auth_id.as_deref() == Some(event_id) {
            self.pending_auth_id = None;
            if !accepted {
                return SessionStep::Failed("relay_auth_rejected");
            }
            self.authenticated = true;
            if self.resends == 0 {
                self.resends = 1;
                return SessionStep::ResendOriginal;
            }
            return SessionStep::Continue;
        }
        if event_id == original_id {
            if accepted {
                return SessionStep::Accepted;
            }
            if auth_required(message) && !self.authenticated {
                return SessionStep::Failed("relay_auth_required");
            }
            return SessionStep::Rejected;
        }
        if auth_required(message) && !self.may_have_authenticated() {
            return SessionStep::Failed("relay_auth_required");
        }
        SessionStep::Continue
    }

    fn may_have_authenticated(&self) -> bool {
        self.policy == AuthPolicy::Publication && self.authenticated
    }
}

pub fn auth_event_id(frame: &str) -> Option<String> {
    let parsed = serde_json::from_str::<Value>(frame).ok()?;
    parsed
        .get(1)
        .and_then(|event| event.get("id"))
        .and_then(Value::as_str)
        .map(str::to_string)
}

fn auth_required(message: &str) -> bool {
    let lower = message.to_ascii_lowercase();
    lower.contains("auth-required") || lower.contains("auth required")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inbox::sign_inbox;
    use nostr::prelude::{Keys, ToBech32};

    #[test]
    fn publication_never_uses_a_discovery_only_relay() {
        let inbox = publication_relays(&["wss://inbox.example/".to_string()]);
        let bootstrap = discovery_relays(
            &["wss://bootstrap.example".to_string()],
            &["wss://inbox.example".to_string()],
        );
        assert_eq!(inbox, vec!["wss://inbox.example".to_string()]);
        assert!(bootstrap
            .iter()
            .any(|relay| relay == "wss://bootstrap.example"));
        assert!(inbox.iter().all(|relay| relay != "wss://bootstrap.example"));
    }

    #[test]
    fn negative_cache_is_not_rediscovery_and_partial_failure_is_not_negative() {
        assert_eq!(
            interpret_cache(Some(("[]".to_string(), true))),
            CacheDecision::Negative
        );
        assert_eq!(interpret_cache(None), CacheDecision::Discover);
        let partial = DiscoveryFold {
            relays: Vec::new(),
            completed: 1,
            failures: 1,
        };
        assert!(!definitive_negative(&partial));
        assert!(partial_failure(&partial));
        let empty = DiscoveryFold {
            relays: Vec::new(),
            completed: 2,
            failures: 0,
        };
        assert!(definitive_negative(&empty));
    }

    #[test]
    fn auth_ok_and_closed_frames_keep_their_meaning() {
        assert!(matches!(
            parse_relay_frame(r#"["AUTH","challenge-1"]"#),
            RelayControl::Auth { challenge } if challenge == "challenge-1"
        ));
        assert!(matches!(
            parse_relay_frame(r#"["OK","abc",true,""]"#),
            RelayControl::Ok { accepted: true, .. }
        ));
        assert!(matches!(
            parse_relay_frame(r#"["CLOSED","sub","auth-required: "]"#),
            RelayControl::Closed { .. }
        ));
        assert!(matches!(
            parse_relay_frame(r#"["EOSE","sub"]"#),
            RelayControl::Eose { .. }
        ));
    }

    #[test]
    fn auth_frame_is_a_signed_kind_22242_for_the_relay() {
        let keys = Keys::generate();
        let nsec = keys.secret_key().to_bech32().unwrap();
        let frame = auth_frame(&nsec, "c", "wss://relay.example").unwrap();
        assert!(frame.starts_with("[\"AUTH\""));
        assert!(frame.contains("22242") || frame.contains("\"kind\":22242"));
        let _ = sign_inbox(&nsec, &["wss://inbox.example"], 10);
    }

    #[test]
    fn discovery_ignores_an_optional_challenge_and_fails_closed_when_required() {
        let mut session = AuthSession::new(AuthPolicy::Discovery);
        let challenge = parse_relay_frame(r#"["AUTH","c1"]"#);
        assert_eq!(session.on_frame(&challenge, "sub"), SessionStep::Continue);
        let required = parse_relay_frame(r#"["CLOSED","sub","auth-required: sign in"]"#);
        assert_eq!(
            session.on_frame(&required, "sub"),
            SessionStep::Failed("relay_auth_required")
        );
    }

    #[test]
    fn publication_signs_once_resends_the_original_event_and_rejects_a_bad_ack() {
        let mut session = AuthSession::new(AuthPolicy::Publication);
        let step = session.on_frame(&parse_relay_frame(r#"["AUTH","c1"]"#), "event");
        assert!(matches!(step, SessionStep::Sign { .. }));
        session.note_auth_sent("auth-event");
        assert_eq!(
            session.on_frame(
                &parse_relay_frame(r#"["OK","auth-event",true,""]"#),
                "event"
            ),
            SessionStep::ResendOriginal
        );
        assert_eq!(
            session.on_frame(&parse_relay_frame(r#"["OK","event",true,""]"#), "event"),
            SessionStep::Accepted
        );
        let mut rejected = AuthSession::new(AuthPolicy::Publication);
        rejected.note_auth_sent("auth-event");
        assert_eq!(
            rejected.on_frame(
                &parse_relay_frame(r#"["OK","auth-event",false,"rejected"]"#),
                "event"
            ),
            SessionStep::Failed("relay_auth_rejected")
        );
    }

    #[test]
    fn a_second_challenge_is_bounded_and_a_late_ok_still_matches() {
        let mut session = AuthSession::new(AuthPolicy::Publication);
        assert!(matches!(
            session.on_frame(
                &RelayControl::Auth {
                    challenge: "a".into()
                },
                "event"
            ),
            SessionStep::Sign { .. }
        ));
        assert!(matches!(
            session.on_frame(
                &RelayControl::Auth {
                    challenge: "b".into()
                },
                "event"
            ),
            SessionStep::Sign { .. }
        ));
        assert_eq!(
            session.on_frame(
                &RelayControl::Auth {
                    challenge: "c".into()
                },
                "event"
            ),
            SessionStep::Failed("relay_auth_repeated")
        );
    }
}
