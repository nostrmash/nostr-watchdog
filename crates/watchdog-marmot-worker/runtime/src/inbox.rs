//! Signed kind 10050 notification-server inbox discovery.
//!
//! Discovery relays are a lookup source. Their URLs are not publication
//! destinations. A cached result expires, and an invalid signature is ignored.

use nostr::event::{Event, Kind};
use serde_json::Value;

const KIND_INBOX: u16 = 10050;
pub const CACHE_TTL_MS: u64 = 3_600_000;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InboxChoice {
    Relays { relays: Vec<String>, event_id: String, created_at: u64 },
    Negative,
}

pub fn cache_fresh(observed_at_ms: u64, now_ms: u64) -> bool {
    now_ms.saturating_sub(observed_at_ms) < CACHE_TTL_MS
}

/// Choose the newest valid kind 10050 authored by `server_hex`.
pub fn select_inbox(events: &[Value], server_hex: &str, allow_loopback: bool) -> InboxChoice {
    let mut best: Option<(u64, String, Vec<String>)> = None;
    for value in events {
        let Ok(event) = serde_json::from_value::<Event>(value.clone()) else {
            continue;
        };
        if event.kind != Kind::Custom(KIND_INBOX) {
            continue;
        }
        if hex::encode(event.pubkey.to_bytes()) != server_hex.to_ascii_lowercase() {
            continue;
        }
        if event.verify().is_err() {
            continue;
        }
        let relays = inbox_relays(&event, allow_loopback);
        if relays.is_empty() {
            continue;
        }
        let created = event.created_at.as_secs();
        let event_id = event.id.to_string();
        let replace = match &best {
            None => true,
            Some((previous_created, previous_id, _)) => {
                created > *previous_created || (created == *previous_created && event_id > *previous_id)
            }
        };
        if replace {
            best = Some((created, event_id, relays));
        }
    }
    match best {
        Some((created_at, event_id, relays)) => InboxChoice::Relays {
            relays,
            event_id,
            created_at,
        },
        None => InboxChoice::Negative,
    }
}

fn inbox_relays(event: &Event, allow_loopback: bool) -> Vec<String> {
    let Ok(value) = serde_json::to_value(event) else {
        return Vec::new();
    };
    let Some(tags) = value.get("tags").and_then(|item| item.as_array()) else {
        return Vec::new();
    };
    let mut relays = Vec::new();
    for tag in tags {
        let Some(parts) = tag.as_array() else {
            continue;
        };
        let name = parts.first().and_then(|item| item.as_str()).unwrap_or("");
        if name != "relay" && name != "r" {
            continue;
        }
        let Some(url) = parts.get(1).and_then(|item| item.as_str()) else {
            continue;
        };
        if inbox_relay_allowed(url, allow_loopback) && !relays.iter().any(|existing| existing == url) {
            relays.push(url.to_owned());
        }
    }
    relays
}

pub fn inbox_relay_allowed(value: &str, allow_loopback: bool) -> bool {
    if value.len() > 300 || value.contains('@') || value.contains('?') || value.contains('#') {
        return false;
    }
    let Some((scheme, rest)) = value.split_once("://") else {
        return false;
    };
    if rest.is_empty() {
        return false;
    }
    let hostport = rest.split('/').next().unwrap_or("");
    if hostport.is_empty() {
        return false;
    }
    let (host, port) = split_host_port(hostport);
    if host.is_empty()
        || host.ends_with(".local")
        || host.ends_with(".internal")
        || host.ends_with(".example")
        || host == "relay.example"
    {
        return false;
    }
    let loopback = host == "localhost" || host == "127.0.0.1" || host == "::1";
    if loopback {
        return allow_loopback && (scheme == "ws" || scheme == "wss");
    }
    if scheme != "wss" {
        return false;
    }
    if port.unwrap_or(443) != 443 {
        return false;
    }
    match host.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(ip)) => {
            let [a, b, _, _] = ip.octets();
            !(ip.is_private()
                || ip.is_loopback()
                || ip.is_link_local()
                || ip.is_broadcast()
                || a == 0
                || (a == 100 && (64..=127).contains(&b))
                || a >= 224)
        }
        Ok(std::net::IpAddr::V6(ip)) => {
            !(ip.is_loopback() || ip.is_unspecified() || (ip.octets()[0] & 0xfe) == 0xfc)
        }
        Err(_) => !host.parse::<std::net::IpAddr>().is_ok(),
    }
}

fn split_host_port(hostport: &str) -> (&str, Option<u16>) {
    if let Some(host) = hostport.strip_prefix('[') {
        let Some((host, rest)) = host.split_once(']') else {
            return ("", None);
        };
        let port = rest.strip_prefix(':').and_then(|value| value.parse().ok());
        return (host, port);
    }
    match hostport.rsplit_once(':') {
        Some((host, port)) if !host.is_empty() && port.chars().all(|ch| ch.is_ascii_digit()) => {
            (host, port.parse().ok())
        }
        _ => (hostport, None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nostr::prelude::{EventBuilder, FinalizeEvent, Kind, Tag, Timestamp};
    use nostr::key::{Keys, SecretKey};
    use serde_json::json;

    fn signed(keys: &Keys, created: u64, relays: &[&str]) -> Value {
        let tags = relays
            .iter()
            .map(|relay| Tag::custom("relay", [(*relay).to_owned()]))
            .collect::<Vec<_>>();
        let event = EventBuilder::new(Kind::Custom(KIND_INBOX), "")
            .tags(tags)
            .custom_created_at(Timestamp::from_secs(created))
            .finalize(keys)
            .expect("sign inbox");
        serde_json::to_value(event).expect("json")
    }

    #[test]
    fn missing_events_are_a_negative_result() {
        let choice = select_inbox(&[], &"ab".repeat(32), false);
        assert_eq!(choice, InboxChoice::Negative);
    }

    #[test]
    fn an_invalid_signature_is_ignored() {
        let keys = Keys::new(SecretKey::from_slice(&[7u8; 32]).unwrap());
        let mut event = signed(&keys, 10, &["wss://inbox.example.com"]);
        event["sig"] = json!("00");
        let server = hex::encode(keys.public_key().to_bytes());
        assert_eq!(select_inbox(&[event], &server, false), InboxChoice::Negative);
    }

    #[test]
    fn a_different_author_is_ignored() {
        let keys = Keys::new(SecretKey::from_slice(&[7u8; 32]).unwrap());
        let event = signed(&keys, 10, &["wss://inbox.example.com"]);
        let other = hex::encode([9u8; 32]);
        assert_eq!(select_inbox(&[event], &other, false), InboxChoice::Negative);
    }

    #[test]
    fn the_newest_valid_event_wins() {
        let keys = Keys::new(SecretKey::from_slice(&[7u8; 32]).unwrap());
        let older = signed(&keys, 10, &["wss://old.example.com"]);
        let newer = signed(&keys, 20, &["wss://new.example.com"]);
        let server = hex::encode(keys.public_key().to_bytes());
        match select_inbox(&[older, newer], &server, false) {
            InboxChoice::Relays { relays, .. } => {
                assert_eq!(relays, vec!["wss://new.example.com".to_owned()])
            }
            InboxChoice::Negative => panic!("expected the newer inbox"),
        }
    }

    #[test]
    fn discovery_does_not_return_an_unrelated_bootstrap_relay() {
        let keys = Keys::new(SecretKey::from_slice(&[7u8; 32]).unwrap());
        let event = signed(
            &keys,
            10,
            &[
                "wss://inbox.example.com",
                "ws://127.0.0.1:1",
                "wss://user:pass@inbox.example.com",
                "wss://secret.example.com:8443",
                "wss://relay.example",
            ],
        );
        let server = hex::encode(keys.public_key().to_bytes());
        match select_inbox(&[event], &server, false) {
            InboxChoice::Relays { relays, .. } => {
                assert_eq!(relays, vec!["wss://inbox.example.com".to_owned()]);
            }
            InboxChoice::Negative => panic!("expected the public inbox"),
        }
    }

    #[test]
    fn an_empty_tag_list_is_negative() {
        let keys = Keys::new(SecretKey::from_slice(&[7u8; 32]).unwrap());
        let event = signed(&keys, 10, &[]);
        let server = hex::encode(keys.public_key().to_bytes());
        assert_eq!(select_inbox(&[event], &server, false), InboxChoice::Negative);
    }

    #[test]
    fn cache_entries_expire() {
        assert!(cache_fresh(1_000, 1_000 + CACHE_TTL_MS - 1));
        assert!(!cache_fresh(1_000, 1_000 + CACHE_TTL_MS));
    }
}
