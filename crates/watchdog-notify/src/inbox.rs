use nostr::prelude::{Event, EventBuilder, FinalizeEvent, Keys, Kind, Tag, Timestamp};

use watchdog_core::url_policy::assert_wss_url;

const FUTURE_SKEW_SECONDS: u64 = 15 * 60;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedInbox {
    pub id: String,
    pub pubkey: String,
    pub created_at: u64,
    pub relays: Vec<String>,
}

pub fn validate_inbox_relays(relays: &[String]) -> Vec<String> {
    let mut unique = Vec::new();
    for relay in relays {
        let Ok(url) = assert_wss_url(relay) else {
            continue;
        };
        let normalized = url.as_str().trim_end_matches('/').to_string();
        if !unique.contains(&normalized) {
            unique.push(normalized);
        }
        if unique.len() >= 5 {
            break;
        }
    }
    unique
}

pub fn verify_inbox_event(json: &str, author: &str, now_sec: u64) -> Option<VerifiedInbox> {
    let event = Event::from_json(json).ok()?;
    if event.kind != Kind::InboxRelays || event.pubkey.to_hex() != author.to_ascii_lowercase() {
        return None;
    }
    let created_at = event.created_at.as_secs();
    if created_at == 0 || created_at > now_sec.saturating_add(FUTURE_SKEW_SECONDS) {
        return None;
    }
    if event.tags.len() > 50 || event.content.len() > 4096 {
        return None;
    }
    if event.verify().is_err() {
        return None;
    }
    let mut relays = Vec::new();
    for tag in event.tags.clone() {
        let slice = tag.as_slice();
        if slice.first().map(String::as_str) == Some("relay") {
            if let Some(url) = slice.get(1) {
                relays.push(url.clone());
            }
        }
    }
    Some(VerifiedInbox {
        id: event.id.to_hex(),
        pubkey: event.pubkey.to_hex(),
        created_at,
        relays: validate_inbox_relays(&relays),
    })
}

pub fn select_inbox(events: &[VerifiedInbox]) -> Option<VerifiedInbox> {
    let mut best: Option<VerifiedInbox> = None;
    for event in events {
        let replace = match &best {
            None => true,
            Some(current) => {
                event.created_at > current.created_at
                    || (event.created_at == current.created_at && event.id < current.id)
            }
        };
        if replace {
            best = Some(event.clone());
        }
    }
    best
}

pub fn sign_inbox(nsec: &str, relays: &[&str], created_at: u64) -> Result<String, ()> {
    let keys = Keys::parse(nsec).map_err(|_| ())?;
    let tags = relays
        .iter()
        .map(|relay| Tag::custom("relay", [*relay]))
        .collect::<Vec<_>>();
    let event = EventBuilder::new(Kind::InboxRelays, "")
        .tags(tags)
        .custom_created_at(Timestamp::from_secs(created_at))
        .finalize(&keys)
        .map_err(|_| ())?;
    Ok(event.as_json())
}

#[cfg(test)]
mod tests {
    use super::*;
    use nostr::prelude::{Keys, ToBech32};

    #[test]
    fn newest_valid_inbox_wins_and_private_relays_are_dropped() {
        let keys = Keys::generate();
        let nsec = keys.secret_key().to_bech32().unwrap();
        let author = keys.public_key().to_hex();
        let older = sign_inbox(&nsec, &["wss://old.example", "wss://127.0.0.1"], 100).unwrap();
        let newer = sign_inbox(&nsec, &["wss://new.example/"], 200).unwrap();
        let verified = [
            verify_inbox_event(&older, &author, 300).unwrap(),
            verify_inbox_event(&newer, &author, 300).unwrap(),
        ];
        assert_eq!(verified[0].relays, vec!["wss://old.example".to_string()]);
        let selected = select_inbox(&verified).unwrap();
        assert_eq!(selected.relays, vec!["wss://new.example".to_string()]);
        assert!(verify_inbox_event(&newer, &"ab".repeat(32), 300).is_none());
    }
}
