use nostr::nips::nip59::{GiftWrapBuilder, UnwrappedGift};
use nostr::prelude::{Event, FinalizeEvent, Keys, Kind, PublicKey, Tag, Timestamp, UnsignedEvent};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Nip17Error {
    #[error("sender key is invalid")]
    Sender,
    #[error("recipient is invalid")]
    Recipient,
    #[error("gift wrap could not be built")]
    Wrap,
    #[error("stored event is invalid")]
    Event,
}

pub fn recipient_pubkey(value: &str) -> Result<String, Nip17Error> {
    let trimmed = value.trim();
    if trimmed.len() == 64 && trimmed.chars().all(|ch| ch.is_ascii_hexdigit()) {
        return Ok(trimmed.to_ascii_lowercase());
    }
    let key = PublicKey::parse(trimmed).map_err(|_| Nip17Error::Recipient)?;
    Ok(key.to_hex())
}

pub fn public_key_hex(nsec: &str) -> Result<String, Nip17Error> {
    let keys = Keys::parse(nsec.trim()).map_err(|_| Nip17Error::Sender)?;
    Ok(keys.public_key().to_hex())
}

pub fn build_gift_wrap(
    nsec: &str,
    recipient_hex: &str,
    message: &str,
    title: &str,
    created_at_secs: u64,
) -> Result<Event, Nip17Error> {
    let keys = Keys::parse(nsec.trim()).map_err(|_| Nip17Error::Sender)?;
    let receiver = PublicKey::from_hex(recipient_hex).map_err(|_| Nip17Error::Recipient)?;
    let rumor = UnsignedEvent::new(
        keys.public_key(),
        Timestamp::from_secs(created_at_secs),
        Kind::PrivateDirectMessage,
        [Tag::public_key(receiver), Tag::custom("subject", [title])],
        message,
    );
    GiftWrapBuilder::new(receiver, rumor)
        .finalize(&keys)
        .map_err(|_| Nip17Error::Wrap)
}

pub fn open_gift_wrap(
    event_json: &str,
    recipient_nsec: &str,
) -> Result<(String, String), Nip17Error> {
    let keys = Keys::parse(recipient_nsec.trim()).map_err(|_| Nip17Error::Recipient)?;
    let event = Event::from_json(event_json).map_err(|_| Nip17Error::Event)?;
    if event.kind != Kind::GiftWrap {
        return Err(Nip17Error::Event);
    }
    let opened = UnwrappedGift::from_gift_wrap(&keys, &event).map_err(|_| Nip17Error::Event)?;
    Ok((opened.rumor.content, opened.sender.to_hex()))
}

pub fn event_json(event: &Event) -> String {
    event.as_json()
}

pub fn parse_event(json: &str) -> Result<Event, Nip17Error> {
    Event::from_json(json).map_err(|_| Nip17Error::Event)
}

#[cfg(test)]
mod tests {
    use super::*;
    use nostr::prelude::ToBech32;

    #[test]
    fn gift_wrap_round_trip_hides_plaintext_from_the_published_event() {
        let sender = Keys::generate();
        let recipient = Keys::generate();
        let event = build_gift_wrap(
            &sender.secret_key().to_bech32().unwrap(),
            &recipient.public_key().to_hex(),
            "disk is full",
            "SmartFlowSocial Watchdog",
            1_700_000_000,
        )
        .unwrap();
        let json = event.as_json();
        assert!(!json.contains("disk is full"));
        assert_eq!(event.kind, Kind::GiftWrap);
        let (content, author) =
            open_gift_wrap(&json, &recipient.secret_key().to_bech32().unwrap()).unwrap();
        assert_eq!(content, "disk is full");
        assert_eq!(author, sender.public_key().to_hex());
        let again = parse_event(&json).unwrap();
        assert_eq!(again.id, event.id);
    }
}
