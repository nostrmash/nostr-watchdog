//! One NIP-17 delivery path for the native process and the Worker.
//!
//! The relay adapter supplies sockets. This module decides which relays are
//! discovery relays and which relays may receive the gift wrap, persists the
//! signed event before the first publish, and reuses that event on retry.

use watchdog_core::catalog::{project_by_id, project_recipient};
use watchdog_core::clock::Clock;
use watchdog_core::settings::load_settings;
use watchdog_core::url_policy::assert_wss_url;
pub use watchdog_notify::InboxFrames;
use watchdog_notify::{
    build_gift_wrap, definitive_negative, discovery_relays, event_json, fold_discovery,
    interpret_cache, parse_event, publication_relays, recipient_pubkey, verify_frames,
    CacheDecision,
};
use watchdog_store::{OperationalStore, OutboxRow};

use crate::cycle::DeliveryOutcome;

pub trait RelayIo {
    fn query_inbox(
        &self,
        relay: &str,
        author: &str,
        signer: Option<&str>,
        timeout_ms: i64,
    ) -> impl std::future::Future<Output = Result<InboxFrames, String>>;

    fn publish(
        &self,
        relay: &str,
        event_json: &str,
        signer: Option<&str>,
        timeout_ms: i64,
    ) -> impl std::future::Future<Output = Result<bool, String>>;
}

pub async fn deliver_nip17<S: OperationalStore, R: RelayIo, C: Clock>(
    store: &S,
    relay_io: &R,
    get: &impl Fn(&str) -> String,
    row: &OutboxRow,
    claim: &str,
    timeout_ms: i64,
    clock: &C,
) -> DeliveryOutcome {
    let settings = load_settings(get);
    if !store
        .extend_claim(
            &row.id,
            claim,
            clock.unix_ms() + settings.delivery_claim_ms,
            clock.unix_ms(),
        )
        .await
        .unwrap_or(false)
    {
        return retry("claim_lost");
    }
    let Some(project) = project_by_id(&row.project_id) else {
        return terminal("project_invalid");
    };
    let nsec = get(project.sender_secret);
    if nsec.is_empty() {
        return terminal("sender_key_missing");
    }
    let Some(recipient_raw) =
        project_recipient(&get("PROJECT_RECIPIENTS"), &get("ADMIN_NPUB"), project.id)
    else {
        return terminal("recipient_missing");
    };
    let Ok(recipient) = recipient_pubkey(&recipient_raw) else {
        return terminal("recipient_invalid");
    };
    let relays = match interpret_cache(
        store
            .relay_cache(&recipient, clock.unix_ms())
            .await
            .ok()
            .flatten(),
    ) {
        CacheDecision::Negative => return terminal("recipient_inbox_missing"),
        CacheDecision::Fresh(relays) => relays,
        CacheDecision::Discover => {
            let remembered = store.remembered_inbox(&recipient).await.unwrap_or_default();
            let candidates = discovery_relays(&settings.bootstrap, &remembered);
            if candidates.is_empty() {
                return terminal("bootstrap_relays_missing");
            }
            let mut verified = Vec::new();
            let mut completed = 0usize;
            let mut failures = 0usize;
            for relay in &candidates {
                if assert_wss_url(relay).is_err() {
                    failures += 1;
                    continue;
                }
                if !store
                    .extend_claim(
                        &row.id,
                        claim,
                        clock.unix_ms() + settings.delivery_claim_ms,
                        clock.unix_ms(),
                    )
                    .await
                    .unwrap_or(false)
                {
                    return retry("claim_lost");
                }
                match relay_io
                    .query_inbox(relay, &recipient, Some(nsec.as_str()), timeout_ms)
                    .await
                {
                    Ok(frames) => {
                        if frames.eose {
                            completed += 1;
                        } else {
                            failures += 1;
                        }
                        verified.extend(verify_frames(
                            &frames.events,
                            &recipient,
                            (clock.unix_ms() / 1000) as u64,
                        ));
                    }
                    Err(error) if error == "relay_auth_required" => {
                        failures += 1;
                    }
                    Err(_) => failures += 1,
                }
            }
            let fold = fold_discovery(&verified, completed, failures);
            if definitive_negative(&fold) {
                let _ = store
                    .save_relay_cache(
                        &recipient,
                        "[]",
                        true,
                        clock.unix_ms(),
                        clock.unix_ms() + settings.relay_ttl_seconds.min(300) * 1000,
                    )
                    .await;
                return terminal("recipient_inbox_missing");
            }
            if fold.relays.is_empty() {
                return retry("inbox_discovery_failed");
            }
            let relays = publication_relays(&fold.relays);
            let _ = store
                .save_relay_cache(
                    &recipient,
                    &serde_json::to_string(&relays).unwrap_or_else(|_| "[]".to_string()),
                    false,
                    clock.unix_ms(),
                    clock.unix_ms() + settings.relay_ttl_seconds * 1000,
                )
                .await;
            relays
        }
    };
    let relays = publication_relays(&relays);
    if relays.is_empty() {
        return terminal("recipient_inbox_missing");
    }
    if !store
        .extend_claim(
            &row.id,
            claim,
            clock.unix_ms() + settings.delivery_claim_ms,
            clock.unix_ms(),
        )
        .await
        .unwrap_or(false)
    {
        return retry("claim_lost");
    }
    let event_json = if let Some(stored) =
        row.envelope_json
            .clone()
            .or(store.read_envelope(&row.id).await.ok().flatten())
    {
        stored
    } else {
        let Ok(event) = build_gift_wrap(
            &nsec,
            &recipient,
            &row.payload_text,
            project.contact_name,
            (row.created_at / 1000) as u64,
        ) else {
            return terminal("envelope_invalid");
        };
        let json = event_json(&event);
        match store
            .save_envelope(&row.id, claim, &json, clock.unix_ms())
            .await
        {
            Ok("saved") => json,
            Ok("exists") => store
                .read_envelope(&row.id)
                .await
                .ok()
                .flatten()
                .unwrap_or(json),
            _ => return terminal("envelope_invalid"),
        }
    };
    let Ok(event) = parse_event(&event_json) else {
        return terminal("envelope_invalid");
    };
    let event_id = event.id.to_hex();
    let mut accepted = Vec::new();
    let mut failed = Vec::new();
    for relay in &relays {
        if !store
            .extend_claim(
                &row.id,
                claim,
                clock.unix_ms() + settings.delivery_claim_ms,
                clock.unix_ms(),
            )
            .await
            .unwrap_or(false)
        {
            return retry("claim_lost");
        }
        match relay_io
            .publish(relay, &event_json, Some(nsec.as_str()), timeout_ms)
            .await
        {
            Ok(true) => accepted.push(relay.clone()),
            _ => failed.push(relay.clone()),
        }
    }
    let published = !accepted.is_empty();
    DeliveryOutcome {
        accepted: published,
        terminal: false,
        hold_attempt: false,
        error: if !published {
            Some("relay_rejected".to_string())
        } else if failed.is_empty() {
            None
        } else {
            Some("partial_relay_acceptance".to_string())
        },
        accepted_relays: accepted,
        failed_relays: failed,
        message_phase: Some(if published {
            "message_accepted".to_string()
        } else {
            "relay_rejected".to_string()
        }),
        push_phase: None,
        message_event_id: Some(event_id),
        push_envelope: None,
    }
}

fn terminal(error: &str) -> DeliveryOutcome {
    DeliveryOutcome {
        accepted: false,
        terminal: true,
        hold_attempt: false,
        error: Some(error.to_string()),
        accepted_relays: Vec::new(),
        failed_relays: Vec::new(),
        message_phase: None,
        push_phase: None,
        message_event_id: None,
        push_envelope: None,
    }
}

fn retry(error: &str) -> DeliveryOutcome {
    DeliveryOutcome {
        accepted: false,
        terminal: false,
        hold_attempt: false,
        error: Some(error.to_string()),
        accepted_relays: Vec::new(),
        failed_relays: Vec::new(),
        message_phase: None,
        push_phase: None,
        message_event_id: None,
        push_envelope: None,
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use nostr::prelude::{Keys, ToBech32};
    use watchdog_core::clock::ManualClock;
    use watchdog_core::domain::{AlertClass, AlertDraft, Destination, Severity};
    use watchdog_notify::sign_inbox;
    use watchdog_store::SqliteStore;

    use super::*;

    struct Scripted {
        inbox_on: String,
        inbox_json: String,
        published: Mutex<Vec<(String, String)>>,
    }

    impl RelayIo for Scripted {
        async fn query_inbox(
            &self,
            relay: &str,
            _author: &str,
            _signer: Option<&str>,
            _timeout_ms: i64,
        ) -> Result<InboxFrames, String> {
            if relay == self.inbox_on {
                Ok(InboxFrames {
                    events: vec![self.inbox_json.clone()],
                    eose: true,
                })
            } else {
                Ok(InboxFrames {
                    events: Vec::new(),
                    eose: true,
                })
            }
        }

        async fn publish(
            &self,
            relay: &str,
            event_json: &str,
            _signer: Option<&str>,
            _timeout_ms: i64,
        ) -> Result<bool, String> {
            self.published
                .lock()
                .unwrap()
                .push((relay.to_string(), event_json.to_string()));
            Ok(relay == "wss://inbox.example")
        }
    }

    fn draft(text: &str) -> AlertDraft {
        AlertDraft {
            id: "alt_nip17".to_string(),
            alert_class: AlertClass::Test,
            incident_id: None,
            monitor_id: "test-smartflowsocial".to_string(),
            project_id: "smartflowsocial".to_string(),
            dedupe_key: "test:nip17:1".to_string(),
            destination: Destination::Nostr,
            severity: Severity::Info,
            text: text.to_string(),
        }
    }

    #[tokio::test]
    async fn scripted_relay_publishes_only_to_the_advertised_inbox() {
        let store = SqliteStore::memory().unwrap();
        let recipient = Keys::generate();
        let sender = Keys::generate();
        let inbox = sign_inbox(
            &recipient.secret_key().to_bech32().unwrap(),
            &["wss://inbox.example/"],
            1_700_000_000,
        )
        .unwrap();
        let relay = Scripted {
            inbox_on: "wss://bootstrap.example".to_string(),
            inbox_json: inbox,
            published: Mutex::new(Vec::new()),
        };
        store
            .insert_alert(&draft("disk is full"), 1_700_000_000_000)
            .unwrap();
        let claimed = store
            .claim_outbox(1_700_000_000_000, 1_700_000_120_000, Some("nostr"), 1)
            .unwrap();
        let claim = claimed[0].claim_token.clone().unwrap();
        let clock = ManualClock::new(1_700_000_000_000);
        let get = |key: &str| match key {
            "SFS_BOT_NSEC" => sender.secret_key().to_bech32().unwrap(),
            "ADMIN_NPUB" => recipient.public_key().to_hex(),
            "BOOTSTRAP_RELAYS" => "wss://bootstrap.example".to_string(),
            "DELIVERY_CLAIM_MS" => "120000".to_string(),
            _ => String::new(),
        };
        let first = deliver_nip17(&store, &relay, &get, &claimed[0], &claim, 5_000, &clock).await;
        assert!(first.accepted, "{first:?}");
        let published = relay.published.lock().unwrap().clone();
        assert_eq!(published.len(), 1);
        assert_eq!(published[0].0, "wss://inbox.example");
        assert!(!published[0].1.contains("disk is full"));
        let stored = store.read_envelope("alt_nip17").unwrap().unwrap();
        let again =
            store.claim_outbox(clock.unix_ms(), clock.unix_ms() + 120_000, Some("nostr"), 1);
        // The first delivery accepted the alert, so it is not claimed again.
        // A retry of the same stored envelope is what the outbox keeps.
        assert!(again.unwrap().is_empty());
        let event_id = first.message_event_id.clone().unwrap();
        assert!(stored.contains(&event_id));
        assert_eq!(
            parse_event(&stored).unwrap().id.to_hex(),
            parse_event(&published[0].1).unwrap().id.to_hex()
        );
    }

    #[tokio::test]
    async fn a_rejected_publish_is_retried_with_the_same_event_id() {
        let store = SqliteStore::memory().unwrap();
        let recipient = Keys::generate();
        let sender = Keys::generate();
        let inbox = sign_inbox(
            &recipient.secret_key().to_bech32().unwrap(),
            &["wss://inbox.example/"],
            1_700_000_000,
        )
        .unwrap();
        let relay = Scripted {
            inbox_on: "wss://bootstrap.example".to_string(),
            inbox_json: inbox,
            published: Mutex::new(Vec::new()),
        };
        store
            .insert_alert(&draft("disk is full"), 1_700_000_000_000)
            .unwrap();
        let claimed = store
            .claim_outbox(1_700_000_000_000, 1_700_000_120_000, Some("nostr"), 1)
            .unwrap();
        let claim = claimed[0].claim_token.clone().unwrap();
        let clock = ManualClock::new(1_700_000_000_000);
        let get = |key: &str| match key {
            "SFS_BOT_NSEC" => sender.secret_key().to_bech32().unwrap(),
            "ADMIN_NPUB" => recipient.public_key().to_hex(),
            "BOOTSTRAP_RELAYS" => "wss://bootstrap.example".to_string(),
            "DELIVERY_CLAIM_MS" => "120000".to_string(),
            _ => String::new(),
        };
        // The scripted adapter accepts only the inbox relay. Point publication
        // at a relay that rejects once by using a fresh adapter whose publish
        // fails, then a second adapter that accepts the stored event.
        let rejecting = RejectOnce {
            inner: &relay,
            failed: Mutex::new(false),
        };
        let first =
            deliver_nip17(&store, &rejecting, &get, &claimed[0], &claim, 5_000, &clock).await;
        assert!(!first.accepted, "{first:?}");
        let stored = store.read_envelope("alt_nip17").unwrap().unwrap();
        let first_id = parse_event(&stored).unwrap().id.to_hex();
        let mut row = claimed[0].clone();
        row.envelope_json = Some(stored.clone());
        let second = deliver_nip17(&store, &relay, &get, &row, &claim, 5_000, &clock).await;
        assert!(second.accepted, "{second:?}");
        assert_eq!(second.message_event_id.as_deref(), Some(first_id.as_str()));
        let published = relay.published.lock().unwrap().clone();
        assert!(published
            .iter()
            .all(|(target, _)| target == "wss://inbox.example"));
        assert!(published.len() >= 2);
        let ids: Vec<_> = published
            .iter()
            .map(|(_, json)| parse_event(json).unwrap().id.to_hex())
            .collect();
        assert!(ids.iter().all(|id| id == &first_id));
    }

    struct RejectOnce<'a> {
        inner: &'a Scripted,
        failed: Mutex<bool>,
    }

    impl RelayIo for RejectOnce<'_> {
        async fn query_inbox(
            &self,
            relay: &str,
            author: &str,
            signer: Option<&str>,
            timeout_ms: i64,
        ) -> Result<InboxFrames, String> {
            self.inner
                .query_inbox(relay, author, signer, timeout_ms)
                .await
        }

        async fn publish(
            &self,
            relay: &str,
            event_json: &str,
            signer: Option<&str>,
            timeout_ms: i64,
        ) -> Result<bool, String> {
            let mut failed = self.failed.lock().unwrap();
            if !*failed {
                *failed = true;
                self.inner
                    .published
                    .lock()
                    .unwrap()
                    .push((relay.to_string(), event_json.to_string()));
                return Ok(false);
            }
            self.inner
                .publish(relay, event_json, signer, timeout_ms)
                .await
        }
    }
}
