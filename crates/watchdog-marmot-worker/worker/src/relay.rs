//! Bounded Nostr relay client for the Durable Object.
//!
//! Publication runs outside the cryptographic gate. An `OK` frame is accepted
//! only when its event id is the prepared event. Loopback relays are accepted
//! only when the test flag is set. The client does not answer NIP-42 `AUTH`:
//! a relay that requires authentication stays unobservable, and the sender key
//! is not sent to prove identity.

use std::pin::pin;
use std::time::Duration;

use futures_util::future::{Either, select};
use futures_util::StreamExt;
use marmot_worker_runtime::publication::{
    self, DestinationReport, DestinationVerdict, FrameClass, PublishAttempt,
};
use serde_json::{Value, json};
use url::Url;
use worker::{Delay, WebSocket, WebsocketEvent};

const MAX_RELAYS: usize = 4;
const MAX_EVENT_BYTES: usize = 64 * 1024;
const MAX_TOTAL_BYTES: usize = 256 * 1024;
const MAX_FRAMES: usize = 64;
const TIMEOUT: Duration = Duration::from_secs(5);
const SUBSCRIPTION: &str = "marmot";

#[derive(Clone, Debug)]
pub struct RelayPublication {
    pub event_id: String,
    pub attempt_id: String,
    pub outcome: String,
    pub relay: String,
    pub reason: String,
    pub retryable: bool,
    pub started_ms: u64,
    pub finished_ms: u64,
}

impl From<PublishAttempt> for RelayPublication {
    fn from(attempt: PublishAttempt) -> Self {
        Self {
            event_id: attempt.event_id,
            attempt_id: attempt.attempt_id,
            outcome: attempt.outcome,
            relay: attempt.relay,
            reason: attempt.reason,
            retryable: attempt.retryable,
            started_ms: 0,
            finished_ms: 0,
        }
    }
}

pub fn validate_relays(relays: &[String], allow_loopback: bool) -> Result<(), String> {
    if relays.is_empty() || relays.len() > MAX_RELAYS {
        return Err("relay list must contain 1 to 4 destinations".into());
    }
    for relay in relays {
        validate_relay(relay, allow_loopback)?;
    }
    Ok(())
}

pub fn validate_relay(value: &str, allow_loopback: bool) -> Result<(), String> {
    let url = Url::parse(value).map_err(|_| "relay url is invalid".to_owned())?;
    if !url.username().is_empty() || url.password().is_some() {
        return Err("relay url contains credentials".into());
    }
    if url.query().is_some() || url.fragment().is_some() {
        return Err("relay url is not allowed".into());
    }
    let host = url.host_str().unwrap_or("");
    if host == "relay.example" || host.ends_with(".example") {
        return Err("placeholder relay is rejected".into());
    }
    let loopback = is_loopback_host(host);
    let port = url.port();
    if port == Some(0) {
        return Err("relay destination is not allowed".into());
    }
    match url.scheme() {
        "wss" if !loopback && host_is_public(host) && port.unwrap_or(443) == 443 => Ok(()),
        "ws" | "wss" if allow_loopback && loopback => Ok(()),
        _ => Err("relay destination is not allowed".into()),
    }
}

/// Publish one event. The returned relay is the one whose `OK` matched the
/// event id. A timeout is `unobservable`, not `rejected`.
pub async fn publish_event(
    relays: &[String],
    event: &Value,
    allow_loopback: bool,
    attempt_id: &str,
) -> Result<RelayPublication, String> {
    validate_relays(relays, allow_loopback)?;
    let encoded = serde_json::to_vec(event).map_err(|error| error.to_string())?;
    if encoded.len() > MAX_EVENT_BYTES {
        return Err("relay event exceeds the size limit".into());
    }
    let event_id = event
        .get("id")
        .and_then(|item| item.as_str())
        .ok_or("event id is missing")?
        .to_owned();
    let started_ms = js_sys::Date::now() as u64;
    let mut reports = Vec::new();
    for relay in relays {
        let verdict = match publish_socket(relay, &event_id, event).await {
            Ok(Some(FrameClass::Accepted)) => DestinationVerdict::Accepted,
            Ok(Some(FrameClass::Rejected { reason })) => DestinationVerdict::Rejected { reason },
            Ok(Some(FrameClass::Unrelated)) | Ok(None) => DestinationVerdict::Ambiguous {
                reason: "publication_timeout".into(),
            },
            Err(error) if error.contains("timed out") => DestinationVerdict::Ambiguous {
                reason: "publication_timeout".into(),
            },
            Err(_) => DestinationVerdict::Ambiguous {
                reason: "relay_disconnected".into(),
            },
        };
        let accepted = matches!(verdict, DestinationVerdict::Accepted);
        reports.push(DestinationReport {
            relay: relay.clone(),
            verdict,
        });
        if accepted {
            break;
        }
    }
    let mut publication = RelayPublication::from(publication::aggregate_destinations(
        &event_id,
        attempt_id,
        &reports,
    ));
    publication.started_ms = started_ms;
    publication.finished_ms = js_sys::Date::now() as u64;
    Ok(publication)
}

pub async fn fetch_events(
    relays: &[String],
    filter: Value,
    allow_loopback: bool,
) -> Result<Vec<Value>, String> {
    validate_relays(relays, allow_loopback)?;
    let mut events = Vec::new();
    for relay in relays {
        if events.len() >= 32 {
            break;
        }
        let Ok(found) = query_socket(relay, &filter).await else {
            continue;
        };
        events.extend(found);
    }
    Ok(events)
}

async fn publish_socket(
    relay: &str,
    event_id: &str,
    event: &Value,
) -> Result<Option<FrameClass>, String> {
    let deadline = js_sys::Date::now() + TIMEOUT.as_millis() as f64;
    let ws = connect_bounded(relay, deadline).await?;
    let result = read_publish(&ws, event_id, event, deadline).await;
    let _ = ws.close(Some(1000), Some("done"));
    result
}

async fn query_socket(relay: &str, filter: &Value) -> Result<Vec<Value>, String> {
    let deadline = js_sys::Date::now() + TIMEOUT.as_millis() as f64;
    let ws = connect_bounded(relay, deadline).await?;
    let result = read_query(&ws, filter, deadline).await;
    let _ = ws.close(Some(1000), Some("done"));
    result
}

async fn connect_bounded(relay: &str, deadline: f64) -> Result<WebSocket, String> {
    let url = Url::parse(relay).map_err(|_| "relay url is invalid".to_owned())?;
    let remaining = remaining_ms(deadline)?;
    let connect = WebSocket::connect(url);
    let mut connect = pin!(connect);
    let mut wait = pin!(Delay::from(Duration::from_millis(remaining)));
    match select(connect.as_mut(), wait.as_mut()).await {
        Either::Left((Ok(ws), _)) => Ok(ws),
        Either::Left((Err(error), _)) => Err(error.to_string()),
        Either::Right(_) => Err("relay timed out".into()),
    }
}

async fn read_publish(
    ws: &WebSocket,
    event_id: &str,
    event: &Value,
    deadline: f64,
) -> Result<Option<FrameClass>, String> {
    let mut incoming = ws.events().map_err(|error| error.to_string())?;
    ws.accept().map_err(|error| error.to_string())?;
    ws.send(&json!(["EVENT", event]))
        .map_err(|error| error.to_string())?;
    let mut total = 0usize;
    let mut frames = 0usize;
    loop {
        let remaining = remaining_ms(deadline)?;
        let mut next = pin!(incoming.next());
        let mut wait = pin!(Delay::from(Duration::from_millis(remaining)));
        match select(next.as_mut(), wait.as_mut()).await {
            Either::Right(_) => return Err("relay timed out".into()),
            Either::Left((None, _)) => return Err("relay disconnected".into()),
            Either::Left((Some(item), _)) => {
                let event = item.map_err(|error| error.to_string())?;
                match event {
                    WebsocketEvent::Close(_) => return Err("relay disconnected".into()),
                    WebsocketEvent::Message(message) => {
                        let Some(text) = message.text() else {
                            continue;
                        };
                        total = total.saturating_add(text.len());
                        frames += 1;
                        if text.len() > MAX_EVENT_BYTES || total > MAX_TOTAL_BYTES || frames > MAX_FRAMES {
                            return Err("relay frame exceeds the size limit".into());
                        }
                        let frame: Value =
                            serde_json::from_str(&text).map_err(|error| error.to_string())?;
                        if frame.get(0).and_then(|item| item.as_str()) == Some("AUTH") {
                            continue;
                        }
                        match publication::classify_ok(&frame, event_id) {
                            FrameClass::Unrelated => continue,
                            matched => return Ok(Some(matched)),
                        }
                    }
                }
            }
        }
    }
}

async fn read_query(ws: &WebSocket, filter: &Value, deadline: f64) -> Result<Vec<Value>, String> {
    let mut incoming = ws.events().map_err(|error| error.to_string())?;
    ws.accept().map_err(|error| error.to_string())?;
    ws.send(&json!(["REQ", SUBSCRIPTION, filter]))
        .map_err(|error| error.to_string())?;
    let mut events = Vec::new();
    let mut total = 0usize;
    let mut frames = 0usize;
    loop {
        let remaining = remaining_ms(deadline)?;
        let mut next = pin!(incoming.next());
        let mut wait = pin!(Delay::from(Duration::from_millis(remaining)));
        match select(next.as_mut(), wait.as_mut()).await {
            Either::Right(_) => return Err("relay timed out".into()),
            Either::Left((None, _)) => return Ok(events),
            Either::Left((Some(item), _)) => {
                let message = item.map_err(|error| error.to_string())?;
                match message {
                    WebsocketEvent::Close(_) => return Ok(events),
                    WebsocketEvent::Message(message) => {
                        let Some(text) = message.text() else {
                            continue;
                        };
                        total = total.saturating_add(text.len());
                        frames += 1;
                        if text.len() > MAX_EVENT_BYTES || total > MAX_TOTAL_BYTES || frames > MAX_FRAMES {
                            return Err("relay frame exceeds the size limit".into());
                        }
                        let frame: Value =
                            serde_json::from_str(&text).map_err(|error| error.to_string())?;
                        let kind = frame.get(0).and_then(|item| item.as_str()).unwrap_or("");
                        let subscription = frame.get(1).and_then(|item| item.as_str()).unwrap_or("");
                        if subscription != SUBSCRIPTION {
                            continue;
                        }
                        if kind == "EVENT" {
                            if let Some(event) = frame.get(2) {
                                events.push(event.clone());
                            }
                        } else if kind == "EOSE" {
                            return Ok(events);
                        }
                    }
                }
            }
        }
    }
}

fn remaining_ms(deadline: f64) -> Result<u64, String> {
    let now = js_sys::Date::now();
    if now >= deadline {
        return Err("relay timed out".into());
    }
    Ok((deadline - now).max(1.0) as u64)
}

fn is_loopback_host(host: &str) -> bool {
    let host = host.trim_matches(|ch| ch == '[' || ch == ']');
    host == "localhost" || host == "127.0.0.1" || host == "::1"
}

fn host_is_public(host: &str) -> bool {
    if host.is_empty() || host.ends_with(".local") || host.ends_with(".internal") {
        return false;
    }
    let Ok(ip) = host.parse::<std::net::IpAddr>() else {
        return true;
    };
    match ip {
        std::net::IpAddr::V4(ip) => {
            let [a, b, _, _] = ip.octets();
            !(ip.is_loopback()
                || ip.is_private()
                || ip.is_link_local()
                || a == 0
                || (a == 100 && (64..=127).contains(&b))
                || a == 192 && b == 0 && ip.octets()[2] == 0
                || a >= 224)
        }
        std::net::IpAddr::V6(ip) => !(ip.is_loopback() || ip.is_unspecified() || is_unique_local(&ip)),
    }
}

fn is_unique_local(ip: &std::net::Ipv6Addr) -> bool {
    (ip.octets()[0] & 0xfe) == 0xfc
}
