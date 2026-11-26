//! Bounded Nostr relay client for the Durable Object.
//!
//! Publication runs outside the cryptographic gate. Loopback relays are
//! accepted only when the test flag is set. `relay.example` is never a destination.

use std::pin::pin;
use std::time::Duration;

use futures_util::future::{Either, select};
use futures_util::StreamExt;
use serde_json::{Value, json};
use url::Url;
use worker::{Delay, WebSocket, WebsocketEvent};

const MAX_RELAYS: usize = 4;
const MAX_EVENT_BYTES: usize = 64 * 1024;
const TIMEOUT: Duration = Duration::from_secs(5);

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
    let host = url.host_str().unwrap_or("");
    if host == "relay.example" || host.ends_with(".example") {
        return Err("placeholder relay is rejected".into());
    }
    let loopback = is_loopback_host(host);
    match url.scheme() {
        "wss" if !loopback && host_is_public(host) => Ok(()),
        "ws" if allow_loopback && loopback => Ok(()),
        "wss" if allow_loopback && loopback => Ok(()),
        _ => Err("relay destination is not allowed".into()),
    }
}

pub async fn publish_event(
    relays: &[String],
    event: &Value,
    allow_loopback: bool,
) -> Result<bool, String> {
    validate_relays(relays, allow_loopback)?;
    let encoded = serde_json::to_vec(event).map_err(|error| error.to_string())?;
    if encoded.len() > MAX_EVENT_BYTES {
        return Err("relay event exceeds the size limit".into());
    }
    let mut accepted = false;
    let mut saw_response = false;
    for relay in relays {
        match one_socket(relay, json!(["EVENT", event]), false).await {
            Ok(frames) => {
                saw_response = true;
                if frames.iter().any(|frame| {
                    frame.get(0).and_then(|item| item.as_str()) == Some("OK")
                        && frame.get(2).and_then(|item| item.as_bool()) == Some(true)
                }) {
                    accepted = true;
                }
            }
            Err(_) => {}
        }
    }
    if accepted {
        Ok(true)
    } else if saw_response {
        Err("relay rejected the event".into())
    } else {
        Err("relay publication was not acknowledged".into())
    }
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
        let Ok(frames) = one_socket(relay, json!(["REQ", "marmot", filter]), true).await else {
            continue;
        };
        for frame in frames {
            if frame.get(0).and_then(|item| item.as_str()) == Some("EVENT") {
                if let Some(event) = frame.get(2) {
                    events.push(event.clone());
                }
            }
        }
    }
    Ok(events)
}

async fn one_socket(relay: &str, first: Value, until_eose: bool) -> Result<Vec<Value>, String> {
    let url = Url::parse(relay).map_err(|_| "relay url is invalid".to_owned())?;
    let ws = WebSocket::connect(url)
        .await
        .map_err(|error| error.to_string())?;
    let mut incoming = ws.events().map_err(|error| error.to_string())?;
    ws.accept().map_err(|error| error.to_string())?;
    ws.send(&first).map_err(|error| error.to_string())?;
    let deadline = js_sys::Date::now() + TIMEOUT.as_millis() as f64;
    let mut frames = Vec::new();
    loop {
        let now = js_sys::Date::now();
        if now >= deadline {
            return Err("relay timed out".into());
        }
        let remaining = (deadline - now).max(1.0) as u64;
        let mut next = pin!(incoming.next());
        let mut wait = pin!(Delay::from(Duration::from_millis(remaining)));
        let step = select(next.as_mut(), wait.as_mut()).await;
        match step {
            Either::Right(_) => return Err("relay timed out".into()),
            Either::Left((None, _)) => break,
            Either::Left((Some(item), _)) => {
                let event = item.map_err(|error| error.to_string())?;
                match event {
                    WebsocketEvent::Close(_) => break,
                    WebsocketEvent::Message(message) => {
                        let Some(text) = message.text() else {
                            continue;
                        };
                        if text.len() > MAX_EVENT_BYTES {
                            return Err("relay frame exceeds the size limit".into());
                        }
                        let frame: Value =
                            serde_json::from_str(&text).map_err(|error| error.to_string())?;
                        let kind = frame.get(0).and_then(|item| item.as_str()).unwrap_or("");
                        let done = kind == "OK" || (until_eose && kind == "EOSE");
                        frames.push(frame);
                        if done || frames.len() >= 32 {
                            break;
                        }
                    }
                }
            }
        }
    }
    Ok(frames)
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
