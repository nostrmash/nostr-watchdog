//! Native relay sockets. Frame size is enforced by the WebSocket library
//! before the message is allocated, and every phase shares one deadline.

use std::time::{Duration, Instant};

use futures_util::{SinkExt, StreamExt};
use serde_json::Value;
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;
use tokio_tungstenite::{client_async_tls_with_config, tungstenite::Message};
use url::Url;
use watchdog_core::url_policy::workers_websocket_url;
use watchdog_engine::{InboxFrames, RelayIo};
use watchdog_notify::{auth_frame, parse_relay_frame, RelayControl};

const MAX_FRAME_BYTES: usize = 65_536;
const MAX_SESSION_BYTES: usize = 262_144;
const MAX_EVENTS: usize = 32;

pub struct NativeRelay;

impl RelayIo for NativeRelay {
    async fn query_inbox(
        &self,
        relay: &str,
        author: &str,
        signer: Option<&str>,
        timeout_ms: i64,
    ) -> Result<InboxFrames, String> {
        query_inbox(relay, author, signer, timeout_ms).await
    }

    async fn publish(
        &self,
        relay: &str,
        event_json: &str,
        signer: Option<&str>,
        timeout_ms: i64,
    ) -> Result<bool, String> {
        publish(relay, event_json, signer, timeout_ms).await
    }
}

pub async fn query_inbox(
    relay: &str,
    author: &str,
    signer: Option<&str>,
    timeout_ms: i64,
) -> Result<InboxFrames, String> {
    let deadline = Instant::now() + Duration::from_millis(timeout_ms.max(1) as u64);
    let mut socket = connect(relay, deadline).await?;
    let sub = uuid_like();
    let request =
        serde_json::json!(["REQ", sub, {"kinds": [10050], "authors": [author], "limit": 5}])
            .to_string();
    send_text(&mut socket, &request, deadline).await?;
    let mut events = Vec::new();
    let mut eose = false;
    let mut total = 0usize;
    let mut authed = false;
    let read = async {
        while let Some(message) = socket.next().await {
            if Instant::now() >= deadline {
                return Err("relay_timeout".to_string());
            }
            let message = message.map_err(|_| "relay_malformed".to_string())?;
            let Message::Text(text) = message else {
                continue;
            };
            total = total.saturating_add(text.len());
            if total > MAX_SESSION_BYTES {
                return Err("relay_response_too_large".to_string());
            }
            match parse_relay_frame(&text) {
                RelayControl::Auth { challenge } if !authed => {
                    let Some(nsec) = signer else {
                        return Err("relay_auth_required".to_string());
                    };
                    let frame = auth_frame(nsec, &challenge, relay)
                        .map_err(|_| "relay_auth_required".to_string())?;
                    send_text(&mut socket, &frame, deadline).await?;
                    authed = true;
                }
                RelayControl::Auth { .. } => return Err("relay_auth_required".to_string()),
                RelayControl::Event {
                    subscription,
                    event_json,
                } if subscription == sub => {
                    if events.len() >= MAX_EVENTS {
                        return Err("relay_event_limit".to_string());
                    }
                    events.push(event_json);
                }
                RelayControl::Eose { subscription } if subscription == sub => {
                    eose = true;
                    break;
                }
                RelayControl::Closed { subscription } if subscription == sub => {
                    return Err("relay_closed".to_string());
                }
                _ => {}
            }
        }
        Ok(())
    };
    let read = timeout_until(deadline, read).await;
    let _ = send_text(&mut socket, &format!("[\"CLOSE\",\"{sub}\"]"), deadline).await;
    let _ = timeout_until(deadline, socket.close(None)).await;
    read?;
    Ok(InboxFrames { events, eose })
}

pub async fn publish(
    relay: &str,
    event_json: &str,
    signer: Option<&str>,
    timeout_ms: i64,
) -> Result<bool, String> {
    let deadline = Instant::now() + Duration::from_millis(timeout_ms.max(1) as u64);
    let mut socket = connect(relay, deadline).await?;
    let event: Value =
        serde_json::from_str(event_json).map_err(|_| "envelope_invalid".to_string())?;
    let id = event
        .get("id")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let frame = serde_json::json!(["EVENT", event]).to_string();
    if frame.len() > MAX_FRAME_BYTES {
        return Err("relay_frame_too_large".to_string());
    }
    send_text(&mut socket, &frame, deadline).await?;
    let mut accepted = false;
    let mut total = 0usize;
    let mut authed = false;
    let read = async {
        while let Some(message) = socket.next().await {
            if Instant::now() >= deadline {
                return Err("relay_timeout".to_string());
            }
            let message = message.map_err(|_| "relay_malformed".to_string())?;
            let Message::Text(text) = message else {
                continue;
            };
            total = total.saturating_add(text.len());
            if total > MAX_SESSION_BYTES {
                return Err("relay_response_too_large".to_string());
            }
            match parse_relay_frame(&text) {
                RelayControl::Auth { challenge } if !authed => {
                    let Some(nsec) = signer else {
                        return Err("relay_auth_required".to_string());
                    };
                    let frame = auth_frame(nsec, &challenge, relay)
                        .map_err(|_| "relay_auth_required".to_string())?;
                    send_text(&mut socket, &frame, deadline).await?;
                    authed = true;
                }
                RelayControl::Auth { .. } => return Err("relay_auth_required".to_string()),
                RelayControl::Ok {
                    event_id,
                    accepted: ok,
                } if event_id == id => {
                    accepted = ok;
                    break;
                }
                RelayControl::Closed { .. } => return Err("relay_closed".to_string()),
                _ => {}
            }
        }
        Ok(())
    };
    let read = timeout_until(deadline, read).await;
    let _ = timeout_until(deadline, socket.close(None)).await;
    read?;
    Ok(accepted)
}

async fn send_text(
    socket: &mut tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<TcpStream>>,
    text: &str,
    deadline: Instant,
) -> Result<(), String> {
    timeout_until(
        deadline,
        socket.send(Message::Text(text.to_string().into())),
    )
    .await?
    .map_err(|_| "relay_closed".to_string())
}

async fn connect(
    relay: &str,
    deadline: Instant,
) -> Result<tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<TcpStream>>, String>
{
    let https = workers_websocket_url(relay).map_err(|error| error.message.to_string())?;
    let url = https.replacen("https://", "wss://", 1);
    let parsed = Url::parse(&url).map_err(|_| "relay_url_invalid".to_string())?;
    let host = parsed
        .host_str()
        .ok_or_else(|| "relay_url_invalid".to_string())?
        .to_string();
    let port = parsed.port_or_known_default().unwrap_or(443);
    let address = timeout_until(deadline, crate::net::resolve_pinned(&host, port, false)).await??;
    let stream = timeout_until(deadline, TcpStream::connect(address))
        .await?
        .map_err(|_| "relay_connect_failed".to_string())?;
    let config = WebSocketConfig::default()
        .max_frame_size(Some(MAX_FRAME_BYTES))
        .max_message_size(Some(MAX_FRAME_BYTES));
    let (socket, _) = timeout_until(
        deadline,
        client_async_tls_with_config(&url, stream, Some(config), None),
    )
    .await?
    .map_err(|_| "relay_connect_failed".to_string())?;
    Ok(socket)
}

async fn timeout_until<T>(
    deadline: Instant,
    future: impl std::future::Future<Output = T>,
) -> Result<T, String> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Err("relay_timeout".to_string());
    }
    timeout(remaining, future)
        .await
        .map_err(|_| "relay_timeout".to_string())
}

fn uuid_like() -> String {
    format!(
        "{:032x}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or(0)
    )
}
