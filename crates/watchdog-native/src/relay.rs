use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use serde_json::Value;
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_tungstenite::{client_async_tls, tungstenite::Message};
use url::Url;
use watchdog_core::url_policy::workers_websocket_url;

const MAX_FRAME_BYTES: usize = 65_536;
const MAX_SESSION_BYTES: usize = 262_144;
const MAX_EVENTS: usize = 32;

pub async fn query_inbox(
    relay: &str,
    author: &str,
    timeout_ms: i64,
) -> Result<(Vec<String>, bool), String> {
    let mut socket = connect(relay, timeout_ms).await?;
    let sub = uuid_like();
    let request =
        serde_json::json!(["REQ", sub, {"kinds": [10050], "authors": [author], "limit": 5}])
            .to_string();
    socket
        .send(Message::Text(request.into()))
        .await
        .map_err(|_| "relay_closed".to_string())?;
    let mut events = Vec::new();
    let mut eose = false;
    let mut total = 0usize;
    let deadline = Duration::from_millis(timeout_ms as u64);
    let read = timeout(deadline, async {
        while let Some(message) = socket.next().await {
            let message = message.map_err(|_| "relay_malformed")?;
            let Message::Text(text) = message else {
                continue;
            };
            if text.len() > MAX_FRAME_BYTES {
                return Err("relay_frame_too_large");
            }
            total = total.saturating_add(text.len());
            if total > MAX_SESSION_BYTES {
                return Err("relay_response_too_large");
            }
            let Ok(parsed) = serde_json::from_str::<Value>(&text) else {
                continue;
            };
            let Some(items) = parsed.as_array() else {
                continue;
            };
            if items.first().and_then(Value::as_str) == Some("AUTH") {
                return Err("relay_auth_required");
            }
            if items.first().and_then(Value::as_str) == Some("EVENT")
                && items.get(1).and_then(Value::as_str) == Some(sub.as_str())
            {
                if events.len() >= MAX_EVENTS {
                    return Err("relay_event_limit");
                }
                if let Some(event) = items.get(2) {
                    events.push(event.to_string());
                }
            }
            if items.first().and_then(Value::as_str) == Some("EOSE")
                && items.get(1).and_then(Value::as_str) == Some(sub.as_str())
            {
                eose = true;
                break;
            }
        }
        Ok(())
    })
    .await;
    let _ = socket
        .send(Message::Text(format!("[\"CLOSE\",\"{sub}\"]").into()))
        .await;
    let _ = socket.close(None).await;
    match read {
        Ok(Ok(())) => Ok((events, eose)),
        Ok(Err(error)) => Err(error.to_string()),
        Err(_) => Err("relay_timeout".to_string()),
    }
}

pub async fn publish(relay: &str, event_json: &str, timeout_ms: i64) -> Result<bool, String> {
    let mut socket = connect(relay, timeout_ms).await?;
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
    socket
        .send(Message::Text(frame.into()))
        .await
        .map_err(|_| "relay_closed".to_string())?;
    let mut accepted = false;
    let mut total = 0usize;
    let read = timeout(Duration::from_millis(timeout_ms as u64), async {
        while let Some(message) = socket.next().await {
            let message = message.map_err(|_| "relay_malformed")?;
            let Message::Text(text) = message else {
                continue;
            };
            if text.len() > MAX_FRAME_BYTES {
                return Err("relay_frame_too_large");
            }
            total = total.saturating_add(text.len());
            if total > MAX_SESSION_BYTES {
                return Err("relay_response_too_large");
            }
            let Ok(parsed) = serde_json::from_str::<Value>(&text) else {
                continue;
            };
            let Some(items) = parsed.as_array() else {
                continue;
            };
            if items.first().and_then(Value::as_str) == Some("AUTH") {
                return Err("relay_auth_required");
            }
            if items.first().and_then(Value::as_str) == Some("OK")
                && items.get(1).and_then(Value::as_str) == Some(id.as_str())
            {
                accepted = items.get(2).and_then(Value::as_bool).unwrap_or(false);
                break;
            }
        }
        Ok(())
    })
    .await;
    let _ = socket.close(None).await;
    match read {
        Ok(Ok(())) => Ok(accepted),
        Ok(Err(error)) => Err(error.to_string()),
        Err(_) => Err("relay_timeout".to_string()),
    }
}

async fn connect(
    relay: &str,
    timeout_ms: i64,
) -> Result<tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<TcpStream>>, String>
{
    let https = workers_websocket_url(relay).map_err(|error| error.message.to_string())?;
    let url = https.replacen("https://", "wss://", 1);
    let parsed = Url::parse(&url).map_err(|_| "relay_url_invalid".to_string())?;
    let host = parsed
        .host_str()
        .ok_or_else(|| "relay_url_invalid".to_string())?;
    let port = parsed.port_or_known_default().unwrap_or(443);
    let address = crate::net::resolve_pinned(host, port, false).await?;
    let stream = timeout(
        Duration::from_millis(timeout_ms as u64),
        TcpStream::connect(address),
    )
    .await
    .map_err(|_| "relay_timeout".to_string())?
    .map_err(|_| "relay_connect_failed".to_string())?;
    let (socket, _) = timeout(
        Duration::from_millis(timeout_ms as u64),
        client_async_tls(&url, stream),
    )
    .await
    .map_err(|_| "relay_timeout".to_string())?
    .map_err(|_| "relay_connect_failed".to_string())?;
    Ok(socket)
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
