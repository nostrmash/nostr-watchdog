use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use serde_json::Value;
use tokio::time::timeout;
use tokio_tungstenite::{connect_async, tungstenite::Message};
use watchdog_core::url_policy::workers_websocket_url;

pub async fn query_inbox(
    relay: &str,
    author: &str,
    timeout_ms: i64,
) -> Result<(Vec<String>, bool), String> {
    let url = workers_websocket_url(relay).map_err(|error| error.message.to_string())?;
    let url = url.replacen("https://", "wss://", 1);
    let (mut socket, _) = timeout(
        Duration::from_millis(timeout_ms as u64),
        connect_async(&url),
    )
    .await
    .map_err(|_| "relay_timeout".to_string())?
    .map_err(|_| "relay_connect_failed".to_string())?;
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
    let deadline = Duration::from_millis(timeout_ms as u64);
    let _ = timeout(deadline, async {
        while let Some(message) = socket.next().await {
            let Ok(message) = message else { break };
            let Message::Text(text) = message else {
                continue;
            };
            if text.len() > 65_536 {
                continue;
            }
            let Ok(parsed) = serde_json::from_str::<Value>(&text) else {
                continue;
            };
            let Some(items) = parsed.as_array() else {
                continue;
            };
            if items.first().and_then(Value::as_str) == Some("EVENT")
                && items.get(1).and_then(Value::as_str) == Some(&sub)
            {
                if let Some(event) = items.get(2) {
                    events.push(event.to_string());
                }
            }
            if items.first().and_then(Value::as_str) == Some("EOSE")
                && items.get(1).and_then(Value::as_str) == Some(&sub)
            {
                eose = true;
                break;
            }
        }
    })
    .await;
    let _ = socket
        .send(Message::Text(format!("[\"CLOSE\",\"{sub}\"]").into()))
        .await;
    let _ = socket.close(None).await;
    Ok((events, eose))
}

pub async fn publish(relay: &str, event_json: &str, timeout_ms: i64) -> Result<bool, String> {
    let url = workers_websocket_url(relay).map_err(|error| error.message.to_string())?;
    let url = url.replacen("https://", "wss://", 1);
    let event: Value =
        serde_json::from_str(event_json).map_err(|_| "envelope_invalid".to_string())?;
    let id = event
        .get("id")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let (mut socket, _) = timeout(
        Duration::from_millis(timeout_ms as u64),
        connect_async(&url),
    )
    .await
    .map_err(|_| "relay_timeout".to_string())?
    .map_err(|_| "relay_connect_failed".to_string())?;
    let frame = serde_json::json!(["EVENT", event]).to_string();
    socket
        .send(Message::Text(frame.into()))
        .await
        .map_err(|_| "relay_closed".to_string())?;
    let mut accepted = false;
    let _ = timeout(Duration::from_millis(timeout_ms as u64), async {
        while let Some(message) = socket.next().await {
            let Ok(Message::Text(text)) = message else {
                continue;
            };
            let Ok(parsed) = serde_json::from_str::<Value>(&text) else {
                continue;
            };
            let Some(items) = parsed.as_array() else {
                continue;
            };
            if items.first().and_then(Value::as_str) == Some("OK")
                && items.get(1).and_then(Value::as_str) == Some(id.as_str())
            {
                accepted = items.get(2).and_then(Value::as_bool).unwrap_or(false);
                break;
            }
        }
    })
    .await;
    let _ = socket.close(None).await;
    Ok(accepted)
}

fn uuid_like() -> String {
    format!(
        "{:032x}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    )
}
