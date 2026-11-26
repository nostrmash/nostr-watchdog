use serde_json::{json, Value};
use uuid::Uuid;
use watchdog_core::catalog::{known_project, monitor_by_id, project_by_id, project_recipient};
use watchdog_core::clock::Clock;
use watchdog_core::crypto::{
    canonical_heartbeat, hmac_sha256_hex, secrets_equal, verify_hmac_sha256,
};
use watchdog_core::domain::{AlertClass, AlertDraft, Destination, Severity};
use watchdog_core::format::format_test_message;
use watchdog_core::heartbeat::parse_heartbeat;
use watchdog_core::settings::Settings;
use watchdog_core::status::{derive_operational_status, DestinationFlags};
use watchdog_notify::marmot_blocker;
use watchdog_store::OperationalStore;

use crate::cycle::{dispatch_due, Notifier};

#[derive(Clone, Debug)]
pub enum ApiRequest {
    Healthz,
    Status {
        authorization: Option<String>,
    },
    Heartbeat {
        monitor_id: String,
        content_type: String,
        timestamp: String,
        nonce: String,
        signature: String,
        body: Vec<u8>,
    },
    TestAlert {
        authorization: Option<String>,
        body: Vec<u8>,
        transport: Option<String>,
    },
    MarmotDiagnostic {
        authorization: Option<String>,
        project: String,
    },
    Relays {
        authorization: Option<String>,
        project: String,
    },
    FailedOutbox {
        authorization: Option<String>,
    },
    RetryOutbox {
        authorization: Option<String>,
        id: String,
    },
    Incident {
        authorization: Option<String>,
        id: String,
        action: String,
        body: Vec<u8>,
    },
    NotFound,
}

#[derive(Clone, Debug)]
pub struct ApiResponse {
    pub status: u16,
    pub body: Value,
    /// Exact JSON bytes the caller must send. The status HMAC covers these bytes.
    pub body_bytes: Vec<u8>,
    pub signature: Option<String>,
}

pub struct ApiError;

pub async fn handle<S: OperationalStore, N: Notifier, C: Clock>(
    store: &S,
    settings: &Settings,
    get: &impl Fn(&str) -> String,
    notifier: &N,
    request: ApiRequest,
    now: i64,
    clock: &C,
) -> ApiResponse {
    match request {
        ApiRequest::Healthz => json_response(
            200,
            json!({
                "status": "ok",
                "service": "nostr-watchdog",
                "enabled": settings.enabled,
            }),
        ),
        ApiRequest::Status { authorization } => {
            status(store, settings, get, authorization.as_deref(), now).await
        }
        ApiRequest::Heartbeat {
            monitor_id,
            content_type,
            timestamp,
            nonce,
            signature,
            body,
        } => {
            heartbeat(
                store,
                settings,
                get,
                &monitor_id,
                &content_type,
                &timestamp,
                &nonce,
                &signature,
                &body,
                now,
            )
            .await
        }
        ApiRequest::TestAlert {
            authorization,
            body,
            transport,
        } => {
            test_alert(
                store,
                settings,
                get,
                notifier,
                authorization.as_deref(),
                &body,
                transport.as_deref(),
                now,
                clock,
            )
            .await
        }
        ApiRequest::Relays {
            authorization,
            project,
        } => {
            relays(
                store,
                settings,
                get,
                authorization.as_deref(),
                &project,
                now,
            )
            .await
        }
        ApiRequest::MarmotDiagnostic {
            authorization,
            project,
        } => marmot_diagnostic(store, get, authorization.as_deref(), &project, now).await,
        ApiRequest::FailedOutbox { authorization } => {
            failed(store, get, authorization.as_deref()).await
        }
        ApiRequest::RetryOutbox { authorization, id } => {
            retry(store, get, authorization.as_deref(), &id, now).await
        }
        ApiRequest::Incident {
            authorization,
            id,
            action,
            body,
        } => {
            incident(
                store,
                get,
                authorization.as_deref(),
                &id,
                &action,
                &body,
                now,
            )
            .await
        }
        ApiRequest::NotFound => json_response(404, json!({"error": "not_found"})),
    }
}

async fn status<S: OperationalStore>(
    store: &S,
    settings: &Settings,
    get: &impl Fn(&str) -> String,
    authorization: Option<&str>,
    now: i64,
) -> ApiResponse {
    if let Some(response) = authorize(get, authorization, true) {
        return response;
    }
    let Ok(snapshot) = store.snapshot().await else {
        return json_response(503, json!({"error": "status_unavailable"}));
    };
    let enabled = watchdog_core::catalog::enabled_monitors(get);
    let nostr_ready = destinations_ready(settings, get, &enabled);
    let derived = derive_operational_status(
        settings,
        now,
        &snapshot,
        &enabled,
        DestinationFlags {
            nostr_ready,
            telegram_configured: !get("TELEGRAM_BOT_TOKEN").is_empty()
                && !get("TELEGRAM_CHAT_IDS").is_empty(),
        },
    );
    let mut response = json_response(derived.http_status, derived.body);
    let secret = get("STATUS_SIGNING_SECRET");
    if !secret.is_empty() {
        if let Ok(body) = std::str::from_utf8(&response.body_bytes) {
            response.signature = Some(hmac_sha256_hex(&secret, body));
        }
    }
    response
}

async fn heartbeat<S: OperationalStore>(
    store: &S,
    settings: &Settings,
    get: &impl Fn(&str) -> String,
    monitor_id: &str,
    content_type: &str,
    timestamp: &str,
    nonce: &str,
    signature: &str,
    body: &[u8],
    now: i64,
) -> ApiResponse {
    let Some(monitor) = monitor_by_id(monitor_id) else {
        return json_response(404, json!({"error": "not_found"}));
    };
    if monitor.kind != watchdog_core::CheckKind::SignedHeartbeat {
        return json_response(404, json!({"error": "not_found"}));
    }
    if get("HEARTBEAT_KEYS").trim().is_empty() {
        return json_response(503, json!({"error": "not_configured"}));
    }
    if body.len() > settings.max_body as usize {
        return json_response(413, json!({"error": "payload_too_large"}));
    }
    if content_type.split(';').next().unwrap_or("").trim() != "application/json" {
        return json_response(415, json!({"error": "unsupported_media_type"}));
    }
    if timestamp.len() != 10 || !timestamp.chars().all(|ch| ch.is_ascii_digit()) || !nonce_ok(nonce)
    {
        return json_response(401, json!({"error": "unauthorized"}));
    }
    let Ok(reported) = timestamp.parse::<i64>() else {
        return json_response(401, json!({"error": "unauthorized"}));
    };
    if (now - reported * 1000).abs() > settings.skew_seconds * 1000 {
        return json_response(401, json!({"error": "unauthorized"}));
    }
    let current = key_for(&get("HEARTBEAT_KEYS"), monitor.id);
    if current == KeyLookup::Invalid {
        return json_response(503, json!({"error": "not_configured"}));
    }
    let KeyLookup::Value(current) = current else {
        return json_response(401, json!({"error": "unauthorized"}));
    };
    let canonical = canonical_heartbeat(
        timestamp,
        nonce,
        "POST",
        &format!("/v1/heartbeats/{monitor_id}"),
        body,
    );
    let current_ok = verify_hmac_sha256(&current, &canonical, signature);
    let previous_ok = if current_ok {
        false
    } else {
        match key_for(&get("HEARTBEAT_KEYS_PREVIOUS"), monitor.id) {
            KeyLookup::Value(previous) => verify_hmac_sha256(&previous, &canonical, signature),
            _ => false,
        }
    };
    if !current_ok && !previous_ok {
        return json_response(401, json!({"error": "unauthorized"}));
    }
    let Ok(payload) = serde_json::from_slice::<Value>(body)
        .map_err(|_| ())
        .and_then(|value| parse_heartbeat(&value))
    else {
        return json_response(400, json!({"error": "bad_request"}));
    };
    match store
        .store_heartbeat(
            monitor.id,
            monitor.project_id,
            now,
            reported * 1000,
            nonce,
            reported * 1000 + settings.skew_seconds * 1000,
            payload.progress.as_deref(),
            payload.idle.unwrap_or(false),
            payload.loop_at.map(|value| value as i64),
        )
        .await
    {
        Ok(true) => json_response(200, json!({"status": "ok"})),
        Ok(false) => json_response(401, json!({"error": "replay"})),
        Err(_) => json_response(500, json!({"error": "internal_error"})),
    }
}

async fn test_alert<S: OperationalStore, N: Notifier, C: Clock>(
    store: &S,
    settings: &Settings,
    get: &impl Fn(&str) -> String,
    notifier: &N,
    authorization: Option<&str>,
    body: &[u8],
    transport: Option<&str>,
    now: i64,
    clock: &C,
) -> ApiResponse {
    if let Some(response) = authorize(get, authorization, false) {
        return response;
    }
    if body.len() > 2048 {
        return json_response(413, json!({"error": "payload_too_large"}));
    }
    let Ok(value) = serde_json::from_slice::<Value>(body) else {
        return json_response(400, json!({"error": "bad_request"}));
    };
    let Some(project_id) = value.get("projectId").and_then(Value::as_str) else {
        return json_response(400, json!({"error": "bad_request"}));
    };
    if !known_project(project_id) {
        return json_response(400, json!({"error": "bad_request"}));
    }
    // Callers that omit transport keep the TypeScript behaviour: NIP-17.
    let requested = value
        .get("transport")
        .and_then(Value::as_str)
        .or(transport)
        .unwrap_or("nip17")
        .to_string();
    let destination = match requested.as_str() {
        "marmot" => Destination::Marmot,
        "telegram" => Destination::Telegram,
        "nip17" | "nostr" => Destination::Nostr,
        _ => return json_response(400, json!({"error": "transport_invalid"})),
    };
    let Some(project) = project_by_id(project_id) else {
        return json_response(400, json!({"error": "bad_request"}));
    };
    let alert = AlertDraft {
        id: format!("alt_{}", Uuid::new_v4()),
        alert_class: AlertClass::Test,
        incident_id: None,
        monitor_id: format!("test-{project_id}"),
        project_id: project_id.to_string(),
        dedupe_key: format!("test:{project_id}:{}", Uuid::new_v4()),
        destination,
        severity: Severity::Info,
        text: format_test_message(project.display_name, now),
    };
    let allowed = store
        .insert_alert_if_allowed(
            &alert,
            now,
            &format!("test:{project_id}:"),
            now - 3_600_000,
            3,
        )
        .await;
    match allowed {
        Ok(false) => return json_response(429, json!({"error": "rate_limited"})),
        Err(_) => return json_response(500, json!({"error": "internal_error"})),
        Ok(true) => {}
    }
    let _ = dispatch_due(store, settings, get, notifier, clock).await;
    let delivery = store
        .outbox_state(&alert.id)
        .await
        .ok()
        .flatten()
        .unwrap_or_else(|| "queued".to_string());
    json_response(
        202,
        json!({
            "queued": delivery == "queued" || delivery == "retrying",
            "alertId": alert.id,
            "transport": requested,
            "queueStatus": delivery,
            "delivery": delivery,
            "deliveryState": delivery,
            "note": "Omitting transport selects nip17. Queue state is read after dispatch. Relay acceptance is not phone delivery."
        }),
    )
}

async fn marmot_diagnostic<S: OperationalStore>(
    store: &S,
    get: &impl Fn(&str) -> String,
    authorization: Option<&str>,
    project: &str,
    now: i64,
) -> ApiResponse {
    if let Some(response) = authorize(get, authorization, false) {
        return response;
    }
    if !known_project(project) {
        return json_response(400, json!({"error": "bad_request"}));
    }
    let row = store.marmot_project(project).await.ok().flatten();
    json_response(
        200,
        json!({
            "projectId": project,
            "checkedAt": watchdog_core::format::format_unix_ms(now),
            "engineStatus": row.as_ref().map(|item| item.engine_status.clone()).unwrap_or_else(|| "not_initialized".to_string()),
            "pubkey": row.as_ref().and_then(|item| item.pubkey.clone()),
            "conversationId": row.as_ref().and_then(|item| item.conversation_id.clone()),
            "groupId": row.as_ref().and_then(|item| item.group_id_hex.clone()),
            "peer": row.as_ref().and_then(|item| item.peer_pubkey.clone()),
            "lastSyncAt": row.as_ref().and_then(|item| item.last_sync_at).map(watchdog_core::format::format_unix_ms),
            "lastSyncError": row.as_ref().and_then(|item| item.last_sync_error.clone()),
            "pushTokenAvailable": false,
            "blocker": marmot_blocker(),
            "note": "Relay acceptance is not phone delivery. Push tokens are not returned by this endpoint.",
        }),
    )
}

async fn failed<S: OperationalStore>(
    store: &S,
    get: &impl Fn(&str) -> String,
    authorization: Option<&str>,
) -> ApiResponse {
    if let Some(response) = authorize(get, authorization, false) {
        return response;
    }
    let alerts = store.list_failed().await.unwrap_or_default();
    json_response(
        200,
        json!({
            "alerts": alerts.into_iter().map(|alert| json!({
                "id": alert.id,
                "monitorId": alert.monitor_id,
                "destination": alert.destination,
                "lastError": alert.last_error,
            })).collect::<Vec<_>>(),
        }),
    )
}

async fn retry<S: OperationalStore>(
    store: &S,
    get: &impl Fn(&str) -> String,
    authorization: Option<&str>,
    id: &str,
    now: i64,
) -> ApiResponse {
    if let Some(response) = authorize(get, authorization, false) {
        return response;
    }
    match store.retry_dead_letter(id, now).await {
        Ok(true) => json_response(200, json!({"id": id, "status": "queued"})),
        Ok(false) => json_response(404, json!({"error": "not_found"})),
        Err(_) => json_response(500, json!({"error": "internal_error"})),
    }
}

async fn incident<S: OperationalStore>(
    store: &S,
    get: &impl Fn(&str) -> String,
    authorization: Option<&str>,
    id: &str,
    action: &str,
    body: &[u8],
    now: i64,
) -> ApiResponse {
    if let Some(response) = authorize(get, authorization, false) {
        return response;
    }
    let Ok(Some((monitor_id, status))) = store.open_incident_status(id).await else {
        return json_response(404, json!({"error": "not_found"}));
    };
    if status != "open" {
        return json_response(404, json!({"error": "not_found"}));
    }
    if action == "ack" {
        let _ = store.ack_incident(id, now).await;
        return json_response(
            200,
            json!({"id": id, "monitorId": monitor_id, "status": "acked"}),
        );
    }
    let mut minutes = 60_i64;
    if !body.is_empty() {
        let Ok(value) = serde_json::from_slice::<Value>(body) else {
            return json_response(400, json!({"error": "bad_request"}));
        };
        if let Some(parsed) = value.get("minutes").and_then(Value::as_i64) {
            if !(1..=10_080).contains(&parsed) {
                return json_response(400, json!({"error": "bad_request"}));
            }
            minutes = parsed;
        }
    }
    let _ = store
        .silence_incident(id, now + minutes * 60_000, now)
        .await;
    json_response(
        200,
        json!({"id": id, "monitorId": monitor_id, "status": "silenced"}),
    )
}

fn destinations_ready(
    settings: &Settings,
    get: &impl Fn(&str) -> String,
    enabled: &[watchdog_core::MonitorDefinition],
) -> bool {
    if !settings.alerts_enabled {
        return true;
    }
    if settings.bootstrap.is_empty() && settings.nip17_enabled {
        return false;
    }
    let mut projects = Vec::new();
    for monitor in enabled {
        if !projects.contains(&monitor.project_id) {
            projects.push(monitor.project_id);
        }
    }
    for id in projects {
        let Some(project) = project_by_id(id) else {
            return false;
        };
        if get(project.sender_secret).is_empty()
            || project_recipient(&get("PROJECT_RECIPIENTS"), &get("ADMIN_NPUB"), id).is_none()
        {
            return false;
        }
    }
    true
}

fn authorize(
    get: &impl Fn(&str) -> String,
    authorization: Option<&str>,
    status_scope: bool,
) -> Option<ApiResponse> {
    let operator = get("OPERATOR_TOKEN");
    let reader = if status_scope {
        get("STATUS_READ_TOKEN")
    } else {
        String::new()
    };
    if operator.is_empty() && reader.is_empty() {
        return Some(json_response(503, json!({"error": "not_configured"})));
    }
    let header = authorization.unwrap_or("");
    let token = header
        .strip_prefix("Bearer ")
        .or_else(|| header.strip_prefix("bearer "))
        .unwrap_or("")
        .trim();
    if !operator.is_empty() && secrets_equal(&operator, token) {
        return None;
    }
    if !reader.is_empty() && secrets_equal(&reader, token) {
        return None;
    }
    Some(json_response(401, json!({"error": "unauthorized"})))
}

#[derive(PartialEq, Eq)]
enum KeyLookup {
    Missing,
    Invalid,
    Value(String),
}

fn key_for(raw: &str, monitor_id: &str) -> KeyLookup {
    if raw.trim().is_empty() {
        return KeyLookup::Missing;
    }
    let Ok(parsed) = serde_json::from_str::<Value>(raw) else {
        return KeyLookup::Invalid;
    };
    match parsed.get(monitor_id).and_then(Value::as_str) {
        Some(value) if value.len() >= 32 => KeyLookup::Value(value.to_string()),
        Some(_) => KeyLookup::Invalid,
        None => KeyLookup::Missing,
    }
}

fn nonce_ok(nonce: &str) -> bool {
    (16..=128).contains(&nonce.len())
        && nonce
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '_' || ch == '-')
}

async fn relays<S: OperationalStore>(
    store: &S,
    _settings: &Settings,
    get: &impl Fn(&str) -> String,
    authorization: Option<&str>,
    project: &str,
    now: i64,
) -> ApiResponse {
    if let Some(response) = authorize(get, authorization, false) {
        return response;
    }
    if !known_project(project) {
        return json_response(400, json!({"error": "bad_request"}));
    }
    let Some(raw) = project_recipient(&get("PROJECT_RECIPIENTS"), &get("ADMIN_NPUB"), project)
    else {
        return json_response(
            409,
            json!({"error": "recipient_missing", "inboxRelays": [], "cached": false}),
        );
    };
    let Ok(author) = watchdog_notify::recipient_pubkey(&raw) else {
        return json_response(
            409,
            json!({"error": "recipient_invalid", "inboxRelays": [], "cached": false}),
        );
    };
    let cached = store.relay_cache(&author, now).await.ok().flatten();
    let remembered = store.remembered_inbox(&author).await.unwrap_or_default();
    match watchdog_notify::interpret_cache(cached) {
        watchdog_notify::CacheDecision::Fresh(relays) => json_response(
            200,
            json!({
                "projectId": project,
                "inboxRelays": relays,
                "cached": true,
                "fresh": true,
                "negative": false,
                "rememberedRelays": remembered,
                "error": null,
            }),
        ),
        watchdog_notify::CacheDecision::Negative => json_response(
            200,
            json!({
                "projectId": project,
                "inboxRelays": [],
                "cached": true,
                "fresh": true,
                "negative": true,
                "rememberedRelays": remembered,
                "error": "recipient_inbox_missing",
            }),
        ),
        watchdog_notify::CacheDecision::Discover => json_response(
            200,
            json!({
                "projectId": project,
                "inboxRelays": [],
                "cached": false,
                "fresh": false,
                "negative": false,
                "rememberedRelays": remembered,
                "error": "discovery_required",
            }),
        ),
    }
}

fn json_response(status: u16, body: Value) -> ApiResponse {
    let body_bytes = serde_json::to_vec(&body).unwrap_or_else(|_| b"{}".to_vec());
    ApiResponse {
        status,
        body,
        body_bytes,
        signature: None,
    }
}
