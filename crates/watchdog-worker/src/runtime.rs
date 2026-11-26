//! Worker fetch, scheduled monitoring, and notification I/O.

use std::collections::HashMap;

use futures_util::StreamExt;
use serde_json::Value;
use watchdog_core::settings::load_settings;
use watchdog_engine::{
    handle, run_check_cycle, run_update_cycle, ApiRequest, DeliveryOutcome, HttpClient, Notifier,
    ProbeRequest, ProbeResponse,
};
use watchdog_notify::{
    build_gift_wrap, event_json, parse_event, recipient_pubkey, MARMOT_ENGINE_STATUS,
};
use watchdog_store::OutboxRow;
use worker::{
    console_log, D1Database, Env, Fetch, Headers, Method, Request, RequestInit, Response, Result,
    ScheduledEvent, WebSocket,
};

use crate::d1_store::{self, D1Store};

pub async fn fetch(mut req: Request, env: Env) -> Result<Response> {
    let path = req.path();
    if req.method() == Method::Get && path == "/healthz" {
        return Response::from_json(&serde_json::json!({
            "status": "ok",
            "service": "nostr-watchdog",
            "runtime": "cloudflare",
            "live": true
        }));
    }
    let Ok(db) = env.d1("DB") else {
        if req.method() == Method::Get && path == "/readyz" {
            return Ok(Response::from_json(&serde_json::json!({
                "ready": false,
                "database": "unconfigured"
            }))?
            .with_status(503));
        }
        return Response::error("database_unconfigured", 503);
    };
    if let Err(error) = d1_store::migrate(&db).await {
        return Response::error(error.to_string(), 503);
    }
    if req.method() == Method::Get && path == "/readyz" {
        let ready = db
            .prepare("SELECT 1 AS n")
            .first::<Value>(None)
            .await
            .ok()
            .flatten()
            .is_some();
        let status = if ready { 200 } else { 503 };
        return Ok(Response::from_json(&serde_json::json!({
            "ready": ready,
            "database": if ready { "ok" } else { "unavailable" },
            "marmot": "native_only"
        }))?
        .with_status(status));
    }
    let vars = read_config(&env);
    let settings = load_settings(|key| vars.get(key).cloned().unwrap_or_default());
    let store = D1Store::new(db);
    let notifier = WorkerNotifier {
        db: env.d1("DB")?,
        vars: vars.clone(),
    };
    let get = |key: &str| vars.get(key).cloned().unwrap_or_default();
    let request = match api_request(&mut req).await {
        Some(request) => request,
        None => return Response::error("not_found", 404),
    };
    let response = handle(&store, &settings, &get, &notifier, request, now_ms()).await;
    Ok(Response::from_json(&response.body)?.with_status(response.status))
}

pub async fn scheduled(event: ScheduledEvent, env: Env) -> Result<()> {
    let db = env.d1("DB")?;
    d1_store::migrate(&db)
        .await
        .map_err(|error| worker::Error::RustError(error.to_string()))?;
    let vars = read_config(&env);
    let settings = load_settings(|key| vars.get(key).cloned().unwrap_or_default());
    let store = D1Store::new(db);
    let notifier = WorkerNotifier {
        db: env.d1("DB")?,
        vars: vars.clone(),
    };
    let http = WorkerHttp;
    let get = |key: &str| vars.get(key).cloned().unwrap_or_default();
    let now = now_ms();
    let cycle = if event.cron().starts_with("0 ") {
        run_update_cycle(&store, &settings, &get, &http, &notifier, now).await
    } else {
        run_check_cycle(&store, &settings, &get, &http, &notifier, now).await
    };
    if let Err(error) = cycle {
        console_log!("monitoring cycle failed: {error}");
        return Err(worker::Error::RustError(error.to_string()));
    }
    Ok(())
}

struct WorkerHttp;

impl HttpClient for WorkerHttp {
    async fn send(&self, request: ProbeRequest) -> Result<ProbeResponse, String> {
        let mut headers = Headers::new();
        for (key, value) in &request.headers {
            headers.set(key, value).map_err(|error| error.to_string())?;
        }
        let mut init = RequestInit::new();
        init.with_method(Method::Get).with_headers(headers);
        let http_request =
            Request::new_with_init(&request.url, &init).map_err(|error| error.to_string())?;
        let mut response = Fetch::Request(http_request)
            .send()
            .await
            .map_err(|error| error.to_string())?;
        let status = response.status_code();
        let bytes = response.bytes().await.map_err(|error| error.to_string())?;
        let too_large = bytes.len() > request.max_bytes;
        Ok(ProbeResponse {
            status,
            headers: HashMap::new(),
            body: if too_large { Vec::new() } else { bytes },
            too_large,
        })
    }
}

struct WorkerNotifier {
    db: D1Database,
    vars: HashMap<String, String>,
}

impl Notifier for WorkerNotifier {
    async fn deliver_nostr(&self, row: &OutboxRow, _claim: &str) -> DeliveryOutcome {
        let get = |key: &str| self.vars.get(key).cloned().unwrap_or_default();
        let settings = load_settings(&get);
        let Some(project) = watchdog_core::catalog::project_by_id(&row.project_id) else {
            return terminal("project_invalid");
        };
        let nsec = get(project.sender_secret);
        let Some(recipient_raw) = watchdog_core::catalog::project_recipient(
            &get("PROJECT_RECIPIENTS"),
            &get("ADMIN_NPUB"),
            project.id,
        ) else {
            return terminal("recipient_missing");
        };
        let Ok(recipient) = recipient_pubkey(&recipient_raw) else {
            return terminal("recipient_invalid");
        };
        let Some(relay) = settings.bootstrap.first().cloned() else {
            return terminal("bootstrap_relays_missing");
        };
        let Ok(event) = build_gift_wrap(
            &nsec,
            &recipient,
            &row.payload_text,
            project.contact_name,
            (row.created_at / 1000) as u64,
        ) else {
            return terminal("envelope_invalid");
        };
        let payload = event_json(&event);
        match publish_gift_wrap(&relay, &payload).await {
            Ok(true) => DeliveryOutcome {
                accepted: true,
                terminal: false,
                error: None,
                accepted_relays: vec![relay],
                failed_relays: Vec::new(),
                message_phase: Some("message_accepted".to_string()),
                push_phase: None,
                message_event_id: parse_event(&payload).ok().map(|event| event.id.to_hex()),
                push_envelope: None,
            },
            Ok(false) => retry("relay_rejected"),
            Err(error) => retry(&error),
        }
    }

    async fn deliver_telegram(&self, row: &OutboxRow) -> DeliveryOutcome {
        let token = self
            .vars
            .get("TELEGRAM_BOT_TOKEN")
            .cloned()
            .unwrap_or_default();
        let Some(chat) = watchdog_core::catalog::telegram_chat(
            self.vars
                .get("TELEGRAM_CHAT_IDS")
                .map(String::as_str)
                .unwrap_or(""),
            &row.project_id,
        ) else {
            return terminal("telegram_unavailable");
        };
        if token.is_empty() {
            return terminal("telegram_unavailable");
        }
        let url = format!("https://api.telegram.org/bot{token}/sendMessage");
        let body = serde_json::json!({
            "chat_id": chat,
            "text": row.payload_text,
            "disable_web_page_preview": true
        });
        let mut headers = Headers::new();
        let _ = headers.set("content-type", "application/json");
        let mut init = RequestInit::new();
        init.with_method(Method::Post)
            .with_headers(headers)
            .with_body(Some(wasm_bindgen::JsValue::from_str(&body.to_string())));
        let Ok(request) = Request::new_with_init(&url, &init) else {
            return retry("telegram_failed");
        };
        match Fetch::Request(request).send().await {
            Ok(response) if (200..300).contains(&response.status_code()) => DeliveryOutcome {
                accepted: true,
                terminal: false,
                error: None,
                accepted_relays: Vec::new(),
                failed_relays: Vec::new(),
                message_phase: None,
                push_phase: None,
                message_event_id: None,
                push_envelope: None,
            },
            _ => retry("telegram_failed"),
        }
    }

    async fn deliver_marmot(&self, _row: &OutboxRow, _claim: &str) -> DeliveryOutcome {
        let _ = self.db;
        let _ = MARMOT_ENGINE_STATUS;
        DeliveryOutcome {
            accepted: false,
            terminal: false,
            error: Some("marmot_engine_unavailable".to_string()),
            accepted_relays: Vec::new(),
            failed_relays: Vec::new(),
            message_phase: None,
            push_phase: Some("push_token_unavailable".to_string()),
            message_event_id: None,
            push_envelope: None,
        }
    }
}

async fn publish_gift_wrap(relay: &str, event_json: &str) -> Result<bool, String> {
    let url = watchdog_core::url_policy::workers_websocket_url(relay)
        .map_err(|error| error.message.to_string())?;
    let url = url.replacen("https://", "wss://", 1);
    let parsed = url.parse().map_err(|_| "relay_url_invalid".to_string())?;
    let socket = WebSocket::connect(parsed)
        .await
        .map_err(|_| "relay_connect_failed".to_string())?;
    socket
        .accept()
        .map_err(|_| "relay_connect_failed".to_string())?;
    let event: Value =
        serde_json::from_str(event_json).map_err(|_| "envelope_invalid".to_string())?;
    let id = event
        .get("id")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let frame = serde_json::json!(["EVENT", event]).to_string();
    socket
        .send_with_str(&frame)
        .map_err(|_| "relay_closed".to_string())?;
    let mut events = socket.events().map_err(|_| "relay_closed".to_string())?;
    let mut accepted = false;
    for _ in 0..8 {
        let Some(Ok(event)) = events.next().await else {
            break;
        };
        let worker::WebsocketEvent::Message(message) = event else {
            continue;
        };
        let Some(text) = message.text() else { continue };
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
    Ok(accepted)
}

async fn api_request(req: &mut Request) -> Option<ApiRequest> {
    let path = req.path();
    let authorization = req.headers().get("authorization").ok().flatten();
    let header = |name: &str| req.headers().get(name).ok().flatten().unwrap_or_default();
    let parts: Vec<&str> = path.split('/').filter(|part| !part.is_empty()).collect();
    match (req.method(), parts.as_slice()) {
        (Method::Get, ["v1", "status"]) => Some(ApiRequest::Status { authorization }),
        (Method::Get, ["v1", "outbox", "failed"]) => {
            Some(ApiRequest::FailedOutbox { authorization })
        }
        (Method::Get, ["v1", "diagnostics", "marmot"]) => {
            let project = req
                .url()
                .ok()
                .and_then(|url| {
                    url.query_pairs()
                        .find(|(key, _)| key == "project")
                        .map(|(_, value)| value.into_owned())
                })
                .unwrap_or_default();
            Some(ApiRequest::MarmotDiagnostic {
                authorization,
                project,
            })
        }
        (Method::Post, ["v1", "heartbeats", monitor_id]) => {
            let monitor_id = (*monitor_id).to_string();
            let content_type = header("content-type");
            let timestamp = header("x-watchdog-timestamp");
            let nonce = header("x-watchdog-nonce");
            let signature = header("x-watchdog-signature");
            let body = req.bytes().await.unwrap_or_default();
            Some(ApiRequest::Heartbeat {
                monitor_id,
                content_type,
                timestamp,
                nonce,
                signature,
                body,
            })
        }
        (Method::Post, ["v1", "diagnostics", "test-alert"]) => {
            let body = req.bytes().await.unwrap_or_default();
            Some(ApiRequest::TestAlert {
                authorization,
                body,
                transport: None,
            })
        }
        (Method::Post, ["v1", "outbox", id, "retry"]) => Some(ApiRequest::RetryOutbox {
            authorization,
            id: (*id).to_string(),
        }),
        (Method::Post, ["v1", "incidents", id, action]) => {
            let body = req.bytes().await.unwrap_or_default();
            Some(ApiRequest::Incident {
                authorization,
                id: (*id).to_string(),
                action: (*action).to_string(),
                body,
            })
        }
        _ => None,
    }
}

fn read_config(env: &Env) -> HashMap<String, String> {
    const KEYS: &[&str] = &[
        "WATCHDOG_ENABLED",
        "ALERTS_ENABLED",
        "ENABLE_MARMOT",
        "ENABLE_NIP17",
        "CHECK_CONCURRENCY",
        "CHECK_TIMEOUT_MS",
        "BOOTSTRAP_RELAYS",
        "PROJECT_RECIPIENTS",
        "ADMIN_NPUB",
        "SFS_BOT_NSEC",
        "NOSTRMASH_BOT_NSEC",
        "TELEGRAM_BOT_TOKEN",
        "TELEGRAM_CHAT_IDS",
        "TELEGRAM_CRITICAL_MODE",
        "OPERATOR_TOKEN",
        "STATUS_READER_TOKEN",
        "STATUS_SIGNING_KEY",
        "ENABLE_SFS_WEB",
        "SFS_WEB_READY_URL",
        "ENABLE_SFS_WORKER",
        "ENABLE_SFS_BLOSSOM",
        "SFS_BLOSSOM_READY_URL",
        "ENABLE_SFS_BLASTR",
        "SFS_BLASTR_READY_URL",
        "ENABLE_SFS_ALBY",
        "ALBY_BASE_URL",
        "ALBY_ROUTING_PROFILE",
        "ALBY_HUB_NAME",
        "ALBY_HUB_REGION",
        "ALBY_AUTH_TOKEN",
        "ENABLE_SFS_BTCPAY",
        "BTCPAY_BASE_URL",
        "BTCPAY_API_KEY",
        "ENABLE_NOSTRMASH_API",
        "NOSTRMASH_API_READY_URL",
        "ENABLE_NOSTRMASH_INGESTOR",
        "ENABLE_NOSTRMASH_WORKER",
        "ENABLE_NOSTRMASH_READ_GATEWAY",
        "NOSTRMASH_READ_GATEWAY_URL",
        "ENABLE_NOSTRMASH_PUBLISH_GATEWAY",
        "NOSTRMASH_PUBLISH_GATEWAY_URL",
        "ENABLE_NOSTRMASH_READ_GATEWAY_DEEP",
        "NOSTRMASH_READ_GATEWAY_DEEP_URL",
        "READ_GATEWAY_HEALTH_TOKEN",
        "ENABLE_NOSTRMASH_PUBLISH_GATEWAY_DEEP",
        "NOSTRMASH_PUBLISH_GATEWAY_DEEP_URL",
        "PUBLISH_GATEWAY_HEALTH_TOKEN",
        "HEARTBEAT_KEYS",
        "HEARTBEAT_KEYS_PREVIOUS",
        "GITHUB_TOKEN",
        "GITHUB_API_BASE",
        "FAILURE_THRESHOLD",
        "RECOVERY_THRESHOLD",
        "ENVIRONMENT",
        "RUNBOOK_BASE_URL",
        "NOTIFY_SMARTFLOWSOCIAL_MARMOT",
        "NOTIFY_SMARTFLOWSOCIAL_NIP17",
        "NOTIFY_SMARTFLOWSOCIAL_TELEGRAM",
        "NOTIFY_NOSTRMASH_MARMOT",
        "NOTIFY_NOSTRMASH_NIP17",
        "NOTIFY_NOSTRMASH_TELEGRAM",
    ];
    let mut vars = HashMap::new();
    for key in KEYS {
        if let Ok(secret) = env.secret(key) {
            vars.insert((*key).to_string(), secret.to_string());
            continue;
        }
        if let Ok(value) = env.var(key) {
            vars.insert((*key).to_string(), value.to_string());
        }
    }
    vars
}

fn now_ms() -> i64 {
    js_sys::Date::now() as i64
}

fn terminal(error: &str) -> DeliveryOutcome {
    DeliveryOutcome {
        accepted: false,
        terminal: true,
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
        error: Some(error.to_string()),
        accepted_relays: Vec::new(),
        failed_relays: Vec::new(),
        message_phase: None,
        push_phase: None,
        message_event_id: None,
        push_envelope: None,
    }
}
