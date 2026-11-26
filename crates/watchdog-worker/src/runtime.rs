//! Worker fetch, scheduled monitoring, and notification I/O.

use std::collections::HashMap;
use std::time::Duration;

use futures_util::{future::Either, StreamExt};
use serde_json::Value;
use watchdog_core::clock::SystemClock;
use watchdog_core::settings::{config_alias, load_settings, CONFIG_KEYS};
use watchdog_engine::{
    deliver_nip17, dispatch_due, handle, run_check_cycle, run_update_cycle, ApiRequest,
    ApiResponse, DeliveryOutcome, HttpClient, InboxFrames, Notifier, ProbeRequest, ProbeResponse,
    RelayIo,
};
use watchdog_notify::{auth_frame, parse_relay_frame, RelayControl, MARMOT_ENGINE_STATUS};
use watchdog_store::OutboxRow;
use worker::{
    console_log, AbortController, D1Database, Delay, Env, Fetch, Headers, Method, Request,
    RequestInit, RequestRedirect, Response, Result, ScheduledEvent, WebSocket,
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
    if let Err(error) = d1_store::schema_ready(&db).await {
        return Response::error(schema_error(&error), 503);
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
    let store = D1Store::new(&db);
    let notifier = WorkerNotifier {
        db: env.d1("DB")?,
        vars: vars.clone(),
    };
    let get = |key: &str| vars.get(key).cloned().unwrap_or_default();
    let request = match api_request(&mut req).await {
        Some(request) => request,
        None => return Response::error("not_found", 404),
    };
    let response = handle(
        &store,
        &settings,
        &get,
        &notifier,
        request,
        now_ms(),
        &SystemClock,
    )
    .await;
    exact_json(response)
}

pub async fn scheduled(event: ScheduledEvent, env: Env) -> Result<()> {
    let db = env.d1("DB")?;
    d1_store::schema_ready(&db)
        .await
        .map_err(|error| worker::Error::RustError(schema_error(&error).to_string()))?;
    let vars = read_config(&env);
    let settings = load_settings(|key| vars.get(key).cloned().unwrap_or_default());
    let store = D1Store::new(&db);
    let notifier = WorkerNotifier {
        db: env.d1("DB")?,
        vars: vars.clone(),
    };
    let http = WorkerHttp;
    let get = |key: &str| vars.get(key).cloned().unwrap_or_default();
    let now = now_ms();
    let cycle = if event.cron().starts_with("0 ") {
        run_update_cycle(&store, &settings, &get, &http, &notifier, now, &SystemClock).await
    } else {
        run_check_cycle(&store, &settings, &get, &http, &notifier, now, &SystemClock).await
    };
    if let Err(error) = cycle {
        console_log!("monitoring cycle failed: {error}");
    }
    if let Err(error) = dispatch_due(&store, &settings, &get, &notifier, &SystemClock).await {
        console_log!("dispatch failed: {error}");
    }
    Ok(())
}

struct WorkerHttp;

impl HttpClient for WorkerHttp {
    async fn send(&self, request: ProbeRequest) -> Result<ProbeResponse, String> {
        bounded_http(
            &request.method,
            &request.url,
            &request.headers,
            None,
            request.timeout,
            request.max_bytes,
        )
        .await
    }
}

struct WorkerNotifier {
    db: D1Database,
    vars: HashMap<String, String>,
}

impl Notifier for WorkerNotifier {
    async fn deliver_nostr(&self, row: &OutboxRow, claim: &str) -> DeliveryOutcome {
        let get = |key: &str| self.vars.get(key).cloned().unwrap_or_default();
        let settings = load_settings(&get);
        let store = D1Store::new(&self.db);
        deliver_nip17(
            &store,
            &WorkerRelay,
            &get,
            row,
            claim,
            settings.timeout_ms,
            &SystemClock,
        )
        .await
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
        })
        .to_string();
        let mut headers = HashMap::new();
        headers.insert("content-type".to_string(), "application/json".to_string());
        let response = bounded_http(
            "POST",
            &url,
            &headers,
            Some(body),
            Duration::from_secs(15),
            65_536,
        )
        .await;
        let Ok(response) = response else {
            return retry("telegram_failed");
        };
        if !(200..300).contains(&response.status) || response.too_large {
            return retry("telegram_failed");
        }
        let Ok(body) = serde_json::from_slice::<Value>(&response.body) else {
            return retry("telegram_failed");
        };
        if body.get("ok") == Some(&Value::Bool(true)) {
            DeliveryOutcome {
                accepted: true,
                terminal: false,
                hold_attempt: false,
                error: None,
                accepted_relays: Vec::new(),
                failed_relays: Vec::new(),
                message_phase: None,
                push_phase: None,
                message_event_id: None,
                push_envelope: None,
            }
        } else {
            retry("telegram_failed")
        }
    }

    async fn deliver_marmot(&self, _row: &OutboxRow, _claim: &str) -> DeliveryOutcome {
        let _ = self.db;
        let _ = MARMOT_ENGINE_STATUS;
        DeliveryOutcome {
            accepted: false,
            terminal: false,
            hold_attempt: false,
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

struct WorkerRelay;

impl RelayIo for WorkerRelay {
    async fn query_inbox(
        &self,
        relay: &str,
        author: &str,
        signer: Option<&str>,
        timeout_ms: i64,
    ) -> std::result::Result<InboxFrames, String> {
        let sub = format!("{:032x}", now_ms() as u64);
        let request =
            serde_json::json!(["REQ", sub, {"kinds": [10050], "authors": [author], "limit": 5}])
                .to_string();
        let frames =
            relay_exchange(relay, &request, signer, timeout_ms, Exchange::Query { sub }).await?;
        match frames {
            ExchangeResult::Inbox(frames) => Ok(frames),
            ExchangeResult::Published(_) => Err("relay_malformed".to_string()),
        }
    }

    async fn publish(
        &self,
        relay: &str,
        event_json: &str,
        signer: Option<&str>,
        timeout_ms: i64,
    ) -> std::result::Result<bool, String> {
        let event: Value =
            serde_json::from_str(event_json).map_err(|_| "envelope_invalid".to_string())?;
        let id = event
            .get("id")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let frame = serde_json::json!(["EVENT", event]).to_string();
        if frame.len() > 65_536 {
            return Err("relay_frame_too_large".to_string());
        }
        let frames = relay_exchange(
            relay,
            &frame,
            signer,
            timeout_ms,
            Exchange::Publish { event_id: id },
        )
        .await?;
        match frames {
            ExchangeResult::Published(accepted) => Ok(accepted),
            ExchangeResult::Inbox(_) => Err("relay_malformed".to_string()),
        }
    }
}

enum Exchange {
    Query { sub: String },
    Publish { event_id: String },
}

enum ExchangeResult {
    Inbox(InboxFrames),
    Published(bool),
}

async fn relay_exchange(
    relay: &str,
    frame: &str,
    signer: Option<&str>,
    timeout_ms: i64,
    goal: Exchange,
) -> std::result::Result<ExchangeResult, String> {
    let url = watchdog_core::url_policy::workers_websocket_url(relay)
        .map_err(|error| error.message.to_string())?;
    let url = url.replacen("https://", "wss://", 1);
    let parsed = url.parse().map_err(|_| "relay_url_invalid".to_string())?;
    let deadline = now_ms() + timeout_ms.max(1);
    let connect = WebSocket::connect(parsed);
    futures_util::pin_mut!(connect);
    let socket = match futures_util::future::select(
        connect,
        Delay::from(Duration::from_millis(
            deadline.saturating_sub(now_ms()).max(1) as u64,
        )),
    )
    .await
    {
        Either::Left((Ok(socket), _)) => socket,
        Either::Left((Err(_), _)) => return Err("relay_connect_failed".to_string()),
        Either::Right((_, _)) => return Err("relay_timeout".to_string()),
    };
    // Register the listener before accept so an immediate AUTH or OK is kept.
    let mut events = socket.events().map_err(|_| "relay_closed".to_string())?;
    socket
        .accept()
        .map_err(|_| "relay_connect_failed".to_string())?;
    socket
        .send_with_str(frame)
        .map_err(|_| "relay_closed".to_string())?;
    let mut seen = Vec::new();
    let mut eose = false;
    let mut accepted = false;
    let mut total = 0usize;
    let mut authed = false;
    loop {
        let remaining = deadline.saturating_sub(now_ms());
        if remaining == 0 {
            let _ = socket.close(Some(1000), Some("timeout"));
            return Err("relay_timeout".to_string());
        }
        let next = events.next();
        futures_util::pin_mut!(next);
        let event = match futures_util::future::select(
            next,
            Delay::from(Duration::from_millis(remaining as u64)),
        )
        .await
        {
            Either::Left((Some(Ok(event)), _)) => event,
            Either::Left((Some(Err(_)), _)) => {
                let _ = socket.close(Some(1000), Some("error"));
                return Err("relay_closed".to_string());
            }
            Either::Left((None, _)) => break,
            Either::Right((_, _)) => {
                let _ = socket.close(Some(1000), Some("timeout"));
                return Err("relay_timeout".to_string());
            }
        };
        let worker::WebsocketEvent::Message(message) = event else {
            continue;
        };
        let Some(text) = message.text() else {
            continue;
        };
        if text.len() > 65_536 {
            let _ = socket.close(Some(1009), Some("frame"));
            return Err("relay_frame_too_large".to_string());
        }
        total = total.saturating_add(text.len());
        if total > 262_144 {
            let _ = socket.close(Some(1009), Some("size"));
            return Err("relay_response_too_large".to_string());
        }
        match parse_relay_frame(&text) {
            RelayControl::Auth { challenge } if !authed => {
                let Some(nsec) = signer else {
                    let _ = socket.close(Some(1008), Some("auth"));
                    return Err("relay_auth_required".to_string());
                };
                let frame = auth_frame(nsec, &challenge, relay)
                    .map_err(|_| "relay_auth_required".to_string())?;
                socket
                    .send_with_str(&frame)
                    .map_err(|_| "relay_closed".to_string())?;
                authed = true;
            }
            RelayControl::Auth { .. } => {
                let _ = socket.close(Some(1008), Some("auth"));
                return Err("relay_auth_required".to_string());
            }
            RelayControl::Event {
                subscription,
                event_json,
            } => {
                if let Exchange::Query { sub } = &goal {
                    if subscription == *sub {
                        if seen.len() >= 32 {
                            let _ = socket.close(Some(1009), Some("events"));
                            return Err("relay_event_limit".to_string());
                        }
                        seen.push(event_json);
                    }
                }
            }
            RelayControl::Eose { subscription } => {
                if let Exchange::Query { sub } = &goal {
                    if subscription == *sub {
                        eose = true;
                        break;
                    }
                }
            }
            RelayControl::Ok {
                event_id,
                accepted: ok,
            } => {
                if let Exchange::Publish { event_id: wanted } = &goal {
                    if event_id == *wanted {
                        accepted = ok;
                        break;
                    }
                }
            }
            RelayControl::Closed { .. } => {
                let _ = socket.close(Some(1000), Some("closed"));
                return Err("relay_closed".to_string());
            }
            _ => {}
        }
    }
    let _ = socket.close(Some(1000), Some("done"));
    Ok(match goal {
        Exchange::Query { .. } => ExchangeResult::Inbox(InboxFrames { events: seen, eose }),
        Exchange::Publish { .. } => ExchangeResult::Published(accepted),
    })
}

async fn bounded_http(
    method: &str,
    url: &str,
    headers: &HashMap<String, String>,
    body: Option<String>,
    timeout: Duration,
    max_bytes: usize,
) -> std::result::Result<ProbeResponse, String> {
    let method = match method.to_ascii_uppercase().as_str() {
        "GET" => Method::Get,
        "POST" => Method::Post,
        "HEAD" => Method::Head,
        "PUT" => Method::Put,
        "PATCH" => Method::Patch,
        "DELETE" => Method::Delete,
        _ => return Err("probe_method_invalid".to_string()),
    };
    let header_set = Headers::new();
    for (key, value) in headers {
        header_set
            .set(key, value)
            .map_err(|_| "probe_failed".to_string())?;
    }
    let mut init = RequestInit::new();
    init.with_method(method)
        .with_headers(header_set)
        .with_redirect(RequestRedirect::Manual);
    if let Some(body) = body {
        init.with_body(Some(wasm_bindgen::JsValue::from_str(&body)));
    }
    let http_request =
        Request::new_with_init(url, &init).map_err(|_| "probe_url_invalid".to_string())?;
    let deadline = now_ms() + timeout.as_millis() as i64;
    let controller = AbortController::default();
    let signal = controller.signal();
    let fetch_handle = Fetch::Request(http_request);
    let fetch = fetch_handle.send_with_signal(&signal);
    futures_util::pin_mut!(fetch);
    let mut response = match futures_util::future::select(
        fetch,
        Delay::from(Duration::from_millis(
            deadline.saturating_sub(now_ms()).max(1) as u64,
        )),
    )
    .await
    {
        Either::Left((Ok(response), _)) => response,
        Either::Left((Err(_), _)) => return Err("probe_failed".to_string()),
        Either::Right((_, fetch)) => {
            controller.abort();
            drop(fetch);
            return Err("probe_timeout".to_string());
        }
    };
    let status = response.status_code();
    let mut kept = HashMap::new();
    for name in [
        "location",
        "etag",
        "retry-after",
        "x-ratelimit-reset",
        "x-ratelimit-remaining",
    ] {
        if let Ok(Some(value)) = response.headers().get(name) {
            kept.insert(name.to_string(), value);
        }
    }
    if let Ok(Some(length)) = response.headers().get("content-length") {
        if length
            .parse::<usize>()
            .ok()
            .is_some_and(|len| len > max_bytes)
        {
            return Ok(ProbeResponse {
                status,
                headers: kept,
                body: Vec::new(),
                too_large: true,
            });
        }
    }
    let mut body = Vec::new();
    let mut stream = response.stream().map_err(|_| "probe_failed".to_string())?;
    loop {
        let remaining = deadline.saturating_sub(now_ms());
        if remaining == 0 {
            controller.abort();
            return Err("probe_timeout".to_string());
        }
        let next = stream.next();
        futures_util::pin_mut!(next);
        let chunk = match futures_util::future::select(
            next,
            Delay::from(Duration::from_millis(remaining as u64)),
        )
        .await
        {
            Either::Left((Some(Ok(chunk)), _)) => chunk,
            Either::Left((Some(Err(_)), _)) => return Err("probe_failed".to_string()),
            Either::Left((None, _)) => break,
            Either::Right((_, _)) => return Err("probe_timeout".to_string()),
        };
        if body.len().saturating_add(chunk.len()) > max_bytes {
            return Ok(ProbeResponse {
                status,
                headers: kept,
                body: Vec::new(),
                too_large: true,
            });
        }
        body.extend_from_slice(&chunk);
    }
    Ok(ProbeResponse {
        status,
        headers: kept,
        body,
        too_large: false,
    })
}

fn exact_json(response: ApiResponse) -> Result<Response> {
    let headers = Headers::new();
    headers.set("content-type", "application/json")?;
    if let Some(signature) = &response.signature {
        headers.set("x-watchdog-signature", signature)?;
    }
    Ok(Response::from_bytes(response.body_bytes)?
        .with_headers(headers)
        .with_status(response.status))
}

fn schema_error(error: &watchdog_store::StoreError) -> &'static str {
    if error.to_string() == "schema_unsupported" {
        "schema_unsupported"
    } else {
        "schema_not_ready"
    }
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
        (Method::Get, ["v1", "diagnostics", "relays"]) => {
            let project = req
                .url()
                .ok()
                .and_then(|url| {
                    url.query_pairs()
                        .find(|(key, _)| key == "project")
                        .map(|(_, value)| value.into_owned())
                })
                .unwrap_or_default();
            Some(ApiRequest::Relays {
                authorization,
                project,
            })
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
    let mut vars = HashMap::new();
    let mut keys = CONFIG_KEYS.to_vec();
    keys.extend(["STATUS_READER_TOKEN", "STATUS_SIGNING_KEY"]);
    for key in keys {
        let value = if let Ok(secret) = env.secret(key) {
            secret.to_string()
        } else if let Ok(value) = env.var(key) {
            value.to_string()
        } else {
            continue;
        };
        let canonical = config_alias(key).unwrap_or(key);
        vars.entry(canonical.to_string()).or_insert(value);
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
