//! Native Nostr Watchdog. No Cloudflare account is required.
#![allow(clippy::too_many_arguments, clippy::result_unit_err)]

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{json, Value};
use tokio::net::TcpListener;
use tracing::info;
use watchdog_core::catalog::telegram_chat;
use watchdog_core::clock::SystemClock;
use watchdog_core::settings::load_settings;
use watchdog_engine::{
    handle, run_update_cycle, ApiRequest, ApiResponse, DeliveryOutcome, HttpClient, Notifier,
    ProbeRequest, ProbeResponse,
};
use watchdog_store::{OutboxRow, SqliteStore};

mod marmot;
mod net;
mod relay;

struct AppState {
    store: SqliteStore,
    vars: HashMap<String, String>,
    http: ReqwestClient,
}

struct ReqwestClient;

impl HttpClient for ReqwestClient {
    async fn send(&self, request: ProbeRequest) -> Result<ProbeResponse, String> {
        let url = reqwest::Url::parse(&request.url).map_err(|_| "probe_url_invalid".to_string())?;
        let host = url
            .host_str()
            .ok_or_else(|| "probe_url_invalid".to_string())?
            .to_string();
        let port = url.port_or_known_default().unwrap_or(443);
        let address = net::resolve_pinned(&host, port, request.allow_private).await?;
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .resolve(&host, address)
            .build()
            .map_err(|_| "probe_client_failed".to_string())?;
        let mut builder = client.request(
            reqwest::Method::from_bytes(request.method.as_bytes())
                .map_err(|_| "probe_method_invalid".to_string())?,
            url,
        );
        builder = builder.timeout(request.timeout);
        for (key, value) in &request.headers {
            builder = builder.header(key, value);
        }
        let response = builder.send().await.map_err(|error| network_code(&error))?;
        let status = response.status().as_u16();
        let mut headers = HashMap::new();
        for name in [
            "location",
            "etag",
            "retry-after",
            "x-ratelimit-reset",
            "x-ratelimit-remaining",
        ] {
            if let Some(value) = response
                .headers()
                .get(name)
                .and_then(|value| value.to_str().ok())
            {
                headers.insert(name.to_string(), value.to_string());
            }
        }
        let encoded = response
            .headers()
            .get(reqwest::header::CONTENT_ENCODING)
            .is_some();
        if !encoded
            && response
                .content_length()
                .is_some_and(|len| len > request.max_bytes as u64)
        {
            return Ok(ProbeResponse {
                status,
                headers,
                body: Vec::new(),
                too_large: true,
            });
        }
        let mut body = Vec::new();
        let mut stream = response.bytes_stream();
        while let Some(chunk) = futures_util::StreamExt::next(&mut stream).await {
            let chunk = chunk.map_err(|_| "probe_failed".to_string())?;
            if body.len().saturating_add(chunk.len()) > request.max_bytes {
                return Ok(ProbeResponse {
                    status,
                    headers,
                    body: Vec::new(),
                    too_large: true,
                });
            }
            body.extend_from_slice(&chunk);
        }
        Ok(ProbeResponse {
            status,
            headers,
            body,
            too_large: false,
        })
    }
}

struct NativeNotifier {
    vars: HashMap<String, String>,
    store: SqliteStore,
    timeout_ms: i64,
}

impl Notifier for NativeNotifier {
    async fn deliver_nostr(&self, row: &OutboxRow, claim: &str) -> DeliveryOutcome {
        deliver_nostr(&self.store, &self.vars, row, claim, self.timeout_ms).await
    }
    async fn deliver_telegram(&self, row: &OutboxRow) -> DeliveryOutcome {
        deliver_telegram(&self.vars, row, self.timeout_ms).await
    }
    async fn deliver_marmot(&self, row: &OutboxRow, claim: &str) -> DeliveryOutcome {
        marmot::deliver(&self.store, &self.vars, row, claim).await
    }
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
    let vars = load_vars().expect("configuration");
    let database = vars
        .get("DATABASE_PATH")
        .cloned()
        .unwrap_or_else(|| "data/watchdog.sqlite".to_string());
    let store = SqliteStore::open(PathBuf::from(&database).as_path()).expect("open sqlite");
    let state = Arc::new(AppState {
        store,
        vars,
        http: ReqwestClient,
    });
    let app = Router::new()
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
        .route("/v1/status", get(status))
        .route("/v1/heartbeats/{monitor_id}", post(heartbeat))
        .route("/v1/diagnostics/test-alert", post(test_alert))
        .route("/v1/diagnostics/marmot", get(marmot))
        .route("/v1/diagnostics/relays", get(relays))
        .route("/v1/outbox/failed", get(failed))
        .route("/v1/outbox/{id}/retry", post(retry_outbox))
        .route("/v1/incidents/{id}/{action}", post(incident))
        .with_state(state.clone());
    let addr: SocketAddr = match state.vars.get("LISTEN_ADDR") {
        Some(value) => value.parse().unwrap_or_else(|_| {
            panic!("LISTEN_ADDR is not a valid socket address");
        }),
        None => "127.0.0.1:8787".parse().expect("default listen address"),
    };
    let listener = TcpListener::bind(addr).await.expect("bind");
    info!(%addr, "nostr-watchdog listening");
    let scheduler = state.clone();
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let scheduler_stop = stop.clone();
    let scheduler_task = tokio::spawn(async move {
        let mut ticker = tokio::time::interval(Duration::from_secs(60));
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            if scheduler_stop.load(std::sync::atomic::Ordering::Relaxed) {
                break;
            }
            ticker.tick().await;
            if scheduler_stop.load(std::sync::atomic::Ordering::Relaxed) {
                break;
            }
            let now = now_ms();
            let settings =
                load_settings(|key| scheduler.vars.get(key).cloned().unwrap_or_default());
            let get = |key: &str| scheduler.vars.get(key).cloned().unwrap_or_default();
            let notifier = NativeNotifier {
                vars: scheduler.vars.clone(),
                store: scheduler.store.clone(),
                timeout_ms: settings.timeout_ms,
            };
            if let Err(error) = watchdog_engine::run_check_cycle(
                &scheduler.store,
                &settings,
                &get,
                &scheduler.http,
                &notifier,
                now,
                &SystemClock,
            )
            .await
            {
                tracing::error!(%error, "check cycle failed");
            }
            let updates_due = scheduler
                .store
                .snapshot()
                .ok()
                .and_then(|snapshot| snapshot.runs.into_iter().find(|run| run.name == "updates"))
                .and_then(|run| run.started_at)
                .is_none_or(|started| now - started >= 3_600_000);
            if updates_due {
                if let Err(error) = run_update_cycle(
                    &scheduler.store,
                    &settings,
                    &get,
                    &scheduler.http,
                    &notifier,
                    now,
                    &SystemClock,
                )
                .await
                {
                    tracing::error!(%error, "update cycle failed");
                }
            }
        }
    });
    let dispatch_state = state.clone();
    let dispatch_stop = stop.clone();
    let dispatch_task = tokio::spawn(async move {
        let mut ticker = tokio::time::interval(Duration::from_secs(15));
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut last_marmot_sync = 0i64;
        loop {
            if dispatch_stop.load(std::sync::atomic::Ordering::Relaxed) {
                break;
            }
            ticker.tick().await;
            if dispatch_stop.load(std::sync::atomic::Ordering::Relaxed) {
                break;
            }
            let now = now_ms();
            let settings =
                load_settings(|key| dispatch_state.vars.get(key).cloned().unwrap_or_default());
            let get = |key: &str| dispatch_state.vars.get(key).cloned().unwrap_or_default();
            let notifier = NativeNotifier {
                vars: dispatch_state.vars.clone(),
                store: dispatch_state.store.clone(),
                timeout_ms: settings.timeout_ms,
            };
            if let Err(error) = watchdog_engine::dispatch_due(
                &dispatch_state.store,
                &settings,
                &get,
                &notifier,
                &SystemClock,
            )
            .await
            {
                tracing::error!(%error, "dispatch failed");
            }
            if settings.marmot_enabled
                && now.saturating_sub(last_marmot_sync)
                    >= settings.sync_interval_seconds.saturating_mul(1000)
            {
                if let Err(error) = marmot::sync(&dispatch_state.vars).await {
                    tracing::warn!(%error, "marmot sync failed");
                }
                last_marmot_sync = now;
            }
        }
    });
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown(stop.clone()))
        .await
        .expect("serve");
    let _ = scheduler_task.await;
    let _ = dispatch_task.await;
    marmot::shutdown_helper();
}

async fn shutdown(stop: Arc<std::sync::atomic::AtomicBool>) {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut terminate = signal(SignalKind::terminate()).expect("sigterm handler");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = terminate.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
    stop.store(true, std::sync::atomic::Ordering::Relaxed);
    info!("shutting down");
}

fn network_code(error: &reqwest::Error) -> String {
    if error.is_timeout() {
        "probe_timeout".to_string()
    } else if error.is_connect() {
        "probe_connect_failed".to_string()
    } else {
        "probe_failed".to_string()
    }
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_millis() as i64)
        .unwrap_or(0)
}

async fn healthz(State(state): State<Arc<AppState>>) -> Json<Value> {
    Json(dispatch(&state, ApiRequest::Healthz, None).await.body)
}

async fn readyz(State(state): State<Arc<AppState>>) -> (StatusCode, Json<Value>) {
    let response = dispatch(&state, ApiRequest::Healthz, None).await;
    let ready = state.store.snapshot().is_ok();
    (
        if ready {
            StatusCode::OK
        } else {
            StatusCode::SERVICE_UNAVAILABLE
        },
        Json(json!({"ready": ready, "liveness": response.body})),
    )
}

async fn status(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> (StatusCode, HeaderMap, Bytes) {
    let response = dispatch(
        &state,
        ApiRequest::Status {
            authorization: header(&headers, "authorization"),
        },
        None,
    )
    .await;
    signed(response)
}

async fn heartbeat(
    State(state): State<Arc<AppState>>,
    Path(monitor_id): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> (StatusCode, Json<Value>) {
    let response = dispatch(
        &state,
        ApiRequest::Heartbeat {
            monitor_id,
            content_type: header(&headers, "content-type").unwrap_or_default(),
            timestamp: header(&headers, "x-watchdog-timestamp").unwrap_or_default(),
            nonce: header(&headers, "x-watchdog-nonce").unwrap_or_default(),
            signature: header(&headers, "x-watchdog-signature").unwrap_or_default(),
            body: body.to_vec(),
        },
        None,
    )
    .await;
    (
        StatusCode::from_u16(response.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
        Json(response.body),
    )
}

async fn test_alert(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: Bytes,
) -> (StatusCode, Json<Value>) {
    let response = dispatch(
        &state,
        ApiRequest::TestAlert {
            authorization: header(&headers, "authorization"),
            body: body.to_vec(),
            transport: None,
        },
        None,
    )
    .await;
    (
        StatusCode::from_u16(response.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
        Json(response.body),
    )
}

async fn marmot(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    axum::extract::Query(query): axum::extract::Query<ProjectQuery>,
) -> (StatusCode, Json<Value>) {
    let response = dispatch(
        &state,
        ApiRequest::MarmotDiagnostic {
            authorization: header(&headers, "authorization"),
            project: query.project.unwrap_or_default(),
        },
        None,
    )
    .await;
    (
        StatusCode::from_u16(response.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
        Json(response.body),
    )
}

async fn failed(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> (StatusCode, Json<Value>) {
    let response = dispatch(
        &state,
        ApiRequest::FailedOutbox {
            authorization: header(&headers, "authorization"),
        },
        None,
    )
    .await;
    (
        StatusCode::from_u16(response.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
        Json(response.body),
    )
}

async fn retry_outbox(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> (StatusCode, Json<Value>) {
    let response = dispatch(
        &state,
        ApiRequest::RetryOutbox {
            authorization: header(&headers, "authorization"),
            id,
        },
        None,
    )
    .await;
    (
        StatusCode::from_u16(response.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
        Json(response.body),
    )
}

async fn incident(
    State(state): State<Arc<AppState>>,
    Path((id, action)): Path<(String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> (StatusCode, Json<Value>) {
    let response = dispatch(
        &state,
        ApiRequest::Incident {
            authorization: header(&headers, "authorization"),
            id,
            action,
            body: body.to_vec(),
        },
        None,
    )
    .await;
    (
        StatusCode::from_u16(response.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
        Json(response.body),
    )
}

async fn dispatch(state: &AppState, request: ApiRequest, _body: Option<Bytes>) -> ApiResponse {
    let settings = load_settings(|key| state.vars.get(key).cloned().unwrap_or_default());
    let get = |key: &str| state.vars.get(key).cloned().unwrap_or_default();
    let notifier = NativeNotifier {
        vars: state.vars.clone(),
        store: state.store.clone(),
        timeout_ms: settings.timeout_ms,
    };
    handle(
        &state.store,
        &settings,
        &get,
        &notifier,
        request,
        now_ms(),
        &SystemClock,
    )
    .await
}

fn signed(response: ApiResponse) -> (StatusCode, HeaderMap, Bytes) {
    let mut headers = HeaderMap::new();
    headers.insert(
        axum::http::header::CONTENT_TYPE,
        "application/json".parse().expect("content type"),
    );
    if let Some(signature) = response.signature {
        if let Ok(value) = signature.parse() {
            headers.insert("x-watchdog-signature", value);
        }
    }
    (
        StatusCode::from_u16(response.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
        headers,
        Bytes::from(response.body_bytes),
    )
}

async fn relays(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    axum::extract::Query(query): axum::extract::Query<ProjectQuery>,
) -> (StatusCode, Json<Value>) {
    let response = dispatch(
        &state,
        ApiRequest::Relays {
            authorization: header(&headers, "authorization"),
            project: query.project.unwrap_or_default(),
        },
        None,
    )
    .await;
    (
        StatusCode::from_u16(response.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
        Json(response.body),
    )
}

fn header(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::to_string)
}

#[derive(Deserialize)]
struct ProjectQuery {
    project: Option<String>,
}

fn load_vars() -> Result<HashMap<String, String>, String> {
    let mut vars = HashMap::new();
    if let Ok(path) = std::env::var("WATCHDOG_CONFIG") {
        let text = std::fs::read_to_string(&path)
            .map_err(|error| format!("WATCHDOG_CONFIG could not be read: {error}"))?;
        let file = toml::from_str::<FileConfig>(&text)
            .map_err(|error| format!("WATCHDOG_CONFIG is not valid TOML: {error}"))?;
        vars.extend(file.vars);
    }
    for (key, value) in std::env::vars() {
        vars.insert(key, value);
    }
    Ok(vars)
}

#[derive(Deserialize)]
struct FileConfig {
    #[serde(default)]
    vars: HashMap<String, String>,
}

async fn deliver_nostr(
    store: &SqliteStore,
    vars: &HashMap<String, String>,
    row: &OutboxRow,
    claim: &str,
    timeout_ms: i64,
) -> DeliveryOutcome {
    let get = |key: &str| vars.get(key).cloned().unwrap_or_default();
    watchdog_engine::deliver_nip17(
        store,
        &relay::NativeRelay,
        &get,
        row,
        claim,
        timeout_ms,
        &SystemClock,
    )
    .await
}

async fn deliver_telegram(
    vars: &HashMap<String, String>,
    row: &OutboxRow,
    timeout_ms: i64,
) -> DeliveryOutcome {
    let get = |key: &str| vars.get(key).cloned().unwrap_or_default();
    let token = get("TELEGRAM_BOT_TOKEN");
    let Some(chat) = telegram_chat(&get("TELEGRAM_CHAT_IDS"), &row.project_id) else {
        return terminal("telegram_unavailable");
    };
    if token.is_empty() {
        return terminal("telegram_unavailable");
    }
    let url = format!("https://api.telegram.org/bot{token}/sendMessage");
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build();
    let Ok(client) = client else {
        return retry_error("telegram_failed");
    };
    let response = client
        .post(url)
        .timeout(Duration::from_millis(timeout_ms as u64))
        .json(&json!({"chat_id": chat, "text": row.payload_text, "disable_web_page_preview": true}))
        .send()
        .await;
    let Ok(response) = response else {
        return retry_error("telegram_failed");
    };
    if !response.status().is_success() {
        return retry_error("telegram_failed");
    }
    let Ok(body) = response.json::<Value>().await else {
        return retry_error("telegram_failed");
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
        retry_error("telegram_failed")
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

enum CachedInbox {
    Fresh(Vec<String>),
    Negative,
    Discover,
}

fn interpret_cache(entry: Option<(String, bool)>) -> CachedInbox {
    match entry {
        Some((_, true)) => CachedInbox::Negative,
        Some((json, false)) => match serde_json::from_str::<Vec<String>>(&json) {
            Ok(relays) if relays.iter().any(|relay| !relay.is_empty()) => {
                CachedInbox::Fresh(dedupe_relays(relays))
            }
            _ => CachedInbox::Discover,
        },
        None => CachedInbox::Discover,
    }
}

fn dedupe_relays(relays: Vec<String>) -> Vec<String> {
    let mut seen = std::collections::BTreeSet::new();
    let mut unique = Vec::new();
    for relay in relays {
        let normalized = relay.trim().trim_end_matches('/').to_ascii_lowercase();
        if normalized.is_empty() || !seen.insert(normalized.clone()) {
            continue;
        }
        unique.push(normalized);
    }
    unique
}

fn retry_error(error: &str) -> DeliveryOutcome {
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
    use super::{dedupe_relays, interpret_cache, CachedInbox};

    #[test]
    fn positive_cache_is_reused_and_negative_cache_is_terminal() {
        match interpret_cache(Some((r#"["wss://relay.example"]"#.to_string(), false))) {
            CachedInbox::Fresh(relays) => assert_eq!(relays, vec!["wss://relay.example"]),
            _ => panic!("positive cache was ignored"),
        }
        assert!(matches!(
            interpret_cache(Some(("[]".to_string(), true))),
            CachedInbox::Negative
        ));
        assert!(matches!(interpret_cache(None), CachedInbox::Discover));
        assert!(matches!(
            interpret_cache(Some(("not-json".to_string(), false))),
            CachedInbox::Discover
        ));
    }

    #[test]
    fn relay_urls_are_normalized_and_deduplicated() {
        let relays = dedupe_relays(vec![
            "wss://Relay.Example/".to_string(),
            "wss://relay.example".to_string(),
            "wss://other.example".to_string(),
        ]);
        assert_eq!(
            relays,
            vec![
                "wss://relay.example".to_string(),
                "wss://other.example".to_string()
            ]
        );
    }
}
