//! Native Nostr Watchdog. No Cloudflare account is required.
#![allow(clippy::too_many_arguments, clippy::result_unit_err)]

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, Path, State};
use axum::http::{HeaderMap, Request, StatusCode};
use axum::middleware::{self, Next};
use axum::response::IntoResponse;
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
use watchdog_store::{OperationalStore, OutboxRow, SqliteStore};

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
        let started = std::time::Instant::now();
        let address =
            net::resolve_pinned(&host, port, request.allow_private, request.timeout).await?;
        let remaining = request.timeout.saturating_sub(started.elapsed());
        if remaining.is_zero() {
            return Err("probe_timeout".to_string());
        }
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .resolve(&host, address)
            .timeout(remaining)
            .build()
            .map_err(|_| "probe_client_failed".to_string())?;
        let mut builder = client.request(
            reqwest::Method::from_bytes(request.method.as_bytes())
                .map_err(|_| "probe_method_invalid".to_string())?,
            url,
        );
        builder = builder.timeout(remaining);
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
    deadline_ms: Option<i64>,
}

impl NativeNotifier {
    fn remaining_ms(&self) -> i64 {
        self.deadline_ms.map_or(self.timeout_ms, |deadline| {
            deadline.saturating_sub(now_ms()).clamp(1, self.timeout_ms)
        })
    }
}

impl Notifier for NativeNotifier {
    async fn deliver_nostr(&self, row: &OutboxRow, claim: &str) -> DeliveryOutcome {
        deliver_nostr(&self.store, &self.vars, row, claim, self.remaining_ms()).await
    }

    async fn deliver_telegram(&self, row: &OutboxRow) -> DeliveryOutcome {
        deliver_telegram(&self.vars, row, self.remaining_ms()).await
    }

    async fn deliver_marmot(&self, row: &OutboxRow, claim: &str) -> DeliveryOutcome {
        let delivery = marmot::deliver(&self.store, &self.vars, row, claim);
        let Some(deadline) = self.deadline_ms else {
            return delivery.await;
        };
        let remaining = deadline.saturating_sub(now_ms()).max(0) as u64;
        tokio::time::timeout(Duration::from_millis(remaining), delivery)
            .await
            .unwrap_or_else(|_| marmot::ambiguous_timeout())
    }
}

#[tokio::main]
async fn main() {
    let _ = PROCESS_STARTED.set(std::time::Instant::now());
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
        .route("/v1/outbox/{id}", get(alert_status))
        .route("/v1/outbox/{id}/ack", post(ack_alert))
        .route("/v1/outbox/{id}/retry", post(retry_outbox))
        .route("/v1/diagnostics/marmot/onboard", post(onboard))
        .route("/v1/incidents/{id}/{action}", post(incident))
        .layer(DefaultBodyLimit::max(16 * 1024))
        .layer(middleware::from_fn(request_deadline))
        .with_state(state.clone());
    let addr: SocketAddr = match state.vars.get("LISTEN_ADDR") {
        Some(value) => value.parse().unwrap_or_else(|_| {
            panic!("LISTEN_ADDR is not a valid socket address");
        }),
        None => "127.0.0.1:8787".parse().expect("default listen address"),
    };
    let listener = TcpListener::bind(addr).await.expect("bind");
    info!(%addr, "nostr-watchdog listening");
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let runtime_id = Arc::new(format!("native-{}", std::process::id()));
    let mut jobs = tokio::task::JoinSet::new();
    jobs.spawn(check_loop(state.clone(), stop.clone()));
    jobs.spawn(vendor_loop(state.clone(), stop.clone()));
    jobs.spawn(transport_loop(
        state.clone(),
        stop.clone(),
        runtime_id.clone(),
        "telegram",
        15,
        2,
        1,
    ));
    jobs.spawn(transport_loop(
        state.clone(),
        stop.clone(),
        runtime_id.clone(),
        "nostr",
        15,
        2,
        1,
    ));
    jobs.spawn(transport_loop(
        state.clone(),
        stop.clone(),
        runtime_id.clone(),
        "marmot",
        15,
        1,
        1,
    ));
    jobs.spawn(push_loop(state.clone(), stop.clone(), runtime_id.clone()));
    jobs.spawn(sync_loop(state.clone(), stop.clone()));
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown(stop.clone()))
        .await
        .expect("serve");
    let drain = async { while jobs.join_next().await.is_some() {} };
    if tokio::time::timeout(Duration::from_secs(25), drain)
        .await
        .is_err()
    {
        jobs.abort_all();
        tracing::warn!("shutdown grace elapsed");
    }
    let _ = OperationalStore::release_open_claims(&state.store, &runtime_id, now_ms()).await;
    marmot::shutdown_helper();
}

async fn check_loop(state: Arc<AppState>, stop: Arc<std::sync::atomic::AtomicBool>) {
    let mut ticker = tokio::time::interval(Duration::from_secs(60));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        if stop.load(std::sync::atomic::Ordering::Relaxed) {
            break;
        }
        ticker.tick().await;
        if stop.load(std::sync::atomic::Ordering::Relaxed) {
            break;
        }
        let settings = load_settings(|key| state.vars.get(key).cloned().unwrap_or_default());
        let get = |key: &str| state.vars.get(key).cloned().unwrap_or_default();
        let notifier = native_notifier(&state, settings.timeout_ms);
        if let Err(error) = watchdog_engine::run_check_cycle(
            &state.store,
            &settings,
            &get,
            &state.http,
            &notifier,
            now_ms(),
            &SystemClock,
            now_ms() + 55_000,
        )
        .await
        {
            tracing::error!(%error, "check cycle failed");
        }
    }
}

async fn vendor_loop(state: Arc<AppState>, stop: Arc<std::sync::atomic::AtomicBool>) {
    let mut ticker = tokio::time::interval(Duration::from_secs(3600));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        if stop.load(std::sync::atomic::Ordering::Relaxed) {
            break;
        }
        ticker.tick().await;
        if stop.load(std::sync::atomic::Ordering::Relaxed) {
            break;
        }
        let settings = load_settings(|key| state.vars.get(key).cloned().unwrap_or_default());
        let get = |key: &str| state.vars.get(key).cloned().unwrap_or_default();
        let notifier = native_notifier(&state, settings.timeout_ms);
        if let Err(error) = run_update_cycle(
            &state.store,
            &settings,
            &get,
            &state.http,
            &notifier,
            now_ms(),
            &SystemClock,
            now_ms() + 180_000,
        )
        .await
        {
            tracing::error!(%error, "vendor cycle failed");
        }
    }
}

async fn transport_loop(
    state: Arc<AppState>,
    stop: Arc<std::sync::atomic::AtomicBool>,
    runtime_id: Arc<String>,
    destination: &'static str,
    every_seconds: u64,
    critical: usize,
    other: usize,
) {
    let mut ticker = tokio::time::interval(Duration::from_secs(every_seconds));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        if stop.load(std::sync::atomic::Ordering::Relaxed) {
            break;
        }
        ticker.tick().await;
        if stop.load(std::sync::atomic::Ordering::Relaxed) {
            break;
        }
        let settings = load_settings(|key| state.vars.get(key).cloned().unwrap_or_default());
        let get = |key: &str| state.vars.get(key).cloned().unwrap_or_default();
        let deadline = now_ms() + 10_000;
        let mut notifier = native_notifier(&state, settings.timeout_ms);
        notifier.deadline_ms = Some(deadline);
        if let Err(error) = watchdog_engine::dispatch_transport(
            &state.store,
            &settings,
            &get,
            &notifier,
            &SystemClock,
            destination,
            critical,
            other,
            deadline,
            "delivery",
            &runtime_id,
        )
        .await
        {
            tracing::error!(%error, %destination, "dispatch failed");
        }
    }
}

async fn push_loop(
    state: Arc<AppState>,
    stop: Arc<std::sync::atomic::AtomicBool>,
    runtime_id: Arc<String>,
) {
    let mut ticker = tokio::time::interval(Duration::from_secs(30));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        if stop.load(std::sync::atomic::Ordering::Relaxed) {
            break;
        }
        ticker.tick().await;
        if stop.load(std::sync::atomic::Ordering::Relaxed) {
            break;
        }
        let settings = load_settings(|key| state.vars.get(key).cloned().unwrap_or_default());
        let get = |key: &str| state.vars.get(key).cloned().unwrap_or_default();
        let deadline = now_ms() + 8_000;
        let mut notifier = native_notifier(&state, settings.timeout_ms);
        notifier.deadline_ms = Some(deadline);
        if let Err(error) = watchdog_engine::dispatch_transport(
            &state.store,
            &settings,
            &get,
            &notifier,
            &SystemClock,
            "marmot",
            1,
            0,
            deadline,
            "push",
            &runtime_id,
        )
        .await
        {
            tracing::error!(%error, "push reconciliation failed");
        }
    }
}

async fn sync_loop(state: Arc<AppState>, stop: Arc<std::sync::atomic::AtomicBool>) {
    let get = |key: &str| state.vars.get(key).cloned().unwrap_or_default();
    let settings = load_settings(&get);
    if !watchdog_core::catalog::PROJECTS
        .iter()
        .any(|project| watchdog_core::settings::marmot_enabled_for(&settings, &get, project.id))
    {
        return;
    }
    let mut ticker =
        tokio::time::interval(Duration::from_secs(settings.sync_interval_seconds as u64));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        ticker.tick().await;
        if stop.load(std::sync::atomic::Ordering::Relaxed) {
            break;
        }
        if let Err(error) = marmot::sync(&state.vars).await {
            tracing::warn!(%error, "marmot sync failed");
        }
    }
}

fn native_notifier(state: &AppState, timeout_ms: i64) -> NativeNotifier {
    NativeNotifier {
        vars: state.vars.clone(),
        store: state.store.clone(),
        timeout_ms,
        deadline_ms: None,
    }
}

async fn request_deadline(request: Request<axum::body::Body>, next: Next) -> impl IntoResponse {
    match tokio::time::timeout(Duration::from_secs(10), next.run(request)).await {
        Ok(response) => response,
        Err(_) => (StatusCode::REQUEST_TIMEOUT, "request_timeout").into_response(),
    }
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

static PROCESS_STARTED: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();

fn startup_grace() -> bool {
    PROCESS_STARTED
        .get()
        .map(|started| started.elapsed() < Duration::from_secs(180))
        .unwrap_or(false)
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
    let response = dispatch(
        &state,
        ApiRequest::Ready {
            marmot_supported: state
                .vars
                .get("MARMOT_SOCKET")
                .is_some_and(|value| !value.is_empty())
                || state
                    .vars
                    .get("MARMOT_ROOT")
                    .is_some_and(|value| !value.is_empty()),
            startup_grace: startup_grace(),
        },
        None,
    )
    .await;
    (
        StatusCode::from_u16(response.status).unwrap_or(StatusCode::SERVICE_UNAVAILABLE),
        Json(response.body),
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

async fn alert_status(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> (StatusCode, Json<Value>) {
    let response = dispatch(
        &state,
        ApiRequest::Alert {
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

async fn ack_alert(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> (StatusCode, Json<Value>) {
    let response = dispatch(
        &state,
        ApiRequest::AcknowledgeAlert {
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

async fn onboard(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: Bytes,
) -> (StatusCode, Json<Value>) {
    let response = dispatch(
        &state,
        ApiRequest::Onboard {
            authorization: header(&headers, "authorization"),
            body: body.to_vec(),
        },
        None,
    )
    .await;
    if response.status != 202 {
        return (
            StatusCode::from_u16(response.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
            Json(response.body),
        );
    }
    let request = serde_json::from_slice::<Value>(&body).unwrap_or(Value::Null);
    let project = request
        .get("projectId")
        .and_then(Value::as_str)
        .unwrap_or("");
    let operation = request
        .get("operationId")
        .or_else(|| request.get("idempotencyKey"))
        .and_then(Value::as_str)
        .unwrap_or("");
    let replace = request
        .get("replace")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let mut recorded = response.body;
    match marmot::operator_onboard(&state.vars, project, operation, replace).await {
        Ok(transport) => {
            let persisted = state.store.complete_marmot_onboarding(
                project,
                operation,
                transport["pubkey"].as_str().unwrap_or_default(),
                transport["recipient"].as_str().unwrap_or_default(),
                transport["group"].as_str().unwrap_or_default(),
                now_ms(),
            );
            if !matches!(persisted, Ok(true)) {
                return (
                    StatusCode::SERVICE_UNAVAILABLE,
                    Json(json!({
                        "connected": false, "error": "onboarding_persistence_failed"
                    })),
                );
            }
            if let Some(object) = recorded.as_object_mut() {
                object.insert("status".to_string(), json!("accepted"));
                object.insert("connected".to_string(), json!(true));
                object.insert(
                    "phase".to_string(),
                    transport
                        .get("phase")
                        .cloned()
                        .unwrap_or(json!("established")),
                );
                object.insert(
                    "accountPrefix".to_string(),
                    transport
                        .get("accountPrefix")
                        .cloned()
                        .unwrap_or(Value::Null),
                );
                object.insert(
                    "group".to_string(),
                    transport.get("group").cloned().unwrap_or(Value::Null),
                );
                object.remove("dependency");
                object.insert(
                    "note".to_string(),
                    json!("The helper recorded this onboarding operation. A group id is not proof the recipient accepted the Welcome."),
                );
            }
        }
        Err(error) => {
            if let Some(object) = recorded.as_object_mut() {
                object.insert("status".to_string(), json!("unavailable"));
                object.insert("connected".to_string(), json!(false));
                object.insert("error".to_string(), json!(error));
                object.insert(
                    "note".to_string(),
                    json!("The operation id is stored. The helper did not establish the conversation."),
                );
            }
        }
    }
    (StatusCode::ACCEPTED, Json(recorded))
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
        deadline_ms: None,
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
    let budget = Duration::from_millis(timeout_ms.max(1) as u64);
    let started = std::time::Instant::now();
    let mut builder = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy();
    let url = if get("ENVIRONMENT") == "test" {
        let Some(fixture) = watchdog_core::settings::telegram_fixture_url(
            "test",
            &get("WATCHDOG_TEST_TELEGRAM_ENDPOINT"),
        ) else {
            return terminal("telegram_fixture_unavailable");
        };
        fixture.to_string()
    } else {
        let Ok(address) = net::resolve_pinned("api.telegram.org", 443, false, budget).await else {
            return retry_error("telegram_failed");
        };
        builder = builder.resolve("api.telegram.org", address);
        format!("https://api.telegram.org/bot{token}/sendMessage")
    };
    let remaining = budget.saturating_sub(started.elapsed());
    if remaining.is_zero() {
        return retry_error("telegram_failed");
    }
    let client = builder.timeout(remaining).build();
    let Ok(client) = client else {
        return retry_error("telegram_failed");
    };
    let response = client
        .post(url)
        .json(&json!({"chat_id": chat, "text": row.payload_text, "disable_web_page_preview": true}))
        .send()
        .await;
    let Ok(mut response) = response else {
        return retry_error("telegram_failed");
    };
    if !response.status().is_success()
        || response.content_length().is_some_and(|size| size > 65_536)
    {
        return retry_error("telegram_failed");
    }
    let mut bytes = Vec::new();
    loop {
        match response.chunk().await {
            Ok(Some(chunk)) if bytes.len().saturating_add(chunk.len()) <= 65_536 => {
                bytes.extend_from_slice(&chunk)
            }
            Ok(None) => break,
            _ => return retry_error("telegram_failed"),
        }
    }
    let Ok(body) = serde_json::from_slice::<Value>(&bytes) else {
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
            operation: None,
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
        operation: None,
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
        operation: None,
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
