//! Worker fetch, scheduled monitoring, and notification I/O.

use std::cell::Cell;
use std::collections::HashMap;
use std::time::Duration;

use futures_util::{future::Either, StreamExt};
use serde_json::Value;
use watchdog_core::clock::SystemClock;
use watchdog_core::settings::{
    config_alias, load_settings, marmot_enabled_for, Settings, CONFIG_KEYS,
};
use watchdog_engine::{
    deliver_nip17, dispatch_transport, handle, run_check_cycle, run_update_cycle, ApiRequest,
    ApiResponse, DeliveryOutcome, HttpClient, InboxFrames, Notifier, ProbeRequest, ProbeResponse,
    RelayIo,
};
use watchdog_notify::{
    auth_event_id, auth_frame, parse_relay_frame, AuthPolicy, AuthSession, RelayControl,
    SessionStep, MARMOT_ENGINE_STATUS,
};
use watchdog_store::{OperationalStore, OutboxRow};
use worker::{
    console_log, AbortController, D1Database, Delay, Env, Fetch, Headers, Method, ObjectNamespace,
    Request, RequestInit, RequestRedirect, Response, Result, ScheduledEvent, WebSocket,
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
    let vars = read_config(&env);
    let settings = load_settings(|key| vars.get(key).cloned().unwrap_or_default());
    let store = D1Store::new(&db);
    let marmot = env.durable_object("MARMOT_SENDER").ok();
    let marmot_supported = marmot.is_some()
        && vars
            .get("MARMOT_OPERATOR_TOKEN")
            .is_some_and(|token| !token.is_empty());
    let notifier = WorkerNotifier {
        db: env.d1("DB")?,
        vars: vars.clone(),
        timeout_ms: settings.timeout_ms as u64,
        deadline_ms: Cell::new(i64::MAX),
        marmot,
    };
    let get = |key: &str| vars.get(key).cloned().unwrap_or_default();
    if req.method() == Method::Post && path == "/v1/diagnostics/runtime-fence" {
        if get("ENVIRONMENT") != "test" {
            return Response::error("not_found", 404);
        }
        let authorization = req.headers().get("authorization").ok().flatten();
        if !operator_authorized(&authorization, &get("OPERATOR_TOKEN")) {
            return Response::error("unauthorized", 401);
        }
        return runtime_fence(&store, now_ms()).await;
    }
    if req.method() == Method::Get && path == "/readyz" {
        let mut response = handle(
            &store,
            &settings,
            &get,
            &notifier,
            ApiRequest::Ready {
                marmot_supported,
                startup_grace: false,
            },
            now_ms(),
            &SystemClock,
        )
        .await;
        let observations = futures_util::future::join_all(
            watchdog_core::catalog::PROJECTS
                .iter()
                .filter(|project| marmot_enabled_for(&settings, &get, project.id))
                .map(|project| notifier.marmot_evidence(project.id)),
        )
        .await;
        if !observations.is_empty() {
            let conversations_ready = observations
                .iter()
                .all(|view| view["conversationReady"] == true);
            let connected = observations
                .iter()
                .all(|view| view["binding"] == "authenticated");
            let tokens_ready = observations
                .iter()
                .all(|view| view["recipientTokenReady"] == true);
            response.body["transports"]["marmot"] = serde_json::json!(if conversations_ready {
                "ready"
            } else if connected {
                "waiting"
            } else {
                "unavailable"
            });
            response.body["pushTokens"] =
                serde_json::json!(if tokens_ready { "ready" } else { "missing" });
            if !conversations_ready {
                response.status = 503;
                response.body["ready"] = serde_json::json!(false);
            }
            response.body_bytes = encode_body(&response.body)?;
        }
        return exact_json(response);
    }
    let request = match api_request(&mut req, &get("OPERATOR_TOKEN")).await {
        Some(request) => request,
        None => return Response::error("not_found", 404),
    };
    let mut response = handle(
        &store,
        &settings,
        &get,
        &notifier,
        request.clone(),
        now_ms(),
        &SystemClock,
    )
    .await;
    match request {
        ApiRequest::Onboard { body, .. } if response.status == 202 => {
            response = cloudflare_onboard(&store, &notifier, &body, response).await;
            response.body_bytes = encode_body(&response.body)?;
        }
        ApiRequest::MarmotDiagnostic { project, .. } if response.status == 200 => {
            response.body["authority"] = notifier.marmot_evidence(&project).await;
            if response.body["authority"]["binding"] == "authenticated" {
                response
                    .body
                    .as_object_mut()
                    .expect("diagnostics object")
                    .remove("dependency");
            }
            response.body_bytes = encode_body(&response.body)?;
        }
        _ => {}
    }
    exact_json(response)
}

async fn cloudflare_onboard(
    store: &D1Store<'_>,
    notifier: &WorkerNotifier,
    body: &[u8],
    mut response: ApiResponse,
) -> ApiResponse {
    let Ok(value) = serde_json::from_slice::<Value>(body) else {
        return response;
    };
    let project = value.get("projectId").and_then(Value::as_str).unwrap_or("");
    let operation = value
        .get("operationId")
        .or_else(|| value.get("idempotencyKey"))
        .and_then(Value::as_str)
        .unwrap_or("");
    let replace = value
        .get("replace")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let Some(namespace) = &notifier.marmot else {
        return onboard_note(response, "marmot_engine_unavailable", false);
    };
    let Some(token) = notifier
        .vars
        .get("MARMOT_OPERATOR_TOKEN")
        .filter(|token| !token.is_empty())
    else {
        return onboard_note(response, "marmot_unauthorized", false);
    };
    let Some(url) = watchdog_core::delivery::marmot_sender_url(project) else {
        return onboard_note(response, "invalid_project", false);
    };
    let (secret, expected_account, recipient) = match notifier.marmot_identity(project) {
        Ok(identity) => identity,
        Err(error) => return onboard_note(response, error, false),
    };
    let relays: Vec<&str> = notifier
        .vars
        .get("BOOTSTRAP_RELAYS")
        .map(|value| {
            value
                .split(',')
                .map(str::trim)
                .filter(|item| !item.is_empty())
                .collect()
        })
        .unwrap_or_default();
    let command = serde_json::json!({
        "op": "onboard",
        "operationId": operation,
        "projectId": project,
        "recipient": recipient,
        "replace": replace,
        "relays": relays,
        "senderSecretHex": secret
    });
    match post_marmot(
        namespace,
        token,
        &url,
        command.to_string(),
        notifier.timeout_ms,
    )
    .await
    {
        MarmotCall::Response(status, transport) if (200..300).contains(&status) => {
            if transport["ok"] != true
                || transport["operationId"].as_str() != Some(operation)
                || transport["projectId"].as_str() != Some(project)
                || transport["pubkey"].as_str() != Some(expected_account.as_str())
            {
                return onboard_note(response, "operation_identity_mismatch", false);
            }
            match store
                .complete_onboarding(project, operation, &expected_account, &recipient, now_ms())
                .await
            {
                Ok(true) => {}
                Ok(false) => return onboard_note(response, "onboarding_superseded", false),
                Err(_) => return onboard_note(response, "onboarding_persistence_failed", false),
            }
            if let Some(object) = response.body.as_object_mut() {
                object.insert("status".to_string(), serde_json::json!("accepted"));
                object.insert("connected".to_string(), serde_json::json!(true));
                object.insert(
                    "phase".to_string(),
                    transport
                        .get("messagePhase")
                        .cloned()
                        .unwrap_or(serde_json::json!("not_submitted")),
                );
                object.insert(
                    "reused".to_string(),
                    transport
                        .get("reused")
                        .cloned()
                        .unwrap_or(serde_json::json!(false)),
                );
                object.insert(
                    "accountPrefix".to_string(),
                    serde_json::json!(&expected_account[..8]),
                );
                object.insert(
                    "engineStatus".to_string(),
                    serde_json::json!("account_initialized"),
                );
                if let Some(onboarding) =
                    transport.get("onboarding").filter(|item| item.is_object())
                {
                    object.insert("onboarding".to_string(), onboarding.clone());
                }
                object.remove("dependency");
                object.insert(
                    "note".to_string(),
                    serde_json::json!(
                        "The Durable Object recorded this onboarding operation. A persisted group is not proof the recipient accepted the Welcome."
                    ),
                );
            }
            response
        }
        MarmotCall::Response(401, _) => onboard_note(response, "marmot_unauthorized", false),
        MarmotCall::Timeout => onboard_note(response, "marmot_timeout", false),
        MarmotCall::Malformed => onboard_note(response, "marmot_response_invalid", false),
        MarmotCall::Transport | MarmotCall::Response(_, _) => {
            onboard_note(response, "marmot_transport_error", false)
        }
    }
}

fn onboard_note(mut response: ApiResponse, error: &str, connected: bool) -> ApiResponse {
    if let Some(object) = response.body.as_object_mut() {
        object.insert("status".to_string(), serde_json::json!("unavailable"));
        object.insert("connected".to_string(), serde_json::json!(connected));
        object.insert("error".to_string(), serde_json::json!(error));
        object.insert(
            "note".to_string(),
            serde_json::json!(
                "The operation id is stored. The Marmot transport did not establish the conversation."
            ),
        );
    }
    response
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
        timeout_ms: settings.timeout_ms as u64,
        deadline_ms: Cell::new(i64::MAX),
        marmot: env.durable_object("MARMOT_SENDER").ok(),
    };
    let http = WorkerHttp;
    let get = |key: &str| vars.get(key).cloned().unwrap_or_default();
    let started = now_ms();
    let hourly = event.cron().starts_with("0 ");
    if hourly {
        let deadline = started + 15_000;
        if let Err(error) = run_update_cycle(
            &store,
            &settings,
            &get,
            &http,
            &notifier,
            started,
            &SystemClock,
            deadline,
        )
        .await
        {
            console_log!("vendor cycle failed: {error}");
        }
        if now_ms() < deadline {
            let _ = store.prune(now_ms()).await;
        }
        return Ok(());
    }
    futures_util::join!(
        run_operational_cycle(&store, &notifier, &settings, &get, started),
        drive_marmot_lifecycle(&store, &notifier, &settings, &get, started),
    );
    Ok(())
}

async fn run_operational_cycle(
    store: &D1Store<'_>,
    notifier: &WorkerNotifier,
    settings: &Settings,
    get: &impl Fn(&str) -> String,
    started: i64,
) {
    let http = WorkerHttp;
    let health_deadline = started + 12_000;
    notifier.deadline_ms.set(health_deadline);
    if let Err(error) = run_check_cycle(
        store,
        settings,
        get,
        &http,
        notifier,
        started,
        &SystemClock,
        health_deadline,
    )
    .await
    {
        console_log!("monitoring cycle failed: {error}");
    }
    let message_deadline = started + 17_000;
    notifier.deadline_ms.set(message_deadline);
    for (destination, critical, other) in [
        ("telegram", 2_usize, 1_usize),
        ("nostr", 2, 1),
        ("marmot", 1, 1),
    ] {
        if message_deadline.saturating_sub(now_ms()) < 1_500 {
            break;
        }
        if let Err(error) = dispatch_transport(
            store,
            settings,
            get,
            notifier,
            &SystemClock,
            destination,
            critical,
            other,
            message_deadline,
            "delivery",
            "worker",
        )
        .await
        {
            console_log!("dispatch failed: {error}");
        }
    }
    let push_deadline = started + 20_000;
    notifier.deadline_ms.set(push_deadline);
    if let Err(error) = dispatch_transport(
        store,
        settings,
        get,
        notifier,
        &SystemClock,
        "telegram",
        1,
        0,
        push_deadline,
        "delivery",
        "worker",
    )
    .await
    {
        console_log!("critical fallback dispatch failed: {error}");
    }
    if push_deadline.saturating_sub(now_ms()) >= 1_500 {
        if let Err(error) = dispatch_transport(
            store,
            settings,
            get,
            notifier,
            &SystemClock,
            "marmot",
            1,
            0,
            push_deadline,
            "push",
            "worker",
        )
        .await
        {
            console_log!("push reconciliation failed: {error}");
        }
    }
}

async fn drive_marmot_lifecycle(
    store: &D1Store<'_>,
    notifier: &WorkerNotifier,
    settings: &Settings,
    get: &impl Fn(&str) -> String,
    started: i64,
) {
    let (Some(namespace), Some(token)) = (&notifier.marmot, notifier.marmot_token()) else {
        return;
    };
    let deadline = started + 18_000;
    futures_util::future::join_all(watchdog_core::catalog::PROJECTS.iter().map(
        |project| async move {
            if !marmot_enabled_for(settings, get, project.id) {
                return;
            }
            let Ok((_, sender, recipient)) = notifier.marmot_identity(project.id) else {
                return;
            };
            let Ok(Some(row)) = store.marmot_project(project.id).await else {
                return;
            };
            if row.pubkey.as_deref() != Some(sender.as_str())
                || row.peer_pubkey.as_deref() != Some(recipient.as_str())
            {
                return;
            }
            let Some(url) = watchdog_core::delivery::marmot_sender_url(project.id) else {
                return;
            };
            let owner = uuid::Uuid::new_v4().to_string();
            let now = now_ms();
            if !store
                .acquire_lease(
                    &format!("marmot-sync:{}", project.id),
                    &owner,
                    now + settings.sync_interval_seconds * 1_000,
                    now,
                )
                .await
                .unwrap_or(false)
            {
                return;
            }

            let call = |op, publish| {
                post_marmot(namespace, token, &url, serde_json::json!({
            "op": op, "projectId": project.id, "senderPubkey": sender, "recipient": recipient,
            "publish": publish,
        }).to_string(), remaining_timeout(deadline, notifier.timeout_ms))
            };
            let _ = call("establish", false).await;
            let synced = call("sync", false).await;
            if let MarmotCall::Response(200, value) = synced {
                if value["ok"] == true && value["projectId"].as_str() == Some(project.id) {
                    let _ = store
                        .record_marmot_sync(project.id, &sender, &recipient, now_ms())
                        .await;
                }
            }
            let now = now_ms();
            if remaining_timeout(deadline, notifier.timeout_ms) >= 1_500
                && store
                    .acquire_lease(
                        &format!("marmot-maintain:{}", project.id),
                        &owner,
                        now + 6 * 3_600_000,
                        now,
                    )
                    .await
                    .unwrap_or(false)
            {
                let _ = call("maintain", true).await;
            }
        },
    ))
    .await;
}

fn remaining_timeout(deadline_ms: i64, configured_ms: u64) -> u64 {
    deadline_ms
        .saturating_sub(now_ms())
        .max(0)
        .min(configured_ms as i64) as u64
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
    timeout_ms: u64,
    deadline_ms: Cell<i64>,
    marmot: Option<ObjectNamespace>,
}

impl WorkerNotifier {
    async fn marmot_evidence(&self, project: &str) -> Value {
        let Some(namespace) = &self.marmot else {
            return serde_json::json!({"binding": "missing"});
        };
        let Some(token) = self.marmot_token() else {
            return serde_json::json!({"binding": "credentials_missing"});
        };
        let Ok((_, sender, recipient)) = self.marmot_identity(project) else {
            return serde_json::json!({"binding": "identity_invalid"});
        };
        let Some(url) = watchdog_core::delivery::marmot_sender_url(project) else {
            return serde_json::json!({"binding": "invalid_project"});
        };
        let command = serde_json::json!({"op": "readiness", "projectId": project});
        let reply = post_marmot(namespace, token, &url, command.to_string(), 2_000).await;
        let MarmotCall::Response(200, value) = reply else {
            return serde_json::json!({"binding": if matches!(reply, MarmotCall::Response(401, _)) {
                "unauthorized"
            } else { "unavailable" }});
        };
        if value["ok"] != true
            || value["projectId"].as_str() != Some(project)
            || value["pubkey"].as_str() != Some(sender.as_str())
            || value["recipient"].as_str() != Some(recipient.as_str())
        {
            return serde_json::json!({"binding": "identity_mismatch"});
        }
        serde_json::json!({
            "binding": "authenticated",
            "accountInitialized": true,
            "groupPersisted": value["groupBound"] == true,
            "welcomeAccepted": value["onboarding"]["welcomeAccepted"] == true,
            "recipientParticipationObserved": value["onboarding"]["recipientParticipationObserved"] == true,
            "conversationReady": value["onboarding"]["conversationReady"] == true && value["canonicalMembership"] == true,
            "canonicalMembership": value["canonicalMembership"] == true,
            "keyPackageReady": value["keyPackagePublished"] == true,
            "recipientTokenReady": value["recipientTokenCount"].as_u64().is_some_and(|count| count > 0),
            "storageIntegrity": value["storageIntegrity"] == "checked",
            "storageCapacity": value["storageCapacity"],
        })
    }

    fn request_timeout_ms(&self) -> u64 {
        remaining_timeout(self.deadline_ms.get(), self.timeout_ms)
    }

    fn marmot_token(&self) -> Option<&str> {
        self.vars
            .get("MARMOT_OPERATOR_TOKEN")
            .map(String::as_str)
            .filter(|token| !token.is_empty())
    }

    fn marmot_identity(
        &self,
        project: &str,
    ) -> std::result::Result<(String, String, String), &'static str> {
        let config = watchdog_core::catalog::project_by_id(project).ok_or("invalid_project")?;
        let get = |key| self.vars.get(key).map(String::as_str).unwrap_or_default();
        let recipient = watchdog_core::catalog::project_recipient(
            get("PROJECT_RECIPIENTS"),
            get("ADMIN_NPUB"),
            project,
        )
        .ok_or("recipient_unconfigured")?;
        let recipient =
            watchdog_notify::recipient_pubkey(&recipient).map_err(|_| "recipient_invalid")?;
        let secret = watchdog_notify::normalize_sender_secret(get(config.sender_secret))
            .map_err(|_| "sender_identity_invalid")?;
        let sender =
            watchdog_notify::public_key_hex(&secret).map_err(|_| "sender_identity_invalid")?;
        Ok((secret, sender, recipient))
    }
}

impl Notifier for WorkerNotifier {
    async fn deliver_nostr(&self, row: &OutboxRow, claim: &str) -> DeliveryOutcome {
        let get = |key: &str| self.vars.get(key).cloned().unwrap_or_default();
        let store = D1Store::new(&self.db);
        deliver_nip17(
            &store,
            &WorkerRelay,
            &get,
            row,
            claim,
            self.request_timeout_ms() as i64,
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
        let get = |key| self.vars.get(key).map(String::as_str).unwrap_or_default();
        let url = if get("ENVIRONMENT") == "test" {
            let Some(url) = watchdog_core::settings::telegram_fixture_url(
                "test",
                get("WATCHDOG_TEST_TELEGRAM_ENDPOINT"),
            ) else {
                return terminal("telegram_fixture_unavailable");
            };
            url.to_string()
        } else {
            format!("https://api.telegram.org/bot{token}/sendMessage")
        };
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
            Duration::from_millis(self.request_timeout_ms()),
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
                operation: None,
            }
        } else {
            retry("telegram_failed")
        }
    }

    async fn deliver_marmot(&self, row: &OutboxRow, _claim: &str) -> DeliveryOutcome {
        let _ = self.db;
        let _ = MARMOT_ENGINE_STATUS;
        let admitted = watchdog_core::delivery::marmot_operation_admitted(
            row.message_state.as_deref(),
            row.message_event_id.as_deref(),
            row.preserve_message,
        );
        let Some(namespace) = &self.marmot else {
            return marmot_unavailable("marmot_engine_unavailable");
        };
        let Some(token) = self
            .vars
            .get("MARMOT_OPERATOR_TOKEN")
            .filter(|token| !token.is_empty())
        else {
            return marmot_unavailable("marmot_unauthorized");
        };
        let Some(url) = watchdog_core::delivery::marmot_sender_url(&row.project_id) else {
            return marmot_unavailable("invalid_project");
        };
        let (_, sender, recipient) = match self.marmot_identity(&row.project_id) {
            Ok(identity) => identity,
            Err(error) => return marmot_unavailable(error),
        };
        let deadline = now_ms() + self.request_timeout_ms() as i64;
        let call = |reconcile| {
            post_marmot(
                namespace,
                token,
                &url,
                marmot_delivery_body(row, reconcile, &sender, &recipient),
                remaining_timeout(deadline, self.timeout_ms),
            )
        };
        let mut result = call(admitted).await;
        if admitted
            && row.message_event_id.is_none()
            && row.message_state.as_deref() == Some("completion_unknown")
            && matches!(&result, MarmotCall::Response(200, value)
                if value["ok"] == true && value["admission"] == "absent"
                && value["projectId"].as_str() == Some(row.project_id.as_str())
                && value["operationId"].as_str() == Some(row.id.as_str()))
            && remaining_timeout(deadline, self.timeout_ms) > 0
        {
            result = call(false).await;
        }
        match result {
            MarmotCall::Response(status, value) => {
                cloudflare_outcome(status, &value, &row.project_id, &row.id)
            }
            MarmotCall::Timeout => marmot_hold("marmot_timeout"),
            MarmotCall::Transport => marmot_hold("marmot_transport_error"),
            MarmotCall::Malformed => marmot_hold("marmot_response_invalid"),
        }
    }
}

fn marmot_delivery_body(row: &OutboxRow, admitted: bool, sender: &str, recipient: &str) -> String {
    let mut body = serde_json::json!({
        "op": watchdog_core::delivery::marmot_transport_op(admitted),
        "operationId": row.id,
        "projectId": row.project_id,
        "senderPubkey": sender,
        "recipient": recipient,
        "publish": true
    });
    if !admitted {
        body["text"] = serde_json::json!(row.payload_text);
    }
    body.to_string()
}

enum MarmotCall {
    Response(u16, Value),
    Timeout,
    Transport,
    Malformed,
}

async fn post_marmot(
    namespace: &ObjectNamespace,
    token: &str,
    url: &str,
    body: String,
    timeout_ms: u64,
) -> MarmotCall {
    let project = url
        .split("sender=")
        .nth(1)
        .unwrap_or_default()
        .split('&')
        .next()
        .unwrap_or_default();
    let Ok(id) = namespace.id_from_name(project) else {
        return MarmotCall::Transport;
    };
    let Ok(stub) = id.get_stub() else {
        return MarmotCall::Transport;
    };
    let headers = Headers::new();
    if headers
        .set("authorization", &format!("Bearer {token}"))
        .is_err()
        || headers.set("content-type", "application/json").is_err()
    {
        return MarmotCall::Transport;
    }
    let mut init = RequestInit::new();
    init.with_method(Method::Post)
        .with_headers(headers)
        .with_body(Some(wasm_bindgen::JsValue::from_str(&body)));
    let Ok(request) = Request::new_with_init(url, &init) else {
        return MarmotCall::Transport;
    };
    if timeout_ms == 0 {
        return MarmotCall::Timeout;
    }
    let call = async {
        let mut response = match stub.fetch_with_request(request).await {
            Ok(response) => response,
            Err(_) => return MarmotCall::Transport,
        };
        let status = response.status_code();
        // Error bodies may contain private diagnostic details. Only keep status.
        if !(200..300).contains(&status) {
            return MarmotCall::Response(status, Value::Null);
        }
        let Ok(mut stream) = response.stream() else {
            return MarmotCall::Malformed;
        };
        let mut bytes = Vec::new();
        while let Some(chunk) = stream.next().await {
            let Ok(chunk) = chunk else {
                return MarmotCall::Malformed;
            };
            if bytes.len().saturating_add(chunk.len()) > 65_536 {
                return MarmotCall::Malformed;
            }
            bytes.extend_from_slice(&chunk);
        }
        match serde_json::from_slice::<Value>(&bytes) {
            Ok(value) => MarmotCall::Response(status, value),
            Err(_) => MarmotCall::Malformed,
        }
    };
    futures_util::pin_mut!(call);
    match futures_util::future::select(call, Delay::from(Duration::from_millis(timeout_ms))).await {
        Either::Left((result, _)) => result,
        Either::Right((_, _)) => MarmotCall::Timeout,
    }
}

fn marmot_unavailable(error: &str) -> DeliveryOutcome {
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

fn marmot_hold(error: &str) -> DeliveryOutcome {
    DeliveryOutcome {
        accepted: false,
        terminal: false,
        hold_attempt: true,
        error: Some(error.to_string()),
        accepted_relays: Vec::new(),
        failed_relays: Vec::new(),
        message_phase: Some("completion_unknown".to_owned()),
        push_phase: None,
        message_event_id: None,
        push_envelope: None,
        operation: None,
    }
}

fn cloudflare_outcome(
    status: u16,
    value: &Value,
    project: &str,
    operation_id: &str,
) -> DeliveryOutcome {
    if status == 401 || value.get("error").and_then(Value::as_str) == Some("unauthorized") {
        return marmot_unavailable("marmot_unauthorized");
    }
    if !(200..300).contains(&status) {
        return marmot_hold("marmot_transport_error");
    }
    if value["ok"] != true {
        return marmot_hold("marmot_response_invalid");
    }
    let operation = watchdog_core::delivery::operation_from_transport(
        value,
        watchdog_core::delivery::TransportOrigin::CloudflareObject,
    );
    if !watchdog_core::delivery::transport_identity_matches(&operation, project, operation_id) {
        return marmot_hold("operation_identity_mismatch");
    }
    let accepted = operation.message == Some(watchdog_core::delivery::MessageState::RelayAccepted);
    let settled = operation.disposition == watchdog_core::delivery::OperationDisposition::Settled;
    DeliveryOutcome {
        accepted,
        terminal: settled && !accepted,
        hold_attempt: !settled,
        error: operation.error.clone(),
        accepted_relays: Vec::new(),
        failed_relays: Vec::new(),
        message_phase: operation
            .message
            .map(watchdog_core::delivery::MessageState::as_str)
            .map(str::to_string),
        push_phase: operation
            .push
            .map(watchdog_core::delivery::PushState::as_str)
            .map(str::to_string),
        message_event_id: operation.message_event_id.clone(),
        push_envelope: None,
        operation: Some(operation),
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
    let policy = match &goal {
        Exchange::Query { .. } => AuthPolicy::Discovery,
        Exchange::Publish { .. } => AuthPolicy::Publication,
    };
    let original_id = match &goal {
        Exchange::Query { sub } => sub.clone(),
        Exchange::Publish { event_id } => event_id.clone(),
    };
    let mut session = AuthSession::new(policy);
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
        let message = match event {
            worker::WebsocketEvent::Close(_) => {
                let _ = socket.close(Some(1000), Some("closed"));
                return Err("relay_closed".to_string());
            }
            worker::WebsocketEvent::Message(message) => message,
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
        let control = parse_relay_frame(&text);
        if let RelayControl::Event {
            subscription,
            event_json,
        } = &control
        {
            if let Exchange::Query { sub } = &goal {
                if subscription == sub {
                    if seen.len() >= 32 {
                        let _ = socket.close(Some(1009), Some("events"));
                        return Err("relay_event_limit".to_string());
                    }
                    seen.push(event_json.clone());
                    continue;
                }
            }
        }
        if let RelayControl::Eose { subscription } = &control {
            if let Exchange::Query { sub } = &goal {
                if subscription == sub {
                    eose = true;
                    break;
                }
            }
        }
        match session.on_frame(&control, &original_id) {
            SessionStep::Sign { challenge } => {
                if !matches!(policy, AuthPolicy::Publication) {
                    let _ = socket.close(Some(1008), Some("auth"));
                    return Err("relay_auth_required".to_string());
                }
                let Some(nsec) = signer else {
                    let _ = socket.close(Some(1008), Some("auth"));
                    return Err("relay_auth_required".to_string());
                };
                let auth = auth_frame(nsec, &challenge, relay)
                    .map_err(|_| "relay_auth_required".to_string())?;
                if let Some(auth_id) = auth_event_id(&auth) {
                    session.note_auth_sent(&auth_id);
                }
                socket
                    .send_with_str(&auth)
                    .map_err(|_| "relay_closed".to_string())?;
            }
            SessionStep::ResendOriginal => {
                socket
                    .send_with_str(frame)
                    .map_err(|_| "relay_closed".to_string())?;
            }
            SessionStep::Accepted => {
                accepted = true;
                break;
            }
            SessionStep::Rejected => {
                accepted = false;
                break;
            }
            SessionStep::Failed(error) => {
                let _ = socket.close(Some(1008), Some("auth"));
                return Err(error.to_string());
            }
            SessionStep::Continue => {}
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

fn encode_body(body: &Value) -> Result<Vec<u8>> {
    serde_json::to_vec(body).map_err(|error| worker::Error::RustError(error.to_string()))
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

async fn read_limited(
    req: &mut Request,
    limit: usize,
) -> std::result::Result<Vec<u8>, &'static str> {
    if let Some(value) = req.headers().get("content-length").ok().flatten() {
        if value.parse::<usize>().unwrap_or(usize::MAX) > limit {
            return Err("payload_too_large");
        }
    }
    let mut stream = req.stream().map_err(|_| "payload_invalid")?;
    let mut body = Vec::new();
    let started = now_ms();
    while let Some(chunk) = stream.next().await {
        if now_ms().saturating_sub(started) > 5_000 {
            return Err("payload_timeout");
        }
        let chunk = chunk.map_err(|_| "payload_invalid")?;
        if body.len().saturating_add(chunk.len()) > limit {
            return Err("payload_too_large");
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

fn schema_error(error: &watchdog_store::StoreError) -> &'static str {
    if error.to_string() == "schema_unsupported" {
        "schema_unsupported"
    } else {
        "schema_not_ready"
    }
}

fn operator_authorized(header: &Option<String>, operator: &str) -> bool {
    let header = header.as_deref().unwrap_or("");
    let token = header
        .strip_prefix("Bearer ")
        .or_else(|| header.strip_prefix("bearer "))
        .unwrap_or("")
        .trim();
    !operator.is_empty() && watchdog_core::crypto::secrets_equal(operator, token)
}

async fn api_request(req: &mut Request, operator: &str) -> Option<ApiRequest> {
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
        (Method::Get, ["v1", "outbox", id]) if *id != "failed" => Some(ApiRequest::Alert {
            authorization,
            id: (*id).to_string(),
        }),
        (Method::Post, ["v1", "outbox", id, "ack"]) => Some(ApiRequest::AcknowledgeAlert {
            authorization,
            id: (*id).to_string(),
        }),
        (Method::Post, ["v1", "diagnostics", "marmot", "onboard"]) => {
            if !operator_authorized(&authorization, operator) {
                return Some(ApiRequest::Onboard {
                    authorization,
                    body: Vec::new(),
                });
            }
            match read_limited(req, 2_048).await {
                Ok(body) => Some(ApiRequest::Onboard {
                    authorization,
                    body,
                }),
                Err(error) => Some(ApiRequest::Rejected { status: 413, error }),
            }
        }
        (Method::Post, ["v1", "heartbeats", monitor_id]) => {
            let monitor_id = (*monitor_id).to_string();
            let content_type = header("content-type");
            let timestamp = header("x-watchdog-timestamp");
            let nonce = header("x-watchdog-nonce");
            let signature = header("x-watchdog-signature");
            let body = match read_limited(req, 16_384).await {
                Ok(body) => body,
                Err(error) => return Some(ApiRequest::Rejected { status: 413, error }),
            };
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
            if !operator_authorized(&authorization, operator) {
                return Some(ApiRequest::TestAlert {
                    authorization,
                    body: Vec::new(),
                    transport: None,
                });
            }
            let body = match read_limited(req, 2_048).await {
                Ok(body) => body,
                Err(error) => return Some(ApiRequest::Rejected { status: 413, error }),
            };
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
            if !operator_authorized(&authorization, operator) {
                return Some(ApiRequest::Incident {
                    authorization,
                    id: (*id).to_string(),
                    action: (*action).to_string(),
                    body: Vec::new(),
                });
            }
            let body = match read_limited(req, 2_048).await {
                Ok(body) => body,
                Err(error) => return Some(ApiRequest::Rejected { status: 413, error }),
            };
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

async fn runtime_fence(store: &D1Store<'_>, now: i64) -> Result<Response> {
    let completion = d1_store::probe_completion_fence(store, now)
        .await
        .map_err(|error| worker::Error::RustError(error.to_string()))?;
    let loaded = store
        .load_memory("sfs-web")
        .await
        .map_err(|error| worker::Error::RustError(error.to_string()))?;
    let check = watchdog_core::domain::check_result(
        watchdog_core::domain::MonitorStatus::Healthy,
        None,
        "fence",
        None,
        None,
    );
    let first = store
        .commit_check(
            "sfs-web",
            "smartflowsocial",
            loaded.generation,
            &loaded.memory,
            &check,
            now,
            &[],
            &[],
        )
        .await
        .map_err(|error| worker::Error::RustError(error.to_string()))?;
    let second = store
        .commit_check(
            "sfs-web",
            "smartflowsocial",
            loaded.generation,
            &loaded.memory,
            &check,
            now,
            &[],
            &[],
        )
        .await
        .map_err(|error| worker::Error::RustError(error.to_string()))?;
    let mut body = completion;
    if let Some(object) = body.as_object_mut() {
        object.insert(
            "generationFirst".to_string(),
            serde_json::json!(first.committed),
        );
        object.insert(
            "generationSecond".to_string(),
            serde_json::json!(second.committed),
        );
    }
    Response::from_json(&body)
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
        operation: None,
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
        operation: None,
    }
}
