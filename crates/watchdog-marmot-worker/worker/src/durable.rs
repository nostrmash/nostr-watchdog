use std::collections::{BTreeMap, HashMap};
use std::ops::Deref;

use cgka_traits::storage::GroupStorage;
use cgka_traits::{GroupId, KeyPackage, KeyPackageSource, MessageId, TransportMessage};
use marmot_worker_runtime::inbox::{self, InboxChoice};
use marmot_worker_runtime::publication::{self, revalidate_trigger_envelope};
use marmot_worker_runtime::push::{capability_identity, notification_gift_wrap, CapabilityId, Platform, TokenRecord};
use marmot_worker_runtime::{
    stamp_tombstone, verify_tombstone, HistoryManifest, OperationTombstone, ServerRelays, Session, StoredWake,
};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use worker::wasm_bindgen::{closure::ScopedClosure, JsCast, JsValue};
use worker::*;

use crate::cas::commit_won;
use crate::relay;

const ACCOUNT: &str = "self";
const MAX_BODY: usize = 256 * 1024;
const MAX_HISTORY_BUCKET: usize = 256;
const MAX_TRIGGER_ATTEMPTS: usize = 3;

#[durable_object]
pub struct MarmotSender {
    state: State,
    sql: AccountSql,
    storage_key: Option<[u8; 32]>,
    operator_token: String,
    allow_loopback: bool,
}

struct Gate {
    response: Value,
    publish: Option<Publish>,
    pull: Option<Pull>,
    hide: bool,
    follow_push: bool,
}

struct Pull {
    relays: Vec<String>,
    filters: Vec<Value>,
    streams: Vec<String>,
    purpose: String,
    operation_id: String,
    fault: Option<String>,
}

struct Publish {
    operation_id: String,
    relays: Vec<String>,
    event: Value,
    kind: PublishKind,
}

enum PublishKind {
    Message,
    Push,
}

#[derive(Deserialize)]
struct Command {
    op: String,
    #[serde(default)]
    project_id: Option<String>,
    #[serde(rename = "projectId", default)]
    project_id_camel: Option<String>,
    #[serde(default)]
    operation_id: Option<String>,
    #[serde(rename = "operationId", default)]
    operation_id_camel: Option<String>,
    #[serde(default)]
    recipient: Option<String>,
    #[serde(rename = "senderSecretHex", default)]
    sender_secret_hex: Option<String>,
    #[serde(default, rename = "senderPubkey")]
    sender_pubkey: Option<String>,
    #[serde(default, rename = "generateTestIdentity")]
    generate_test_identity: bool,
    #[serde(default)]
    replace: bool,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    group_id_hex: Option<String>,
    #[serde(rename = "groupIdHex", default)]
    group_id_hex_camel: Option<String>,
    #[serde(default)]
    text: Option<String>,
    #[serde(default)]
    relays: Vec<String>,
    #[serde(default)]
    members: Vec<MemberPackage>,
    #[serde(default)]
    message: Option<Value>,
    #[serde(default)]
    welcome: Option<Value>,
    #[serde(default)]
    publish: bool,
    #[serde(default)]
    accepted: Option<bool>,
    #[serde(default)]
    fault: Option<String>,
    #[serde(rename = "serverPubkeyHex", default)]
    server_pubkey_hex: Option<String>,
    #[serde(rename = "encryptedTokenHex", default)]
    encrypted_token_hex: Option<String>,
}

#[derive(Deserialize)]
struct MemberPackage {
    #[serde(rename = "bytesHex", alias = "bytes_hex")]
    bytes_hex: String,
    #[serde(default, rename = "protocolProfile", alias = "protocol_profile")]
    protocol_profile: Option<String>,
    #[serde(default, rename = "eventIdHex", alias = "event_id_hex")]
    event_id_hex: Option<String>,
}

struct Row {
    revision: i64,
    writer: String,
    account_hex: String,
    floors: String,
    sealed: Vec<u8>,
}

#[derive(Clone)]
struct AccountSql {
    sql: SqlStorage,
    raw_storage: JsValue,
}

impl Deref for AccountSql {
    type Target = SqlStorage;

    fn deref(&self) -> &SqlStorage {
        &self.sql
    }
}

impl AccountSql {
    fn transaction(&self, mut action: impl FnMut() -> std::result::Result<(), String>) -> std::result::Result<(), String> {
        // workers-rs exposes the underlying context but does not bind transactionSync.
        let method = js_sys::Reflect::get(&self.raw_storage, &JsValue::from_str("transactionSync"))
            .and_then(|value| value.dyn_into::<js_sys::Function>())
            .map_err(|_| "synchronous SQLite transaction is unavailable")?;
        let mut callback = || action().map_err(|error| JsValue::from_str(&error));
        let closure = ScopedClosure::<dyn FnMut() -> std::result::Result<(), JsValue>>::borrow_mut_assert_unwind_safe(&mut callback);
        method.call1(&self.raw_storage, closure.as_ref())
            .map_err(|error| error.as_string().unwrap_or_else(|| "SQLite transaction failed".into()))?;
        Ok(())
    }
}

impl DurableObject for MarmotSender {
    fn new(state: State, env: Env) -> Self {
        let sql = AccountSql {
            sql: state.storage().sql(),
            raw_storage: state.as_raw().storage().expect("Durable Object storage").into(),
        };
        sql.exec(
            "CREATE TABLE IF NOT EXISTS marmot_account (
                id TEXT PRIMARY KEY,
                revision INTEGER NOT NULL,
                writer TEXT NOT NULL,
                account_hex TEXT NOT NULL,
                floors TEXT NOT NULL,
                sealed BLOB NOT NULL
            )",
            None,
        )
        .expect("create marmot_account");
        sql.exec(
            "CREATE TABLE IF NOT EXISTS marmot_operation (
                alert_id TEXT PRIMARY KEY,
                record TEXT NOT NULL
            )",
            None,
        )
        .expect("create marmot_operation");
        sql.exec(
            "CREATE TABLE IF NOT EXISTS marmot_history_bucket (
                bucket INTEGER PRIMARY KEY,
                entries TEXT NOT NULL
            )",
            None,
        )
        .expect("create marmot_history_bucket");
        let storage_key = env
            .secret("MARMOT_STORAGE_KEY")
            .ok()
            .and_then(|secret| parse_key(&secret.to_string()));
        let operator_token = env
            .secret("MARMOT_OPERATOR_TOKEN")
            .map(|secret| secret.to_string())
            .unwrap_or_default();
        let allow_loopback = env
            .var("MARMOT_ALLOW_LOOPBACK")
            .map(|value| value.to_string() == "1")
            .unwrap_or(false);
        Self {
            state,
            sql,
            storage_key,
            operator_token,
            allow_loopback,
        }
    }

    async fn fetch(&self, mut req: Request) -> Result<Response> {
        let url = req.url()?;
        if url.scheme() == "http" && !(self.allow_loopback && is_loopback_host(&url)) {
            return Response::error("https is required", 403);
        }
        if !authorized(req.headers().get("authorization")?, &self.operator_token) {
            return Response::error("unauthorized", 401);
        }
        let Some(storage_key) = self.storage_key else {
            return Response::error("marmot secrets are not configured", 503);
        };
        if self.operator_token.is_empty() {
            return Response::error("marmot secrets are not configured", 503);
        }
        let project = query_value(&url, "sender").unwrap_or_default();
        if !valid_name(&project) {
            return Response::error("sender name is invalid", 400);
        }
        if let Some(length) = req.headers().get("content-length")? {
            if length.parse::<usize>().unwrap_or(usize::MAX) > MAX_BODY {
                return Response::error("request body is too large", 413);
            }
        }
        let bytes = match read_limited(&mut req).await {
            Ok(bytes) => bytes,
            Err(error) if error.to_string().contains("too large") => {
                return Response::error("request body is too large", 413);
            }
            Err(error) => return Err(error),
        };
        let command: Command = serde_json::from_slice(&bytes).map_err(|_| Error::RustError("invalid json".into()))?;
        let sql = self.sql.clone();
        let allow_loopback = self.allow_loopback;
        let project_for_gate = project.clone();
        let gate = self
            .state
            .block_concurrency_while(async move {
                Ok(execute(&sql, storage_key, allow_loopback, &project_for_gate, command).await)
            })
            .await?;
        let gate = match gate {
            Ok(gate) => gate,
            Err(error) => return Response::error(sanitize(&error), 400),
        };
        if gate.hide {
            return Response::error("crash_injected:after_store", 500);
        }
        if let Some(pull) = gate.pull {
            let mut events = Vec::new();
            if pull.purpose == "sync" {
                let mut pages = Vec::new();
                let mut chats = Vec::new();
                for (index, filter) in pull.filters.iter().enumerate() {
                    let Ok(found) = relay::fetch_events(&pull.relays, filter.clone(), allow_loopback).await else {
                        continue;
                    };
                    let stream = pull
                        .streams
                        .get(index)
                        .cloned()
                        .unwrap_or_else(|| format!("sync-{index}"));
                    let sql = self.sql.clone();
                    let project_for_sync = project.clone();
                    let ingested = self
                        .state
                        .block_concurrency_while(async move {
                            Ok(ingest_pulled(
                                &sql,
                                storage_key,
                                &project_for_sync,
                                found,
                                &stream,
                            )
                            .await)
                        })
                        .await?;
                    let ingested = ingested.map_err(|error| Error::RustError(sanitize(&error)))?;
                    if let Some(found) = ingested.get("chats").and_then(|value| value.as_array()) {
                        chats.extend(found.clone());
                    }
                    pages.push(ingested);
                }
                return Response::from_json(&json!({
                    "ok": !pages.is_empty() && pages.iter().all(|page| page["failed"] != true),
                    "projectId": project,
                    "pages": pages,
                    "chats": chats
                }));
            }
            for filter in &pull.filters {
                if let Ok(found) = relay::fetch_events(&pull.relays, filter.clone(), allow_loopback).await {
                    events.extend(found);
                }
            }
            if pull.purpose == "establish" {
                let relays = pull.relays.clone();
                let operation_id = pull.operation_id.clone();
                let sql = self.sql.clone();
                let project_for_group = project.clone();
                let created = self
                    .state
                    .block_concurrency_while(async move {
                        Ok(establish_from(
                            &sql,
                            storage_key,
                            &project_for_group,
                            &operation_id,
                            relays,
                            events,
                        )
                        .await)
                    })
                    .await?;
                let mut response = created.map_err(|error| Error::RustError(sanitize(&error)))?;
                if pull.fault.as_deref() == Some("before_welcome_publish") {
                    response = apply_projection(
                        &self.state,
                        &self.sql,
                        storage_key,
                        &project,
                        allow_loopback,
                        response,
                    )
                    .await?;
                    return Response::from_json(&response);
                }
                let relays = response
                    .get("publicationRelays")
                    .and_then(|value| value.as_array())
                    .map(|items| {
                        items
                            .iter()
                            .filter_map(|item| item.as_str().map(str::to_owned))
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or_default();
                if let Some(welcomes) = response.get("welcomes").and_then(|value| value.as_array()).cloned() {
                    for welcome in welcomes {
                        let message: TransportMessage = serde_json::from_value(welcome)
                            .map_err(|error| Error::RustError(error.to_string()))?;
                        let event = Session::transport_json(&message)
                            .map_err(|error| Error::RustError(error.to_string()))?;
                        let operation_id = response["operationId"]
                            .as_str()
                            .unwrap_or_default()
                            .to_string();
                        let phase = publish_and_record(
                            &self.state,
                            &self.sql,
                            storage_key,
                            &project,
                            &operation_id,
                            "message",
                            &relays,
                            &event,
                            allow_loopback,
                        )
                        .await?;
                        response["messagePhase"] = json!(phase);
                        response["messageState"] = json!(phase);
                    }
                }
                response = apply_projection(
                    &self.state,
                    &self.sql,
                    storage_key,
                    &project,
                    allow_loopback,
                    response,
                )
                .await?;
                return Response::from_json(&response);
            }
            return Response::error("pull purpose is not recognized", 400);
        }
        let mut response = gate.response;
        if response.get("welcomes").and_then(|value| value.as_array()).is_some()
            && response.get("publicationRelays").and_then(|value| value.as_array()).is_some_and(|items| !items.is_empty())
        {
            let relays = response
                .get("publicationRelays")
                .and_then(|value| value.as_array())
                .map(|items| {
                    items
                        .iter()
                        .filter_map(|item| item.as_str().map(str::to_owned))
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            if let Some(welcomes) = response.get("welcomes").and_then(|value| value.as_array()).cloned() {
                for welcome in welcomes {
                    let message: TransportMessage = serde_json::from_value(welcome)
                        .map_err(|error| Error::RustError(error.to_string()))?;
                    let event = Session::transport_json(&message)
                        .map_err(|error| Error::RustError(error.to_string()))?;
                    let operation_id = response["operationId"].as_str().unwrap_or_default().to_string();
                    let phase = publish_and_record(
                        &self.state,
                        &self.sql,
                        storage_key,
                        &project,
                        &operation_id,
                        "message",
                        &relays,
                        &event,
                        allow_loopback,
                    )
                    .await?;
                    response["messagePhase"] = json!(phase);
                    response["messageState"] = json!(phase);
                }
            }
        }
        if let Some(publish) = gate.publish {
            let kind = match publish.kind {
                PublishKind::Message => "message",
                PublishKind::Push => "push",
            };
            let phase = publish_and_record(
                &self.state,
                &self.sql,
                storage_key,
                &project,
                &publish.operation_id,
                kind,
                &publish.relays,
                &publish.event,
                allow_loopback,
            )
            .await?;
            if kind == "message" {
                response["messagePhase"] = json!(phase);
                response["messageState"] = json!(phase);
            } else {
                response["pushPhase"] = json!(phase);
                response["pushState"] = json!(phase);
            }
        }
        if gate.follow_push && response["messagePhase"] == "relay_accepted" {
            if let Some(operation_id) = response["operationId"].as_str().map(str::to_string) {
                let sql = self.sql.clone();
                let project_for_push = project.clone();
                let operation_for_push = operation_id.clone();
                let prepared = self
                    .state
                    .block_concurrency_while(async move {
                        Ok(prepare_push(
                            &sql,
                            storage_key,
                            &project_for_push,
                            &operation_for_push,
                            allow_loopback,
                            false,
                        )
                        .await)
                    })
                    .await?;
                let mut prepared = prepared.map_err(|error| Error::RustError(sanitize(&error)))?;
                if !prepared.discover.is_empty() && !prepared.discovery_relays.is_empty() {
                    let mut found = Vec::new();
                    for server in &prepared.discover {
                        let filter = json!({"kinds": [10050], "authors": [server], "limit": 8});
                        if let Ok(events) = relay::fetch_events(&prepared.discovery_relays, filter, allow_loopback).await {
                            found.extend(events);
                        }
                    }
                    let sql = self.sql.clone();
                    let project_for_inbox = project.clone();
                    let servers = prepared.discover.clone();
                    let admitted = self
                        .state
                        .block_concurrency_while(async move {
                            Ok(admit_inboxes(&sql, storage_key, &project_for_inbox, &servers, found, allow_loopback).await)
                        })
                        .await?;
                    let _ = admitted.map_err(|error| Error::RustError(sanitize(&error)))?;
                    let sql = self.sql.clone();
                    let project_for_push = project.clone();
                    let operation_for_push = operation_id.clone();
                    prepared = self
                        .state
                        .block_concurrency_while(async move {
                            Ok(prepare_push(
                                &sql,
                                storage_key,
                                &project_for_push,
                                &operation_for_push,
                                allow_loopback,
                                true,
                            )
                            .await)
                        })
                        .await?
                        .map_err(|error| Error::RustError(sanitize(&error)))?;
                }
                let jobs = prepared.jobs;
                let phase = prepared.phase;
                if true {
                    if jobs.is_empty() {
                        if let Some(phase) = phase {
                            response["pushPhase"] = json!(phase);
                            response["pushState"] = json!(phase);
                        }
                    }
                    for (event, relays) in jobs {
                        let operation_id = response["operationId"]
                            .as_str()
                            .unwrap_or_default()
                            .to_string();
                        let phase = publish_and_record(
                            &self.state,
                            &self.sql,
                            storage_key,
                            &project,
                            &operation_id,
                            "push",
                            &relays,
                            &event,
                            allow_loopback,
                        )
                        .await?;
                        response["pushPhase"] = json!(phase);
                        response["pushState"] = json!(phase);
                        if let Some(event_id) = event.get("id").and_then(|item| item.as_str()) {
                            if response["pushEventId"].is_null() {
                                response["pushEventId"] = json!(event_id);
                            }
                        }
                    }
                }
            }
        }
        response = apply_projection(
            &self.state,
            &self.sql,
            storage_key,
            &project,
            allow_loopback,
            response,
        )
        .await?;
        Response::from_json(&response)
    }
}

async fn apply_projection(
    state: &State,
    sql: &AccountSql,
    storage_key: [u8; 32],
    project: &str,
    allow_loopback: bool,
    mut response: Value,
) -> Result<Value> {
    if let Some(operation_id) = response["operationId"].as_str().map(str::to_owned) {
        let sql_view = sql.clone();
        let project_view = project.to_owned();
        let projected = state
            .block_concurrency_while(async move {
                Ok(project_stored(&sql_view, storage_key, &project_view, &operation_id))
            })
            .await?;
        if let Ok(projected) = projected {
            overlay_projection(&mut response, projected);
        }
    }
    if let Some(map) = response.as_object_mut() {
        map.remove("publicationRelays");
        if !allow_loopback {
            map.remove("welcomes");
            map.remove("message");
            map.remove("trigger");
        }
    }
    Ok(response)
}

fn project_stored(
    sql: &AccountSql,
    storage_key: [u8; 32],
    project: &str,
    operation_id: &str,
) -> std::result::Result<Value, String> {
    let (session, _row) = open_account(sql, storage_key, project)?;
    consult_operation(sql, &session, project, &storage_key, operation_id)?;
    session
        .project_operation(operation_id)
        .map_err(|error| error.to_string())
}

fn overlay_projection(response: &mut Value, projected: Value) {
    let Some(map) = response.as_object_mut() else {
        return;
    };
    let Some(projected) = projected.as_object() else {
        return;
    };
    for key in [
        "ok",
        "messagePhase",
        "messageState",
        "pushPhase",
        "pushState",
        "pushEventId",
        "messageEventId",
        "disposition",
        "settled",
        "retryAfterMs",
        "retryAtMs",
        "reconcileAfterMs",
        "error",
        "evidence",
        "phoneDelivery",
        "pushRetryable",
        "projectId",
        "targets",
        "triggers",
        "messageAttempts",
        "messagePublicationAttempts",
        "messageReconcileAttempts",
        "unknownAttempts",
        "tokenWaitAttempts",
        "pushPublicationAttempts",
        "unobservableAttempts",
        "pushAttempts",
        "operationAgeMs",
        "startedAtMs",
        "updatedAtMs",
        "resubmittable",
    ] {
        if key == "evidence" && projected[key] == "not_observed" {
            continue;
        }
        if let Some(value) = projected.get(key) {
            map.insert(key.to_owned(), value.clone());
        }
    }
}

async fn execute(
    sql: &AccountSql,
    storage_key: [u8; 32],
    allow_loopback: bool,
    project: &str,
    command: Command,
) -> std::result::Result<Gate, String> {
    if command.project_id.as_deref().or(command.project_id_camel.as_deref())
        .is_some_and(|identity| identity != project)
    {
        return Err("project identity mismatch".into());
    }
    if command.op == "status" {
        return Ok(Gate {
            response: status(sql, storage_key, project)?,
            publish: None,
            pull: None,
            hide: false,
            follow_push: false,
        });
    }
    if command.op == "sync" {
        return sync_plan(sql, storage_key, allow_loopback, project, &command);
    }
    if command.op == "establish" {
        return establish_plan(sql, storage_key, allow_loopback, project, &command);
    }
    if command.op == "cas_self_test" {
        if !allow_loopback {
            return Err("diagnostic commands are test-only".into());
        }
        return Ok(Gate {
            response: cas_self_test(sql)?,
            publish: None,
            pull: None,
            hide: false,
            follow_push: false,
        });
    }
    if command.op == "stale_write" {
        if !allow_loopback {
            return Err("diagnostic commands are test-only".into());
        }
        return Ok(Gate {
            response: stale_write(sql)?,
            publish: None,
            pull: None,
            hide: false,
            follow_push: false,
        });
    }
    let loaded = load(sql)?;
    let fault = command.fault.clone();
    if fault.is_some() && !allow_loopback {
        return Err("fault injection is test-only".into());
    }
    let session = open_session(sql, &loaded, storage_key, project, allow_loopback, &command)?;
    verify_configured_identity(&session, &command)?;
    if let Some(operation_id) = command
        .operation_id
        .clone()
        .or(command.operation_id_camel.clone())
    {
        consult_operation(
            sql,
            &session,
            project,
            &storage_key,
            &operation_id,
        )?;
    }
    if matches!(command.op.as_str(), "key_package" | "maintain") {
        consult_operation(
            sql,
            &session,
            project,
            &storage_key,
            "key-package",
        )?;
    }
    let body = dispatch(&session, project, allow_loopback, &command).await?;
    if command.op == "readiness" || body["admission"] == "absent" {
        return Ok(Gate { response: body, publish: None, pull: None, hide: false, follow_push: false });
    }
    if fault.as_deref() == Some("before_store") {
        return Err("crash_injected:before_store".into());
    }
    remember_consistent(&session)?;
    commit_account(
        sql,
        storage_key,
        project,
        &session,
        loaded.as_ref().map(|row| row.revision as u64),
        fault.as_deref(),
    )?;
    if fault.as_deref() == Some("after_store") {
        return Ok(Gate {
            response: json!({"ok": false}),
            publish: None,
            pull: None,
            hide: true,
            follow_push: false,
        });
    }
    let publish = publish_job(&session, &command, &body, allow_loopback)?;
    let follow_push = matches!(command.op.as_str(), "deliver" | "reconcile") && body["retired"] != true;
    let mut body = body;
    if matches!(command.op.as_str(), "deliver" | "reconcile") {
        if let Some(map) = body.as_object_mut() {
            map.remove("message");
            map.remove("trigger");
            map.remove("welcomes");
        }
    }
    Ok(Gate {
        response: body,
        publish,
        pull: None,
        hide: false,
        follow_push,
    })
}

fn verify_configured_identity(session: &Session, command: &Command) -> std::result::Result<(), String> {
    if command.sender_pubkey.as_ref().is_some_and(|sender| sender != &session.public_key_hex()) {
        return Err("sender identity mismatch".into());
    }
    // Reconciliation can refer to an earlier conversation of the same sender.
    if !matches!(command.op.as_str(), "onboard" | "init" | "reconcile") {
        let binding = session.binding().map_err(|error| error.to_string())?;
        if command.recipient.as_ref().is_some_and(|recipient| recipient != &binding.recipient_hex) {
            return Err("recipient identity mismatch".into());
        }
    }
    Ok(())
}

fn establish_plan(
    sql: &AccountSql,
    storage_key: [u8; 32],
    allow_loopback: bool,
    project: &str,
    command: &Command,
) -> std::result::Result<Gate, String> {
    if command.fault.is_some() && !allow_loopback {
        return Err("fault injection is test-only".into());
    }
    let (session, _row) = open_account(sql, storage_key, project)?;
    verify_configured_identity(&session, command)?;
    let binding = session.binding().map_err(|error| error.to_string())?;
    let operation = command
        .operation_id
        .clone()
        .or(command.operation_id_camel.clone())
        .unwrap_or_else(|| "establish".into());
    if binding.group_id_hex.is_some() {
        return Ok(Gate {
            response: recovery_response(&session, &operation)?,
            publish: None,
            pull: None,
            hide: false,
            follow_push: false,
        });
    }
    let relays = if allow_loopback && !command.relays.is_empty() {
        command.relays.clone()
    } else {
        binding.relays.clone()
    };
    relay::validate_relays(&relays, allow_loopback)?;
    if binding.recipient_hex.len() != 64 {
        return Err("recipient is not configured".into());
    }
    Ok(Gate {
        response: json!({}),
        publish: None,
        pull: Some(Pull {
            filters: vec![json!({
                "kinds": [30443],
                "authors": [binding.recipient_hex],
                "limit": 5
            })],
            relays,
            streams: vec!["key-packages".into()],
            purpose: "establish".into(),
            operation_id: operation,
            fault: command.fault.clone(),
        }),
        hide: false,
        follow_push: false,
    })
}

async fn establish_from(
    sql: &AccountSql,
    storage_key: [u8; 32],
    project: &str,
    operation_id: &str,
    relays: Vec<String>,
    events: Vec<Value>,
) -> std::result::Result<Value, String> {
    let (session, row) = open_account(sql, storage_key, project)?;
    let binding = session.binding().map_err(|error| error.to_string())?;
    if binding.group_id_hex.is_some() {
        return recovery_response(&session, operation_id);
    }
    let mut package = None;
    for event in events {
        if let Ok(found) = Session::key_package_from_relay_event(&event, &binding.recipient_hex) {
            package = Some(found);
            break;
        }
    }
    let package = package.ok_or("recipient key package was not found")?;
    consult_operation(
        sql,
        &session,
        project,
        &storage_key,
        operation_id,
    )?;
    let (group_id, welcomes) = session
        .create_group(operation_id, "watchdog", vec![package], relays.clone())
        .await
        .map_err(|error| error.to_string())?;
    persist_session(sql, storage_key, project, &session, row.revision as u64)?;
    Ok(outcome(
        operation_id,
        "accepted_pending",
        welcomes.first().map(Session::message_id_hex),
        "not_required",
        None,
        "prepared_welcome",
        false,
        json!({
            "groupIdHex": hex::encode(group_id.as_slice()),
            "welcomes": welcomes,
            "publicationRelays": relays
        }),
    ))
}

fn sync_plan(
    sql: &AccountSql,
    storage_key: [u8; 32],
    allow_loopback: bool,
    project: &str,
    command: &Command,
) -> std::result::Result<Gate, String> {
    let (session, _row) = open_account(sql, storage_key, project)?;
    verify_configured_identity(&session, command)?;
    let binding = session.binding().map_err(|error| error.to_string())?;
    let relays = if allow_loopback && !command.relays.is_empty() {
        command.relays.clone()
    } else {
        binding.relays.clone()
    };
    relay::validate_relays(&relays, allow_loopback)?;
    let stored_cursors = session.storage().sync_cursors().map_err(|error| error.to_string())?;
    let cursors = stored_cursors
        .iter()
        .map(|cursor| CursorView {
            stream: cursor.stream.clone(),
            since: cursor.since,
            until: cursor.until,
            caught_up: cursor.caught_up,
        })
        .collect::<Vec<_>>();
    let mut filters = Vec::new();
    let mut streams = Vec::new();
    if let Some(group) = binding.nostr_group_hex.clone() {
        filters.push(cursor_filter(
            json!({"kinds": [445], "#h": [group.clone()], "limit": 20}),
            cursor_since(&cursors, "group-445"),
            cursor_until(&cursors, "group-445"),
        ));
        streams.push("group-445".into());
        filters.push(cursor_filter(
            json!({"kinds": [447, 448, 449], "#h": [group], "limit": 20}),
            cursor_since(&cursors, "group-gossip"),
            cursor_until(&cursors, "group-gossip"),
        ));
        streams.push("group-gossip".into());
    }
    filters.push(cursor_filter(
        json!({"kinds": [1059], "#p": [session.public_key_hex()], "limit": 20}),
        cursor_since(&cursors, "inbox-1059"),
        cursor_until(&cursors, "inbox-1059"),
    ));
    streams.push("inbox-1059".into());
    Ok(Gate {
        response: json!({
            "syncCursors": cursors.iter().map(|cursor| json!({
                "stream": cursor.stream,
                "since": cursor.since,
                "until": cursor.until,
                "caughtUp": cursor.caught_up
            })).collect::<Vec<_>>()
        }),
        publish: None,
        pull: Some(Pull {
            relays,
            filters,
            streams,
            purpose: "sync".into(),
            operation_id: String::new(),
            fault: None,
        }),
        hide: false,
        follow_push: false,
    })
}

async fn ingest_pulled(
    sql: &AccountSql,
    storage_key: [u8; 32],
    project: &str,
    events: Vec<Value>,
    stream: &str,
) -> std::result::Result<Value, String> {
    let (session, row) = open_account(sql, storage_key, project)?;
    let mut chats = Vec::new();
    let mut processed = Vec::new();
    let mut failed = false;
    for event in events {
        let stamp = event.get("created_at").and_then(|value| value.as_u64()).unwrap_or(0);
        let event_id = event.get("id").and_then(|value| value.as_str()).unwrap_or("").to_owned();
        if event_id.is_empty() {
            failed = true;
        }
        match session.ingest_event(event).await {
            Ok(mut found) => {
                chats.append(&mut found);
                processed.push((stamp, event_id));
            }
            Err(_) => {
                failed = true;
                processed.push((stamp, event_id));
            }
        }
    }
    session
        .note_sync_page(stream, &processed, 20, !failed)
        .map_err(|error| error.to_string())?;
    commit_account(sql, storage_key, project, &session, Some(row.revision as u64), None)?;
    Ok(json!({
        "stream": stream,
        "chats": chats,
        "ingested": chats.len(),
        "failed": failed
    }))
}

struct CursorView {
    stream: String,
    since: u64,
    until: Option<u64>,
    caught_up: bool,
}

fn cursor_since(cursors: &[CursorView], stream: &str) -> u64 {
    cursors
        .iter()
        .find(|cursor| cursor.stream == stream)
        .map(|cursor| cursor.since)
        .unwrap_or(0)
}

fn cursor_until(cursors: &[CursorView], stream: &str) -> Option<u64> {
    cursors
        .iter()
        .find(|cursor| cursor.stream == stream)
        .and_then(|cursor| cursor.until)
}

fn cursor_filter(mut filter: Value, since: u64, until: Option<u64>) -> Value {
    if since == 0 && until.is_none() {
        return filter;
    }
    if let Some(map) = filter.as_object_mut() {
        if since > 0 {
            map.insert("since".into(), json!(since));
        }
        if let Some(until) = until {
            map.insert("until".into(), json!(until));
        }
    }
    filter
}

fn open_session(
    sql: &AccountSql,
    loaded: &Option<Row>,
    storage_key: [u8; 32],
    project: &str,
    allow_loopback: bool,
    command: &Command,
) -> std::result::Result<Session, String> {
    if let Some(row) = loaded {
        let session = open_committed(sql, storage_key, project, row)?;
        if let Some(secret) = command.sender_secret_hex.as_deref() {
            let imported = Session::import(parse_secret(secret)?).map_err(|error| error.to_string())?;
            if imported.public_key_hex() != session.public_key_hex() {
                return Err("sender_identity_mismatch".into());
            }
        }
        return Ok(session);
    }
    if command.op != "onboard" && command.op != "init" {
        return Err("account is not initialized".into());
    }
    if count_operations(sql)? != 0 || sql.exec("SELECT bucket FROM marmot_history_bucket LIMIT 1", None)
        .map_err(|error| error.to_string())?.raw().next().is_some()
    {
        return Err("account snapshot is missing from existing history".into());
    }
    let session = match command.sender_secret_hex.as_deref() {
        Some(secret) => Session::import(parse_secret(secret)?).map_err(|error| error.to_string())?,
        None if allow_loopback && command.generate_test_identity => {
            Session::generate().map_err(|error| error.to_string())?
        }
        None => return Err("sender_identity_required".into()),
    };
    hydrate(&session)?;
    Ok(session)
}

async fn dispatch(
    session: &Session,
    project: &str,
    allow_loopback: bool,
    command: &Command,
) -> std::result::Result<Value, String> {
    let operation_id = command
        .operation_id
        .clone()
        .or(command.operation_id_camel.clone());
    let project_field = command
        .project_id
        .clone()
        .or(command.project_id_camel.clone());
    match command.op.as_str() {
        "onboard" | "init" => {
            let requested = project_field.unwrap_or_else(|| project.to_owned());
            if requested != project {
                return Err("project id does not match the durable object".into());
            }
            let operation = operation_id.ok_or("operationId is required")?;
            let recipient = command.recipient.clone().unwrap_or_default();
            if !valid_name(&operation) || recipient.len() != 64 {
                return Err("onboarding identity is invalid".into());
            }
            if !command.relays.is_empty() {
                relay::validate_relays(&command.relays, allow_loopback)?;
            }
            let reused = session
                .configure(project, &recipient, &command.relays, command.replace)
                .map_err(|error| error.to_string())?;
            Ok(outcome(
                &operation,
                "not_submitted",
                None,
                "not_required",
                None,
                "onboarding",
                true,
                json!({
                    "reused": reused,
                    "pubkey": session.public_key_hex(),
                    "projectId": project
                }),
            ))
        }
        "key_package" | "maintain" => {
            let event = session
                .ensure_key_package_event()
                .await
                .map_err(|error| error.to_string())?;
            let bytes_hex = Session::encoded_package_hex(&event).map_err(|error| error.to_string())?;
            Ok(json!({
                "ok": true,
                "operationId": "key-package",
                "bytesHex": bytes_hex,
                "protocolProfile": "current",
                "pubkey": session.public_key_hex(),
                "event": event,
                "maintenance": "republish_stored_key_package"
            }))
        }
        "create_group" => {
            let operation = operation_id.ok_or("operationId is required")?;
            relay::validate_relays(&command.relays, allow_loopback)?;
            let members = decode_members(&command.members)?;
            let name = command.name.clone().unwrap_or_else(|| "watchdog".into());
            let (group_id, welcomes) = session
                .create_group(&operation, &name, members, command.relays.clone())
                .await
                .map_err(|error| error.to_string())?;
            Ok(outcome(
                &operation,
                "accepted_pending",
                welcomes.first().map(Session::message_id_hex),
                "not_required",
                None,
                "prepared_welcome",
                false,
                json!({
                    "groupIdHex": hex::encode(group_id.as_slice()),
                    "welcomes": welcomes
                }),
            ))
        }
        "join_welcome" => {
            let welcome = decode_message(command.welcome.clone())?;
            session
                .join_welcome(welcome)
                .await
                .map_err(|error| error.to_string())?;
            Ok(json!({"joined": true}))
        }
        "ingest" => {
            let message = decode_message(command.message.clone())?;
            let chats = session.ingest(message).await.map_err(|error| error.to_string())?;
            Ok(json!({"chats": chats}))
        }
        "send" | "deliver" => {
            let operation = operation_id.clone().or(command.operation_id_camel.clone()).ok_or("operationId is required")?;
            let group_id = if command.op == "deliver" {
                let bound = session.binding().map_err(|error| error.to_string())?;
                decode_group(bound.group_id_hex)?
            } else {
                decode_group(command.group_id_hex.clone().or(command.group_id_hex_camel.clone()))?
            };
            let text = command.text.clone().unwrap_or_default();
            if text.len() > 16 * 1024 {
                return Err("alert text is too large".into());
            }
            let message = match session.send_chat(&operation, &group_id, &text).await {
                Ok(message) => message,
                Err(marmot_worker_runtime::SessionError::Retired(_)) => {
                    return retired_outcome(session, &operation);
                }
                Err(error) => return Err(error.to_string()),
            };
            let stored = session
                .storage()
                .publication(&operation)
                .map_err(|error| error.to_string())?
                .ok_or("publication missing after send")?;
            Ok(outcome(
                &operation,
                &stored.message_phase,
                Some(Session::message_id_hex(&message)),
                &stored.push_phase,
                stored.push_event_id.clone(),
                "prepared_message",
                false,
                with_counters(
                    json!({
                        "message": message,
                        "groupIdHex": hex::encode(group_id.as_slice())
                    }),
                    stored.message_attempts,
                    stored.push_attempts,
                    stored.started_at_ms,
                ),
            ))
        }
        "self_update" => {
            let operation = operation_id.ok_or("operationId is required")?;
            let group_id = decode_group(command.group_id_hex.clone().or(command.group_id_hex_camel.clone()))?;
            let (message, pending) = session
                .self_update(&operation, &group_id)
                .await
                .map_err(|error| error.to_string())?;
            Ok(outcome(
                &operation,
                "accepted_pending",
                Some(Session::message_id_hex(&message)),
                "not_required",
                None,
                "prepared_commit",
                false,
                json!({"pending": pending, "message": message}),
            ))
        }
        "ack" | "confirm" => {
            if !allow_loopback {
                return Err("synthetic acknowledgement is test-only".into());
            }
            let operation = operation_id.ok_or("operationId is required")?;
            let accepted = command.accepted.unwrap_or(true);
            session
                .note_publication(&operation, accepted)
                .await
                .map_err(|error| error.to_string())?;
            let stored = session
                .storage()
                .publication(&operation)
                .map_err(|error| error.to_string())?
                .ok_or("publication missing")?;
            Ok(outcome(
                &operation,
                &stored.message_phase,
                Some(Session::message_id_hex(&stored.message)),
                &stored.push_phase,
                stored.push_event_id.clone(),
                "publication_recorded",
                stored.message_phase == "relay_accepted" || stored.message_phase == "rejected",
                with_counters(json!({}), stored.message_attempts, stored.push_attempts, stored.started_at_ms),
            ))
        }
        "publication" => {
            let operation = operation_id.ok_or("operationId is required")?;
            let stored = session
                .storage()
                .publication(&operation)
                .map_err(|error| error.to_string())?
                .ok_or("publication missing")?;
            Ok(outcome(
                &operation,
                &stored.message_phase,
                Some(Session::message_id_hex(&stored.message)),
                &stored.push_phase,
                stored.push_event_id.clone(),
                "stored_publication",
                stored.message_phase == "relay_accepted",
                with_counters(
                    json!({
                        "message": stored.message,
                        "groupIdHex": hex::encode(stored.group_id.as_slice())
                    }),
                    stored.message_attempts,
                    stored.push_attempts,
                    stored.started_at_ms,
                ),
            ))
        }
        "reconcile" => {
            let operation = operation_id.ok_or("operationId is required")?;
            if let Some(stored) = session
                .storage()
                .publication(&operation)
                .map_err(|error| error.to_string())?
            {
                return Ok(outcome(
                    &operation,
                    &stored.message_phase,
                    Some(Session::message_id_hex(&stored.message)),
                    &stored.push_phase,
                    stored.push_event_id.clone(),
                    "reconcile",
                    stored.message_phase == "relay_accepted"
                        && matches!(
                            stored.push_phase.as_str(),
                            "relay_accepted" | "rejected" | "not_required" | "terminal_failure" | "expired"
                        ),
                    with_counters(
                        json!({"message": stored.message}),
                        stored.message_attempts,
                        stored.push_attempts,
                        stored.started_at_ms,
                    ),
                ));
            }
            if session.storage().tombstone(&operation).map_err(|error| error.to_string())?.is_some() {
                return retired_outcome(session, &operation);
            }
            Ok(json!({
                "ok": true,
                "projectId": project,
                "operationId": operation,
                "admission": "absent",
                "disposition": "reconcile"
            }))
        }
        "readiness" => {
            let binding = session.binding().map_err(|error| error.to_string())?;
            let tokens = if let Some(group) = binding.group_id_hex.clone() {
                session
                    .select_push_tokens(&decode_group(Some(group))?)
                    .map(|rows| rows.len())
                    .unwrap_or(0)
            } else {
                0
            };
            let onboarding = session.onboarding_view().map_err(|error| error.to_string())?;
            let canonical = if let Some(group) = binding.group_id_hex.clone() {
                let group = decode_group(Some(group))?;
                let members = session.member_ids(&group).map_err(|error| error.to_string())?;
                let sender = session.public_key_hex();
                members.contains(&sender) && members.contains(&binding.recipient_hex) &&
                    members.iter().all(|id| id == &sender || id == &binding.recipient_hex || binding.extra_recipients.contains(id))
            } else {
                false
            };
            let key_package_ready = session.storage().publication("key-package")
                .map_err(|error| error.to_string())?.is_some_and(|row| row.message_phase == "relay_accepted");
            Ok(json!({
                "ok": true,
                "projectId": project,
                "account": true,
                "pubkey": session.public_key_hex(),
                "groupIdHex": binding.group_id_hex,
                "groupBound": binding.group_id_hex.is_some(),
                "recipient": binding.recipient_hex,
                "recipientTokenCount": tokens,
                "onboarding": onboarding,
                "canonicalMembership": canonical,
                "keyPackagePublished": key_package_ready,
                "storageIntegrity": "checked",
                "phoneDelivery": false
            }))
        }
        "stage_push" => {
            if !allow_loopback {
                return Err("token injection is test-only".into());
            }
            let operation = operation_id.ok_or("operationId is required")?;
            let server = command.server_pubkey_hex.clone().ok_or("serverPubkeyHex is required")?;
            let token = hex::decode(command.encrypted_token_hex.clone().unwrap_or_default())
                .map_err(|_| "encrypted token is not hex".to_owned())?;
            let trigger = notification_gift_wrap(&server, &[token])
                .await
                .map_err(|error| error.to_string())?;
            let bytes = serde_json::to_vec(&trigger).map_err(|error| error.to_string())?;
            let stored = session.stage_push(&operation, &bytes).map_err(|error| error.to_string())?;
            let publication = session
                .storage()
                .publication(&operation)
                .map_err(|error| error.to_string())?
                .ok_or("publication missing after push staging")?;
            Ok(outcome(
                &operation,
                &publication.message_phase,
                Some(Session::message_id_hex(&publication.message)),
                "prepared",
                None,
                "prepared_push",
                false,
                with_counters(
                    json!({"trigger": serde_json::from_slice::<Value>(&stored).unwrap_or(Value::Null)}),
                    publication.message_attempts,
                    publication.push_attempts,
                    publication.started_at_ms,
                ),
            ))
        }
        other => Err(format!("unknown operation {other}")),
    }
}

fn publish_job(
    session: &Session,
    command: &Command,
    body: &Value,
    allow_loopback: bool,
) -> std::result::Result<Option<Publish>, String> {
    if !command.publish {
        return Ok(None);
    }
    let publishing_trigger = command.op == "stage_push";
    if !publishing_trigger && body.get("messagePhase").and_then(|value| value.as_str()) == Some("relay_accepted")
    {
        return Ok(None);
    }
    let relays = if allow_loopback && !command.relays.is_empty() {
        command.relays.clone()
    } else {
        session.binding().map_err(|error| error.to_string())?.relays
    };
    relay::validate_relays(&relays, allow_loopback)?;
    let operation_id = body
        .get("operationId")
        .and_then(|value| value.as_str())
        .unwrap_or_default()
        .to_owned();
    let event = if command.op == "stage_push" {
        body.get("trigger").cloned().unwrap_or(Value::Null)
    } else if command.op == "key_package" || command.op == "maintain" {
        body.get("event").cloned().unwrap_or(Value::Null)
    } else if let Some(message) = body.get("message") {
        let message: TransportMessage = serde_json::from_value(message.clone()).map_err(|error| error.to_string())?;
        Session::transport_json(&message).map_err(|error| error.to_string())?
    } else if let Some(welcomes) = body.get("welcomes").and_then(|value| value.as_array()) {
        let welcome: TransportMessage = serde_json::from_value(welcomes[0].clone()).map_err(|error| error.to_string())?;
        Session::transport_json(&welcome).map_err(|error| error.to_string())?
    } else {
        return Err("nothing is prepared for publication".into());
    };
    let kind = if command.op == "stage_push" {
        PublishKind::Push
    } else {
        PublishKind::Message
    };
    Ok(Some(Publish {
        operation_id,
        relays,
        event,
        kind,
    }))
}

async fn publish_and_record(
    state: &State,
    sql: &AccountSql,
    storage_key: [u8; 32],
    project: &str,
    operation_id: &str,
    kind: &str,
    relays: &[String],
    event: &Value,
    allow_loopback: bool,
) -> Result<String> {
    let event_id = event
        .get("id")
        .and_then(|item| item.as_str())
        .unwrap_or_default()
        .to_owned();
    if event_id.is_empty() {
        return Err(Error::RustError("event id is missing".into()));
    }
    let attempt_id = publication::new_attempt_id();
    let destination = relays.first().cloned().unwrap_or_default();
    let sql_begin = sql.clone();
    let project_begin = project.to_owned();
    let operation_begin = operation_id.to_owned();
    let kind_begin = kind.to_owned();
    let attempt_begin = attempt_id.clone();
    let event_begin = event_id.clone();
    let destination_begin = destination.clone();
    let started = state
        .block_concurrency_while(async move {
            Ok(begin_attempt(
                &sql_begin,
                storage_key,
                &project_begin,
                &operation_begin,
                &kind_begin,
                &attempt_begin,
                &event_begin,
                &destination_begin,
            )
            .await)
        })
        .await?;
    let started = started.map_err(|error| Error::RustError(sanitize(&error)))?;
    if !started {
        return Ok("relay_accepted".into());
    }
    let publication = match relay::publish_event(relays, event, allow_loopback, &attempt_id).await {
        Ok(publication) => publication,
        Err(error) => relay::RelayPublication {
            event_id: event_id.clone(),
            attempt_id: attempt_id.clone(),
            outcome: "unobservable".into(),
            relay: destination.clone(),
            reason: if error.contains("timed out") {
                "publication_timeout".into()
            } else {
                "relay_disconnected".into()
            },
            retryable: true,
            started_ms: 0,
            finished_ms: 0,
        },
    };
    let sql_ack = sql.clone();
    let project_ack = project.to_owned();
    let operation_ack = operation_id.to_owned();
    let kind_ack = kind.to_owned();
    let phase = state
        .block_concurrency_while(async move {
            Ok(acknowledge(
                &sql_ack,
                storage_key,
                &project_ack,
                &operation_ack,
                &kind_ack,
                publication,
            )
            .await)
        })
        .await?;
    phase.map_err(|error| Error::RustError(sanitize(&error)))
}

async fn begin_attempt(
    sql: &AccountSql,
    storage_key: [u8; 32],
    project: &str,
    operation_id: &str,
    kind: &str,
    attempt_id: &str,
    event_id: &str,
    destination: &str,
) -> std::result::Result<bool, String> {
    let (session, row) = open_account(sql, storage_key, project)?;
    if kind == "push" {
        let publication = session.storage().publication(operation_id).map_err(|error| error.to_string())?
            .ok_or("push publication is missing")?;
        if let Some(bytes) = publication.push_trigger.as_ref() {
            if let Ok(envelope @ Value::Array(_)) = serde_json::from_slice::<Value>(bytes) {
                let binding = session.binding().map_err(|error| error.to_string())?;
                if binding.recipient_hex != publication.recipient_hex
                    || binding.group_id_hex.as_deref() != Some(&hex::encode(publication.group_id.as_slice()))
                {
                    return Err("push conversation changed".into());
                }
                let authorized = session.select_push_tokens(&publication.group_id).map_err(|error| error.to_string())?
                    .iter().map(wake_capability).collect::<std::result::Result<Vec<_>, _>>()?;
                let (_, jobs, _) = revalidate_trigger_envelope(&envelope, &authorized);
                let accepted = publication.publications.iter().any(|record| record.role == "push" && record.event_id == event_id && record.phase == "relay_accepted");
                if !accepted && !jobs.iter().any(|job| job.event["id"].as_str() == Some(event_id)) {
                    return Err("push capability changed before publication".into());
                }
            }
        }
    }
    let role = if kind == "push" { "push" } else { "message" };
    let started = session
        .begin_network_attempt(operation_id, role, attempt_id, event_id, destination)
        .map_err(|error| error.to_string())?;
    if started {
        persist_session(sql, storage_key, project, &session, row.revision as u64)?;
    }
    Ok(started)
}

async fn acknowledge(
    sql: &AccountSql,
    storage_key: [u8; 32],
    project: &str,
    operation_id: &str,
    kind: &str,
    publication: relay::RelayPublication,
) -> std::result::Result<String, String> {
    let (session, row) = open_account(sql, storage_key, project)?;
    let phase = if kind == "push" {
        let phase = match publication.outcome.as_str() {
            "relay_accepted" => "relay_accepted",
            "rejected" => "rejected",
            _ => "unobservable",
        };
        let reason = if phase == "unobservable" && !publication.retryable {
            "push_unobservable"
        } else {
            publication.reason.as_str()
        };
        let mut server = String::new();
        if let Some(stored) = session
            .storage()
            .publication(operation_id)
            .map_err(|error| error.to_string())?
        {
            if let Some(bytes) = stored.push_trigger.as_deref() {
                let prepared = push_event_ids(bytes);
                if phase == "relay_accepted"
                    && !prepared.is_empty()
                    && !prepared.iter().any(|item| item == &publication.event_id)
                {
                    return Err("push acknowledgement does not match the prepared trigger".into());
                }
                server = server_for_event(bytes, &publication.event_id);
            }
        }
        session
            .note_trigger(
                operation_id,
                phase,
                &publication.event_id,
                &publication.relay,
                &publication.attempt_id,
                reason,
                &server,
            )
            .map_err(|error| error.to_string())?
    } else {
        let message_outcome = match publication.outcome.as_str() {
            "relay_accepted" => "relay_accepted",
            "rejected" => "rejected",
            _ => "completion_unknown",
        };
        session
            .note_message_outcome(
                operation_id,
                message_outcome,
                &publication.event_id,
                &publication.relay,
                &publication.attempt_id,
            )
            .await
            .map_err(|error| error.to_string())?;
        session
            .storage()
            .publication(operation_id)
            .map_err(|error| error.to_string())?
            .map(|stored| stored.message_phase)
            .unwrap_or_else(|| message_outcome.to_owned())
    };
    persist_session(sql, storage_key, project, &session, row.revision as u64)?;
    Ok(phase)
}

fn push_event_ids(bytes: &[u8]) -> Vec<String> {
    let Ok(value) = serde_json::from_slice::<Value>(bytes) else {
        return Vec::new();
    };
    let mut ids = Vec::new();
    if let Some(id) = value.get("id").and_then(|item| item.as_str()) {
        ids.push(id.to_owned());
    }
    if let Some(id) = value.pointer("/event/id").and_then(|item| item.as_str()) {
        ids.push(id.to_owned());
    }
    if let Some(items) = value.as_array() {
        for item in items {
            if let Some(id) = item.pointer("/event/id").and_then(|value| value.as_str()) {
                ids.push(id.to_owned());
            }
        }
    }
    ids
}

fn server_for_event(bytes: &[u8], event_id: &str) -> String {
    let Ok(value) = serde_json::from_slice::<Value>(bytes) else {
        return String::new();
    };
    let Some(items) = value.as_array() else {
        return String::new();
    };
    for item in items {
        if item.pointer("/event/id").and_then(|value| value.as_str()) == Some(event_id) {
            return item
                .get("server")
                .and_then(|value| value.as_str())
                .unwrap_or("")
                .to_owned();
        }
    }
    String::new()
}

fn persist_session(
    sql: &AccountSql,
    storage_key: [u8; 32],
    project: &str,
    session: &Session,
    revision: u64,
) -> std::result::Result<(), String> {
    commit_account(sql, storage_key, project, session, Some(revision), None)
}

fn commit_account(
    sql: &AccountSql,
    storage_key: [u8; 32],
    project: &str,
    session: &Session,
    expected: Option<u64>,
    fault: Option<&str>,
) -> std::result::Result<(), String> {
    remember_consistent(session)?;
    let pending = session
        .storage()
        .take_pending_tombstones()
        .map_err(|error| error.to_string())?;
    let original = session.storage().history_manifest().map_err(|error| error.to_string())?;
    let next = advance(session, expected)?;
    let writer = writer_id()?;
    let account = session.public_key_hex();
    let floors = floor_map(session)?;
    let stamped = pending
        .into_iter()
        .map(|stone| stamp_tombstone(stone, &storage_key, project, &account, next, &writer))
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|error| error.to_string())?;
    sql.transaction(|| {
        // The snapshot and index advance in one transaction. An exception from
        // this callback rolls back both, including writes made before a lost CAS.
        if fault == Some("before_index_insert") {
            return Err("crash_injected:before_index_insert".into());
        }
        let mut manifest = original.clone().unwrap_or_default();
        write_pending_operations(sql, &stamped, &mut manifest)?;
        if fault == Some("after_index_insert") {
            return Err("crash_injected:after_index_insert".into());
        }
        manifest.revision = next;
        manifest.writer = writer.clone();
        session.storage().set_history_manifest(manifest).map_err(|error| error.to_string())?;
        let sealed = session.seal(&storage_key, project).map_err(|error| error.to_string())?;
        let expected = if fault == Some("lose_history_cas") { expected.map(|value| value + 1) } else { expected };
        store(sql, expected, next, &writer, &account, &floors, &sealed)
    })?;
    for hook in session.take_commit_hooks() {
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(hook));
    }
    Ok(())
}

struct PushWork {
    jobs: Vec<(Value, Vec<String>)>,
    discover: Vec<String>,
    discovery_relays: Vec<String>,
    phase: Option<String>,
}

fn empty_push(phase: Option<String>) -> PushWork {
    PushWork {
        jobs: Vec::new(),
        discover: Vec::new(),
        discovery_relays: Vec::new(),
        phase,
    }
}

async fn prepare_push(
    sql: &AccountSql,
    storage_key: [u8; 32],
    project: &str,
    operation_id: &str,
    allow_loopback: bool,
    rediscovery: bool,
) -> std::result::Result<PushWork, String> {
    let (session, row) = open_account(sql, storage_key, project)?;
    let stored = session
        .storage()
        .publication(operation_id)
        .map_err(|error| error.to_string())?
        .ok_or("publication missing")?;
    if stored.message_phase != "relay_accepted" {
        return Ok(empty_push(Some(stored.push_phase)));
    }
    if stored.settled() {
        return Ok(empty_push(Some(stored.push_phase)));
    }
    let binding = session.binding().map_err(|error| error.to_string())?;
    if binding.group_id_hex.as_deref() != Some(&hex::encode(stored.group_id.as_slice()))
        || binding.recipient_hex != stored.recipient_hex
        || marmot_worker_runtime::clock::unix_ms().saturating_sub(stored.started_at_ms) >= 900_000
    {
        session.expire_push(operation_id).map_err(|error| error.to_string())?;
        persist_session(sql, storage_key, project, &session, row.revision as u64)?;
        return Ok(empty_push(Some("expired".into())));
    }
    let discovery_relays = binding.relays.clone();
    let now = js_sys::Date::now() as u64;
    let directories = session
        .storage()
        .server_relays()
        .map_err(|error| error.to_string())?;
    let Some(group_hex) = binding.group_id_hex.clone() else {
        session
            .note_token_wait(operation_id)
            .map_err(|error| error.to_string())?;
        persist_session(sql, storage_key, project, &session, row.revision as u64)?;
        return Ok(empty_push(Some("token_unavailable".into())));
    };
    let tokens = session
        .select_push_tokens(&decode_group(Some(group_hex))?)
        .map_err(|error| error.to_string())?;
    if let Some(bytes) = stored.push_trigger.as_deref() {
        if let Ok(envelope) = serde_json::from_slice::<Value>(bytes) {
            if envelope.get(0).and_then(|item| item.get("event")).is_some() {
                return retry_stored_push(
                    sql,
                    storage_key,
                    project,
                    operation_id,
                    allow_loopback,
                    rediscovery,
                    session,
                    row.revision as u64,
                    &tokens,
                    &directories,
                    &discovery_relays,
                    envelope,
                    now,
                )
                .await;
            }
        }
    }
    if tokens.is_empty() {
        session
            .note_token_wait(operation_id)
            .map_err(|error| error.to_string())?;
        persist_session(sql, storage_key, project, &session, row.revision as u64)?;
        return Ok(empty_push(Some("token_unavailable".into())));
    }
    let (jobs, envelope, discover, terminal) =
        build_trigger_batches(&tokens, &directories, allow_loopback, now, rediscovery).await?;
    if !envelope.is_empty() {
        let bytes = serde_json::to_vec(&envelope).map_err(|error| error.to_string())?;
        session
            .stage_push(operation_id, &bytes)
            .map_err(|error| error.to_string())?;
    }
    record_push_targets(&session, operation_id, &envelope, &terminal)?;
    if !discover.is_empty() && !rediscovery {
        if !envelope.is_empty() || !terminal.is_empty() {
            persist_session(sql, storage_key, project, &session, row.revision as u64)?;
        }
        return Ok(PushWork {
            jobs: Vec::new(),
            discover,
            discovery_relays,
            phase: None,
        });
    }
    if jobs.is_empty() {
        if terminal.is_empty() {
            session
                .note_push(operation_id, "unobservable", None)
                .map_err(|error| error.to_string())?;
        }
        persist_session(sql, storage_key, project, &session, row.revision as u64)?;
        return Ok(empty_push(Some("unobservable".into())));
    }
    persist_session(sql, storage_key, project, &session, row.revision as u64)?;
    Ok(PushWork {
        jobs,
        discover: Vec::new(),
        discovery_relays,
        phase: None,
    })
}

fn cached_inbox(
    directories: &[ServerRelays],
    server: &str,
    now: u64,
    allow_loopback: bool,
) -> Option<Vec<String>> {
    let found = directories.iter().find(|item| item.server_pubkey_hex == server)?;
    if !inbox::cache_fresh(found.observed_at_ms, now) {
        return None;
    }
    if found.negative {
        return Some(Vec::new());
    }
    Some(
        found
            .relays
            .iter()
            .filter(|url| relay::validate_relay(url, allow_loopback).is_ok())
            .cloned()
            .collect(),
    )
}

async fn retry_stored_push(
    sql: &AccountSql,
    storage_key: [u8; 32],
    project: &str,
    operation_id: &str,
    allow_loopback: bool,
    rediscovery: bool,
    session: Session,
    revision: u64,
    tokens: &[marmot_worker_runtime::StoredWake],
    directories: &[ServerRelays],
    discovery_relays: &[String],
    envelope: Value,
    now: u64,
) -> std::result::Result<PushWork, String> {
    let mut authorized = Vec::new();
    for wake in tokens {
        authorized.push(wake_capability(wake)?);
    }
    let (updated, _jobs, _uncovered) = revalidate_trigger_envelope(&envelope, &authorized);
    let stored = session.storage().publication(operation_id).map_err(|error| error.to_string())?
        .ok_or("push publication is missing")?;
    let mut publish = Vec::new();
    let mut discover = Vec::new();
    let mut updated = updated;
    if let Some(items) = updated.as_array_mut() {
        for item in items.iter_mut() {
            let phase = item.get("phase").and_then(|value| value.as_str()).unwrap_or("prepared");
            if matches!(phase, "relay_accepted" | "retired" | "rejected" | "expired") {
                continue;
            }
            let server = item
                .get("server")
                .and_then(|value| value.as_str())
                .unwrap_or("")
                .to_owned();
            let event = item.get("event").cloned().unwrap_or(Value::Null);
            let Some(event_id) = event["id"].as_str() else {
                continue;
            };
            let attempts = stored.publications.iter().filter(|record| record.role == "push"
                && record.event_id == event_id && !record.attempt_id.starts_with("target:")).count();
            if attempts >= MAX_TRIGGER_ATTEMPTS {
                item["phase"] = json!("expired");
                continue;
            }
            let mut relays = item
                .get("relays")
                .and_then(|value| value.as_array())
                .map(|values| {
                    values
                        .iter()
                        .filter_map(|value| value.as_str().map(str::to_owned))
                        .filter(|url| relay::validate_relay(url, allow_loopback).is_ok())
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            let failed = phase == "unobservable" || phase == "publication_attempted";
            if failed && !rediscovery {
                if !server.is_empty() && !discover.contains(&server) {
                    discover.push(server);
                }
                continue;
            }
            if rediscovery {
                if let Some(found) = cached_inbox(directories, &server, now, allow_loopback) {
                    if !found.is_empty() {
                        relays = found;
                        if let Some(map) = item.as_object_mut() {
                            map.insert("relays".into(), json!(relays));
                        }
                    }
                }
            }
            if relays.is_empty() {
                if !server.is_empty() && !discover.contains(&server) {
                    discover.push(server);
                }
                continue;
            }
            publish.push((event, relays));
        }
    }
    let covered = covered_capabilities(&updated);
    let mut missing = Vec::new();
    for wake in tokens {
        let capability = wake_capability(wake)?;
        if !covered.iter().any(|item| item == &capability) {
            missing.push(wake.clone());
        }
    }
    let mut terminal = Vec::new();
    if !missing.is_empty() {
        let (extra_jobs, extra_items, extra_discover, extra_terminal) =
            build_trigger_batches(&missing, directories, allow_loopback, now, rediscovery).await?;
        publish.extend(extra_jobs);
        discover.extend(extra_discover);
        terminal.extend(extra_terminal);
        if let Some(items) = updated.as_array_mut() {
            items.extend(extra_items);
        }
    }
    let bytes = serde_json::to_vec(&updated).map_err(|error| error.to_string())?;
    session
        .replace_push_envelope(operation_id, &bytes)
        .map_err(|error| error.to_string())?;
    record_push_targets(&session, operation_id, updated.as_array().map(Vec::as_slice).unwrap_or(&[]), &terminal)?;
    persist_session(sql, storage_key, project, &session, revision)?;
    if !discover.is_empty() && !rediscovery {
        return Ok(PushWork {
            jobs: Vec::new(),
            discover,
            discovery_relays: discovery_relays.to_vec(),
            phase: None,
        });
    }
    if publish.is_empty() && tokens.is_empty() {
        return Ok(empty_push(Some("token_unavailable".into())));
    }
    Ok(PushWork {
        jobs: publish,
        discover: Vec::new(),
        discovery_relays: discovery_relays.to_vec(),
        phase: None,
    })
}

fn covered_capabilities(envelope: &Value) -> Vec<CapabilityId> {
    let mut covered = Vec::new();
    let Some(items) = envelope.as_array() else {
        return covered;
    };
    for item in items {
        let phase = item.get("phase").and_then(|value| value.as_str()).unwrap_or("");
        if phase == "retired" {
            continue;
        }
        if let Ok(capabilities) = item
            .get("capabilities")
            .cloned()
            .map(serde_json::from_value::<Vec<CapabilityId>>)
            .transpose()
        {
            for capability in capabilities.unwrap_or_default() {
                if !covered.iter().any(|item| item == &capability) {
                    covered.push(capability);
                }
            }
        }
    }
    covered
}

fn wake_capability(wake: &StoredWake) -> std::result::Result<CapabilityId, String> {
    let platform = Platform::from_name(&wake.platform)?;
    capability_identity(&TokenRecord {
        group_id_hex: wake.group_id_hex.clone(),
        member_id_hex: wake.member_id_hex.clone(),
        leaf_index: wake.leaf_index,
        platform,
        token_fingerprint: wake.token_fingerprint.clone(),
        server_pubkey_hex: wake.server_pubkey_hex.clone(),
        relay_hint: wake.relay_hint.clone(),
        owner_ts: wake.owner_ts,
        encrypted_token: wake.encrypted_token.clone(),
        owner_sig: wake.owner_sig.clone(),
        removed: wake.removed,
    })
}

fn record_push_targets(
    session: &Session,
    operation_id: &str,
    envelope: &[Value],
    terminal: &[String],
) -> std::result::Result<(), String> {
    for item in envelope {
        if let (Some(server), Some(event_id), Some(phase)) =
            (item["server"].as_str(), item["event"]["id"].as_str(), item["phase"].as_str())
        {
            session.retire_destination_gap(operation_id, server).map_err(|error| error.to_string())?;
            if matches!(phase, "prepared" | "retired" | "expired") {
                session.record_trigger_target(operation_id, event_id, server, phase).map_err(|error| error.to_string())?;
            }
        }
    }
    for server in terminal {
        session
            .note_destination_gap(operation_id, server)
            .map_err(|error| error.to_string())?;
    }
    Ok(())
}

async fn build_trigger_batches(
    tokens: &[StoredWake],
    directories: &[ServerRelays],
    allow_loopback: bool,
    now: u64,
    rediscovery: bool,
) -> std::result::Result<(Vec<(Value, Vec<String>)>, Vec<Value>, Vec<String>, Vec<String>), String> {
    let mut jobs = Vec::new();
    let mut envelope = Vec::new();
    let mut discover = Vec::new();
    let mut terminal = Vec::new();
    let mut grouped: HashMap<String, Vec<(Vec<u8>, CapabilityId)>> = HashMap::new();
    let mut hints: HashMap<String, Vec<String>> = HashMap::new();
    let mut order = Vec::new();
    for wake in tokens {
        let capability = wake_capability(wake)?;
        if !grouped.contains_key(&wake.server_pubkey_hex) {
            order.push(wake.server_pubkey_hex.clone());
        }
        if let Some(hint) = wake.relay_hint.clone() {
            if relay::validate_relay(&hint, allow_loopback).is_ok() {
                let entry = hints.entry(wake.server_pubkey_hex.clone()).or_default();
                if !entry.contains(&hint) {
                    entry.push(hint);
                }
            }
        }
        grouped
            .entry(wake.server_pubkey_hex.clone())
            .or_default()
            .push((wake.encrypted_token.clone(), capability));
    }
    for server in order {
        let mut relays = hints.remove(&server).unwrap_or_default();
        if relays.is_empty() {
            match cached_inbox(directories, &server, now, allow_loopback) {
                Some(found) if !found.is_empty() => relays = found,
                Some(_) => {
                    terminal.push(server);
                    continue;
                }
                None if !rediscovery => {
                    discover.push(server);
                    continue;
                }
                None => {
                    terminal.push(server);
                    continue;
                }
            }
        }
        let batch = grouped.remove(&server).unwrap_or_default();
        let mut offset = 0;
        while offset < batch.len() {
            let end = (offset + 18).min(batch.len());
            let slice = &batch[offset..end];
            let ciphertexts = slice.iter().map(|(token, _)| token.clone()).collect::<Vec<_>>();
            let capabilities = slice
                .iter()
                .map(|(_, capability)| capability.clone())
                .collect::<Vec<_>>();
            let event = notification_gift_wrap(&server, &ciphertexts)
                .await
                .map_err(|error| error.to_string())?;
            let event = serde_json::to_value(&event).map_err(|error| error.to_string())?;
            envelope.push(json!({
                "event": event,
                "relays": relays,
                "server": server,
                "capabilities": capabilities,
                "phase": "prepared"
            }));
            jobs.push((event, relays.clone()));
            offset = end;
        }
    }
    Ok((jobs, envelope, discover, terminal))
}

fn open_account(
    sql: &AccountSql,
    storage_key: [u8; 32],
    project: &str,
) -> std::result::Result<(Session, Row), String> {
    let row = load(sql)?.ok_or("account is not initialized")?;
    let session = open_committed(sql, storage_key, project, &row)?;
    Ok((session, row))
}

fn open_committed(
    sql: &AccountSql,
    storage_key: [u8; 32],
    project: &str,
    row: &Row,
) -> std::result::Result<Session, String> {
    let session = Session::open(&storage_key, project, &row.account_hex, &row.sealed)
        .map_err(|error| error.to_string())?;
    let manifest = session.storage().history_manifest().map_err(|error| error.to_string())?
        .ok_or("legacy operation history requires recovery")?;
    if manifest.revision != row.revision as u64 || manifest.writer != row.writer
        || sql.exec("SELECT 1 FROM marmot_history_bucket WHERE bucket = -1", None)
            .map_err(|error| error.to_string())?.raw().next().is_some()
    {
        return Err("account history integrity check failed".into());
    }
    if parse_floors(&row.floors)? != floor_map(&session)? {
        return Err("epoch floor metadata is corrupt".into());
    }
    hydrate(&session)?;
    Ok(session)
}

fn hydrate(session: &Session) -> std::result::Result<(), String> {
    session
        .storage()
        .enable_incremental_history()
        .map_err(|error| error.to_string())
}

fn consult_operation(
    sql: &AccountSql,
    session: &Session,
    project: &str,
    storage_key: &[u8; 32],
    operation_id: &str,
) -> std::result::Result<(), String> {
    let manifest = session.storage().history_manifest().map_err(|error| error.to_string())?
        .unwrap_or_default();
    let found = verified_operation(sql, session, project, storage_key, operation_id, &manifest);
    if found.is_err() {
        sql.exec("INSERT OR IGNORE INTO marmot_history_bucket VALUES (-1, 'integrity_failure')", None)
            .map_err(|error| error.to_string())?;
    }
    session.storage().consult_history(operation_id, found?).map_err(|error| error.to_string())
}

fn verified_operation(
    sql: &AccountSql,
    session: &Session,
    project: &str,
    storage_key: &[u8; 32],
    operation_id: &str,
    manifest: &HistoryManifest,
) -> std::result::Result<Option<OperationTombstone>, String> {
    let bucket = history_bucket(sql, manifest, bucket_for(operation_id))?;
    let record = read_operation(sql, operation_id)?;
    match (bucket.get(operation_id), record) {
        (None, None) => Ok(None),
        (Some(digest), Some(record)) if *digest == history_digest(&record) => {
            let stone = serde_json::from_str::<OperationTombstone>(&record)
                .map_err(|_| "corrupted historical record")?;
            if stone.alert_id != operation_id {
                return Err("historical record is bound to another operation".into());
            }
            verify_tombstone(&stone, storage_key, project, &session.public_key_hex(), manifest)
                .map_err(|error| error.to_string())?;
            Ok(Some(stone))
        }
        _ => Err("historical operation index is incomplete or corrupt".into()),
    }
}

fn recovery_response(session: &Session, requested_operation: &str) -> std::result::Result<Value, String> {
    let binding = session.binding().map_err(|error| error.to_string())?;
    let view = session.onboarding_view().map_err(|error| error.to_string())?;
    let welcome = session
        .storage()
        .welcome_publication()
        .map_err(|error| error.to_string())?;
    let relays = if binding.welcome_relays.is_empty() {
        binding.relays.clone()
    } else {
        binding.welcome_relays.clone()
    };
    let operation_id = welcome
        .as_ref()
        .map(|row| row.alert_id.clone())
        .unwrap_or_else(|| requested_operation.to_owned());
    let ready = view
        .get("conversationReady")
        .and_then(|value| value.as_bool())
        .unwrap_or(false);
    let mut body = json!({
        "ok": true,
        "operationId": operation_id,
        "requestedOperationId": requested_operation,
        "groupBound": true,
        "groupIdHex": binding.group_id_hex,
        "groupPersisted": binding.group_id_hex.is_some(),
        "onboarding": view,
        "publicationRelays": relays,
        "disposition": if ready { "settled" } else { "reconcile" },
        "settled": ready,
        "phoneDelivery": false
    });
    if let Some(row) = welcome {
        let republish = row.message_phase != "relay_accepted" && row.message_phase != "rejected";
        if republish {
            let welcomes = if row.welcomes.is_empty() {
                vec![row.message.clone()]
            } else {
                row.welcomes.clone()
            };
            body["welcomes"] = serde_json::to_value(&welcomes).map_err(|error| error.to_string())?;
        }
        body["messagePhase"] = json!(row.message_phase);
        body["messageState"] = json!(row.message_phase);
    } else {
        body["completion"] = json!("unknown");
        body["error"] = json!("onboarding_completion_unknown");
    }
    Ok(body)
}

async fn admit_inboxes(
    sql: &AccountSql,
    storage_key: [u8; 32],
    project: &str,
    servers: &[String],
    events: Vec<Value>,
    allow_loopback: bool,
) -> std::result::Result<(), String> {
    let (session, row) = open_account(sql, storage_key, project)?;
    let now = js_sys::Date::now() as u64;
    let mut directories = session.storage().server_relays().map_err(|error| error.to_string())?;
    for server in servers {
        directories.retain(|item| item.server_pubkey_hex != *server);
        match inbox::select_inbox(&events, server, allow_loopback) {
            InboxChoice::Relays { relays, .. } => directories.push(ServerRelays {
                server_pubkey_hex: server.clone(),
                relays,
                observed_at_ms: now,
                negative: false,
            }),
            InboxChoice::Negative => directories.push(ServerRelays {
                server_pubkey_hex: server.clone(),
                relays: Vec::new(),
                observed_at_ms: now,
                negative: true,
            }),
        }
    }
    session
        .storage()
        .put_server_relays(directories)
        .map_err(|error| error.to_string())?;
    persist_session(sql, storage_key, project, &session, row.revision as u64)?;
    Ok(())
}

fn read_operation(sql: &AccountSql, alert_id: &str) -> std::result::Result<Option<String>, String> {
    let cursor = sql
        .exec("SELECT record FROM marmot_operation WHERE alert_id = ?", vec![alert_id.into()])
        .map_err(|error| error.to_string())?;
    cursor.raw().next().map(|values| {
        let values = values.map_err(|error| error.to_string())?;
        sql_string(values.first().ok_or("historical record is corrupt")?)
    }).transpose()
}

fn bucket_for(operation_id: &str) -> u8 {
    Sha256::digest(operation_id.as_bytes())[0]
}

fn history_digest(record: &str) -> String {
    hex::encode(Sha256::digest(record.as_bytes()))
}

fn history_bucket(
    sql: &AccountSql, manifest: &HistoryManifest, bucket: u8,
) -> std::result::Result<BTreeMap<String, String>, String> {
    let cursor = sql.exec(
        "SELECT entries FROM marmot_history_bucket WHERE bucket = ?",
        vec![(bucket as i64).into()],
    ).map_err(|error| error.to_string())?;
    let row = cursor.raw().next().transpose().map_err(|error| error.to_string())?;
    match (manifest.buckets.get(&bucket), row) {
        (None, None) => Ok(BTreeMap::new()),
        (Some(expected), Some(row)) => {
            let entries = sql_string(row.first().ok_or("history bucket is malformed")?)?;
            if history_digest(&entries) != *expected {
                return Err("history bucket commitment mismatch".into());
            }
            let entries: BTreeMap<String, String> = serde_json::from_str(&entries)
                .map_err(|_| "malformed history bucket")?;
            if entries.len() > MAX_HISTORY_BUCKET {
                return Err("history bucket exceeds capacity".into());
            }
            Ok(entries)
        }
        _ => Err("history bucket missing or uncommitted".into()),
    }
}

fn count_operations(sql: &AccountSql) -> std::result::Result<i64, String> {
    let cursor = sql
        .exec("SELECT COUNT(*) FROM marmot_operation", None)
        .map_err(|error| error.to_string())?;
    let mut raw = cursor.raw();
    let Some(values) = raw.next() else {
        return Ok(0);
    };
    let values = values.map_err(|error| error.to_string())?;
    sql_i64(values.first().ok_or("operation count is missing")?)
}

fn write_pending_operations(
    sql: &AccountSql, stones: &[OperationTombstone], manifest: &mut HistoryManifest,
) -> std::result::Result<(), String> {
    for stone in stones {
        let bucket = bucket_for(&stone.alert_id);
        let mut entries = history_bucket(sql, manifest, bucket)?;
        if entries.len() >= MAX_HISTORY_BUCKET {
            return Err("history capacity exhausted".into());
        }
        let record = serde_json::to_string(stone).map_err(|error| error.to_string())?;
        if entries.insert(stone.alert_id.clone(), history_digest(&record)).is_some() {
            return Err("operation already retired".into());
        }
        sql.exec(
            "INSERT INTO marmot_operation (alert_id, record) VALUES (?, ?)",
            vec![stone.alert_id.clone().into(), record.into()],
        ).map_err(|error| error.to_string())?;
        let serialized = serde_json::to_string(&entries).map_err(|error| error.to_string())?;
        manifest.buckets.insert(bucket, history_digest(&serialized));
        sql.exec(
            "INSERT INTO marmot_history_bucket (bucket, entries) VALUES (?, ?)
             ON CONFLICT(bucket) DO UPDATE SET entries = excluded.entries",
            vec![(bucket as i64).into(), serialized.into()],
        ).map_err(|error| error.to_string())?;
    }
    Ok(())
}

async fn read_limited(req: &mut Request) -> Result<Vec<u8>> {
    use futures_util::StreamExt;
    let mut stream = req.stream()?;
    let mut bytes = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|error| Error::RustError(error.to_string()))?;
        if bytes.len().saturating_add(chunk.len()) > MAX_BODY {
            return Err(Error::RustError("request body is too large".into()));
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

fn retired_outcome(session: &Session, operation: &str) -> std::result::Result<Value, String> {
    let stone = session
        .storage()
        .tombstone(operation)
        .map_err(|error| error.to_string())?
        .ok_or("retired operation has no record")?;
    Ok(outcome(
        operation,
        &stone.message_phase,
        Some(stone.message_event_id),
        &stone.push_phase,
        stone.push_event_id,
        "retired",
        true,
        json!({"retired": true, "resubmittable": false}),
    ))
}

fn with_counters(extra: Value, message_attempts: u64, push_attempts: u64, started_at_ms: u64) -> Value {
    let mut extra = extra;
    if let Some(map) = extra.as_object_mut() {
        map.insert("messageAttempts".into(), json!(message_attempts));
        map.insert("pushAttempts".into(), json!(push_attempts));
        map.insert(
            "operationAgeMs".into(),
            json!(marmot_worker_runtime::clock::unix_ms().saturating_sub(started_at_ms)),
        );
    }
    extra
}

fn outcome(
    operation_id: &str,
    message_phase: &str,
    message_event_id: Option<String>,
    push_phase: &str,
    push_event_id: Option<String>,
    evidence: &str,
    settled: bool,
    extra: Value,
) -> Value {
    let mut body = json!({
        "ok": true,
        "operationId": operation_id,
        "messagePhase": message_phase,
        "messageEventId": message_event_id,
        "pushPhase": push_phase,
        "pushEventId": push_event_id,
        "evidence": evidence,
        "error": null,
        "settled": settled,
        "messageState": message_phase,
        "pushState": push_phase,
        "disposition": if settled { "settled" } else { "reconcile" },
        "retryAtMs": if settled { 0 } else { 15_000 },
        "reconcileAfterMs": if settled { 0 } else { 15_000 },
        "phoneDelivery": false,
        "messageAttempts": 1,
        "pushAttempts": 0
    });
    if let (Some(map), Some(extra)) = (body.as_object_mut(), extra.as_object()) {
        for (key, value) in extra {
            map.insert(key.clone(), value.clone());
        }
    }
    body
}

fn status(sql: &AccountSql, storage_key: [u8; 32], project: &str) -> std::result::Result<Value, String> {
    if load(sql)?.is_none() {
        return Ok(json!({
            "ready": false,
            "revision": null,
            "pubkey": null,
            "groups": 0,
            "databaseBytes": sql.database_size(),
            "historicalOperations": 0,
            "historicalCapacityRemaining": 4096
        }));
    }
    let (session, row) = open_account(sql, storage_key, project)?;
    let groups = session.storage().list_groups().map_err(|error| error.to_string())?.len();
    let binding = session.binding().map_err(|error| error.to_string())?;
    let onboarding = session.onboarding_view().map_err(|error| error.to_string())?;
    let (_used, remaining) = session.storage().tombstone_status().map_err(|error| error.to_string())?;
    let historical = count_operations(sql)?;
    Ok(json!({
        "ready": true,
        "revision": row.revision,
        "pubkey": session.public_key_hex(),
        "groups": groups,
        "projectId": binding.project_id,
        "recipient": binding.recipient_hex,
        "onboarding": onboarding,
        "historicalOperations": historical,
        "historicalCapacityRemaining": remaining,
        "databaseBytes": sql.database_size()
    }))
}

fn cas_self_test(sql: &AccountSql) -> std::result::Result<Value, String> {
    let Some(row) = load(sql)? else {
        return Err("account is not initialized".into());
    };
    let next = row.revision + 1;
    let mut outcome = None;
    let result = sql.transaction(|| {
        let first = sql.exec(
            "UPDATE marmot_account SET revision = ?, writer = ? WHERE id = ? AND revision = ?",
            vec![next.into(), "winner".into(), ACCOUNT.into(), row.revision.into()],
        ).map_err(|error| error.to_string())?.rows_written();
        let second = sql.exec(
            "UPDATE marmot_account SET revision = ?, writer = ? WHERE id = ? AND revision = ?",
            vec![next.into(), "loser".into(), ACCOUNT.into(), row.revision.into()],
        ).map_err(|error| error.to_string())?.rows_written();
        let stored = load(sql)?.ok_or("account disappeared")?;
        outcome = Some(json!({
            "firstRows": first, "secondRows": second,
            "winner": commit_won(first, &stored.writer, "winner"),
            "loserWon": commit_won(second, &stored.writer, "loser"),
        }));
        Err("rollback_cas_test".into())
    });
    match result {
        Err(error) if error == "rollback_cas_test" => outcome.ok_or(error),
        Err(error) => Err(error),
        Ok(()) => Err("test transaction committed".into()),
    }
}

fn stale_write(sql: &AccountSql) -> std::result::Result<Value, String> {
    let cursor = sql
        .exec(
            "UPDATE marmot_account SET writer = ? WHERE id = ? AND revision = ?",
            vec!["stale".into(), ACCOUNT.into(), 0i64.into()],
        )
        .map_err(|error| error.to_string())?;
    if commit_won(cursor.rows_written(), "stale", "stale") {
        return Err("stale writer was accepted".into());
    }
    Ok(json!({
        "accepted": false,
        "rows": cursor.rows_written(),
        "ciphertext": null
    }))
}

fn advance(session: &Session, loaded: Option<u64>) -> std::result::Result<u64, String> {
    let floor = loaded.unwrap_or(0);
    let mut revision = session.revision().map_err(|error| error.to_string())?;
    while revision <= floor {
        revision = session
            .storage()
            .bump_revision()
            .map_err(|error| error.to_string())?;
    }
    Ok(revision)
}

fn remember_consistent(session: &Session) -> std::result::Result<(), String> {
    for group_id in session.storage().list_groups().map_err(|error| error.to_string())? {
        let epoch = session
            .storage()
            .get_group(&group_id)
            .map_err(|error| error.to_string())?
            .epoch
            .0;
        let floor = session
            .storage()
            .epoch_floor(&group_id)
            .map_err(|error| error.to_string())?;
        if epoch < floor {
            return Err("refusing to persist an earlier MLS epoch".into());
        }
    }
    Ok(())
}

fn floor_map(session: &Session) -> std::result::Result<HashMap<String, u64>, String> {
    let mut floors = HashMap::new();
    for group_id in session.storage().list_groups().map_err(|error| error.to_string())? {
        let epoch = session
            .storage()
            .epoch_floor(&group_id)
            .map_err(|error| error.to_string())?;
        floors.insert(hex::encode(group_id.as_slice()), epoch);
    }
    Ok(floors)
}

fn parse_floors(value: &str) -> std::result::Result<HashMap<String, u64>, String> {
    serde_json::from_str(value).map_err(|_| "epoch floor metadata is corrupt".to_owned())
}

fn load(sql: &AccountSql) -> std::result::Result<Option<Row>, String> {
    let cursor = sql
        .exec(
            "SELECT revision, writer, account_hex, floors, sealed FROM marmot_account WHERE id = ?",
            vec![ACCOUNT.into()],
        )
        .map_err(|error| error.to_string())?;
    let mut raw = cursor.raw();
    let Some(values) = raw.next() else {
        return Ok(None);
    };
    let values = values.map_err(|error| error.to_string())?;
    if values.len() != 5 {
        return Err("account row is malformed".into());
    }
    Ok(Some(Row {
        revision: sql_i64(&values[0])?,
        writer: sql_string(&values[1])?,
        account_hex: sql_string(&values[2])?,
        floors: sql_string(&values[3])?,
        sealed: sql_blob(&values[4])?,
    }))
}

fn sql_i64(value: &SqlStorageValue) -> std::result::Result<i64, String> {
    match value {
        SqlStorageValue::Integer(value) => Ok(*value),
        SqlStorageValue::Float(value) => Ok(*value as i64),
        _ => Err("sql integer is malformed".into()),
    }
}

fn sql_string(value: &SqlStorageValue) -> std::result::Result<String, String> {
    match value {
        SqlStorageValue::String(value) => Ok(value.clone()),
        _ => Err("sql text is malformed".into()),
    }
}

fn sql_blob(value: &SqlStorageValue) -> std::result::Result<Vec<u8>, String> {
    match value {
        SqlStorageValue::Blob(value) => Ok(value.clone()),
        _ => Err("sql blob is malformed".into()),
    }
}

fn store(
    sql: &AccountSql,
    expected: Option<u64>,
    revision: u64,
    writer: &str,
    account_hex: &str,
    floors: &HashMap<String, u64>,
    sealed: &[u8],
) -> std::result::Result<(), String> {
    if revision == 0 || sealed.len() > 1_500_000 {
        return Err("sealed account is not a valid committed revision".into());
    }
    let floors_json = serde_json::to_string(floors).map_err(|error| error.to_string())?;
    let cursor = match expected {
        None => sql.exec(
            "INSERT INTO marmot_account (id, revision, writer, account_hex, floors, sealed) VALUES (?, ?, ?, ?, ?, ?)",
            vec![
                ACCOUNT.into(),
                (revision as i64).into(),
                writer.into(),
                account_hex.into(),
                floors_json.into(),
                sealed.to_vec().into(),
            ],
        ),
        Some(expected) => sql.exec(
            "UPDATE marmot_account SET revision = ?, writer = ?, account_hex = ?, floors = ?, sealed = ? WHERE id = ? AND revision = ?",
            vec![
                (revision as i64).into(),
                writer.into(),
                account_hex.into(),
                floors_json.into(),
                sealed.to_vec().into(),
                ACCOUNT.into(),
                (expected as i64).into(),
            ],
        ),
    }
    .map_err(|error| error.to_string())?;
    let stored = load(sql)?.ok_or("account row is missing after write")?;
    if !commit_won(cursor.rows_written(), &stored.writer, writer) || stored.revision as u64 != revision {
        return Err("revision_conflict".into());
    }
    Ok(())
}

fn decode_members(members: &[MemberPackage]) -> std::result::Result<Vec<KeyPackage>, String> {
    members
        .iter()
        .map(|member| {
            let bytes = hex::decode(&member.bytes_hex).map_err(|_| "member key package is not hex".to_owned())?;
            if bytes.len() > 64 * 1024 {
                return Err("member key package is too large".into());
            }
            let mut package = KeyPackage::new(bytes);
            if member.protocol_profile.as_deref() == Some("current") {
                package = package.with_protocol_profile(cgka_traits::group::ProtocolProfile::Current);
            }
            if let Some(event_id) = &member.event_id_hex {
                let bytes = hex::decode(event_id).map_err(|_| "key package event id is not hex".to_owned())?;
                package.source = Some(KeyPackageSource {
                    event_id: MessageId::new(bytes),
                });
            }
            Ok(package)
        })
        .collect()
}

fn decode_group(value: Option<String>) -> std::result::Result<GroupId, String> {
    let hex_id = value.ok_or("groupIdHex is required")?;
    let bytes = hex::decode(hex_id).map_err(|_| "group id is not hex".to_owned())?;
    if bytes.len() > 64 {
        return Err("group id is too long".into());
    }
    Ok(GroupId::new(bytes))
}

fn decode_message(value: Option<Value>) -> std::result::Result<TransportMessage, String> {
    let value = value.ok_or("transport message is required")?;
    let encoded = serde_json::to_vec(&value).map_err(|error| error.to_string())?;
    if encoded.len() > MAX_BODY {
        return Err("transport message is too large".into());
    }
    serde_json::from_value(value).map_err(|error| error.to_string())
}

fn writer_id() -> std::result::Result<String, String> {
    let mut bytes = [0u8; 16];
    getrandom::getrandom(&mut bytes).map_err(|_| "randomness failed".to_owned())?;
    Ok(hex::encode(bytes))
}

fn parse_key(value: &str) -> Option<[u8; 32]> {
    let bytes = hex::decode(value.trim()).ok()?;
    if bytes.len() != 32 {
        return None;
    }
    bytes.try_into().ok()
}

fn parse_secret(value: &str) -> std::result::Result<[u8; 32], String> {
    parse_key(value).ok_or_else(|| "sender secret must be 32 bytes of hex".into())
}

fn authorized(header: Option<String>, token: &str) -> bool {
    let Some(header) = header else {
        return false;
    };
    let Some(presented) = header.strip_prefix("Bearer ") else {
        return false;
    };
    if presented.len() != token.len() || token.is_empty() {
        return false;
    }
    presented
        .bytes()
        .zip(token.bytes())
        .fold(0u8, |diff, (left, right)| diff | (left ^ right))
        == 0
}

fn is_loopback_host(url: &url::Url) -> bool {
    matches!(url.host_str(), Some("127.0.0.1") | Some("localhost") | Some("[::1]"))
}

fn query_value(url: &url::Url, name: &str) -> Option<String> {
    url.query_pairs()
        .find(|(key, _)| key == name)
        .map(|(_, value)| value.to_string())
}

fn valid_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' || ch == ':')
}

fn sanitize(error: &str) -> String {
    let lower = error.to_ascii_lowercase();
    if lower.contains("nsec") || lower.contains("bearer") || lower.contains("token") {
        return "marmot_error".into();
    }
    if error.chars().count() > 180 {
        return "marmot_error".into();
    }
    error.to_owned()
}

#[event(fetch)]
async fn main(req: Request, env: Env, _ctx: Context) -> Result<Response> {
    let url = req.url()?;
    if url.path() != "/marmot" {
        return Response::error("not found", 404);
    }
    let sender = query_value(&url, "sender").unwrap_or_default();
    if !valid_name(&sender) {
        return Response::error("sender name is invalid", 400);
    }
    let namespace = env.durable_object("MARMOT_SENDER")?;
    let stub = namespace.id_from_name(&sender)?.get_stub()?;
    stub.fetch_with_request(req).await
}
