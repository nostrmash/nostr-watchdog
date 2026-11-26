use std::collections::HashMap;

use cgka_traits::storage::GroupStorage;
use cgka_traits::{GroupId, KeyPackage, KeyPackageSource, MessageId, TransportMessage};
use marmot_worker_runtime::push::notification_gift_wrap;
use marmot_worker_runtime::Session;
use serde::Deserialize;
use serde_json::{Value, json};
use worker::*;

use crate::cas::commit_won;
use crate::relay;

const ACCOUNT: &str = "self";
const MAX_BODY: usize = 256 * 1024;

#[durable_object]
pub struct MarmotSender {
    state: State,
    sql: SqlStorage,
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
    purpose: String,
    operation_id: String,
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

impl DurableObject for MarmotSender {
    fn new(state: State, env: Env) -> Self {
        let sql = state.storage().sql();
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
                        let outcome = relay::publish_event(&relays, &event, allow_loopback)
                            .await
                            .unwrap_or_else(|_| "unobservable".into());
                        let event_id = event
                            .get("id")
                            .and_then(|item| item.as_str())
                            .unwrap_or_default()
                            .to_string();
                        let destination = relays.first().cloned().unwrap_or_default();
                        let sql = self.sql.clone();
                        let operation_id = response["operationId"]
                            .as_str()
                            .unwrap_or_default()
                            .to_string();
                        let project_for_ack = project.clone();
                        let ack = self
                            .state
                            .block_concurrency_while(async move {
                                Ok(acknowledge(
                                    &sql,
                                    storage_key,
                                    &project_for_ack,
                                    &operation_id,
                                    "message",
                                    &outcome,
                                    &event_id,
                                    &destination,
                                )
                                .await)
                            })
                            .await?;
                        if let Ok(phase) = ack {
                            response["messagePhase"] = json!(phase);
                            response["messageState"] = json!(phase);
                        }
                    }
                }
                if let Some(map) = response.as_object_mut() {
                    map.remove("publicationRelays");
                    if !allow_loopback {
                        map.remove("welcomes");
                    }
                }
                return Response::from_json(&response);
            }
            let sql = self.sql.clone();
            let project_for_sync = project.clone();
            let ingested = self
                .state
                .block_concurrency_while(async move {
                    Ok(ingest_pulled(&sql, storage_key, &project_for_sync, events).await)
                })
                .await?;
            let ingested = ingested.map_err(|error| Error::RustError(sanitize(&error)))?;
            return Response::from_json(&ingested);
        }
        let mut response = gate.response;
        if let Some(publish) = gate.publish {
            let outcome = relay::publish_event(&publish.relays, &publish.event, allow_loopback)
                .await
                .unwrap_or_else(|_| "unobservable".into());
            let event_id = publish
                .event
                .get("id")
                .and_then(|item| item.as_str())
                .unwrap_or_default()
                .to_string();
            let destination = publish.relays.first().cloned().unwrap_or_default();
            let sql = self.sql.clone();
            let operation_id = publish.operation_id.clone();
            let project_for_ack = project.clone();
            let kind = match publish.kind {
                PublishKind::Message => "message",
                PublishKind::Push => "push",
            };
            let ack = self
                .state
                .block_concurrency_while(async move {
                    Ok(acknowledge(
                        &sql,
                        storage_key,
                        &project_for_ack,
                        &operation_id,
                        kind,
                        &outcome,
                        &event_id,
                        &destination,
                    )
                    .await)
                })
                .await?;
            if let Ok(phase) = ack {
                if kind == "message" {
                    response["messagePhase"] = json!(phase);
                    response["messageState"] = json!(phase);
                } else {
                    response["pushPhase"] = json!(phase);
                    response["pushState"] = json!(phase);
                }
            }
        }
        if gate.follow_push && response["messagePhase"] == "relay_accepted" {
            if let Some(operation_id) = response["operationId"].as_str().map(str::to_string) {
                let sql = self.sql.clone();
                let project_for_push = project.clone();
                let prepared = self
                    .state
                    .block_concurrency_while(async move {
                        Ok(prepare_push(
                            &sql,
                            storage_key,
                            &project_for_push,
                            &operation_id,
                            allow_loopback,
                        )
                        .await)
                    })
                    .await?;
                if let Ok((jobs, phase)) = prepared {
                    if jobs.is_empty() {
                        if let Some(phase) = phase {
                            response["pushPhase"] = json!(phase);
                            response["pushState"] = json!(phase);
                        }
                    }
                    for (event, relays) in jobs {
                        let outcome = relay::publish_event(&relays, &event, allow_loopback)
                            .await
                            .unwrap_or_else(|_| "unobservable".into());
                        let event_id = event
                            .get("id")
                            .and_then(|item| item.as_str())
                            .unwrap_or_default()
                            .to_string();
                        let recorded_event = event_id.clone();
                        let destination = relays.first().cloned().unwrap_or_default();
                        let sql = self.sql.clone();
                        let operation_id = response["operationId"]
                            .as_str()
                            .unwrap_or_default()
                            .to_string();
                        let project_for_ack = project.clone();
                        let ack = self
                            .state
                            .block_concurrency_while(async move {
                                Ok(acknowledge(
                                    &sql,
                                    storage_key,
                                    &project_for_ack,
                                    &operation_id,
                                    "push",
                                    &outcome,
                                    &event_id,
                                    &destination,
                                )
                                .await)
                            })
                            .await?;
                        if let Ok(phase) = ack {
                            if response["pushPhase"] != "relay_accepted" {
                                response["pushPhase"] = json!(phase);
                                response["pushState"] = json!(phase);
                                response["pushEventId"] = json!(recorded_event);
                            }
                        }
                    }
                }
            }
        }
        Response::from_json(&response)
    }
}

async fn execute(
    sql: &SqlStorage,
    storage_key: [u8; 32],
    allow_loopback: bool,
    project: &str,
    command: Command,
) -> std::result::Result<Gate, String> {
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
        return Ok(Gate {
            response: cas_self_test(sql)?,
            publish: None,
            pull: None,
            hide: false,
            follow_push: false,
        });
    }
    if command.op == "stale_write" {
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
    let (session, created) = open_session(&loaded, storage_key, project, &command)?;
    if let Some(row) = &loaded {
        let declared = parse_floors(&row.floors)?;
        if declared != floor_map(&session)? {
            return Err("epoch floor metadata is corrupt".into());
        }
    }
    let body = dispatch(&session, project, allow_loopback, &command).await?;
    if fault.as_deref() == Some("before_store") {
        return Err("crash_injected:before_store".into());
    }
    let revision = advance(&session, loaded.as_ref().map(|row| row.revision as u64))?;
    remember_consistent(&session)?;
    let floors = floor_map(&session)?;
    let sealed = session
        .seal(&storage_key, project)
        .map_err(|error| error.to_string())?;
    let writer = writer_id()?;
    store(
        sql,
        loaded.as_ref().map(|row| row.revision as u64),
        revision,
        &writer,
        &session.public_key_hex(),
        &floors,
        &sealed,
    )?;
    for hook in session.take_commit_hooks() {
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(hook));
    }
    let _ = created;
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
    let follow_push = command.op == "deliver" || command.op == "reconcile";
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

fn establish_plan(
    sql: &SqlStorage,
    storage_key: [u8; 32],
    allow_loopback: bool,
    project: &str,
    command: &Command,
) -> std::result::Result<Gate, String> {
    let Some(row) = load(sql)? else {
        return Err("account is not initialized".into());
    };
    let session = Session::open(&storage_key, project, &row.account_hex, &row.sealed)
        .map_err(|error| error.to_string())?;
    let binding = session.binding().map_err(|error| error.to_string())?;
    let operation = command
        .operation_id
        .clone()
        .or(command.operation_id_camel.clone())
        .unwrap_or_else(|| "establish".into());
    if binding.group_id_hex.is_some() {
        return Ok(Gate {
            response: json!({
                "ok": true,
                "operationId": operation,
                "groupBound": true,
                "groupIdHex": binding.group_id_hex,
                "pubkey": session.public_key_hex(),
                "disposition": "settled",
                "phoneDelivery": false
            }),
            publish: None,
            pull: None,
            hide: false,
            follow_push: false,
        });
    }
    let relays = if command.relays.is_empty() {
        binding.relays
    } else {
        command.relays.clone()
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
            purpose: "establish".into(),
            operation_id: operation,
        }),
        hide: false,
        follow_push: false,
    })
}

async fn establish_from(
    sql: &SqlStorage,
    storage_key: [u8; 32],
    project: &str,
    operation_id: &str,
    relays: Vec<String>,
    events: Vec<Value>,
) -> std::result::Result<Value, String> {
    let Some(row) = load(sql)? else {
        return Err("account is not initialized".into());
    };
    let session = Session::open(&storage_key, project, &row.account_hex, &row.sealed)
        .map_err(|error| error.to_string())?;
    let binding = session.binding().map_err(|error| error.to_string())?;
    if binding.group_id_hex.is_some() {
        return Ok(json!({
            "ok": true,
            "operationId": operation_id,
            "groupBound": true,
            "groupIdHex": binding.group_id_hex,
            "disposition": "settled"
        }));
    }
    let mut package = None;
    for event in events {
        if let Ok(found) = Session::key_package_from_relay_event(&event, &binding.recipient_hex) {
            package = Some(found);
            break;
        }
    }
    let package = package.ok_or("recipient key package was not found")?;
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
    sql: &SqlStorage,
    storage_key: [u8; 32],
    allow_loopback: bool,
    project: &str,
    command: &Command,
) -> std::result::Result<Gate, String> {
    let Some(row) = load(sql)? else {
        return Err("account is not initialized".into());
    };
    let session = Session::open(&storage_key, project, &row.account_hex, &row.sealed)
        .map_err(|error| error.to_string())?;
    let binding = session.binding().map_err(|error| error.to_string())?;
    let relays = if command.relays.is_empty() {
        binding.relays
    } else {
        command.relays.clone()
    };
    relay::validate_relays(&relays, allow_loopback)?;
    let mut filters = Vec::new();
    if let Some(group) = binding.nostr_group_hex {
        filters.push(json!({"kinds": [445], "#h": [group], "limit": 20}));
    }
    filters.push(json!({"kinds": [1059], "#p": [session.public_key_hex()], "limit": 20}));
    Ok(Gate {
        response: json!({}),
        publish: None,
        pull: Some(Pull {
            relays,
            filters,
            purpose: "sync".into(),
            operation_id: String::new(),
        }),
        hide: false,
        follow_push: false,
    })
}

async fn ingest_pulled(
    sql: &SqlStorage,
    storage_key: [u8; 32],
    project: &str,
    events: Vec<Value>,
) -> std::result::Result<Value, String> {
    let Some(row) = load(sql)? else {
        return Err("account is not initialized".into());
    };
    let session = Session::open(&storage_key, project, &row.account_hex, &row.sealed)
        .map_err(|error| error.to_string())?;
    let mut chats = Vec::new();
    for event in events {
        match session.ingest_event(event).await {
            Ok(mut found) => chats.append(&mut found),
            Err(_) => {}
        }
    }
    let revision = advance(&session, Some(row.revision as u64))?;
    let floors = floor_map(&session)?;
    let sealed = session.seal(&storage_key, project).map_err(|error| error.to_string())?;
    let writer = writer_id()?;
    store(
        sql,
        Some(row.revision as u64),
        revision,
        &writer,
        &session.public_key_hex(),
        &floors,
        &sealed,
    )?;
    Ok(json!({"chats": chats, "ingested": chats.len()}))
}

fn open_session(
    loaded: &Option<Row>,
    storage_key: [u8; 32],
    project: &str,
    command: &Command,
) -> std::result::Result<(Session, bool), String> {
    if let Some(row) = loaded {
        let session = Session::open(&storage_key, project, &row.account_hex, &row.sealed)
            .map_err(|error| error.to_string())?;
        if let Some(secret) = command.sender_secret_hex.as_deref() {
            let imported = Session::import(parse_secret(secret)?).map_err(|error| error.to_string())?;
            if imported.public_key_hex() != session.public_key_hex() {
                return Err("sender_identity_mismatch".into());
            }
        }
        return Ok((session, false));
    }
    if command.op != "onboard" && command.op != "init" {
        return Err("account is not initialized".into());
    }
    let session = match command.sender_secret_hex.as_deref() {
        Some(secret) => Session::import(parse_secret(secret)?).map_err(|error| error.to_string())?,
        None => Session::generate().map_err(|error| error.to_string())?,
    };
    Ok((session, true))
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
        "key_package" => {
            let package = session
                .fresh_key_package()
                .await
                .map_err(|error| error.to_string())?;
            let event = session
                .signed_key_package_event(&package)
                .map_err(|error| error.to_string())?;
            Ok(json!({
                "bytesHex": hex::encode(package.bytes),
                "protocolProfile": "current",
                "pubkey": session.public_key_hex(),
                "event": event
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
            retired_outcome(session, &operation)
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
            Ok(json!({
                "ok": true,
                "account": true,
                "pubkey": session.public_key_hex(),
                "groupBound": binding.group_id_hex.is_some(),
                "recipient": binding.recipient_hex,
                "recipientTokenCount": tokens,
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
    let relays = if command.relays.is_empty() {
        session.binding().map_err(|error| error.to_string())?.relays
    } else {
        command.relays.clone()
    };
    relay::validate_relays(&relays, allow_loopback)?;
    let operation_id = body
        .get("operationId")
        .and_then(|value| value.as_str())
        .unwrap_or_default()
        .to_owned();
    let event = if command.op == "stage_push" {
        body.get("trigger").cloned().unwrap_or(Value::Null)
    } else if command.op == "key_package" {
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

async fn acknowledge(
    sql: &SqlStorage,
    storage_key: [u8; 32],
    project: &str,
    operation_id: &str,
    kind: &str,
    outcome: &str,
    event_id: &str,
    destination: &str,
) -> std::result::Result<String, String> {
    let Some(row) = load(sql)? else {
        return Err("account is not initialized".into());
    };
    let session = Session::open(&storage_key, project, &row.account_hex, &row.sealed)
        .map_err(|error| error.to_string())?;
    let phase = if kind == "push" {
        let phase = match outcome {
            "relay_accepted" => "relay_accepted",
            "rejected" => "rejected",
            _ => "unobservable",
        };
        if let Some(stored) = session
            .storage()
            .publication(operation_id)
            .map_err(|error| error.to_string())?
        {
            if let Some(bytes) = stored.push_trigger.as_deref() {
                let prepared = push_event_ids(bytes);
                if phase == "relay_accepted"
                    && !prepared.is_empty()
                    && !prepared.iter().any(|item| item == event_id)
                {
                    return Err("push acknowledgement does not match the prepared trigger".into());
                }
            }
        }
        session
            .note_push(operation_id, phase, Some(event_id.to_owned()))
            .map_err(|error| error.to_string())?;
        phase.to_owned()
    } else {
        let message_outcome = match outcome {
            "relay_accepted" => "relay_accepted",
            "rejected" => "rejected",
            _ => "completion_unknown",
        };
        let already_accepted = session
            .storage()
            .publication(operation_id)
            .map_err(|error| error.to_string())?
            .map(|stored| stored.message_phase == "relay_accepted")
            .unwrap_or(false);
        if !already_accepted {
            session
                .mark_message_publication(operation_id)
                .map_err(|error| error.to_string())?;
        }
        session
            .note_message_outcome(operation_id, message_outcome, event_id, destination, event_id)
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

fn persist_session(
    sql: &SqlStorage,
    storage_key: [u8; 32],
    project: &str,
    session: &Session,
    revision: u64,
) -> std::result::Result<(), String> {
    let next = advance(session, Some(revision))?;
    let floors = floor_map(session)?;
    let sealed = session.seal(&storage_key, project).map_err(|error| error.to_string())?;
    let writer = writer_id()?;
    store(
        sql,
        Some(revision),
        next,
        &writer,
        &session.public_key_hex(),
        &floors,
        &sealed,
    )?;
    for hook in session.take_commit_hooks() {
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(hook));
    }
    Ok(())
}

async fn prepare_push(
    sql: &SqlStorage,
    storage_key: [u8; 32],
    project: &str,
    operation_id: &str,
    allow_loopback: bool,
) -> std::result::Result<(Vec<(Value, Vec<String>)>, Option<String>), String> {
    let Some(row) = load(sql)? else {
        return Err("account is not initialized".into());
    };
    let session = Session::open(&storage_key, project, &row.account_hex, &row.sealed)
        .map_err(|error| error.to_string())?;
    let stored = session
        .storage()
        .publication(operation_id)
        .map_err(|error| error.to_string())?
        .ok_or("publication missing")?;
    if stored.message_phase != "relay_accepted" {
        return Ok((Vec::new(), Some(stored.push_phase)));
    }
    if stored.push_phase == "relay_accepted" {
        return Ok((Vec::new(), Some("relay_accepted".into())));
    }
    if let Some(bytes) = stored.push_trigger.as_deref() {
        if let Some(jobs) = stored_push_jobs(bytes) {
            return Ok((jobs, None));
        }
    }
    let binding = session.binding().map_err(|error| error.to_string())?;
    let Some(group_hex) = binding.group_id_hex else {
        session
            .note_token_wait(operation_id)
            .map_err(|error| error.to_string())?;
        persist_session(sql, storage_key, project, &session, row.revision as u64)?;
        return Ok((Vec::new(), Some("token_unavailable".into())));
    };
    let tokens = session
        .select_push_tokens(&decode_group(Some(group_hex))?)
        .map_err(|error| error.to_string())?;
    if tokens.is_empty() {
        session
            .note_token_wait(operation_id)
            .map_err(|error| error.to_string())?;
        persist_session(sql, storage_key, project, &session, row.revision as u64)?;
        return Ok((Vec::new(), Some("token_unavailable".into())));
    }
    let directories = session
        .storage()
        .server_relays()
        .map_err(|error| error.to_string())?;
    let mut order = Vec::new();
    let mut grouped: HashMap<String, Vec<Vec<u8>>> = HashMap::new();
    let mut hints: HashMap<String, Vec<String>> = HashMap::new();
    for wake in tokens {
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
            .entry(wake.server_pubkey_hex)
            .or_default()
            .push(wake.encrypted_token);
    }
    let mut jobs = Vec::new();
    let mut envelope = Vec::new();
    for server in order {
        let mut relays = hints.remove(&server).unwrap_or_default();
        if relays.is_empty() {
            if let Some(found) = directories.iter().find(|item| item.server_pubkey_hex == server && !item.negative) {
                relays = found
                    .relays
                    .iter()
                    .filter(|url| relay::validate_relay(url, allow_loopback).is_ok())
                    .cloned()
                    .collect();
            }
        }
        if relays.is_empty() {
            continue;
        }
        let tokens = grouped.remove(&server).unwrap_or_default();
        let mut offset = 0;
        while offset < tokens.len() {
            let end = (offset + 18).min(tokens.len());
            let event = notification_gift_wrap(&server, &tokens[offset..end])
                .await
                .map_err(|error| error.to_string())?;
            let event = serde_json::to_value(&event).map_err(|error| error.to_string())?;
            envelope.push(json!({"event": event, "relays": relays}));
            jobs.push((event, relays.clone()));
            offset = end;
        }
    }
    if jobs.is_empty() {
        session
            .note_push(operation_id, "unobservable", None)
            .map_err(|error| error.to_string())?;
        persist_session(sql, storage_key, project, &session, row.revision as u64)?;
        return Ok((Vec::new(), Some("unobservable".into())));
    }
    let bytes = serde_json::to_vec(&envelope).map_err(|error| error.to_string())?;
    session
        .stage_push(operation_id, &bytes)
        .map_err(|error| error.to_string())?;
    persist_session(sql, storage_key, project, &session, row.revision as u64)?;
    Ok((jobs, None))
}

fn stored_push_jobs(bytes: &[u8]) -> Option<Vec<(Value, Vec<String>)>> {
    let value: Value = serde_json::from_slice(bytes).ok()?;
    let items = value.as_array()?;
    if items.is_empty() || items.iter().any(|item| item.get("event").is_none()) {
        return None;
    }
    Some(
        items
            .iter()
            .filter_map(|item| {
                let relays = item
                    .get("relays")?
                    .as_array()?
                    .iter()
                    .filter_map(|relay| relay.as_str().map(str::to_owned))
                    .collect();
                Some((item.get("event")?.clone(), relays))
            })
            .collect(),
    )
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

fn status(sql: &SqlStorage, storage_key: [u8; 32], project: &str) -> std::result::Result<Value, String> {
    let Some(row) = load(sql)? else {
        return Ok(json!({
            "ready": false,
            "revision": null,
            "pubkey": null,
            "groups": 0,
            "databaseBytes": sql.database_size()
        }));
    };
    let session = Session::open(&storage_key, project, &row.account_hex, &row.sealed)
        .map_err(|error| error.to_string())?;
    let groups = session.storage().list_groups().map_err(|error| error.to_string())?.len();
    let binding = session.binding().map_err(|error| error.to_string())?;
    Ok(json!({
        "ready": true,
        "revision": row.revision,
        "pubkey": session.public_key_hex(),
        "groups": groups,
        "projectId": binding.project_id,
        "recipient": binding.recipient_hex,
        "databaseBytes": sql.database_size()
    }))
}

fn cas_self_test(sql: &SqlStorage) -> std::result::Result<Value, String> {
    let Some(row) = load(sql)? else {
        return Err("account is not initialized".into());
    };
    let next = row.revision + 1;
    let first = sql
        .exec(
            "UPDATE marmot_account SET revision = ?, writer = ? WHERE id = ? AND revision = ?",
            vec![
                next.into(),
                "winner".into(),
                ACCOUNT.into(),
                row.revision.into(),
            ],
        )
        .map_err(|error| error.to_string())?;
    let second = sql
        .exec(
            "UPDATE marmot_account SET revision = ?, writer = ? WHERE id = ? AND revision = ?",
            vec![
                next.into(),
                "loser".into(),
                ACCOUNT.into(),
                row.revision.into(),
            ],
        )
        .map_err(|error| error.to_string())?;
    let stored = load(sql)?.ok_or("account disappeared")?;
    Ok(json!({
        "firstRows": first.rows_written(),
        "secondRows": second.rows_written(),
        "winner": commit_won(first.rows_written(), &stored.writer, "winner"),
        "loserWon": commit_won(second.rows_written(), &stored.writer, "loser"),
        "storedRevision": stored.revision
    }))
}

fn stale_write(sql: &SqlStorage) -> std::result::Result<Value, String> {
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

fn load(sql: &SqlStorage) -> std::result::Result<Option<Row>, String> {
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
    sql: &SqlStorage,
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
