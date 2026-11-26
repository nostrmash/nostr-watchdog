use std::collections::HashMap;

use marmot_worker_runtime::Session;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use worker::*;

const ACCOUNT: &str = "self";

#[durable_object]
pub struct MarmotSender {
    sql: SqlStorage,
    storage_key: [u8; 32],
    operator_token: String,
    allow_loopback: bool,
}

#[derive(Deserialize)]
struct Command {
    op: String,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    alert_id: Option<String>,
    #[serde(default)]
    operation_id: Option<String>,
    #[serde(default)]
    group_id_hex: Option<String>,
    #[serde(default)]
    text: Option<String>,
    #[serde(default)]
    members: Vec<MemberPackage>,
    #[serde(default)]
    message: Option<Value>,
    #[serde(default)]
    welcome: Option<Value>,
}

#[derive(Deserialize)]
struct MemberPackage {
    bytes_hex: String,
    #[serde(default)]
    protocol_profile: Option<String>,
}

#[derive(Serialize)]
struct Status {
    ready: bool,
    revision: u64,
    pubkey: Option<String>,
    groups: usize,
    epoch_floor: u64,
}

impl DurableObject for MarmotSender {
    fn new(state: State, env: Env) -> Self {
        let sql = state.storage().sql();
        sql.exec(
            "CREATE TABLE IF NOT EXISTS marmot_account (
                id TEXT PRIMARY KEY,
                revision INTEGER NOT NULL,
                floors TEXT NOT NULL,
                sealed BLOB NOT NULL
            )",
            None,
        )
        .expect("create marmot_account");
        let storage_key = match env.secret("MARMOT_STORAGE_KEY") {
            Ok(secret) => parse_key(&secret.to_string()).unwrap_or([0u8; 32]),
            Err(_) => [0u8; 32],
        };
        let operator_token = env
            .secret("MARMOT_OPERATOR_TOKEN")
            .map(|secret| secret.to_string())
            .unwrap_or_default();
        let allow_loopback = env
            .var("MARMOT_ALLOW_LOOPBACK")
            .map(|value| value.to_string() == "1")
            .unwrap_or(false);
        Self {
            sql,
            storage_key,
            operator_token,
            allow_loopback,
        }
    }

    async fn fetch(&self, mut req: Request) -> Result<Response> {
        if !self.allow_loopback && req.url()?.scheme() == "http" && !is_loopback_host(&req.url()?) {
            // Local workerd uses http. Production must present the operator token
            // even when the platform terminates TLS in front of the object.
        }
        if !authorized(req.headers().get("authorization")?, &self.operator_token) {
            return Response::error("unauthorized", 401);
        }
        if self.storage_key == [0u8; 32] || self.operator_token.is_empty() {
            return Response::error("marmot secrets are not configured", 503);
        }
        let command: Command = req.json().await?;
        let sql = self.sql.clone();
        let storage_key = self.storage_key;
        let outcome = state_gate_unavailable();
        let _ = outcome;
        let result = run_command(&sql, &storage_key, command).await;
        match result {
            Ok(body) => Response::from_json(&body),
            Err(error) => Response::error(error, 400),
        }
    }
}

fn state_gate_unavailable() -> bool {
    // `DurableObject::fetch` already runs under the object's input gate until
    // the first outbound I/O. This handler performs no relay I/O. Publication
    // is returned to the caller, which publishes after this response is durable.
    true
}

async fn run_command(
    sql: &SqlStorage,
    storage_key: &[u8; 32],
    command: Command,
) -> std::result::Result<Value, String> {
    if command.op == "status" {
        return status(sql, storage_key);
    }
    let (revision, floors, sealed) = load(sql)?;
    let session = if sealed.is_empty() {
        if command.op != "init" {
            return Err("account is not initialized".into());
        }
        Session::generate().map_err(|error| error.to_string())?
    } else {
        Session::open(storage_key, &sealed).map_err(|error| error.to_string())?
    };
    let before = revision;
    let mut floors = floors;
    let body = match command.op.as_str() {
        "init" => {
            if !sealed.is_empty() {
                serde_json::json!({ "ready": true, "pubkey": session.public_key_hex() })
            } else {
                serde_json::json!({ "ready": true, "pubkey": session.public_key_hex(), "created": true })
            }
        }
        "key_package" => {
            let package = session.fresh_key_package().await.map_err(|error| error.to_string())?;
            serde_json::json!({
                "bytes_hex": hex::encode(package.bytes),
                "protocol_profile": format!("{:?}", package.protocol_profile).to_ascii_lowercase(),
                "pubkey": session.public_key_hex()
            })
        }
        "create_group" => {
            let members = decode_members(&command.members)?;
            let name = command.name.unwrap_or_else(|| "watchdog".into());
            let (group_id, welcomes) = session
                .create_group(&name, members, vec!["wss://relay.example".into()])
                .await
                .map_err(|error| error.to_string())?;
            serde_json::json!({
                "group_id_hex": hex::encode(group_id.as_slice()),
                "welcomes": welcomes
            })
        }
        "join_welcome" => {
            let welcome = decode_message(command.welcome)?;
            session.join_welcome(welcome).await.map_err(|error| error.to_string())?;
            serde_json::json!({ "joined": true })
        }
        "ingest" => {
            let message = decode_message(command.message)?;
            let chats = session.ingest(message).await.map_err(|error| error.to_string())?;
            serde_json::json!({ "chats": chats })
        }
        "send" => {
            let alert_id = command.alert_id.ok_or("alert_id is required")?;
            let group_id = decode_group(&command.group_id_hex)?;
            let text = command.text.unwrap_or_default();
            let message = session
                .send_chat(&alert_id, &group_id, &text)
                .await
                .map_err(|error| error.to_string())?;
            serde_json::json!({
                "alert_id": alert_id,
                "message": message,
                "confirmed": true
            })
        }
        "self_update" => {
            let operation_id = command.operation_id.ok_or("operation_id is required")?;
            let group_id = decode_group(&command.group_id_hex)?;
            let (message, pending) = session
                .self_update(&operation_id, &group_id)
                .await
                .map_err(|error| error.to_string())?;
            serde_json::json!({
                "operation_id": operation_id,
                "pending": pending,
                "message": message,
                "confirmed": false
            })
        }
        "confirm" => {
            let operation_id = command.operation_id.ok_or("operation_id is required")?;
            session.confirm(&operation_id).await.map_err(|error| error.to_string())?;
            serde_json::json!({ "operation_id": operation_id, "confirmed": true })
        }
        other => return Err(format!("unknown operation {other}")),
    };
    remember_floors(&session, &mut floors)?;
    let next = session.seal(storage_key).map_err(|error| error.to_string())?;
    let revision = session.revision().map_err(|error| error.to_string())?;
    store(sql, before, revision, &floors, &next)?;
    Ok(body)
}

fn status(sql: &SqlStorage, storage_key: &[u8; 32]) -> std::result::Result<Value, String> {
    let (revision, floors, sealed) = load(sql)?;
    if sealed.is_empty() {
        return Ok(serde_json::json!(Status {
            ready: false,
            revision,
            pubkey: None,
            groups: 0,
            epoch_floor: 0
        }));
    }
    let session = Session::open(storage_key, &sealed).map_err(|error| error.to_string())?;
    let groups = session
        .storage()
        .list_groups()
        .map_err(|error| error.to_string())?
        .len();
    Ok(serde_json::json!(Status {
        ready: true,
        revision,
        pubkey: Some(session.public_key_hex()),
        groups,
        epoch_floor: floors.values().copied().max().unwrap_or(0)
    }))
}

fn remember_floors(
    session: &Session,
    floors: &mut HashMap<String, u64>,
) -> std::result::Result<(), String> {
    use cgka_traits::storage::GroupStorage;
    for group_id in session.storage().list_groups().map_err(|error| error.to_string())? {
        let epoch = session
            .storage()
            .get_group(&group_id)
            .map_err(|error| error.to_string())?
            .epoch
            .0;
        let key = hex::encode(group_id.as_slice());
        if let Some(previous) = floors.get(&key) {
            if epoch < *previous {
                return Err("refusing to persist an earlier MLS epoch".into());
            }
        }
        floors.insert(key, epoch);
    }
    Ok(())
}

fn load(sql: &SqlStorage) -> std::result::Result<(u64, HashMap<String, u64>, Vec<u8>), String> {
    let rows = sql
        .exec(
            "SELECT revision, floors, sealed FROM marmot_account WHERE id = ?",
            vec![ACCOUNT.into()],
        )
        .map_err(|error| error.to_string())?
        .to_array::<Row>()
        .map_err(|error| error.to_string())?;
    let Some(row) = rows.into_iter().next() else {
        return Ok((0, HashMap::new(), Vec::new()));
    };
    let floors = serde_json::from_str(&row.floors).unwrap_or_default();
    Ok((row.revision as u64, floors, row.sealed))
}

fn store(
    sql: &SqlStorage,
    expected: u64,
    revision: u64,
    floors: &HashMap<String, u64>,
    sealed: &[u8],
) -> std::result::Result<(), String> {
    if sealed.len() > 1_500_000 {
        return Err("sealed account exceeds the Durable Object value limit".into());
    }
    let floors_json = serde_json::to_string(floors).map_err(|error| error.to_string())?;
    if expected == 0 {
        sql.exec(
            "INSERT INTO marmot_account (id, revision, floors, sealed) VALUES (?, ?, ?, ?)",
            vec![
                ACCOUNT.into(),
                (revision as i64).into(),
                floors_json.into(),
                sealed.to_vec().into(),
            ],
        )
        .map_err(|error| error.to_string())?;
        return Ok(());
    }
    sql.exec(
        "UPDATE marmot_account SET revision = ?, floors = ?, sealed = ? WHERE id = ? AND revision = ?",
        vec![
            (revision as i64).into(),
            floors_json.into(),
            sealed.to_vec().into(),
            ACCOUNT.into(),
            (expected as i64).into(),
        ],
    )
    .map_err(|error| error.to_string())?;
    let (stored, _, _) = load(sql)?;
    if stored != revision {
        return Err("durable revision conflict".into());
    }
    Ok(())
}

fn decode_members(members: &[MemberPackage]) -> std::result::Result<Vec<cgka_traits::KeyPackage>, String> {
    members
        .iter()
        .map(|member| {
            let bytes = hex::decode(&member.bytes_hex).map_err(|_| "member key package is not hex".to_owned())?;
            let mut package = cgka_traits::KeyPackage::new(bytes);
            if member.protocol_profile.as_deref() == Some("current") {
                package = package.with_protocol_profile(cgka_traits::group::ProtocolProfile::Current);
            }
            Ok(package)
        })
        .collect()
}

fn decode_group(value: &Option<String>) -> std::result::Result<cgka_traits::GroupId, String> {
    let hex_id = value.as_deref().ok_or("group_id_hex is required")?;
    let bytes = hex::decode(hex_id).map_err(|_| "group id is not hex".to_owned())?;
    Ok(cgka_traits::GroupId::new(bytes))
}

fn decode_message(value: Option<Value>) -> std::result::Result<cgka_traits::TransportMessage, String> {
    serde_json::from_value(value.ok_or("transport message is required")?)
        .map_err(|error| error.to_string())
}

fn parse_key(value: &str) -> Option<[u8; 32]> {
    let bytes = hex::decode(value.trim()).ok()?;
    bytes.try_into().ok()
}

fn authorized(header: Option<String>, token: &str) -> bool {
    let Some(header) = header else {
        return false;
    };
    let Some(presented) = header.strip_prefix("Bearer ") else {
        return false;
    };
    if presented.len() != token.len() {
        return false;
    }
    presented
        .bytes()
        .zip(token.bytes())
        .fold(0u8, |diff, (left, right)| diff | (left ^ right))
        == 0
}

fn is_loopback_host(url: &url::Url) -> bool {
    matches!(url.host_str(), Some("127.0.0.1") | Some("localhost"))
}

#[derive(Deserialize)]
struct Row {
    revision: i64,
    floors: String,
    sealed: Vec<u8>,
}

#[event(fetch)]
async fn main(req: Request, env: Env, _ctx: Context) -> Result<Response> {
    let url = req.url()?;
    if url.path() != "/marmot" {
        return Response::error("not found", 404);
    }
    let sender = url
        .query_pairs()
        .find(|(key, _)| key == "sender")
        .map(|(_, value)| value.to_string())
        .unwrap_or_else(|| "default".into());
    if sender.len() > 128 || sender.chars().any(|ch| !(ch.is_ascii_alphanumeric() || ch == '-' || ch == '_')) {
        return Response::error("sender name is invalid", 400);
    }
    let namespace = env.durable_object("MARMOT_SENDER")?;
    let stub = namespace.id_from_name(&sender)?.get_stub()?;
    stub.fetch_with_request(req).await
}
