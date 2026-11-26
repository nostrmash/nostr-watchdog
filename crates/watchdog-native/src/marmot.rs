//! Client for the local official-MDK helper.
//!
//! The helper is a separate process because MDK's SQLCipher build and the
//! operational SQLite database cannot be linked into one executable. This
//! module never logs request bodies: they contain the sender secret.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Mutex;
use std::time::Duration;

use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;
use watchdog_core::catalog::{project_by_id, project_recipient};
use watchdog_core::settings::load_settings;
use watchdog_engine::DeliveryOutcome;
use watchdog_notify::recipient_pubkey;
use watchdog_store::{MarmotProjectRow, OutboxRow, SqliteStore};

pub async fn deliver(
    store: &SqliteStore,
    vars: &HashMap<String, String>,
    row: &OutboxRow,
    claim: &str,
) -> DeliveryOutcome {
    let get = |key: &str| vars.get(key).cloned().unwrap_or_default();
    let settings = load_settings(&get);
    if !store
        .extend_claim(&row.id, claim, now_ms() + settings.delivery_claim_ms)
        .unwrap_or(false)
    {
        return pending("claim_lost");
    }
    let Some(socket) = socket_path(vars) else {
        return pending("marmot_helper_unconfigured");
    };
    let Some(project) = project_by_id(&row.project_id) else {
        return failed("project_invalid");
    };
    let nsec = get(project.sender_secret);
    if nsec.is_empty() {
        return failed("sender_key_missing");
    }
    let Some(recipient_raw) =
        project_recipient(&get("PROJECT_RECIPIENTS"), &get("ADMIN_NPUB"), project.id)
    else {
        return failed("recipient_missing");
    };
    let Ok(recipient) = recipient_pubkey(&recipient_raw) else {
        return failed("recipient_invalid");
    };
    if ensure_helper(vars, &socket).await.is_err() {
        return pending("marmot_helper_unavailable");
    }
    let relays = settings.bootstrap.clone();
    let imported = match call(
        &socket,
        json!({"op": "import", "nsec": nsec, "relays": relays}),
        Duration::from_secs(60),
    )
    .await
    {
        Ok(value) => value,
        Err(error) => return pending(&error),
    };
    if imported.get("ok") != Some(&Value::Bool(true)) {
        return outcome_from_error(&imported, false);
    }
    let Some(account) = imported.get("account").and_then(Value::as_str) else {
        return pending("marmot_account_missing");
    };
    let existing = store
        .marmot_project(&row.project_id)
        .ok()
        .flatten()
        .and_then(|row| row.group_id_hex);
    let group = if let Some(group) = existing.filter(|group| !group.is_empty()) {
        group
    } else {
        let created = match call(
            &socket,
            json!({
                "op": "create_group",
                "account": account,
                "name": format!("watchdog-{}", project.id),
                "members": [recipient_raw]
            }),
            Duration::from_secs(90),
        )
        .await
        {
            Ok(value) => value,
            Err(error) => return pending(&error),
        };
        if created.get("ok") != Some(&Value::Bool(true)) {
            remember(store, row, account, None, error_code(&created));
            return outcome_from_error(&created, true);
        }
        let Some(group) = created
            .get("group")
            .and_then(Value::as_str)
            .map(str::to_string)
        else {
            return pending("marmot_group_missing");
        };
        remember(store, row, account, Some(&group), None);
        group
    };
    let sent = match call(
        &socket,
        json!({
            "op": "send",
            "alert": row.id,
            "account": account,
            "group": group,
            "text": row.payload_text,
            "allow": [recipient]
        }),
        Duration::from_secs(90),
    )
    .await
    {
        Ok(value) => value,
        Err(error) => return pending(&error),
    };
    if sent.get("ok") != Some(&Value::Bool(true)) {
        remember(store, row, account, Some(&group), error_code(&sent));
        return outcome_from_error(&sent, true);
    }
    let disposition = sent
        .get("disposition")
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    let push = sent
        .get("push")
        .and_then(Value::as_str)
        .unwrap_or("not_attempted");
    let message_id = sent
        .get("message_ids")
        .and_then(Value::as_array)
        .and_then(|ids| ids.first())
        .and_then(Value::as_str)
        .map(str::to_string);
    remember(store, row, account, Some(&group), None);
    match disposition {
        "published" => DeliveryOutcome {
            accepted: true,
            terminal: false,
            error: None,
            accepted_relays: Vec::new(),
            failed_relays: Vec::new(),
            message_phase: Some("relay_accepted".to_string()),
            push_phase: Some(push.to_string()),
            message_event_id: message_id,
            push_envelope: None,
        },
        "accepted_pending" => pending_phase("marmot_publish_pending", "accepted_pending", push),
        _ => pending_phase("marmot_completion_unknown", "completion_unknown", push),
    }
}

pub async fn sync(vars: &HashMap<String, String>) -> Result<(), String> {
    let Some(socket) = socket_path(vars) else {
        return Ok(());
    };
    if UnixStream::connect(&socket).await.is_err() {
        return Err("marmot_helper_unavailable".to_string());
    }
    let value = call(&socket, json!({"op": "sync"}), Duration::from_secs(60)).await?;
    if value.get("ok") == Some(&Value::Bool(true)) {
        Ok(())
    } else {
        Err(error_code(&value)
            .unwrap_or("marmot_sync_failed")
            .to_string())
    }
}

fn socket_path(vars: &HashMap<String, String>) -> Option<PathBuf> {
    if let Some(path) = vars.get("MARMOT_SOCKET").filter(|path| !path.is_empty()) {
        return Some(PathBuf::from(path));
    }
    vars.get("MARMOT_ROOT")
        .filter(|path| !path.is_empty())
        .map(|root| PathBuf::from(root).join("watchdog.sock"))
}

async fn ensure_helper(vars: &HashMap<String, String>, socket: &Path) -> Result<(), String> {
    if socket.exists() {
        return Ok(());
    }
    spawn_helper(vars, socket)?;
    for _ in 0..50 {
        if socket.exists() {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    Err("marmot_helper_unavailable".to_string())
}

fn spawn_helper(vars: &HashMap<String, String>, socket: &Path) -> Result<(), String> {
    let Some(binary) = vars.get("MARMOT_HELPER").filter(|path| !path.is_empty()) else {
        return Err("marmot_helper_unavailable".to_string());
    };
    let Some(root) = vars.get("MARMOT_ROOT").filter(|path| !path.is_empty()) else {
        return Err("marmot_root_missing".to_string());
    };
    static CHILD: Mutex<Option<std::process::Child>> = Mutex::new(None);
    let mut guard = CHILD
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if guard.is_some() {
        return Ok(());
    }
    let mut command = Command::new(binary);
    command
        .arg("--root")
        .arg(root)
        .arg("--socket")
        .arg(socket)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    for relay in vars
        .get("BOOTSTRAP_RELAYS")
        .map(String::as_str)
        .unwrap_or("")
        .split(',')
    {
        let relay = relay.trim();
        if !relay.is_empty() {
            command.arg("--relay").arg(relay);
        }
    }
    let child = command.spawn().map_err(|_| "marmot_helper_spawn_failed")?;
    *guard = Some(child);
    Ok(())
}

async fn call(socket: &Path, request: Value, timeout: Duration) -> Result<Value, String> {
    let request = serde_json::to_vec(&request).map_err(|_| "marmot_request_invalid".to_string())?;
    tokio::time::timeout(timeout, async {
        let mut stream = UnixStream::connect(socket)
            .await
            .map_err(|_| "marmot_helper_unavailable".to_string())?;
        stream
            .write_all(&request)
            .await
            .map_err(|_| "marmot_helper_unavailable".to_string())?;
        stream
            .write_all(b"\n")
            .await
            .map_err(|_| "marmot_helper_unavailable".to_string())?;
        let mut lines = BufReader::new(stream).lines();
        let line = lines
            .next_line()
            .await
            .map_err(|_| "marmot_response_invalid".to_string())?
            .ok_or_else(|| "marmot_response_invalid".to_string())?;
        serde_json::from_str(&line).map_err(|_| "marmot_response_invalid".to_string())
    })
    .await
    .map_err(|_| "marmot_timeout".to_string())?
}

fn remember(
    store: &SqliteStore,
    row: &OutboxRow,
    account: &str,
    group: Option<&str>,
    error: Option<&str>,
) {
    let _ = store.upsert_marmot_project(
        &MarmotProjectRow {
            project_id: row.project_id.clone(),
            pubkey: Some(account.to_string()),
            conversation_id: group.map(str::to_string),
            group_id_hex: group.map(str::to_string),
            peer_pubkey: None,
            last_sync_at: None,
            last_sync_error: error.map(str::to_string),
            key_package_published_at: None,
            engine_status: "mdk_helper".to_string(),
        },
        now_ms(),
    );
}

fn outcome_from_error(value: &Value, membership_is_terminal: bool) -> DeliveryOutcome {
    let code = error_code(value).unwrap_or("marmot_helper_error");
    if membership_is_terminal
        && matches!(
            code,
            "membership_rejected" | "membership_unknown" | "no_eligible_member"
        )
    {
        failed(code)
    } else {
        pending(code)
    }
}

fn error_code(value: &Value) -> Option<&str> {
    value.get("error").and_then(Value::as_str)
}

fn pending(error: &str) -> DeliveryOutcome {
    pending_phase(error, "not_published", "not_attempted")
}

fn pending_phase(error: &str, message: &str, push: &str) -> DeliveryOutcome {
    DeliveryOutcome {
        accepted: false,
        terminal: false,
        error: Some(error.to_string()),
        accepted_relays: Vec::new(),
        failed_relays: Vec::new(),
        message_phase: Some(message.to_string()),
        push_phase: Some(push.to_string()),
        message_event_id: None,
        push_envelope: None,
    }
}

fn failed(error: &str) -> DeliveryOutcome {
    DeliveryOutcome {
        accepted: false,
        terminal: true,
        error: Some(error.to_string()),
        accepted_relays: Vec::new(),
        failed_relays: Vec::new(),
        message_phase: Some("not_published".to_string()),
        push_phase: Some("not_attempted".to_string()),
        message_event_id: None,
        push_envelope: None,
    }
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_millis() as i64)
        .unwrap_or(0)
}
