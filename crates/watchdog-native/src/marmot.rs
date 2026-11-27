//! Client for the local official-MDK helper.
//!
//! The helper is a separate process because MDK's SQLCipher build and the
//! operational SQLite database cannot be linked into one executable. This
//! module never logs request bodies: they contain the sender secret.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use serde_json::{json, Value};
use tokio::io::AsyncWriteExt;
use tokio::net::UnixStream;
use watchdog_core::catalog::{project_by_id, project_recipient};
use watchdog_core::settings::load_settings;
use watchdog_engine::DeliveryOutcome;
use watchdog_notify::{public_key_hex, recipient_pubkey};
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
        .extend_claim(
            &row.id,
            claim,
            now_ms() + settings.delivery_claim_ms,
            now_ms(),
        )
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
    let known = store.marmot_project(&row.project_id).ok().flatten();
    let expected_sender = if nsec.is_empty() {
        None
    } else {
        match public_key_hex(&nsec) {
            Ok(account) => Some(account),
            Err(_) => return failed("sender_key_invalid"),
        }
    };
    let cached_sender = known.as_ref().and_then(|item| item.pubkey.as_deref());
    let cached_group = known.as_ref().and_then(|item| item.group_id_hex.clone());
    let setup = onboard_request(&get, project.id, cached_sender.is_none());
    let (account, group) = if let Some(setup) = setup {
        if !owns_claim(store, row, claim, &settings) {
            return pending("claim_lost");
        }
        if nsec.is_empty() {
            return failed("sender_key_missing");
        }
        match renew_until(
            store,
            row,
            claim,
            settings.delivery_claim_ms,
            ensure_onboard(&socket, &nsec, &settings.bootstrap, &recipient, &setup),
        )
        .await
        {
            Ok((account, group)) => {
                if let Some(expected) = &expected_sender {
                    if !account.eq_ignore_ascii_case(expected) {
                        return failed("sender_identity_mismatch");
                    }
                }
                remember(store, row, &account, &recipient, Some(&group), None);
                (account, group)
            }
            Err(error) => return error,
        }
    } else {
        let account = cached_sender.unwrap_or_default().to_string();
        let identity = match renew_until(
            store,
            row,
            claim,
            settings.delivery_claim_ms,
            call(
                &socket,
                json!({
                    "op": "identity",
                    "account": account,
                    "recipient": recipient,
                    "group": cached_group.clone().unwrap_or_default()
                }),
                Duration::from_secs(30),
            ),
        )
        .await
        {
            Ok(value) => value,
            Err(error) => return pending(&error),
        };
        if identity.get("ok") != Some(&Value::Bool(true)) {
            return outcome_from_error(&identity, true);
        }
        if let Some(error) = identity_error(identity.get("step").and_then(Value::as_str)) {
            return failed(error);
        }
        let group = if let Some(group) = cached_group.filter(|group| !group.is_empty()) {
            group
        } else {
            if !owns_claim(store, row, claim, &settings) {
                return pending("claim_lost");
            }
            let created = match renew_until(
                store,
                row,
                claim,
                settings.delivery_claim_ms,
                call(
                    &socket,
                    json!({
                        "op": "create_group",
                        "account": account,
                        "name": format!("watchdog-{}", project.id),
                        "members": [recipient]
                    }),
                    Duration::from_secs(90),
                ),
            )
            .await
            {
                Ok(value) => value,
                Err(error) => return pending(&error),
            };
            if created.get("ok") != Some(&Value::Bool(true)) {
                remember(store, row, &account, &recipient, None, error_code(&created));
                return outcome_from_error(&created, true);
            }
            let Some(group) = created
                .get("group")
                .and_then(Value::as_str)
                .map(str::to_string)
            else {
                return pending("marmot_group_missing");
            };
            remember(store, row, &account, &recipient, Some(&group), None);
            group
        };
        (account, group)
    };
    if !owns_claim(store, row, claim, &settings) {
        return pending("claim_lost");
    }
    let sent = match renew_until(
        store,
        row,
        claim,
        settings.delivery_claim_ms,
        call(
            &socket,
            json!({
                "op": "send",
                "alert": row.id,
                "project": row.project_id,
                "account": account,
                "group": group,
                "text": row.payload_text,
                "allow": [recipient]
            }),
            Duration::from_secs(90),
        ),
    )
    .await
    {
        Ok(value) => value,
        Err(error) => return pending_phase(&error, "completion_unknown", "not_attempted"),
    };
    if sent.get("ok") != Some(&Value::Bool(true)) {
        remember(
            store,
            row,
            &account,
            &recipient,
            Some(&group),
            error_code(&sent),
        );
        return outcome_from_error(&sent, true);
    }
    let message_id = sent
        .get("message_ids")
        .and_then(Value::as_array)
        .and_then(|ids| ids.first())
        .and_then(Value::as_str)
        .map(str::to_string);
    remember(store, row, &account, &recipient, Some(&group), None);
    outcome_from_send(&sent, message_id)
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
    let _startup = startup_gate().lock().await;
    reap_helper();
    if ping_health(vars).await.is_ok() {
        return Ok(());
    }
    // A live process that does not answer is busy or still starting. Killing
    // it would interrupt an MDK mutation. The socket is removed only when this
    // parent can see that no helper holds the root lock.
    let socket_accepts = UnixStream::connect(socket).await.is_ok();
    if child_running() || !may_unlink_socket(helper_lock_free(vars), socket_accepts) {
        return Err("marmot_helper_busy".to_string());
    }
    if socket.exists() {
        let _ = std::fs::remove_file(socket);
    }
    if let Some(health) = health_socket(vars) {
        if health.exists() {
            let _ = std::fs::remove_file(&health);
        }
    }
    spawn_helper(vars, socket)?;
    let mut delay = Duration::from_millis(100);
    for _ in 0..8 {
        if ping_health(vars).await.is_ok() {
            return Ok(());
        }
        if !child_running() {
            return Err("marmot_helper_unavailable".to_string());
        }
        tokio::time::sleep(delay).await;
        delay = (delay * 2).min(Duration::from_secs(2));
    }
    Err("marmot_helper_busy".to_string())
}

fn health_socket(vars: &HashMap<String, String>) -> Option<PathBuf> {
    vars.get("MARMOT_ROOT")
        .filter(|path| !path.is_empty())
        .map(|root| PathBuf::from(root).join("health.sock"))
}

async fn ping_health(vars: &HashMap<String, String>) -> Result<(), String> {
    let Some(socket) = health_socket(vars) else {
        return Err("marmot_helper_unavailable".to_string());
    };
    let value: Value = tokio::time::timeout(Duration::from_secs(1), async {
        let mut stream = UnixStream::connect(socket)
            .await
            .map_err(|_| "marmot_helper_unavailable")?;
        // The health socket greets the client and closes without reading a request.
        let line = read_bounded_line(&mut stream, 1024)
            .await
            .map_err(|_| "marmot_helper_unavailable")?;
        serde_json::from_str(&line).map_err(|_| "marmot_helper_unavailable")
    })
    .await
    .map_err(|_| "marmot_helper_unavailable")??;
    if value["ok"] == true && value["pong"] == true {
        Ok(())
    } else {
        Err("marmot_helper_unavailable".to_string())
    }
}

fn child_running() -> bool {
    let mut guard = helper_child()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let Some(child) = guard.as_mut() else {
        return false;
    };
    match child.try_wait() {
        Ok(None) => true,
        _ => {
            *guard = None;
            false
        }
    }
}

/// Ask the helper to leave, then force it only after a short wait.
pub fn shutdown_helper() {
    let mut guard = helper_child()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let Some(mut child) = guard.take() else {
        return;
    };
    signal_term(child.id());
    let started = std::time::Instant::now();
    loop {
        if child.try_wait().ok().flatten().is_some() {
            return;
        }
        if started.elapsed() > Duration::from_secs(5) {
            let _ = child.kill();
            let _ = child.wait();
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn signal_term(pid: u32) {
    #[cfg(unix)]
    unsafe {
        extern "C" {
            fn kill(pid: i32, sig: i32) -> i32;
        }
        const SIGTERM: i32 = 15;
        let _ = kill(pid as i32, SIGTERM);
    }
    #[cfg(not(unix))]
    {
        let _ = pid;
    }
}

fn helper_child() -> &'static Mutex<Option<std::process::Child>> {
    static CHILD: Mutex<Option<std::process::Child>> = Mutex::new(None);
    &CHILD
}

fn reap_helper() {
    let mut guard = helper_child()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if let Some(child) = guard.as_mut() {
        if child.try_wait().ok().flatten().is_some() {
            *guard = None;
        }
    }
}

fn spawn_helper(vars: &HashMap<String, String>, socket: &Path) -> Result<(), String> {
    let Some(binary) = vars.get("MARMOT_HELPER").filter(|path| !path.is_empty()) else {
        return Err("marmot_helper_unavailable".to_string());
    };
    let Some(root) = vars.get("MARMOT_ROOT").filter(|path| !path.is_empty()) else {
        return Err("marmot_root_missing".to_string());
    };
    let mut guard = helper_child()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if let Some(child) = guard.as_mut() {
        if child.try_wait().ok().flatten().is_none() {
            return Ok(());
        }
    }
    let mut command = Command::new(binary);
    command
        .env_clear()
        .env(
            "PATH",
            std::env::var("PATH").unwrap_or_else(|_| "/usr/bin:/bin".to_string()),
        )
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
        let line = read_bounded_line(&mut stream, 65_536)
            .await
            .map_err(|_| "marmot_response_invalid".to_string())?;
        serde_json::from_str(&line).map_err(|_| "marmot_response_invalid".to_string())
    })
    .await
    .map_err(|_| "marmot_timeout".to_string())?
}

fn remember(
    store: &SqliteStore,
    row: &OutboxRow,
    account: &str,
    recipient: &str,
    group: Option<&str>,
    error: Option<&str>,
) {
    let _ = store.upsert_marmot_project(
        &MarmotProjectRow {
            project_id: row.project_id.clone(),
            pubkey: Some(account.to_string()),
            conversation_id: group.map(str::to_string),
            group_id_hex: group.map(str::to_string),
            peer_pubkey: Some(recipient.to_string()),
            last_sync_at: None,
            last_sync_error: error.map(str::to_string),
            key_package_published_at: None,
            engine_status: "mdk_helper".to_string(),
        },
        now_ms(),
    );
}

struct OnboardRequest {
    operation_id: String,
    replace: bool,
}

fn onboard_request(
    get: &impl Fn(&str) -> String,
    project_id: &str,
    uncached: bool,
) -> Option<OnboardRequest> {
    if let Some(operation_id) = nonempty(&get("MARMOT_ONBOARD_OPERATION")) {
        return Some(OnboardRequest {
            operation_id,
            replace: get("MARMOT_ONBOARD_REPLACE") == "true"
                || get("MARMOT_REONBOARD") == project_id,
        });
    }
    if get("MARMOT_REONBOARD") == project_id {
        return Some(OnboardRequest {
            operation_id: format!("reonboard:{project_id}"),
            replace: true,
        });
    }
    if uncached {
        return Some(OnboardRequest {
            operation_id: format!("initial:{project_id}"),
            replace: false,
        });
    }
    None
}

fn nonempty(value: &str) -> Option<String> {
    let value = value.trim();
    if value.is_empty() {
        None
    } else {
        Some(value.to_string())
    }
}

async fn ensure_onboard(
    socket: &Path,
    nsec: &str,
    relays: &[String],
    recipient: &str,
    setup: &OnboardRequest,
) -> Result<(String, String), DeliveryOutcome> {
    let expected = public_key_hex(nsec).map_err(|_| failed("sender_key_invalid"))?;
    let status = call(
        socket,
        json!({"op": "onboard_status", "operation_id": setup.operation_id}),
        Duration::from_secs(15),
    )
    .await
    .map_err(|error| pending(&error))?;
    if status.get("ok") != Some(&Value::Bool(true)) {
        return Err(outcome_from_error(&status, false));
    }
    if status["operation_id"].as_str() != Some(setup.operation_id.as_str()) {
        return Err(failed("operation_identity_mismatch"));
    }
    let established = status.get("phase").and_then(Value::as_str) == Some("established")
        && status.get("recipient").and_then(Value::as_str) == Some(recipient)
        && status.get("replace").and_then(Value::as_bool) == Some(setup.replace);
    if established {
        let account = status
            .get("account")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let group = status
            .get("group")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        if account != expected {
            return Err(failed("sender_identity_mismatch"));
        }
        if account.is_empty() || group.is_empty() {
            return Err(pending("marmot_group_missing"));
        }
        return Ok((account, group));
    }
    let created = call(
        socket,
        json!({
            "op": "onboard",
            "operation_id": setup.operation_id,
            "nsec": nsec,
            "relays": relays,
            "recipient": recipient,
            "replace": setup.replace
        }),
        Duration::from_secs(90),
    )
    .await
    .map_err(|error| pending(&error))?;
    if created.get("ok") != Some(&Value::Bool(true)) {
        return Err(outcome_from_error(&created, true));
    }
    if created["operation_id"].as_str() != Some(setup.operation_id.as_str())
        || created["recipient"].as_str() != Some(recipient)
        || created["replace"].as_bool() != Some(setup.replace)
        || created["account"].as_str() != Some(expected.as_str())
    {
        return Err(failed("operation_identity_mismatch"));
    }
    let account = created
        .get("account")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let group = created
        .get("group")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    if account.is_empty() || group.is_empty() {
        return Err(pending("marmot_group_missing"));
    }
    Ok((account, group))
}

fn identity_error(step: Option<&str>) -> Option<&'static str> {
    match step {
        Some("use_cached") => None,
        Some("sender_identity_mismatch") => Some("sender_identity_mismatch"),
        Some("recipient_identity_mismatch") => Some("recipient_identity_mismatch"),
        Some("recipient_identity_unbound") => Some("recipient_identity_unbound"),
        Some("mdk_storage_missing") => Some("mdk_storage_missing"),
        Some("device_identity_invalid") => Some("device_identity_invalid"),
        Some("mdk_storage_replaced") => Some("mdk_storage_replaced"),
        Some("conversation_unavailable") => Some("conversation_unavailable"),
        Some("import") => Some("sender_identity_mismatch"),
        _ => Some("marmot_identity_invalid"),
    }
}

/// Extends a live claim while `work` is still running. An expired claim is not
/// given a new token. The in-flight helper call is allowed to finish.
async fn renew_until<T>(
    store: &SqliteStore,
    row: &OutboxRow,
    claim: &str,
    claim_ms: i64,
    work: impl std::future::Future<Output = T>,
) -> T {
    let interval = (claim_ms / 3).clamp(5_000, 60_000) as u64;
    tokio::pin!(work);
    loop {
        tokio::select! {
            biased;
            result = &mut work => return result,
            _ = tokio::time::sleep(Duration::from_millis(interval)) => {
                let renewed = store
                    .extend_claim(&row.id, claim, now_ms() + claim_ms, now_ms())
                    .unwrap_or(false);
                if !renewed {
                    return work.await;
                }
            }
        }
    }
}

fn owns_claim(
    store: &SqliteStore,
    row: &OutboxRow,
    claim: &str,
    settings: &watchdog_core::settings::Settings,
) -> bool {
    store
        .extend_claim(
            &row.id,
            claim,
            now_ms() + settings.delivery_claim_ms,
            now_ms(),
        )
        .unwrap_or(false)
}

fn outcome_from_send(sent: &Value, message_id: Option<String>) -> DeliveryOutcome {
    let message = sent
        .get("message_phase")
        .and_then(Value::as_str)
        .unwrap_or("completion_unknown");
    let push = sent
        .get("push")
        .and_then(Value::as_str)
        .unwrap_or("not_attempted");
    let hold = sent.get("hold").and_then(Value::as_bool).unwrap_or(false);
    let preserve = sent
        .get("preserve_message")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let terminal = sent
        .get("terminal")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let detail = sent.get("status_detail").and_then(Value::as_str);
    let accepted = message == "relay_accepted" && preserve && !hold;
    let error = if accepted {
        None
    } else if detail == Some("refused_new_members") {
        Some("membership_rejected".to_string())
    } else if message == "rejected" {
        Some("marmot_send_rejected".to_string())
    } else if hold {
        Some(hold_error(message, push).to_string())
    } else if message == "accepted_pending" {
        Some("marmot_publish_unconfirmed".to_string())
    } else if message == "completion_unknown" {
        Some("marmot_completion_unknown".to_string())
    } else {
        sent.get("push_error")
            .and_then(Value::as_str)
            .map(str::to_string)
    };
    DeliveryOutcome {
        accepted,
        terminal: terminal && !accepted,
        hold_attempt: hold,
        error,
        accepted_relays: Vec::new(),
        failed_relays: Vec::new(),
        message_phase: Some(if preserve || message != "not_published" {
            message.to_string()
        } else {
            "not_published".to_string()
        }),
        push_phase: Some(push.to_string()),
        message_event_id: message_id.or_else(|| {
            sent.get("message_event_id")
                .and_then(Value::as_str)
                .map(str::to_string)
        }),
        push_envelope: None,
        operation: Some(watchdog_core::delivery::operation_from_transport(
            sent,
            watchdog_core::delivery::TransportOrigin::NativeHelper,
        )),
    }
}

fn hold_error(message: &str, push: &str) -> &'static str {
    match message {
        "relay_accepted" => match push {
            "token_unavailable" => "recipient_push_token_unavailable",
            "rejected" | "terminal_failure" => "push_terminal_failure",
            _ => "push_unobservable",
        },
        "accepted_pending" => "marmot_publish_pending",
        _ => "marmot_completion_unknown",
    }
}

/// The socket file is removed only when no helper owns the root and nothing is
/// accepting connections on it.
pub fn may_unlink_socket(lock_free: bool, socket_accepts: bool) -> bool {
    lock_free && !socket_accepts
}

fn helper_lock_free(vars: &HashMap<String, String>) -> bool {
    let Some(root) = vars.get("MARMOT_ROOT").filter(|path| !path.is_empty()) else {
        return false;
    };
    if std::fs::create_dir_all(root).is_err() {
        return false;
    }
    let Ok(file) = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .open(Path::new(root).join("helper.lock"))
    else {
        return false;
    };
    if !exclusive_lock(&file) {
        return false;
    }
    unlock(&file);
    true
}

fn exclusive_lock(file: &std::fs::File) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::io::AsRawFd;
        extern "C" {
            fn flock(fd: i32, operation: i32) -> i32;
        }
        const LOCK_EX: i32 = 2;
        const LOCK_NB: i32 = 4;
        unsafe { flock(file.as_raw_fd(), LOCK_EX | LOCK_NB) == 0 }
    }
    #[cfg(not(unix))]
    {
        let _ = file;
        true
    }
}

fn unlock(file: &std::fs::File) {
    #[cfg(unix)]
    {
        use std::os::unix::io::AsRawFd;
        extern "C" {
            fn flock(fd: i32, operation: i32) -> i32;
        }
        const LOCK_UN: i32 = 8;
        unsafe {
            let _ = flock(file.as_raw_fd(), LOCK_UN);
        }
    }
    #[cfg(not(unix))]
    {
        let _ = file;
    }
}

fn startup_gate() -> &'static tokio::sync::Mutex<()> {
    static GATE: OnceLock<tokio::sync::Mutex<()>> = OnceLock::new();
    GATE.get_or_init(|| tokio::sync::Mutex::new(()))
}

fn outcome_from_error(value: &Value, membership_is_terminal: bool) -> DeliveryOutcome {
    let code = error_code(value).unwrap_or("marmot_helper_error");
    if membership_is_terminal
        && matches!(
            code,
            "membership_rejected"
                | "membership_unknown"
                | "no_eligible_member"
                | "sender_absent"
                | "recipient_absent"
                | "conversation_mismatch"
                | "conversation_not_reusable"
                | "conversation_unavailable"
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

pub fn ambiguous_timeout() -> DeliveryOutcome {
    pending_phase("marmot_timeout", "completion_unknown", "not_attempted")
}

fn pending(error: &str) -> DeliveryOutcome {
    pending_phase(error, "not_submitted", "not_attempted")
}

fn pending_phase(error: &str, message: &str, push: &str) -> DeliveryOutcome {
    DeliveryOutcome {
        accepted: false,
        terminal: false,
        hold_attempt: false,
        error: Some(error.to_string()),
        accepted_relays: Vec::new(),
        failed_relays: Vec::new(),
        message_phase: Some(message.to_string()),
        push_phase: Some(push.to_string()),
        message_event_id: None,
        push_envelope: None,
        operation: None,
    }
}

fn failed(error: &str) -> DeliveryOutcome {
    DeliveryOutcome {
        accepted: false,
        terminal: true,
        hold_attempt: false,
        error: Some(error.to_string()),
        accepted_relays: Vec::new(),
        failed_relays: Vec::new(),
        message_phase: Some("not_submitted".to_string()),
        push_phase: Some("not_attempted".to_string()),
        message_event_id: None,
        push_envelope: None,
        operation: None,
    }
}

async fn read_bounded_line(stream: &mut UnixStream, max: usize) -> Result<String, String> {
    use tokio::io::AsyncReadExt;
    let mut bytes = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        let read = stream
            .read(&mut byte)
            .await
            .map_err(|_| "marmot_response_invalid".to_string())?;
        if read == 0 || byte[0] == b'\n' {
            break;
        }
        if bytes.len() >= max {
            return Err("marmot_response_invalid".to_string());
        }
        bytes.push(byte[0]);
    }
    String::from_utf8(bytes).map_err(|_| "marmot_response_invalid".to_string())
}

pub async fn operator_onboard(
    vars: &HashMap<String, String>,
    project_id: &str,
    operation_id: &str,
    replace: bool,
) -> Result<Value, String> {
    let get = |key: &str| vars.get(key).cloned().unwrap_or_default();
    let Some(project) = project_by_id(project_id) else {
        return Err("project_invalid".to_string());
    };
    let nsec = get(project.sender_secret);
    if nsec.is_empty() {
        return Err("sender_key_missing".to_string());
    }
    let Some(recipient_raw) =
        project_recipient(&get("PROJECT_RECIPIENTS"), &get("ADMIN_NPUB"), project.id)
    else {
        return Err("recipient_missing".to_string());
    };
    let recipient =
        recipient_pubkey(&recipient_raw).map_err(|_| "recipient_invalid".to_string())?;
    let Some(socket) = socket_path(vars) else {
        return Err("marmot_helper_unconfigured".to_string());
    };
    ensure_helper(vars, &socket).await?;
    let settings = load_settings(&get);
    let setup = OnboardRequest {
        operation_id: operation_id.to_string(),
        replace,
    };
    let (account, group) = ensure_onboard(&socket, &nsec, &settings.bootstrap, &recipient, &setup)
        .await
        .map_err(|outcome| {
            outcome
                .error
                .unwrap_or_else(|| "onboard_failed".to_string())
        })?;
    Ok(json!({
        "ok": true,
        "operationId": operation_id,
        "phase": "established",
        "pubkey": account,
        "recipient": recipient,
        "accountPrefix": &account[..account.len().min(8)],
        "group": group,
        "replace": replace
    }))
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_millis() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::{may_unlink_socket, now_ms, onboard_request};

    fn get<'a>(values: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> String + 'a {
        move |key| {
            values
                .iter()
                .find(|(name, _)| *name == key)
                .map(|(_, value)| (*value).to_string())
                .unwrap_or_default()
        }
    }

    #[test]
    fn a_stale_socket_is_removed_only_when_the_helper_lock_is_free() {
        assert!(may_unlink_socket(true, false));
        assert!(!may_unlink_socket(false, false));
        assert!(!may_unlink_socket(false, true));
        assert!(!may_unlink_socket(true, true));
    }

    #[test]
    fn reonboard_is_one_stable_operation_and_does_not_change_its_id_per_alert() {
        let env = get(&[("MARMOT_REONBOARD", "smartflowsocial")]);
        let first = onboard_request(&env, "smartflowsocial", false).expect("operation");
        let second = onboard_request(&env, "smartflowsocial", false).expect("operation");
        assert_eq!(first.operation_id, "reonboard:smartflowsocial");
        assert_eq!(first.operation_id, second.operation_id);
        assert!(first.replace);
        let initial = onboard_request(&get(&[]), "smartflowsocial", true).expect("initial");
        assert_eq!(initial.operation_id, "initial:smartflowsocial");
        assert!(!initial.replace);
        assert!(onboard_request(&get(&[]), "smartflowsocial", false).is_none());
    }

    #[test]
    fn an_expired_claim_is_not_revived_and_a_live_claim_can_be_renewed() {
        use watchdog_core::domain::{AlertClass, AlertDraft, Destination, Severity};
        use watchdog_store::SqliteStore;
        let dir = std::env::temp_dir().join(format!(
            "watchdog-claim-{}-{}",
            std::process::id(),
            now_ms()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("claim dir");
        let path = dir.join("watchdog.sqlite");
        let store = SqliteStore::open(&path).expect("store");
        let now = now_ms();
        store
            .insert_alert(
                &AlertDraft {
                    id: "alt_claim".to_string(),
                    alert_class: AlertClass::Test,
                    incident_id: None,
                    monitor_id: "acceptance".to_string(),
                    project_id: "smartflowsocial".to_string(),
                    dedupe_key: "claim".to_string(),
                    destination: Destination::Marmot,
                    severity: Severity::Info,
                    text: "claim".to_string(),
                },
                now,
            )
            .expect("insert");
        let token = store
            .claim_row("alt_claim", now, now + 60_000)
            .expect("claim")
            .expect("token");
        assert!(store
            .extend_claim("alt_claim", &token, now + 120_000, now)
            .expect("renew"));
        // Production hardening refuses a deadline that is not strictly in the
        // future and inside five minutes. A rejected write leaves the live claim.
        assert!(!store
            .extend_claim("alt_claim", &token, now - 1, now)
            .expect("past"));
        assert!(store
            .extend_claim("alt_claim", &token, now + 180_000, now)
            .expect("still live"));
        assert!(!store
            .extend_claim("alt_claim", "different-token", now + 60_000, now)
            .expect("foreign"));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
