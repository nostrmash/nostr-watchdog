//! Local Marmot helper.
//!
//! The watchdog process connects to the Unix socket. This binary owns the MDK
//! runtime. It is not part of the Cloudflare deployment.

use std::path::PathBuf;

use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use watchdog_marmot::Session;

#[tokio::main]
async fn main() {
    let mut root = None;
    let mut socket = None;
    let mut relays = Vec::new();
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--root" => root = args.next().map(PathBuf::from),
            "--socket" => socket = args.next().map(PathBuf::from),
            "--relay" => {
                if let Some(relay) = args.next() {
                    relays.push(relay);
                }
            }
            _ => {}
        }
    }
    let Some(root) = root else {
        eprintln!("watchdog-marmot requires --root");
        std::process::exit(2);
    };
    let socket = socket.unwrap_or_else(|| root.join("watchdog.sock"));
    let session = match watchdog_marmot::open(&root, &relays) {
        Ok(session) => session,
        Err(error) => {
            eprintln!("watchdog-marmot open failed: {error}");
            std::process::exit(1);
        }
    };
    if socket.exists() {
        let _ = std::fs::remove_file(&socket);
    }
    let listener = match UnixListener::bind(&socket) {
        Ok(listener) => listener,
        Err(error) => {
            eprintln!("watchdog-marmot socket failed: {error}");
            std::process::exit(1);
        }
    };
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600));
    }
    let mut terminate =
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).expect("sigterm");
    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => break,
            _ = terminate.recv() => break,
            accepted = listener.accept() => {
                let Ok((stream, _)) = accepted else { break };
                if let Err(error) = handle(&session, stream).await {
                    eprintln!("watchdog-marmot request failed: {error}");
                }
            }
        }
    }
    let _ = session.shutdown().await;
}

async fn handle(session: &Session, stream: UnixStream) -> Result<(), String> {
    let (read, mut write) = stream.into_split();
    let mut lines = BufReader::new(read).lines();
    let Some(line) = lines.next_line().await.map_err(|error| error.to_string())? else {
        return Ok(());
    };
    if line.len() > 65_536 {
        return write_json(
            &mut write,
            json!({"ok": false, "error": "request_too_large"}),
        )
        .await;
    }
    let request: Value = match serde_json::from_str(&line) {
        Ok(value) => value,
        Err(_) => {
            return write_json(&mut write, json!({"ok": false, "error": "request_invalid"})).await;
        }
    };
    let response = dispatch(session, request).await;
    write_json(&mut write, response).await
}

async fn dispatch(session: &Session, request: Value) -> Value {
    let op = request.get("op").and_then(Value::as_str).unwrap_or("");
    let result = match op {
        "ping" => Ok(json!({"pong": true})),
        "import" => {
            let nsec = request
                .get("nsec")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            let relays = strings(request.get("relays"));
            if nsec.is_empty() {
                Err("sender_missing".to_string())
            } else {
                session
                    .import_sender(nsec, &relays)
                    .await
                    .map(|account| json!({"account": account}))
            }
        }
        "create_group" => {
            let account = text(&request, "account");
            let name = text(&request, "name");
            let members = strings(request.get("members"));
            session
                .create_group(&account, &name, &members)
                .await
                .map(|group| json!({"group": group}))
        }
        "members" => {
            let account = text(&request, "account");
            let group = text(&request, "group");
            session
                .member_ids(&account, &group)
                .await
                .map(|members| json!({"members": members}))
        }
        "send" => {
            let alert = text(&request, "alert");
            let account = text(&request, "account");
            let group = text(&request, "group");
            let body = text(&request, "text");
            let allow = strings(request.get("allow"));
            session
                .send_once(&alert, &account, &group, &body, &allow)
                .await
        }
        "sync" => session.sync().await.map(|_| json!({"synced": true})),
        _ => Err("op_invalid".to_string()),
    };
    match result {
        Ok(mut value) => {
            if let Some(object) = value.as_object_mut() {
                object.insert("ok".to_string(), Value::Bool(true));
            }
            value
        }
        Err(error) => json!({"ok": false, "error": error}),
    }
}

fn text(value: &Value, key: &str) -> String {
    value
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string()
}

fn strings(value: Option<&Value>) -> Vec<String> {
    value
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

async fn write_json(
    write: &mut tokio::net::unix::OwnedWriteHalf,
    value: Value,
) -> Result<(), String> {
    let mut bytes = serde_json::to_vec(&value).map_err(|_| "response_encode".to_string())?;
    bytes.push(b'\n');
    write
        .write_all(&bytes)
        .await
        .map_err(|error| error.to_string())
}
