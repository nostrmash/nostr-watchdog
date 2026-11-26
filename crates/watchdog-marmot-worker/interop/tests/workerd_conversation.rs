//! Two-member Marmot conversation against the actual Worker bundle in workerd.
//!
//! Run after `worker-build` has written `worker/build/worker/shim.mjs`:
//!
//! ```text
//! cargo test -p marmot-worker-interop --test workerd_conversation -- --ignored --nocapture
//! ```

use std::sync::atomic::{AtomicU64, Ordering};

use std::fs::{self, File};
use std::io::Write;
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use base64::Engine as _;
use cgka_traits::{KeyPackageSource, MessageId, TransportMessage};
use marmot_worker_interop::OfficialRecipient;
use marmot_worker_runtime::push::{self, Platform};
use nostr::key::{Keys, SecretKey};
use serde_json::{Value, json};

const SENDER: &str = "workerdtest";
const TOKEN: &str = "local-test-token";
const PORT: u16 = 8794;

#[tokio::test]
#[ignore = "starts wrangler and the loopback relay; requires the built worker bundle"]
async fn cloudflare_sender_talks_to_official_mdk_across_a_workerd_restart() {
    let worker_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../worker");
    let shim = worker_dir.join("build/worker/shim.mjs");
    assert!(shim.is_file(), "worker bundle is missing at {}", shim.display());
    let wasm_bytes = fs::metadata(worker_dir.join("build/index_bg.wasm")).expect("wasm").len();
    write_dev_vars(&worker_dir);

    free_port(PORT);
    let mut relay = start_relay(&worker_dir);
    let relay_url = relay.url.clone();
    let persist = worker_dir.join(".wrangler/workerd-conversation");
    let _ = fs::remove_dir_all(&persist);
    fs::create_dir_all(&persist).expect("persist dir");

    let mut workerd = start_workerd(&worker_dir, &persist);
    let mut workerd_guard = KillProcess(workerd.id());
    let relay_guard = KillProcess(relay.child.id());
    let native = OfficialRecipient::generate().expect("official recipient");
    let recipient = native.public_key_hex();

    let denied = post_raw(PORT, SENDER, b"{\"op\":\"status\"}", false);
    assert_eq!(denied.0, 401, "{}", denied.1);
    let huge = vec![b' '; 300 * 1024];
    let mut limited = Command::new("curl")
        .args([
            "-sS",
            "-o",
            "/dev/null",
            "-w",
            "%{http_code}",
            "--max-time",
            "30",
            "-X",
            "POST",
            &endpoint(),
            "-H",
            &format!("authorization: Bearer {TOKEN}"),
            "-H",
            "content-type: application/json",
            "--data-binary",
            "@-",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("curl");
    {
        let mut stdin = limited.stdin.take().unwrap();
        stdin.write_all(&huge).unwrap();
    }
    let limited = limited.wait_with_output().unwrap();
    assert_eq!(String::from_utf8_lossy(&limited.stdout).trim(), "413");

    let onboard = post(json!({
        "op": "onboard",
        "projectId": SENDER,
        "operationId": "onboarding-operation-id",
        "replace": false,
        "recipient": recipient,
        "relays": [relay_url]
    }));
    assert_eq!(onboard["ok"], true, "{onboard}");
    assert_eq!(onboard["reused"], false);
    assert_eq!(onboard["messagePhase"], "not_submitted");
    let pubkey = onboard["pubkey"].as_str().unwrap().to_owned();
    assert_eq!(pubkey.len(), 64);

    let again = post(json!({
        "op": "onboard",
        "projectId": SENDER,
        "operationId": "onboarding-operation-id",
        "replace": false,
        "recipient": recipient
    }));
    assert_eq!(again["reused"], true, "{again}");
    let wrong_recipient = "ab".repeat(32);
    let mismatch = post_status(json!({
        "op": "onboard",
        "projectId": SENDER,
        "operationId": "onboarding-operation-id",
        "replace": false,
        "recipient": wrong_recipient
    }));
    assert_eq!(mismatch.0, 400, "{}", mismatch.1);

    let package = post(json!({"op": "key_package", "operationId": "kp-1"}));
    assert!(package["bytesHex"].as_str().unwrap().len() > 64, "{package}");
    assert_eq!(package["event"]["kind"], 30443, "{package}");
    assert_eq!(package["pubkey"], pubkey);
    let published_package = post(json!({
        "op": "key_package",
        "operationId": "kp-2",
        "publish": true,
        "relays": [relay_url]
    }));
    assert_eq!(published_package["event"]["kind"], 30443);
    let stats = relay_stats(&relay.http);
    assert!(stats["counts"]["30443"].as_u64().unwrap_or(0) >= 1, "{stats}");

    let cas = post(json!({"op": "cas_self_test"}));
    assert_eq!(cas["firstRows"], 1, "{cas}");
    assert_eq!(cas["secondRows"], 0, "{cas}");
    assert_eq!(cas["winner"], true, "{cas}");
    assert_eq!(cas["loserWon"], false, "{cas}");
    let stale = post(json!({"op": "stale_write"}));
    assert_eq!(stale["accepted"], false, "{stale}");
    assert!(stale["ciphertext"].is_null());

    let mut member = native.fresh_key_package().await.expect("recipient key package");
    member.source = Some(KeyPackageSource {
        event_id: MessageId::new(vec![0x44; 32]),
    });
    let created = post(json!({
        "op": "create_group",
        "operationId": "create-1",
        "name": "watchdog",
        "relays": [relay_url],
        "members": [{
            "bytesHex": hex::encode(&member.bytes),
            "protocolProfile": "current",
            "eventIdHex": "44".repeat(32)
        }]
    }));
    assert_eq!(created["messagePhase"], "accepted_pending", "{created}");
    assert_eq!(created["settled"], false);
    let group_hex = created["groupIdHex"].as_str().unwrap().to_owned();
    let welcome: TransportMessage = serde_json::from_value(created["welcomes"][0].clone()).expect("welcome");
    native.join_welcome(welcome).await.expect("process welcome");

    let placeholder = post_status(json!({
        "op": "create_group",
        "operationId": "create-bad",
        "relays": ["wss://relay.example"],
        "members": []
    }));
    assert_eq!(placeholder.0, 400, "{}", placeholder.1);
    assert!(placeholder.1.contains("placeholder") || placeholder.1.contains("relay"));

    let started = Instant::now();
    let first = post(json!({
        "op": "send",
        "operationId": "alert-1",
        "groupIdHex": group_hex,
        "text": "relay down"
    }));
    let send_ms = started.elapsed().as_millis();
    assert_eq!(first["messagePhase"], "accepted_pending", "{first}");
    assert_eq!(first["pushPhase"], "not_attempted");
    assert_eq!(first["evidence"], "prepared_message");
    assert!(first["reconcileAfterMs"].as_u64().unwrap() > 0);
    let first_message: TransportMessage =
        serde_json::from_value(first["message"].clone()).expect("first message");
    assert_eq!(
        native.ingest(first_message).await.expect("decrypt first"),
        vec!["relay down".to_owned()]
    );
    let wrong_group = post_status(json!({
        "op": "send",
        "operationId": "alert-1",
        "groupIdHex": "99".repeat(16),
        "text": "relay down"
    }));
    assert_eq!(wrong_group.0, 400, "{}", wrong_group.1);

    let server_secret = SecretKey::from_slice(&[7u8; 32]).expect("server secret");
    let server_keys = Keys::new(server_secret.clone());
    let server_hex = hex::encode(server_keys.public_key().to_bytes());
    let device_token = b"fcm-device-token".to_vec();
    let encrypted = push::encrypt_token(Platform::Fcm, &device_token, &server_hex).expect("encrypt token");
    let staged = post(json!({
        "op": "stage_push",
        "operationId": "alert-1",
        "serverPubkeyHex": server_hex,
        "encryptedTokenHex": hex::encode(&encrypted)
    }));
    assert_eq!(staged["messagePhase"], "accepted_pending", "{staged}");
    assert_eq!(staged["pushPhase"], "prepared");
    assert_eq!(staged["messageEventId"], first["messageEventId"]);
    let opened = push::unwrap_notification(
        &server_keys,
        &serde_json::to_vec(&staged["trigger"]).unwrap(),
    )
    .expect("independent server unwrap");
    let raw = base64::engine::general_purpose::STANDARD.decode(opened).expect("token blob");
    assert!(raw.windows(encrypted.len()).any(|window| window == encrypted));
    let restaged = post(json!({
        "op": "stage_push",
        "operationId": "alert-1",
        "serverPubkeyHex": server_hex,
        "encryptedTokenHex": hex::encode(vec![9u8; encrypted.len()])
    }));
    assert_eq!(restaged["trigger"], staged["trigger"]);
    assert_eq!(restaged["messageEventId"], first["messageEventId"]);

    let pushed = post(json!({
        "op": "stage_push",
        "operationId": "alert-1",
        "publish": true,
        "relays": [relay_url],
        "serverPubkeyHex": server_hex,
        "encryptedTokenHex": hex::encode(&encrypted)
    }));
    assert_eq!(pushed["pushPhase"], "relay_accepted", "{pushed}");
    assert_eq!(pushed["messagePhase"], "accepted_pending", "{pushed}");
    assert_eq!(pushed["messageEventId"], first["messageEventId"]);
    let stats = relay_stats(&relay.http);
    assert!(stats["counts"]["1059"].as_u64().unwrap_or(0) >= 1, "{stats}");

    let reply = native.send_chat(&group_from_hex(&group_hex), "ack").await.expect("native reply");
    let ingested = post(json!({
        "op": "ingest",
        "message": reply
    }));
    assert_eq!(ingested["chats"], json!(["ack"]), "{ingested}");

    let crashed = post_status(json!({
        "op": "send",
        "operationId": "alert-crash",
        "groupIdHex": group_hex,
        "text": "lost",
        "fault": "before_store"
    }));
    assert_eq!(crashed.0, 400, "{}", crashed.1);
    assert!(crashed.1.contains("crash_injected:before_store"));
    assert!(!crashed.1.contains("payload"));
    let missing = post_status(json!({"op": "publication", "operationId": "alert-crash"}));
    assert_eq!(missing.0, 400, "{}", missing.1);

    let hidden = post_status(json!({
        "op": "send",
        "operationId": "alert-held",
        "groupIdHex": group_hex,
        "text": "held",
        "fault": "after_store"
    }));
    assert_eq!(hidden.0, 500, "{}", hidden.1);
    assert!(!hidden.1.contains("held"));
    let recovered = post(json!({"op": "publication", "operationId": "alert-held"}));
    let recovered_message = recovered["message"].clone();
    let repeated = post(json!({
        "op": "send",
        "operationId": "alert-held",
        "groupIdHex": group_hex,
        "text": "held"
    }));
    assert_eq!(repeated["message"], recovered_message, "retry minted a second ciphertext");
    assert_eq!(
        native
            .ingest(serde_json::from_value(repeated["message"].clone()).unwrap())
            .await
            .expect("decrypt held"),
        vec!["held".to_owned()]
    );

    let group_left = group_hex.clone();
    let group_right = group_hex.clone();
    let left = thread::spawn(move || {
        post_status(json!({
            "op": "send",
            "operationId": "alert-left",
            "groupIdHex": group_left,
            "text": "left"
        }))
    });
    let right = thread::spawn(move || {
        post_status(json!({
            "op": "send",
            "operationId": "alert-right",
            "groupIdHex": group_right,
            "text": "right"
        }))
    });
    let left = left.join().expect("left request");
    let right = right.join().expect("right request");
    let winners = [left, right]
        .into_iter()
        .filter(|(status, body)| {
            if *status == 200 {
                true
            } else {
                assert_eq!(*status, 400, "{body}");
                assert!(!body.contains("payload"), "{body}");
                false
            }
        })
        .collect::<Vec<_>>();
    assert!(!winners.is_empty(), "both competing sends were rejected");
    for (_, body) in &winners {
        let value: Value = serde_json::from_str(body).expect(body);
        let text = native
            .ingest(serde_json::from_value(value["message"].clone()).unwrap())
            .await
            .expect("decrypt competing send");
        assert!(text == ["left".to_owned()] || text == ["right".to_owned()], "{text:?}");
    }

    stop_child(&mut workerd);
    assert!(port_closed(PORT));
    workerd = start_workerd(&worker_dir, &persist);
    workerd_guard.0 = workerd.id();
    let status = post(json!({"op": "status"}));
    assert_eq!(status["ready"], true, "{status}");
    assert_eq!(status["pubkey"], pubkey);
    assert!(status["groups"].as_u64().unwrap() >= 1, "{status}");
    assert!(status.get("sealed").is_none());
    let after = post(json!({
        "op": "send",
        "operationId": "alert-2",
        "groupIdHex": group_hex,
        "text": "after restart"
    }));
    assert_eq!(
        native
            .ingest(serde_json::from_value(after["message"].clone()).unwrap())
            .await
            .expect("decrypt restored"),
        vec!["after restart".to_owned()]
    );
    let same = post(json!({
        "op": "send",
        "operationId": "alert-2",
        "groupIdHex": group_hex,
        "text": "after restart"
    }));
    assert_eq!(same["message"], after["message"]);
    assert!(same["messageAttempts"].as_u64().unwrap() >= 2, "{same}");

    let commit = post(json!({
        "op": "self_update",
        "operationId": "rotate-1",
        "groupIdHex": group_hex
    }));
    assert_eq!(commit["messagePhase"], "accepted_pending", "{commit}");
    let confirmed = post(json!({
        "op": "ack",
        "operationId": "rotate-1",
        "accepted": true
    }));
    assert_eq!(confirmed["messagePhase"], "relay_accepted", "{confirmed}");
    let commit_message: TransportMessage =
        serde_json::from_value(commit["message"].clone()).expect("commit");
    let group = group_from_hex(&group_hex);
    let recipient_before = native.epoch(&group).expect("recipient epoch");
    native.ingest(commit_message).await.expect("accept remote commit");
    native.settle(&group).await.expect("apply remote commit");
    assert!(native.epoch(&group).expect("new epoch") > recipient_before);
    let third = post(json!({
        "op": "send",
        "operationId": "alert-3",
        "groupIdHex": group_hex,
        "text": "new epoch"
    }));
    assert_eq!(
        native
            .ingest(serde_json::from_value(third["message"].clone()).unwrap())
            .await
            .expect("decrypt new epoch"),
        vec!["new epoch".to_owned()]
    );

    let via = native
        .send_chat(&group, "via-relay")
        .await
        .expect("relay reply");
    let event = nostr_event(&serde_json::to_value(&via).unwrap());
    let event_path = persist.join("reply.json");
    fs::write(&event_path, serde_json::to_vec(&event).unwrap()).unwrap();
    let published = Command::new("node")
        .arg(worker_dir.join("publish-event.mjs"))
        .arg(&relay_url)
        .arg(&event_path)
        .output()
        .expect("publish reply");
    assert!(
        published.status.success(),
        "{} {}",
        String::from_utf8_lossy(&published.stdout),
        String::from_utf8_lossy(&published.stderr)
    );
    let synced = post(json!({"op": "sync", "relays": [relay_url]}));
    let chats = synced["chats"].as_array().cloned().unwrap_or_default();
    assert!(
        chats.iter().any(|chat| chat == "via-relay"),
        "sync did not decrypt the relay reply: {synced}"
    );

    let status = post(json!({"op": "status"}));
    eprintln!(
        "wasm_bytes={wasm_bytes} database_bytes={} send_ms={send_ms} revision={}",
        status["databaseBytes"], status["revision"]
    );

    stop_child(&mut workerd);
    stop_child(&mut relay.child);
    std::mem::forget(workerd_guard);
    std::mem::forget(relay_guard);
}

struct KillProcess(u32);

impl Drop for KillProcess {
    fn drop(&mut self) {
        let _ = Command::new("kill").args(["-KILL", &format!("-{}", self.0)]).status();
    }
}

struct Relay {
    child: Child,
    url: String,
    http: String,
}

fn start_relay(worker_dir: &Path) -> Relay {
    let mut command = Command::new("node");
    command
        .current_dir(worker_dir)
        .arg(worker_dir.join("relay-fixture.mjs"))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0);
    let mut child = command.spawn().expect("fixture relay");
    let mut url = String::new();
    let stdout = child.stdout.take().unwrap();
    let mut reader = std::io::BufReader::new(stdout);
    std::io::BufRead::read_line(&mut reader, &mut url).expect("relay port");
    let url = url.trim().to_owned();
    let http = url.replacen("ws://", "http://", 1);
    Relay { child, url, http }
}

fn start_workerd(worker_dir: &Path, persist: &Path) -> Child {
    let log_path = persist.join("wrangler.log");
    let log = File::create(&log_path).expect("wrangler log");
    let mut command = Command::new(worker_dir.join("node_modules/.bin/wrangler"));
    command
        .current_dir(worker_dir)
        .args([
            "dev",
            "--config",
            "wrangler.toml",
            "--port",
            &PORT.to_string(),
            "--ip",
            "127.0.0.1",
            "--persist-to",
            &persist.display().to_string(),
            "--var",
            "MARMOT_ALLOW_LOOPBACK:1",
            "--show-interactive-dev-session",
            "false",
        ])
        .stdout(Stdio::from(log.try_clone().expect("log")))
        .stderr(Stdio::from(log))
        .process_group(0);
    let child = command.spawn().expect("wrangler");
    let started = Instant::now();
    loop {
        if started.elapsed() > Duration::from_secs(60) {
            panic!("{}", fs::read_to_string(&log_path).unwrap_or_default());
        }
        let text = fs::read_to_string(&log_path).unwrap_or_default();
        if text.contains("Ready on") {
            break;
        }
        if text.contains("Build failed") || text.contains("EADDRINUSE") {
            panic!("{text}");
        }
        thread::sleep(Duration::from_millis(200));
    }
    child
}

fn stop_child(child: &mut Child) {
    let pid = child.id();
    let _ = Command::new("kill").args(["-KILL", &format!("-{pid}")]).status();
    let _ = child.kill();
    let _ = child.wait();
}

fn free_port(port: u16) {
    let output = Command::new("lsof")
        .args(["-tiTCP", &format!(":{port}"), "-sTCP:LISTEN"])
        .output();
    if let Ok(output) = output {
        for pid in String::from_utf8_lossy(&output.stdout).split_whitespace() {
            let _ = Command::new("kill").args(["-9", pid]).status();
        }
    }
    let _ = port_closed(port);
}

fn port_closed(port: u16) -> bool {
    let started = Instant::now();
    while started.elapsed() < Duration::from_secs(10) {
        if TcpStream::connect(("127.0.0.1", port)).is_err() {
            return true;
        }
        thread::sleep(Duration::from_millis(100));
    }
    false
}

fn write_dev_vars(worker_dir: &Path) {
    fs::write(
        worker_dir.join(".dev.vars"),
        "MARMOT_STORAGE_KEY=00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff\nMARMOT_OPERATOR_TOKEN=local-test-token\n",
    )
    .expect("dev vars");
}

fn endpoint() -> String {
    format!("http://127.0.0.1:{PORT}/marmot?sender={SENDER}")
}

fn post(body: Value) -> Value {
    let (status, text) = post_status(body);
    assert_eq!(status, 200, "{text}");
    serde_json::from_str(&text).unwrap_or_else(|_| panic!("{text}"))
}

fn post_status(body: Value) -> (u16, String) {
    let bytes = serde_json::to_vec(&body).unwrap();
    post_raw(PORT, SENDER, &bytes, true)
}

fn post_raw(port: u16, sender: &str, body: &[u8], authorized: bool) -> (u16, String) {
    static REQUESTS: AtomicU64 = AtomicU64::new(0);
    let path = std::env::temp_dir().join(format!(
        "marmot-request-{}-{}.json",
        std::process::id(),
        REQUESTS.fetch_add(1, Ordering::Relaxed)
    ));
    fs::write(&path, body).unwrap();
    let mut command = Command::new("curl");
    command.args([
        "-sS",
        "-w",
        "\n%{http_code}",
        "--max-time",
        "180",
        "-X",
        "POST",
        &format!("http://127.0.0.1:{port}/marmot?sender={sender}"),
        "-H",
        "content-type: application/json",
        "--data-binary",
        &format!("@{}", path.display()),
    ]);
    if authorized {
        command.arg("-H").arg(format!("authorization: Bearer {TOKEN}"));
    }
    let output = command.output().expect("curl");
    let text = String::from_utf8_lossy(&output.stdout).to_string();
    let (body, status) = text.rsplit_once('\n').unwrap_or((&text, "0"));
    (status.trim().parse().unwrap_or(0), body.to_owned())
}

fn relay_stats(http: &str) -> Value {
    let output = Command::new("curl")
        .args(["-sS", "--max-time", "5", &format!("{http}/stats")])
        .output()
        .expect("relay stats");
    serde_json::from_slice(&output.stdout).unwrap_or(json!({}))
}

fn group_from_hex(hex_id: &str) -> cgka_traits::GroupId {
    cgka_traits::GroupId::new(hex::decode(hex_id).expect("group hex"))
}

fn nostr_event(message: &Value) -> Value {
    let bytes: Vec<u8> = serde_json::from_value(message["payload"].clone()).expect("payload bytes");
    serde_json::from_slice(&bytes).expect("nostr event")
}
