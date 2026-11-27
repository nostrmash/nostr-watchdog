//! Sender path is the watchdog helper. The recipient is an official
//! `MarmotApp` runtime, not a second helper. Both talk to the loopback
//! fixture relay. The test prints no keys.

use std::future::Future;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard};
use std::time::Duration;

use base64::Engine;
use cgka_traits::GroupId;
use marmot_app::{
    AccountSetupRequest, AppMessageQuery, MarmotApp, MarmotAppConfig, PushPlatform,
    PUSH_ENCRYPTED_TOKEN_LEN, PUSH_VERSION,
};
use nostr::event::FinalizeEvent;
use nostr::nips::nip59::UnwrappedGift;
use nostr::prelude::{Event, EventBuilder, Keys, Kind, Tag, ToBech32};
use serde_json::Value;
use zeroize::Zeroizing;

fn exclusive_fixture() -> MutexGuard<'static, ()> {
    static LOCK: Mutex<()> = Mutex::new(());
    LOCK.lock().unwrap_or_else(|error| error.into_inner())
}

fn temp_root(label: &str) -> PathBuf {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!("watchdog-{label}-{}-{n}", std::process::id()))
}

struct Relay {
    child: Child,
    url: String,
}

impl Drop for Relay {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn start_relay() -> Relay {
    let repository = std::env::var_os("WATCHDOG_TEST_REPO_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../.."));
    let script = repository.join("scripts/fixture-relay.mjs");
    let mut child = Command::new("node")
        .arg(script)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("node fixture relay");
    let stdout = child.stdout.take().expect("relay stdout");
    let mut line = String::new();
    BufReader::new(stdout)
        .read_line(&mut line)
        .expect("relay address");
    Relay {
        child,
        url: line.trim().to_string(),
    }
}

fn endpoints(url: &str) -> Vec<cgka_traits::TransportEndpoint> {
    vec![cgka_traits::TransportEndpoint(url.to_string())]
}

fn run_exchange<F: Future<Output = ()> + 'static>(exchange: fn() -> F) {
    const STACK_SIZE: usize = 8 * 1024 * 1024;
    // The MDK future also needs this stack when block_on polls it on the calling thread.
    let result = std::thread::Builder::new()
        .stack_size(STACK_SIZE)
        .spawn(move || {
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .thread_stack_size(STACK_SIZE)
                .enable_all()
                .build()
                .expect("runtime");
            runtime.block_on(exchange());
        })
        .expect("fixture thread")
        .join();
    if let Err(panic) = result {
        std::panic::resume_unwind(panic);
    }
}

#[test]
fn helper_message_decrypts_in_an_official_runtime_and_survives_restart() {
    run_exchange(exchange);
}

async fn exchange() {
    let _guard = exclusive_fixture();
    let relay = start_relay();
    assert!(relay.url.starts_with("ws://127.0.0.1:"));
    let sender_keys = Keys::generate();
    let recipient_keys = Keys::generate();
    let sender_nsec = sender_keys.secret_key().to_bech32().expect("sender bech32");
    let recipient_nsec = recipient_keys
        .secret_key()
        .to_bech32()
        .expect("recipient bech32");
    let sender_hex = sender_keys.public_key().to_hex();
    let recipient_hex = recipient_keys.public_key().to_hex();
    let relays = vec![relay.url.clone()];
    let sender_root = temp_root("sender");
    let recipient_root = temp_root("recipient");
    let _ = std::fs::remove_dir_all(&sender_root);
    let _ = std::fs::remove_dir_all(&recipient_root);

    let session = watchdog_marmot::open(&sender_root, &relays, true).expect("sender open");
    let account = session
        .import_sender(sender_nsec, &relays)
        .await
        .expect("sender import");
    assert_eq!(account, sender_hex);

    let config = MarmotAppConfig::white_noise().with_allow_loopback_relay_endpoints(true);
    let app = MarmotApp::with_relays_and_config(&recipient_root, relays.clone(), config);
    let runtime = app.runtime();
    let relay_endpoints = endpoints(&relay.url);
    let imported = runtime
        .create_or_import_account(AccountSetupRequest {
            import_nsec: Some(Zeroizing::new(recipient_nsec)),
            default_relays: relay_endpoints.clone(),
            bootstrap_relays: relay_endpoints.clone(),
            inbox_relays: relay_endpoints,
            publish_missing_relay_lists: true,
            publish_initial_key_package: true,
            ..AccountSetupRequest::default()
        })
        .await
        .expect("recipient import");
    assert_eq!(imported.account.account_id_hex, recipient_hex);
    assert!(imported.key_package_bytes.unwrap_or(0) > 0);

    let mut group = String::new();
    for _ in 0..12 {
        match session
            .create_group(&account, "", &[recipient_hex.clone()])
            .await
        {
            Ok(id) => {
                group = id;
                break;
            }
            Err(error) if error == "conversation_index_not_ready" => {
                let _ = session.sync().await;
                let _ = runtime.catch_up_accounts().await;
                tokio::time::sleep(Duration::from_millis(400)).await;
            }
            Err(error) => panic!("group: {error}"),
        }
    }
    assert!(!group.is_empty(), "group was not established");

    let group_id = GroupId::new(hex::decode(&group).expect("group hex"));
    let sender_members = session
        .member_ids(&account, &group)
        .await
        .expect("sender members");
    assert!(
        sender_members.iter().any(|member| member == &recipient_hex),
        "sender group is missing the recipient"
    );
    let mut welcomed = false;
    let mut last_welcome = String::from("no_attempt");
    for _ in 0..20 {
        let _ = runtime.catch_up_accounts().await;
        match runtime.group_members(&recipient_hex, &group_id).await {
            Ok(_) => {
                welcomed = true;
                break;
            }
            Err(error) => last_welcome = error.to_string(),
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    assert!(welcomed, "recipient welcome: {last_welcome}");

    let server = Keys::generate();
    let server_hex = server.public_key().to_hex();
    runtime
        .set_native_push_enabled(&recipient_hex, true)
        .await
        .expect("native push");
    runtime
        .upsert_push_registration(
            &recipient_hex,
            marmot_app::PushPlatform::Fcm,
            "fixture-token",
            &server_hex,
            Some(relay.url.clone()),
        )
        .await
        .expect("push registration");
    let mut tokens_ready = false;
    for _ in 0..40 {
        let _ = runtime.catch_up_accounts().await;
        let _ = session.sync().await;
        let ready = session
            .readiness(&account, &recipient_hex, &group)
            .await
            .expect("readiness");
        if ready
            .get("active_recipient_tokens")
            .and_then(Value::as_i64)
            .unwrap_or(0)
            >= 1
        {
            tokens_ready = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(400)).await;
    }
    assert!(tokens_ready, "sender did not observe a recipient token");

    let unrelated = Keys::generate();
    let decoy = EventBuilder::new(Kind::GiftWrap, "unrelated")
        .tag(Tag::public_key(server.public_key()))
        .finalize(&Keys::generate())
        .expect("decoy");
    post_json(
        &format!("{}/event", http_base(&relay.url)),
        &serde_json::to_value(&decoy).expect("decoy json"),
    );
    let alien = EventBuilder::new(Kind::Custom(445), "bm90LXRoZS1hbGVydC1ldmVudA==")
        .tag(Tag::parse(["h", "00"]).expect("alien tag"))
        .finalize(&Keys::generate())
        .expect("alien");
    let alien_id = alien.id.to_string();
    post_json(
        &format!("{}/event", http_base(&relay.url)),
        &serde_json::to_value(&alien).expect("alien json"),
    );
    let baseline = max_seq(&relay.url);
    post_json(
        &format!("{}/event", http_base(&relay.url)),
        &serde_json::json!({
            "id": "f".repeat(64),
            "pubkey": "e".repeat(64),
            "created_at": 1,
            "kind": 1,
            "tags": [],
            "content": "not-the-group-message",
            "sig": "a".repeat(128)
        }),
    );

    let alert = "alt_fixture_exchange";
    let text = "watchdog fixture alert";
    let first = until_published(&session, alert, &account, &group, text, &recipient_hex).await;
    let first_ids = first
        .get("message_ids")
        .and_then(|value| value.as_array())
        .cloned()
        .unwrap_or_default();
    assert!(
        !first_ids.is_empty(),
        "disposition {}",
        first
            .get("disposition")
            .and_then(|value| value.as_str())
            .unwrap_or("")
    );

    let mut decrypted = false;
    for _ in 0..15 {
        let _ = runtime.catch_up_accounts().await;
        let rows = runtime
            .messages_with_query(
                &recipient_hex,
                AppMessageQuery {
                    group_id_hex: Some(group.clone()),
                    kinds: Some(vec![9]),
                    limit: Some(20),
                },
            )
            .expect("messages");
        if rows
            .iter()
            .any(|row| row.plaintext == text && !row.invalidated)
        {
            decrypted = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(400)).await;
    }
    assert!(decrypted, "recipient did not decrypt the alert");

    assert_ne!(
        first.get("push").and_then(Value::as_str),
        Some("relay_accepted"),
        "the helper cannot observe push relay acceptance"
    );
    assert!(
        first.get("push_event_id").is_none() || first.get("push_event_id") == Some(&Value::Null)
    );
    let trigger = wait_for_trigger(&relay.url, &server, &decoy.id.to_string(), baseline)
        .expect("kind 446 trigger");
    assert!(trigger.seq > baseline);
    let route = runtime
        .group_conversation_snapshot(&recipient_hex, &group_id)
        .await
        .expect("route")
        .group
        .nostr_routing
        .nostr_group_id_hex;
    assert_eq!(route.len(), 64, "nostr group route was not a 32-byte id");
    let group_event = alert_group_event(&relay.url, &server, &route, baseline);
    assert_ne!(
        group_event.pubkey.to_hex(),
        account,
        "the kind-445 author must be the ephemeral transport key"
    );
    assert_ne!(
        group_event.id.to_string(),
        alien_id,
        "an unrelated group event satisfied the alert check"
    );
    assert!(session
        .group_was_accepted(&account, &group)
        .await
        .expect("delivery"));
    let rows = runtime
        .messages_with_query(
            &recipient_hex,
            AppMessageQuery {
                group_id_hex: Some(group.clone()),
                kinds: Some(vec![9]),
                limit: Some(20),
            },
        )
        .expect("messages");
    assert!(rows.iter().any(|row| {
        row.plaintext == text
            && !row.invalidated
            && row.sender.eq_ignore_ascii_case(&account)
            && row.group_id_hex.eq_ignore_ascii_case(&group)
            && row.kind == 9
            && first_ids
                .iter()
                .any(|id| id.as_str() == Some(row.message_id_hex.as_str()))
    }));
    assert_routed_token(
        &runtime,
        &recipient_hex,
        &group_id,
        &server_hex,
        b"fixture-token",
    )
    .await;

    session.shutdown().await.expect("shutdown");
    drop(session);
    let resumed = watchdog_marmot::open(&sender_root, &relays, true).expect("reopen");
    let second = resumed
        .send_once(alert, &account, &group, text, &[recipient_hex.clone()])
        .await
        .expect("resend");
    let second_ids = second
        .get("message_ids")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    assert_eq!(first_ids, second_ids);
    assert_eq!(
        second.get("operation_id").and_then(Value::as_str),
        Some(alert)
    );
    let mismatch = resumed
        .send_once(
            alert,
            &account,
            &group,
            "a different payload",
            &[recipient_hex.clone()],
        )
        .await;
    assert!(
        matches!(mismatch, Err(error) if error == "alert_identity_mismatch"),
        "a reused alert id accepted a different payload"
    );
    assert_eq!(
        plaintext_count(&runtime, &recipient_hex, &group, "a different payload").await,
        0
    );

    tokio::time::sleep(Duration::from_millis(20)).await;
    let replacement = runtime
        .upsert_push_registration(
            &recipient_hex,
            PushPlatform::Fcm,
            "fixture-token-replaced",
            &server_hex,
            Some(relay.url.clone()),
        )
        .await
        .expect("replace token");
    let expected = marmot_app::push_token_fingerprint(PushPlatform::Fcm, b"fixture-token-replaced");
    assert_eq!(
        replacement.registration.token_fingerprint, expected,
        "replacement registration fingerprint diverged from the official helper"
    );
    let mut share = replacement.share;
    for _ in 0..15 {
        if share.succeeded_groups > 0 && share.pending_groups == 0 && share.failed_groups == 0 {
            break;
        }
        let _ = runtime.catch_up_accounts().await;
        tokio::time::sleep(Duration::from_millis(400)).await;
        share = runtime
            .share_push_registration(&recipient_hex)
            .await
            .expect("retry token share");
    }
    wait_for_fingerprint(
        &resumed,
        &runtime,
        &account,
        &recipient_hex,
        &group,
        &group_id,
        &server_hex,
        &expected,
        share,
    )
    .await;
    let before_replace = wrap_ids(&relay.url);
    let _replaced = until_published(
        &resumed,
        "alt_fixture_replaced",
        &account,
        &group,
        "watchdog replaced token",
        &recipient_hex,
    )
    .await;
    let replaced_trigger =
        wait_for_new_trigger(&relay.url, &server, &before_replace).expect("replacement trigger");
    assert_ne!(
        replaced_trigger.id, trigger.id,
        "replacement reused the gift-wrap id"
    );
    assert!(
        replaced_trigger.content != trigger.content,
        "replacement rumor did not change"
    );

    runtime
        .clear_push_registration(&recipient_hex)
        .await
        .expect("revoke token");
    wait_until_tokens(&resumed, &runtime, &account, &recipient_hex, &group, 0).await;
    let before_revoke = max_seq_kind(&relay.url, 1059);
    let revoked = until_published(
        &resumed,
        "alt_fixture_revoked",
        &account,
        &group,
        "watchdog revoked token",
        &recipient_hex,
    )
    .await;
    assert_eq!(
        revoked.get("push").and_then(Value::as_str),
        Some("token_unavailable")
    );
    assert!(wait_plaintext(&runtime, &recipient_hex, &group, "watchdog revoked token").await);
    tokio::time::sleep(Duration::from_millis(800)).await;
    assert_eq!(
        max_seq_kind(&relay.url, 1059),
        before_revoke,
        "revocation still published a gift wrap"
    );

    let stranger = Keys::generate().public_key().to_hex();
    let before_stranger = max_seq(&relay.url);
    let removed = resumed
        .send_once(
            "alt_fixture_removed",
            &account,
            &group,
            "watchdog removed member",
            &[stranger],
        )
        .await;
    assert!(
        matches!(removed, Err(error) if error == "recipient_absent"),
        "unauthorized recipient was admitted"
    );
    assert_eq!(max_seq(&relay.url), before_stranger);
    assert!(
        !gift_wraps(&relay.url)
            .into_iter()
            .any(|(_seq, event)| p_tag(&event)
                .eq_ignore_ascii_case(&unrelated.public_key().to_hex())),
        "a gift wrap was addressed to an unregistered server"
    );

    runtime
        .upsert_push_registration(
            &recipient_hex,
            PushPlatform::Fcm,
            "fixture-token-reject",
            &server_hex,
            Some(relay.url.clone()),
        )
        .await
        .expect("token before rejection");
    wait_until_tokens(&resumed, &runtime, &account, &recipient_hex, &group, 1).await;
    post_json(
        &format!("{}/control", http_base(&relay.url)),
        &serde_json::json!({"rejectKinds": [1059]}),
    );
    let before_reject = max_seq_kind(&relay.url, 1059);
    let rejected = until_published(
        &resumed,
        "alt_fixture_rejected",
        &account,
        &group,
        "watchdog rejected trigger",
        &recipient_hex,
    )
    .await;
    assert_eq!(
        rejected.get("message_phase").and_then(Value::as_str),
        Some("relay_accepted")
    );
    assert_eq!(
        rejected.get("push").and_then(Value::as_str),
        Some("unobservable"),
        "a relay refusal is not an alert-specific push result"
    );
    assert!(rejected.get("push_event_id").is_none_or(Value::is_null));
    assert!(
        wait_plaintext(
            &runtime,
            &recipient_hex,
            &group,
            "watchdog rejected trigger"
        )
        .await
    );
    tokio::time::sleep(Duration::from_millis(800)).await;
    assert_eq!(max_seq_kind(&relay.url, 1059), before_reject);
    post_json(
        &format!("{}/control", http_base(&relay.url)),
        &serde_json::json!({"rejectKinds": []}),
    );

    let crashed = crash_send(&resumed, &account, &group, &recipient_hex, "intent").await;
    assert!(
        matches!(crashed, Err(error) if error == "crash_injected:intent"),
        "intent crash did not stop before submission"
    );
    let ambiguous = resumed
        .send_once(
            "alt_crash_intent",
            &account,
            &group,
            "watchdog crash intent",
            &[recipient_hex.clone()],
        )
        .await
        .expect("ambiguous recovery");
    assert_eq!(
        ambiguous.get("message_phase").and_then(Value::as_str),
        Some("completion_unknown")
    );
    assert_eq!(
        ambiguous
            .get("message_ids")
            .and_then(Value::as_array)
            .map(Vec::len),
        Some(0)
    );
    assert_eq!(
        ambiguous.get("operation_id").and_then(Value::as_str),
        Some("alt_crash_intent")
    );
    assert_eq!(
        ambiguous.get("preserve_message").and_then(Value::as_bool),
        Some(true)
    );

    for point in ["submitted", "pending", "accepted", "persisted", "push"] {
        let failed = crash_send(&resumed, &account, &group, &recipient_hex, point).await;
        assert!(
            matches!(failed, Err(error) if error == format!("crash_injected:{point}")),
            "{point} did not crash at the requested boundary"
        );
        let alert_id = format!("alt_crash_{point}");
        let body = format!("watchdog crash {point}");
        let recovered = resumed
            .send_once(&alert_id, &account, &group, &body, &[recipient_hex.clone()])
            .await
            .unwrap_or_else(|error| panic!("{point} recovery failed: {error}"));
        let ids = recovered
            .get("message_ids")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        assert!(!ids.is_empty(), "{point} lost the message id");
        let again = resumed
            .send_once(&alert_id, &account, &group, &body, &[recipient_hex.clone()])
            .await
            .unwrap_or_else(|error| panic!("{point} retry failed: {error}"));
        assert_eq!(
            again.get("message_ids").and_then(Value::as_array),
            Some(&ids)
        );
        assert_eq!(
            again.get("operation_id").and_then(Value::as_str),
            Some(alert_id.as_str())
        );
    }

    let _ = resumed.shutdown().await;
    let _ = runtime.shutdown_and_close().await;
    let _ = std::fs::remove_dir_all(&sender_root);
    let _ = std::fs::remove_dir_all(&recipient_root);
}

struct Trigger {
    seq: u64,
    id: String,
    content: String,
}

fn http_base(url: &str) -> String {
    url.replacen("ws://", "http://", 1)
}

fn get_json(url: &str) -> Value {
    let output = Command::new("curl")
        .args(["-fsS", url])
        .output()
        .expect("curl");
    assert!(output.status.success(), "fixture request failed");
    serde_json::from_slice(&output.stdout).expect("fixture json")
}

fn post_json(url: &str, body: &Value) {
    let payload = body.to_string();
    let output = Command::new("curl")
        .args([
            "-fsS",
            "-X",
            "POST",
            "-H",
            "content-type: application/json",
            "--data",
            &payload,
            url,
        ])
        .output()
        .expect("curl");
    assert!(output.status.success(), "fixture post failed");
}

fn gift_wraps(url: &str) -> Vec<(u64, Event)> {
    let value = get_json(&format!("{}/events?kind=1059", http_base(url)));
    value
        .as_array()
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .filter_map(|item| {
            let seq = item.get("seq").and_then(Value::as_u64)?;
            let event = serde_json::from_value(item.get("event")?.clone()).ok()?;
            Some((seq, event))
        })
        .collect()
}

fn p_tag(event: &Event) -> String {
    event
        .tags
        .iter()
        .find_map(|tag| {
            let slice = tag.as_slice();
            if slice.first().map(String::as_str) == Some("p") {
                slice.get(1).cloned()
            } else {
                None
            }
        })
        .unwrap_or_default()
}

fn validated_rumor(server: &Keys, event: &Event) -> Option<String> {
    if event.kind != Kind::GiftWrap || event.verify().is_err() {
        return None;
    }
    if !p_tag(event).eq_ignore_ascii_case(&server.public_key().to_hex()) {
        return None;
    }
    let Ok(unwrapped) = UnwrappedGift::from_gift_wrap(server, event) else {
        return None;
    };
    if unwrapped.rumor.kind != Kind::Custom(446) {
        return None;
    }
    let tags: Vec<&[String]> = unwrapped.rumor.tags.iter().map(Tag::as_slice).collect();
    let version_only = tags.len() == 1
        && tags[0].first().map(String::as_str) == Some("v")
        && tags[0].get(1).map(String::as_str) == Some(PUSH_VERSION);
    if !version_only {
        return None;
    }
    if unwrapped
        .rumor
        .tags
        .iter()
        .any(|tag| tag.as_slice().first().map(String::as_str) == Some("expiration"))
    {
        return None;
    }
    let Ok(raw) =
        base64::engine::general_purpose::STANDARD.decode(unwrapped.rumor.content.as_bytes())
    else {
        return None;
    };
    if raw.is_empty() || !raw.len().is_multiple_of(PUSH_ENCRYPTED_TOKEN_LEN) {
        return None;
    }
    let chunks = raw.len() / PUSH_ENCRYPTED_TOKEN_LEN;
    if !(2..=19).contains(&chunks) {
        return None;
    }
    Some(unwrapped.rumor.content)
}

fn wait_for_trigger(url: &str, server: &Keys, decoy_id: &str, baseline: u64) -> Option<Trigger> {
    for _ in 0..20 {
        if let Some(trigger) = gift_wraps(url).into_iter().find_map(|(seq, event)| {
            if seq <= baseline || event.id.to_string() == decoy_id {
                return None;
            }
            validated_rumor(server, &event).map(|content| Trigger {
                seq,
                id: event.id.to_string(),
                content,
            })
        }) {
            return Some(trigger);
        }
        std::thread::sleep(Duration::from_millis(400));
    }
    None
}

fn wait_for_new_trigger(url: &str, server: &Keys, seen: &[String]) -> Option<Trigger> {
    for _ in 0..20 {
        if let Some(trigger) = gift_wraps(url).into_iter().find_map(|(seq, event)| {
            let id = event.id.to_string();
            if seen.iter().any(|known| known == &id) {
                return None;
            }
            validated_rumor(server, &event).map(|content| Trigger { seq, id, content })
        }) {
            return Some(trigger);
        }
        std::thread::sleep(Duration::from_millis(400));
    }
    None
}

fn wrap_ids(url: &str) -> Vec<String> {
    gift_wraps(url)
        .into_iter()
        .map(|(_, event)| event.id.to_string())
        .collect()
}

fn alert_group_event(url: &str, server: &Keys, group_hex: &str, baseline: u64) -> Event {
    let mut notes = Vec::new();
    for _ in 0..20 {
        let events = get_json(&format!("{}/events?kind=445", http_base(url)));
        let items = events.as_array().cloned().unwrap_or_default();
        let triggers = gift_wraps(url);
        let mut matched = None;
        notes.clear();
        for item in &items {
            let seq = item.get("seq").and_then(Value::as_u64).unwrap_or(0);
            let Some(raw) = item.get("event") else {
                continue;
            };
            let Ok(event) = serde_json::from_value::<Event>(raw.clone()) else {
                notes.push(format!("seq {seq} did not deserialize"));
                continue;
            };
            if seq <= baseline {
                notes.push(format!("seq {seq} is not after the alert baseline"));
                continue;
            }
            let route = event.tags.iter().find_map(|tag| {
                let values = tag.as_slice();
                if values.first().map(String::as_str) == Some("h") {
                    values.get(1).cloned()
                } else {
                    None
                }
            });
            if route
                .as_deref()
                .is_none_or(|value| !value.eq_ignore_ascii_case(group_hex))
            {
                notes.push(format!(
                    "seq {seq} group tag {:?} is not this alert",
                    route.as_deref().unwrap_or("")
                ));
                continue;
            }
            if let Err(error) = event.verify() {
                notes.push(format!("seq {seq} signature: {error}"));
                continue;
            }
            let decoded = base64::engine::general_purpose::STANDARD
                .decode(event.content.as_str())
                .or_else(|_| {
                    base64::engine::general_purpose::STANDARD_NO_PAD.decode(event.content.as_str())
                });
            let Ok(decoded) = decoded else {
                notes.push(format!(
                    "seq {seq} content is not the pinned base64 framing"
                ));
                continue;
            };
            if decoded.len() < 28 {
                notes.push(format!(
                    "seq {seq} framed payload is {} bytes",
                    decoded.len()
                ));
                continue;
            }
            let followed = triggers.iter().any(|(trigger_seq, trigger)| {
                *trigger_seq > seq && validated_rumor(server, trigger).is_some()
            });
            if !followed {
                notes.push(format!(
                    "seq {seq} has no later kind-446 gift wrap (triggers: {})",
                    triggers.len()
                ));
                continue;
            }
            matched = Some(event);
            break;
        }
        if let Some(event) = matched {
            return event;
        }
        std::thread::sleep(Duration::from_millis(400));
    }
    let order = get_json(&format!("{}/order", http_base(url)));
    panic!(
        "the alert's kind-445 group event was not accepted before its trigger\n{notes:?}\norder={order}"
    );
}

fn max_seq(url: &str) -> u64 {
    let order = get_json(&format!("{}/order", http_base(url)));
    order
        .as_array()
        .and_then(|items| {
            items
                .iter()
                .filter_map(|item| item.get("seq").and_then(Value::as_u64))
                .max()
        })
        .unwrap_or(0)
}

fn max_seq_kind(url: &str, kind: u64) -> u64 {
    let order = get_json(&format!("{}/order", http_base(url)));
    order
        .as_array()
        .and_then(|items| {
            items
                .iter()
                .filter(|item| item.get("kind").and_then(Value::as_u64) == Some(kind))
                .filter_map(|item| item.get("seq").and_then(Value::as_u64))
                .max()
        })
        .unwrap_or(0)
}

async fn assert_routed_token(
    runtime: &marmot_app::MarmotAppRuntime,
    recipient: &str,
    group: &GroupId,
    server_hex: &str,
    token: &[u8],
) {
    let expected = marmot_app::push_token_fingerprint(PushPlatform::Fcm, token);
    let info = runtime
        .group_push_debug_info(recipient, group)
        .await
        .expect("push debug");
    let matched = info.tokens.iter().any(|item| {
        item.member_id_hex.eq_ignore_ascii_case(recipient)
            && item.member_matches_active_leaf
            && item.has_relay_hint
            && item.server_pubkey_hex.eq_ignore_ascii_case(server_hex)
            && item.token_fingerprint == expected
    });
    assert!(
        matched,
        "recipient token was not routed to the registered notification server"
    );
}

async fn wait_for_fingerprint(
    session: &watchdog_marmot::Session,
    runtime: &marmot_app::MarmotAppRuntime,
    account: &str,
    recipient: &str,
    group_hex: &str,
    group: &GroupId,
    _server_hex: &str,
    expected: &str,
    share: marmot_app::PushRegistrationShareOutcome,
) {
    let previous = marmot_app::push_token_fingerprint(PushPlatform::Fcm, b"fixture-token");
    let mut sender_error = String::from("none");
    for attempt in 0..40 {
        if attempt % 8 == 0 {
            let _ = session.repair_history(account).await;
        }
        let _ = session.sync().await;
        let _ = runtime.catch_up_accounts().await;
        match session
            .sees_recipient_token(account, group_hex, recipient, expected)
            .await
        {
            Ok(true) => return,
            Ok(false) => {}
            Err(error) => sender_error = error,
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    let sender_previous = session
        .sees_recipient_token(account, group_hex, recipient, &previous)
        .await
        .map(|seen| seen.to_string())
        .unwrap_or_else(|error| error);
    let sender_tokens = session
        .readiness(account, recipient, group_hex)
        .await
        .ok()
        .and_then(|ready| ready.get("active_recipient_tokens").and_then(Value::as_i64))
        .unwrap_or(-1);
    let local_active = runtime
        .group_push_debug_info(recipient, group)
        .await
        .map(|info| {
            info.tokens.iter().any(|token| {
                token.member_id_hex.eq_ignore_ascii_case(recipient)
                    && token.member_matches_active_leaf
                    && token.token_fingerprint == expected
            })
        })
        .unwrap_or(false);
    panic!(
        "replacement token did not become visible to the sender; share attempted={} succeeded={} failed={} pending={}; recipient_active={local_active}; sender_still_has_previous={sender_previous}; sender_tokens={sender_tokens}; sender_error={sender_error}",
        share.attempted_groups, share.succeeded_groups, share.failed_groups, share.pending_groups
    );
}

async fn wait_until_tokens(
    session: &watchdog_marmot::Session,
    runtime: &marmot_app::MarmotAppRuntime,
    account: &str,
    recipient: &str,
    group: &str,
    expected: i64,
) {
    for _ in 0..40 {
        let _ = session.sync().await;
        let _ = runtime.catch_up_accounts().await;
        let ready = session
            .readiness(account, recipient, group)
            .await
            .expect("readiness");
        if ready.get("active_recipient_tokens").and_then(Value::as_i64) == Some(expected) {
            return;
        }
        tokio::time::sleep(Duration::from_millis(400)).await;
    }
    panic!("recipient token count did not reach the expected value");
}

async fn wait_plaintext(
    runtime: &marmot_app::MarmotAppRuntime,
    recipient: &str,
    group: &str,
    text: &str,
) -> bool {
    for _ in 0..20 {
        let _ = runtime.catch_up_accounts().await;
        let rows = runtime
            .messages_with_query(
                recipient,
                AppMessageQuery {
                    group_id_hex: Some(group.to_string()),
                    kinds: Some(vec![9]),
                    limit: Some(40),
                },
            )
            .expect("messages");
        if rows
            .iter()
            .any(|row| row.plaintext == text && !row.invalidated)
        {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(400)).await;
    }
    false
}

async fn until_published(
    session: &watchdog_marmot::Session,
    alert: &str,
    account: &str,
    group: &str,
    text: &str,
    recipient: &str,
) -> Value {
    let mut last = Value::Null;
    for _ in 0..40 {
        let _ = session.sync().await;
        last = session
            .send_once(alert, account, group, text, &[recipient.to_string()])
            .await
            .unwrap_or_else(|error| panic!("send failed: {error}"));
        if last.get("message_phase").and_then(Value::as_str) == Some("relay_accepted") {
            return last;
        }
        tokio::time::sleep(Duration::from_millis(400)).await;
    }
    panic!(
        "message was not relay-accepted ({})",
        last.get("message_phase")
            .and_then(Value::as_str)
            .unwrap_or("")
    );
}

async fn crash_send(
    session: &watchdog_marmot::Session,
    account: &str,
    group: &str,
    recipient: &str,
    point: &str,
) -> Result<Value, String> {
    let alert_id = format!("alt_crash_{point}");
    let body = format!("watchdog crash {point}");
    unsafe { std::env::set_var("WATCHDOG_MARMOT_CRASH_AT", point) };
    let result = session
        .send_once(&alert_id, account, group, &body, &[recipient.to_string()])
        .await;
    unsafe { std::env::remove_var("WATCHDOG_MARMOT_CRASH_AT") };
    result
}

#[test]
#[ignore = "publishes throwaway key packages to the WhiteNoise relays"]
fn whitenoise_relays_deliver_one_alert() {
    run_exchange(public_import);
}

async fn public_import() {
    let _guard = exclusive_fixture();
    let relays = vec![
        "wss://relay.eu.whitenoise.chat".to_string(),
        "wss://relay.us.whitenoise.chat".to_string(),
    ];
    let sender_keys = Keys::generate();
    let recipient_keys = Keys::generate();
    let sender_nsec = sender_keys.secret_key().to_bech32().expect("sender bech32");
    let recipient_nsec = recipient_keys
        .secret_key()
        .to_bech32()
        .expect("recipient bech32");
    let sender_hex = sender_keys.public_key().to_hex();
    let recipient_hex = recipient_keys.public_key().to_hex();
    let sender_root = temp_root("public-sender");
    let recipient_root = temp_root("public-recipient");
    let _ = std::fs::remove_dir_all(&sender_root);
    let _ = std::fs::remove_dir_all(&recipient_root);
    let session = watchdog_marmot::open(&sender_root, &relays, false).expect("sender open");
    let account = session
        .import_sender(sender_nsec, &relays)
        .await
        .expect("sender import");
    assert_eq!(account, sender_hex);
    let app = MarmotApp::with_relays_and_config(
        &recipient_root,
        relays.clone(),
        MarmotAppConfig::white_noise(),
    );
    let runtime = app.runtime();
    let endpoints = endpoints_of(&relays);
    let imported = runtime
        .create_or_import_account(AccountSetupRequest {
            import_nsec: Some(Zeroizing::new(recipient_nsec)),
            default_relays: endpoints.clone(),
            bootstrap_relays: endpoints.clone(),
            inbox_relays: endpoints,
            publish_missing_relay_lists: true,
            publish_initial_key_package: true,
            ..AccountSetupRequest::default()
        })
        .await
        .expect("recipient import");
    assert_eq!(imported.account.account_id_hex, recipient_hex);
    assert!(imported.key_package_bytes.unwrap_or(0) > 0);
    let mut group = String::new();
    for _ in 0..15 {
        match session
            .create_group(&account, "", &[recipient_hex.clone()])
            .await
        {
            Ok(id) => {
                group = id;
                break;
            }
            Err(error) if error == "conversation_index_not_ready" => {
                let _ = session.sync().await;
                let _ = runtime.catch_up_accounts().await;
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
            Err(error) => panic!("group: {error}"),
        }
    }
    assert!(!group.is_empty(), "public group was not established");
    let group_id = GroupId::new(hex::decode(&group).expect("group hex"));
    let mut welcomed = false;
    let mut last_welcome = String::from("no_attempt");
    for _ in 0..20 {
        let _ = runtime.catch_up_accounts().await;
        match runtime.group_members(&recipient_hex, &group_id).await {
            Ok(_) => {
                welcomed = true;
                break;
            }
            Err(error) => last_welcome = error.to_string(),
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    assert!(welcomed, "public welcome: {last_welcome}");
    let text = "watchdog public alert";
    session
        .send_once(
            "alt_public_exchange",
            &account,
            &group,
            text,
            &[recipient_hex.clone()],
        )
        .await
        .expect("public send");
    let mut decrypted = false;
    for _ in 0..20 {
        let _ = runtime.catch_up_accounts().await;
        let rows = runtime
            .messages_with_query(
                &recipient_hex,
                AppMessageQuery {
                    group_id_hex: Some(group.clone()),
                    kinds: Some(vec![9]),
                    limit: Some(10),
                },
            )
            .expect("messages");
        if rows
            .iter()
            .any(|row| row.plaintext == text && !row.invalidated)
        {
            decrypted = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    assert!(decrypted, "public recipient did not decrypt the alert");
    let _ = session.shutdown().await;
    let _ = runtime.shutdown_and_close().await;
    let _ = std::fs::remove_dir_all(&sender_root);
    let _ = std::fs::remove_dir_all(&recipient_root);
}

fn endpoints_of(relays: &[String]) -> Vec<cgka_traits::TransportEndpoint> {
    relays
        .iter()
        .cloned()
        .map(cgka_traits::TransportEndpoint)
        .collect()
}

#[test]
#[ignore = "runs the owner acceptance script against a controlled recipient and relay"]
fn whitenoise_script_onboards_and_reuses_the_conversation() {
    run_exchange(acceptance_script_exchange);
}

async fn acceptance_script_exchange() {
    let _guard = exclusive_fixture();
    let relay = start_relay();
    let recipient = Keys::generate();
    let recipient_hex = recipient.public_key().to_hex();
    let recipient_root = temp_root("acceptance-recipient");
    let config = MarmotAppConfig::white_noise().with_allow_loopback_relay_endpoints(true);
    let app = MarmotApp::with_relays_and_config(&recipient_root, vec![relay.url.clone()], config);
    let runtime = app.runtime();
    let endpoints = endpoints(&relay.url);
    runtime
        .create_or_import_account(AccountSetupRequest {
            import_nsec: Some(Zeroizing::new(recipient.secret_key().to_bech32().unwrap())),
            default_relays: endpoints.clone(),
            bootstrap_relays: endpoints.clone(),
            inbox_relays: endpoints,
            publish_missing_relay_lists: true,
            publish_initial_key_package: true,
            ..AccountSetupRequest::default()
        })
        .await
        .unwrap();
    let fixture = AcceptanceScript {
        script: PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../scripts/whitenoise-acceptance.sh"),
        state: Path::new("/tmp").join(temp_root("acceptance").file_name().unwrap()),
        watchdog: watchdog_binary(),
        listen: format!("127.0.0.1:{}", free_port()),
        relay: relay.url.clone(),
    };
    fixture.run(&["prepare", &recipient_hex]);
    fixture.run(&["start"]);
    let onboarding: Value = serde_json::from_str(&fixture.run(&["conversation"])).unwrap();
    assert_eq!(onboarding["ok"], true, "script onboarding failed");
    let group = onboarding["group"].as_str().expect("test conversation");
    let group_id = GroupId::new(hex::decode(group).unwrap());
    for _ in 0..20 {
        let _ = runtime.catch_up_accounts().await;
        if runtime
            .group_members(&recipient_hex, &group_id)
            .await
            .is_ok()
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    runtime
        .set_native_push_enabled(&recipient_hex, true)
        .await
        .unwrap();
    runtime
        .upsert_push_registration(
            &recipient_hex,
            PushPlatform::Fcm,
            "acceptance-fixture",
            &Keys::generate().public_key().to_hex(),
            Some(relay.url.clone()),
        )
        .await
        .unwrap();
    let mut ready = false;
    for _ in 0..75 {
        let _ = runtime.catch_up_accounts().await;
        let status = fixture.run(&["status"]);
        let readiness: Value = serde_json::from_str(status.lines().last().unwrap()).unwrap();
        if readiness["active_recipient_tokens"]
            .as_u64()
            .is_some_and(|count| count > 0)
        {
            ready = true;
            break;
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    assert!(ready, "the script did not observe an eligible test token");

    for index in 0..2 {
        if index == 1 {
            fixture.run(&["restart"]);
            let resumed: Value = serde_json::from_str(&fixture.run(&["conversation"])).unwrap();
            assert_eq!(resumed["group"].as_str(), Some(group));
        }
        let sent = fixture.run(&["alert-foreground"]);
        let result: Value = serde_json::from_str(sent.lines().next().unwrap()).unwrap();
        let alert = result["alertId"].as_str().expect("script outbox id");
        let db = fixture.state.join("db/watchdog.sqlite");
        wait_outbox_settled(&db, alert).await;
        let text = sql_value(
            &db,
            &format!(
                "SELECT payload_text FROM alert_outbox WHERE id = '{}'",
                sql_id(alert)
            ),
        );
        assert!(wait_plaintext(&runtime, &recipient_hex, group, &text).await);
    }
    let _ = runtime.shutdown_and_close().await;
    let _ = std::fs::remove_dir_all(&recipient_root);
}

struct AcceptanceScript {
    script: PathBuf,
    state: PathBuf,
    watchdog: PathBuf,
    listen: String,
    relay: String,
}

impl AcceptanceScript {
    fn command(&self) -> Command {
        let mut command = Command::new("sh");
        command
            .arg(&self.script)
            .env("WATCHDOG_ACCEPTANCE_ROOT", &self.state)
            .env("WATCHDOG_ACCEPTANCE_WATCHDOG", &self.watchdog)
            .env(
                "WATCHDOG_ACCEPTANCE_HELPER",
                env!("CARGO_BIN_EXE_watchdog-marmot"),
            )
            .env("WATCHDOG_ACCEPTANCE_ADDR", &self.listen)
            .env("WATCHDOG_ACCEPTANCE_LOOPBACK_RELAY", &self.relay);
        command
    }

    fn run(&self, args: &[&str]) -> String {
        let result = self.command().args(args).output().unwrap();
        assert!(
            result.status.success(),
            "{} failed: {}",
            args[0],
            String::from_utf8_lossy(&result.stderr)
        );
        String::from_utf8(result.stdout).unwrap()
    }
}

impl Drop for AcceptanceScript {
    fn drop(&mut self) {
        if self.state.exists() {
            let _ = self.command().arg("stop").output();
            if !std::thread::panicking() {
                let _ = std::fs::remove_dir_all(&self.state);
            }
        }
    }
}

#[test]
fn packaged_binaries_deliver_monitor_incident_reconcile_and_send_recovery() {
    run_exchange(executable_exchange);
}

async fn executable_exchange() {
    let _guard = exclusive_fixture();
    let relay = start_relay();
    let sender_keys = Keys::generate();
    let recipient_keys = Keys::generate();
    let sender_nsec = sender_keys.secret_key().to_bech32().expect("sender bech32");
    let recipient_nsec = recipient_keys
        .secret_key()
        .to_bech32()
        .expect("recipient bech32");
    let sender_hex = sender_keys.public_key().to_hex();
    let recipient_hex = recipient_keys.public_key().to_hex();
    let db_dir = Path::new("/tmp").join(temp_root("exec-data").file_name().unwrap());
    let root = db_dir.join("marmot");
    let recipient_root = temp_root("exec-recipient");
    let db = db_dir.join("watchdog.sqlite");
    let socket = root.join("watchdog.sock");
    let log = db_dir.join("watchdog.log");
    let mut container = DockerFixture::from_environment(&db_dir);
    let helper_bin = PathBuf::from(env!("CARGO_BIN_EXE_watchdog-marmot"));
    let watchdog_bin = if container.is_some() {
        PathBuf::from("/usr/local/bin/nostr-watchdog")
    } else {
        watchdog_binary()
    };
    let port = free_port();
    let listen = format!("127.0.0.1:{port}");
    let operator = "fixture-operator-token";

    let config = MarmotAppConfig::white_noise().with_allow_loopback_relay_endpoints(true);
    let app = MarmotApp::with_relays_and_config(&recipient_root, vec![relay.url.clone()], config);
    let runtime = app.runtime();
    let relay_endpoints = endpoints(&relay.url);
    let imported = runtime
        .create_or_import_account(AccountSetupRequest {
            import_nsec: Some(Zeroizing::new(recipient_nsec)),
            default_relays: relay_endpoints.clone(),
            bootstrap_relays: relay_endpoints.clone(),
            inbox_relays: relay_endpoints,
            publish_missing_relay_lists: true,
            publish_initial_key_package: true,
            ..AccountSetupRequest::default()
        })
        .await
        .expect("recipient import");
    assert_eq!(imported.account.account_id_hex, recipient_hex);

    let mut helper =
        start_fixture_helper(container.as_ref(), &helper_bin, &root, &socket, &relay.url);
    wait_health(&root.join("health.sock"));
    let mut group = String::new();
    let mut account = String::new();
    for _ in 0..20 {
        let response = helper_ipc(
            &socket,
            serde_json::json!({
                "op": "onboard",
                "operation_id": "initial:smartflowsocial",
                "nsec": sender_nsec,
                "relays": [relay.url],
                "recipient": recipient_hex,
                "replace": false
            }),
        );
        if response.get("ok") == Some(&Value::Bool(true)) {
            account = response
                .get("account")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            group = response
                .get("group")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            if !group.is_empty() {
                break;
            }
        } else {
            let error = response.get("error").and_then(Value::as_str).unwrap_or("");
            if error != "conversation_index_not_ready" {
                panic!("onboard failed: {error}");
            }
        }
        let _ = helper_ipc(&socket, serde_json::json!({"op": "sync"}));
        let _ = runtime.catch_up_accounts().await;
        tokio::time::sleep(Duration::from_millis(400)).await;
    }
    assert_eq!(
        account, sender_hex,
        "the packaged helper imported a different sender"
    );
    assert!(
        !group.is_empty(),
        "the packaged helper did not establish a conversation"
    );
    let again = helper_ipc(
        &socket,
        serde_json::json!({
            "op": "onboard",
            "operation_id": "initial:smartflowsocial",
            "nsec": sender_nsec,
            "relays": [relay.url],
            "recipient": recipient_hex,
            "replace": false
        }),
    );
    assert_eq!(again.get("reused"), Some(&Value::Bool(true)));
    assert_eq!(
        again.get("group").and_then(Value::as_str),
        Some(group.as_str())
    );
    let group_id = GroupId::new(hex::decode(&group).expect("group hex"));
    let mut welcomed = false;
    for _ in 0..20 {
        let _ = runtime.catch_up_accounts().await;
        if runtime
            .group_members(&recipient_hex, &group_id)
            .await
            .is_ok()
        {
            welcomed = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(400)).await;
    }
    assert!(welcomed, "recipient did not join the packaged conversation");

    let server = Keys::generate();
    let server_hex = server.public_key().to_hex();
    runtime
        .set_native_push_enabled(&recipient_hex, true)
        .await
        .expect("native push");
    runtime
        .upsert_push_registration(
            &recipient_hex,
            PushPlatform::Fcm,
            "executable-token",
            &server_hex,
            Some(relay.url.clone()),
        )
        .await
        .expect("push registration");
    let mut ready = false;
    for _ in 0..40 {
        let _ = runtime.catch_up_accounts().await;
        let _ = helper_ipc(&socket, serde_json::json!({"op": "sync"}));
        let status = helper_ipc(
            &socket,
            serde_json::json!({
                "op": "readiness",
                "account": account,
                "recipient": recipient_hex,
                "group": group
            }),
        );
        if status
            .get("active_recipient_tokens")
            .and_then(Value::as_i64)
            .unwrap_or(0)
            >= 1
        {
            ready = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(400)).await;
    }
    assert!(ready, "packaged sender did not observe a recipient token");

    let decoy = EventBuilder::new(Kind::GiftWrap, "unrelated")
        .tag(Tag::public_key(server.public_key()))
        .finalize(&Keys::generate())
        .expect("decoy");
    post_json(
        &format!("{}/event", http_base(&relay.url)),
        &serde_json::to_value(&decoy).expect("decoy json"),
    );
    let baseline = max_seq(&relay.url);
    let mut watchdog = start_watchdog(
        container.as_ref(),
        &watchdog_bin,
        &listen,
        &db,
        &root,
        &socket,
        &helper_bin,
        &relay.url,
        &sender_nsec,
        &recipient_hex,
        operator,
        &log,
    );
    wait_http(&format!("http://{listen}/healthz"));
    let onboard = Command::new("curl")
        .args([
            "--fail-with-body",
            "-sS",
            "--max-time",
            "15",
            "-H",
            &format!("authorization: Bearer {operator}"),
            "-H",
            "content-type: application/json",
            "--data",
            r#"{"projectId":"smartflowsocial","idempotencyKey":"initial:smartflowsocial"}"#,
            &format!("http://{listen}/v1/diagnostics/marmot/onboard"),
        ])
        .output()
        .unwrap();
    assert!(
        onboard.status.success(),
        "watchdog onboarding API rejected the established identity"
    );
    let onboard: Value = serde_json::from_slice(&onboard.stdout).unwrap();
    assert_eq!(onboard["connected"], true, "{onboard}");
    assert_eq!(onboard["group"], group);
    assert_eq!(
        sql_value(
            &db,
            "SELECT group_id_hex FROM marmot_projects WHERE project_id = 'smartflowsocial'"
        ),
        group,
    );

    let alert = wait_monitor_alert(&db, false).await;
    wait_outbox_settled(&db, &alert).await;
    let text = sql_value(
        &db,
        &format!(
            "select payload_text from alert_outbox where id = '{}'",
            sql_id(&alert)
        ),
    );
    assert!(!text.is_empty(), "the queued alert has no text");
    let trigger = wait_for_trigger(&relay.url, &server, &decoy.id.to_string(), baseline)
        .expect("packaged kind 446 trigger");
    assert!(trigger.seq > baseline);
    let route = runtime
        .group_conversation_snapshot(&recipient_hex, &group_id)
        .await
        .expect("route")
        .group
        .nostr_routing
        .nostr_group_id_hex;
    assert_eq!(route.len(), 64, "nostr group route was not a 32-byte id");
    let group_event = alert_group_event(&relay.url, &server, &route, baseline);
    assert_ne!(group_event.pubkey.to_hex(), account);
    assert!(group_event.verify().is_ok());
    assert!(
        receive_packaged_alert(&runtime, &recipient_hex, &group, &text).await,
        "the official recipient could not decrypt the accepted outage group event {}",
        group_event.id
    );
    let packaged_rows = runtime
        .messages_with_query(
            &recipient_hex,
            AppMessageQuery {
                group_id_hex: Some(group.clone()),
                kinds: Some(vec![9]),
                limit: Some(20),
            },
        )
        .expect("packaged messages");
    let packaged_ids = journal_ids(&root, &alert);
    assert!(packaged_rows.iter().any(|row| {
        row.plaintext == text
            && row.sender.eq_ignore_ascii_case(&account)
            && row.group_id_hex.eq_ignore_ascii_case(&group)
            && packaged_ids.iter().any(|id| id == &row.message_id_hex)
    }));
    let ids = journal_ids(&root, &alert);
    assert!(!ids.is_empty(), "the helper journal has no message id");
    let recorded = sql_value(
        &db,
        &format!(
            "select ifnull(message_event_id,'') from alert_outbox where id = '{}'",
            sql_id(&alert)
        ),
    );
    assert_eq!(recorded, ids[0]);
    let fallback_query = format!(
        "SELECT f.id FROM alert_outbox f JOIN alert_outbox m ON f.incident_id = m.incident_id
         WHERE m.id = '{}' AND f.destination = 'telegram' AND f.logical_id LIKE 'fallback:%'",
        sql_id(&alert)
    );
    let fallback = sql_value(&db, &fallback_query);
    assert!(fallback.starts_with("alt_"));
    wait_outbox_settled(&db, &fallback).await;
    assert_eq!(
        sql_value(
            &db,
            &format!(
                "SELECT message_state || ':' || push_state FROM alert_outbox WHERE id = '{}'",
                sql_id(&alert),
            )
        ),
        "relay_accepted:unobservable"
    );

    watchdog.stop();
    helper.stop();
    if let Some(container) = &mut container {
        container.replace();
    }
    sql_exec(
        &db,
        &format!(
            "update alert_outbox set state = 'retrying', settled_at = null, next_attempt_at = 0 where id = '{}';
             update monitor_state set last_check_at = 0 where monitor_id = 'sfs-web'",
            sql_id(&alert)
        ),
    );
    post_json(
        &format!("{}/control", http_base(&relay.url)),
        &serde_json::json!({"healthReady": true}),
    );
    helper = start_fixture_helper(container.as_ref(), &helper_bin, &root, &socket, &relay.url);
    wait_health(&root.join("health.sock"));
    watchdog = start_watchdog(
        container.as_ref(),
        &watchdog_bin,
        &listen,
        &db,
        &root,
        &socket,
        &helper_bin,
        &relay.url,
        &sender_nsec,
        &recipient_hex,
        operator,
        &log,
    );
    wait_http(&format!("http://{listen}/healthz"));
    wait_outbox_settled(&db, &alert).await;
    let mut reconciled = false;
    for _ in 0..40 {
        let _ = runtime.catch_up_accounts().await;
        let count = plaintext_count(&runtime, &recipient_hex, &group, &text).await;
        let same = journal_ids(&root, &alert) == ids;
        if count == 1 && same {
            reconciled = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    assert!(
        reconciled,
        "restart changed the original application message"
    );
    assert_eq!(
        sql_value(
            &db,
            &format!(
                "select ifnull(message_event_id,'') from alert_outbox where id = '{}'",
                sql_id(&alert)
            ),
        ),
        ids[0]
    );

    let second_alert = wait_monitor_alert(&db, true).await;
    wait_outbox_settled(&db, &second_alert).await;
    assert_ne!(second_alert, alert);
    let second_text = sql_value(
        &db,
        &format!(
            "select payload_text from alert_outbox where id = '{}'",
            sql_id(&second_alert)
        ),
    );
    assert_ne!(second_text, text);
    assert!(
        receive_packaged_alert(&runtime, &recipient_hex, &group, &second_text).await,
        "the official recipient could not decrypt the recovery alert"
    );
    assert_eq!(
        plaintext_count(&runtime, &recipient_hex, &group, &text).await,
        1
    );
    assert_ne!(journal_ids(&root, &second_alert), ids);

    watchdog.stop();
    helper.stop();
    if container.is_some() {
        drop(container);
        let _ = runtime.shutdown_and_close().await;
        let _ = std::fs::remove_dir_all(&recipient_root);
        let _ = std::fs::remove_dir_all(&db_dir);
        return;
    }
    let crash_text = "process crash boundary";
    let mut crashing = start_crash_helper(&helper_bin, &root, &socket, &relay.url);
    wait_health(&root.join("health.sock"));
    let crashed = helper_ipc_result(
        &socket,
        serde_json::json!({
            "op": "send",
            "alert": "alt_process_crash",
            "project": "smartflowsocial",
            "account": account,
            "group": group,
            "text": crash_text,
            "allow": [recipient_hex]
        }),
    );
    assert!(
        crashed.is_err(),
        "the helper answered after it was told to stop"
    );
    let status = crashing.0.wait().expect("crash wait");
    assert_eq!(
        status.code(),
        Some(75),
        "the helper did not exit at the crash boundary"
    );
    let recovered_helper = start_helper(&helper_bin, &root, &socket, &relay.url);
    wait_health(&root.join("health.sock"));
    let recovered = helper_ipc(
        &socket,
        serde_json::json!({
            "op": "send",
            "alert": "alt_process_crash",
            "project": "smartflowsocial",
            "account": account,
            "group": group,
            "text": crash_text,
            "allow": [recipient_hex]
        }),
    );
    assert_eq!(recovered.get("ok"), Some(&Value::Bool(true)));
    let recovered_ids = recovered
        .get("message_ids")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    assert!(
        !recovered_ids.is_empty(),
        "restart did not recover the submitted message"
    );
    let repeated = helper_ipc(
        &socket,
        serde_json::json!({
            "op": "send",
            "alert": "alt_process_crash",
            "project": "smartflowsocial",
            "account": account,
            "group": group,
            "text": crash_text,
            "allow": [recipient_hex]
        }),
    );
    assert_eq!(
        repeated
            .get("message_ids")
            .and_then(Value::as_array)
            .map(Vec::as_slice),
        Some(recovered_ids.as_slice())
    );
    assert_eq!(
        plaintext_count(&runtime, &recipient_hex, &group, crash_text).await,
        1,
        "process restart encrypted the alert a second time"
    );
    drop(recovered_helper);
    assert_eq!(
        crash_and_reconcile(
            &runtime,
            &helper_bin,
            &root,
            &socket,
            &relay.url,
            &account,
            &group,
            &recipient_hex,
            "intent",
            "alt_crash_intent_process",
            "intent was not submitted",
        )
        .await,
        0,
        "a crash before submission encrypted the alert"
    );
    assert_eq!(
        crash_and_reconcile(
            &runtime,
            &helper_bin,
            &root,
            &socket,
            &relay.url,
            &account,
            &group,
            &recipient_hex,
            "submitted",
            "alt_crash_submitted_process",
            "submitted before the result was stored",
        )
        .await,
        1,
        "a crash after MDK admitted the alert did not reconcile to one message"
    );
    let _ = runtime.shutdown_and_close().await;
    let _ = std::fs::remove_dir_all(&root);
    let _ = std::fs::remove_dir_all(&recipient_root);
    let _ = std::fs::remove_dir_all(&db_dir);
}

async fn receive_packaged_alert(
    runtime: &marmot_app::MarmotAppRuntime,
    recipient: &str,
    group: &str,
    text: &str,
) -> bool {
    if wait_plaintext(runtime, recipient, group, text).await {
        return true;
    }
    // Use the official recipient's relay history repair if incremental catch-up missed the event.
    eprintln!("incremental catch-up missed the packaged alert, repairing recipient history");
    runtime
        .repair_full_history(recipient)
        .await
        .expect("official recipient history repair");
    wait_plaintext(runtime, recipient, group, text).await
}

async fn wait_monitor_alert(db: &Path, resolved: bool) -> String {
    let state = if resolved { "closed" } else { "open" };
    let suffix = if resolved { "close" } else { "open" };
    let query = format!(
        "SELECT o.id FROM alert_outbox o JOIN incidents i ON o.incident_id = i.id
         WHERE i.monitor_id = 'sfs-web' AND i.status = '{state}' AND o.destination = 'marmot'
           AND o.dedupe_key LIKE '%:{suffix}:marmot'"
    );
    for _ in 0..60 {
        let alert = sql_value(db, &query);
        if alert.starts_with("alt_") {
            return alert;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    panic!("no Marmot outbox entry for the {state} monitor incident");
}

fn watchdog_binary() -> PathBuf {
    if let Some(path) = std::env::var_os("WATCHDOG_TEST_BINARY") {
        return PathBuf::from(path);
    }
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let status = Command::new("cargo")
        .args([
            "build",
            "--locked",
            "-p",
            "watchdog-native",
            "--bin",
            "nostr-watchdog",
        ])
        .current_dir(&root)
        .status()
        .expect("cargo");
    assert!(status.success(), "nostr-watchdog did not build");
    root.join("target/debug/nostr-watchdog")
}

fn free_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("port");
    listener.local_addr().expect("port").port()
}

struct OwnedProc(Child);

impl OwnedProc {
    fn stop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

impl Drop for OwnedProc {
    fn drop(&mut self) {
        self.stop();
    }
}

struct DockerFixture {
    name: String,
    image: String,
    directory: PathBuf,
    user: String,
    running: bool,
}

impl DockerFixture {
    fn from_environment(directory: &Path) -> Option<Self> {
        let image = std::env::var("WATCHDOG_TEST_IMAGE").ok()?;
        let id = |flag| {
            let output = Command::new("id").arg(flag).output().unwrap();
            assert!(output.status.success());
            String::from_utf8(output.stdout).unwrap().trim().to_owned()
        };
        let uid = id("-u");
        assert_ne!(
            uid, "0",
            "the Docker qualification driver must use an unprivileged host user"
        );
        let mut fixture = Self {
            name: format!("watchdog-fixture-{}", std::process::id()),
            image,
            directory: directory.to_owned(),
            user: format!("{uid}:{}", id("-g")),
            running: false,
        };
        std::fs::create_dir_all(directory).unwrap();
        fixture.start();
        Some(fixture)
    }

    fn start(&mut self) {
        let output = Command::new("docker")
            .args([
                "run",
                "--detach",
                "--network",
                "host",
                "--name",
                &self.name,
                "--user",
                &self.user,
            ])
            .args([
                "--mount",
                &format!("type=bind,src={},dst=/data", self.directory.display()),
            ])
            .args(["--entrypoint", "/bin/sleep", &self.image, "infinity"])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "start image fixture: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        self.running = true;
    }

    fn remove(&mut self) {
        if self.running {
            let status = Command::new("docker")
                .args(["rm", "--force", &self.name])
                .stdout(Stdio::null())
                .status()
                .unwrap();
            assert!(status.success(), "remove image fixture");
            self.running = false;
        }
    }

    fn replace(&mut self) {
        self.remove();
        self.start();
    }
}

impl Drop for DockerFixture {
    fn drop(&mut self) {
        if self.running {
            let _ = Command::new("docker")
                .args(["rm", "--force", &self.name])
                .stdout(Stdio::null())
                .status();
        }
    }
}

fn start_fixture_helper(
    container: Option<&DockerFixture>,
    binary: &Path,
    root: &Path,
    socket: &Path,
    relay: &str,
) -> OwnedProc {
    let Some(container) = container else {
        return start_helper(binary, root, socket, relay);
    };
    let child = Command::new("docker")
        .args([
            "exec",
            &container.name,
            "/usr/local/bin/watchdog-marmot",
            "--root",
            "/data/marmot",
            "--socket",
            "/data/marmot/watchdog.sock",
            "--allow-loopback",
            "--relay",
            relay,
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("image helper");
    OwnedProc(child)
}

fn start_helper(binary: &Path, root: &Path, socket: &Path, relay: &str) -> OwnedProc {
    spawn_helper(binary, root, socket, relay, None)
}

fn start_crash_helper(binary: &Path, root: &Path, socket: &Path, relay: &str) -> OwnedProc {
    spawn_helper(binary, root, socket, relay, Some("accepted"))
}

fn spawn_helper(
    binary: &Path,
    root: &Path,
    socket: &Path,
    relay: &str,
    crash_at: Option<&str>,
) -> OwnedProc {
    let mut command = Command::new(binary);
    if let Some(point) = crash_at {
        command
            .env("WATCHDOG_MARMOT_CRASH_AT", point)
            .env("WATCHDOG_MARMOT_CRASH_EXIT", "1");
    }
    let child = command
        .arg("--root")
        .arg(root)
        .arg("--socket")
        .arg(socket)
        .arg("--allow-loopback")
        .arg("--relay")
        .arg(relay)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("helper");
    OwnedProc(child)
}

fn start_watchdog(
    container: Option<&DockerFixture>,
    binary: &Path,
    listen: &str,
    db: &Path,
    root: &Path,
    socket: &Path,
    helper: &Path,
    relay: &str,
    sender_nsec: &str,
    recipient: &str,
    operator: &str,
    log: &Path,
) -> OwnedProc {
    if let Some(parent) = log.parent() {
        std::fs::create_dir_all(parent).expect("log dir");
    }
    let log_file = std::fs::File::create(log).expect("log");
    let err = log_file.try_clone().expect("log");
    let relay_health = format!("{}/healthcheck", http_base(relay));
    let telegram_endpoint = format!("{}/telegram", http_base(relay));
    let vars = [
        ("OPERATOR_TOKEN", operator),
        (
            "DATABASE_PATH",
            if container.is_some() {
                "/data/watchdog.sqlite"
            } else {
                db.to_str().unwrap()
            },
        ),
        ("LISTEN_ADDR", listen),
        (
            "MARMOT_ROOT",
            if container.is_some() {
                "/data/marmot"
            } else {
                root.to_str().unwrap()
            },
        ),
        (
            "MARMOT_SOCKET",
            if container.is_some() {
                "/data/marmot/watchdog.sock"
            } else {
                socket.to_str().unwrap()
            },
        ),
        (
            "MARMOT_HELPER",
            if container.is_some() {
                "/usr/local/bin/watchdog-marmot"
            } else {
                helper.to_str().unwrap()
            },
        ),
        ("ENABLE_MARMOT", "true"),
        ("ENABLE_NIP17", "false"),
        ("ALERTS_ENABLED", "true"),
        ("WATCHDOG_ENABLED", "true"),
        ("ENVIRONMENT", "test"),
        ("TELEGRAM_CRITICAL_MODE", "nostr_fallback"),
        ("TELEGRAM_BOT_TOKEN", "local-fixture"),
        ("TELEGRAM_CHAT_IDS", r#"{"smartflowsocial":"1"}"#),
        ("WATCHDOG_TEST_TELEGRAM_ENDPOINT", &telegram_endpoint),
        ("ENABLE_SFS_WEB", "true"),
        ("FAILURE_THRESHOLD", "1"),
        ("RECOVERY_THRESHOLD", "1"),
        ("PRIVATE_NETWORK_PROFILE", "true"),
        ("SFS_WEB_READY_URL", &relay_health),
        ("BOOTSTRAP_RELAYS", relay),
        ("SFS_BOT_NSEC", sender_nsec),
        ("ADMIN_NPUB", recipient),
    ];
    let mut command = if let Some(container) = container {
        let mut command = Command::new("docker");
        command.arg("exec");
        for (name, _) in vars {
            command.args(["--env", name]);
        }
        command
            .args(["--env", "HOME=/tmp", &container.name])
            .arg(binary);
        command
    } else {
        let mut command = Command::new(binary);
        command
            .env_clear()
            .env(
                "PATH",
                std::env::var("PATH").unwrap_or_else(|_| "/usr/bin:/bin".into()),
            )
            .env(
                "HOME",
                std::env::var("HOME").unwrap_or_else(|_| "/tmp".into()),
            )
            .env(
                "TMPDIR",
                std::env::var("TMPDIR").unwrap_or_else(|_| "/tmp".into()),
            );
        command
    };
    let child = command
        .envs(vars)
        .stdin(Stdio::null())
        .stdout(Stdio::from(log_file))
        .stderr(Stdio::from(err))
        .spawn()
        .expect("watchdog");
    OwnedProc(child)
}

fn wait_health(path: &Path) {
    for _ in 0..50 {
        if let Ok(stream) = UnixStream::connect(path) {
            let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
            let mut line = String::new();
            if BufReader::new(stream).read_line(&mut line).is_ok() && line.contains("pong") {
                return;
            }
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    panic!("helper health did not answer");
}

fn wait_http(url: &str) {
    for _ in 0..50 {
        let status = Command::new("curl")
            .args(["-fsS", "--max-time", "1", url])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
        if status.map(|code| code.success()).unwrap_or(false) {
            return;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    panic!("watchdog did not listen");
}

fn helper_ipc(socket: &Path, request: Value) -> Value {
    helper_ipc_result(socket, request).expect("helper ipc")
}

fn helper_ipc_result(socket: &Path, request: Value) -> Result<Value, String> {
    let mut stream = UnixStream::connect(socket).map_err(|error| error.to_string())?;
    let _ = stream.set_read_timeout(Some(Duration::from_secs(120)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(10)));
    let mut bytes = serde_json::to_vec(&request).map_err(|error| error.to_string())?;
    bytes.push(b'\n');
    stream
        .write_all(&bytes)
        .map_err(|error| error.to_string())?;
    let mut line = String::new();
    BufReader::new(stream)
        .read_line(&mut line)
        .map_err(|error| error.to_string())?;
    if line.is_empty() {
        return Err("helper_closed".to_string());
    }
    serde_json::from_str(&line).map_err(|error| error.to_string())
}

async fn wait_outbox_settled(db: &Path, alert: &str) {
    let query = format!(
        "SELECT state || ':' || COALESCE(last_error, '') FROM alert_outbox WHERE id = '{}'",
        sql_id(alert)
    );
    let mut state = String::new();
    for _ in 0..170 {
        state = sql_value(db, &query);
        if state.starts_with("relay_accepted:") {
            return;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    panic!("watchdog did not settle the monitor alert: {state}");
}

fn sql_id(id: &str) -> String {
    assert!(
        id.chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '_' || ch == '-'),
        "unexpected alert id"
    );
    id.to_string()
}

fn sql_value(db: &Path, statement: &str) -> String {
    let output = Command::new("sqlite3")
        .arg("-cmd")
        .arg(".timeout 2500")
        .arg(db)
        .arg(statement)
        .output()
        .expect("sqlite3");
    assert!(output.status.success(), "sqlite read failed");
    String::from_utf8_lossy(&output.stdout).trim().to_string()
}

fn sql_exec(db: &Path, statement: &str) {
    let status = Command::new("sqlite3")
        .arg(db)
        .arg(statement)
        .status()
        .expect("sqlite3");
    assert!(status.success(), "sqlite update failed");
}

fn journal_ids(root: &Path, alert: &str) -> Vec<String> {
    let path = root.join("outbox-boundary").join(format!("{alert}.json"));
    let Ok(bytes) = std::fs::read(path) else {
        return Vec::new();
    };
    let Ok(value) = serde_json::from_slice::<Value>(&bytes) else {
        return Vec::new();
    };
    value
        .get("message_ids")
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

async fn crash_and_reconcile(
    runtime: &marmot_app::MarmotAppRuntime,
    helper_bin: &Path,
    root: &Path,
    socket: &Path,
    relay: &str,
    account: &str,
    group: &str,
    recipient: &str,
    point: &str,
    alert: &str,
    text: &str,
) -> usize {
    let mut crashing = spawn_helper(helper_bin, root, socket, relay, Some(point));
    wait_health(&root.join("health.sock"));
    let crashed = helper_ipc_result(
        socket,
        serde_json::json!({
            "op": "send",
            "alert": alert,
            "project": "smartflowsocial",
            "account": account,
            "group": group,
            "text": text,
            "allow": [recipient]
        }),
    );
    assert!(
        crashed.is_err(),
        "{point} returned a response after process exit"
    );
    let status = crashing.0.wait().expect("wait");
    assert_eq!(
        status.code(),
        Some(75),
        "{point} did not exit at the boundary"
    );
    let helper = start_helper(helper_bin, root, socket, relay);
    wait_health(&root.join("health.sock"));
    let recovered = helper_ipc(
        socket,
        serde_json::json!({
            "op": "send",
            "alert": alert,
            "project": "smartflowsocial",
            "account": account,
            "group": group,
            "text": text,
            "allow": [recipient]
        }),
    );
    assert_eq!(
        recovered.get("ok"),
        Some(&Value::Bool(true)),
        "{point} did not reconcile"
    );
    if point != "intent" {
        let ids = recovered.get("message_ids").and_then(Value::as_array);
        assert!(
            ids.is_some_and(|items| !items.is_empty()),
            "{point} lost the admitted message"
        );
    }
    let repeated = helper_ipc(
        socket,
        serde_json::json!({
            "op": "send",
            "alert": alert,
            "project": "smartflowsocial",
            "account": account,
            "group": group,
            "text": text,
            "allow": [recipient]
        }),
    );
    assert_eq!(
        repeated.get("message_ids"),
        recovered.get("message_ids"),
        "{point} changed message ids on the second reconcile"
    );
    let count = plaintext_count(runtime, recipient, group, text).await;
    drop(helper);
    count
}

async fn plaintext_count(
    runtime: &marmot_app::MarmotAppRuntime,
    recipient: &str,
    group: &str,
    text: &str,
) -> usize {
    let _ = runtime.catch_up_accounts().await;
    runtime
        .messages_with_query(
            recipient,
            AppMessageQuery {
                group_id_hex: Some(group.to_string()),
                kinds: Some(vec![9]),
                limit: Some(20),
            },
        )
        .expect("messages")
        .iter()
        .filter(|row| row.plaintext == text && !row.invalidated)
        .count()
}
