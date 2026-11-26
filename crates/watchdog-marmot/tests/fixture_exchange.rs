//! Sender path is the watchdog helper. The recipient is an official
//! `MarmotApp` runtime, not a second helper. Both talk to the loopback
//! fixture relay. The test prints no keys.

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
    std::env::temp_dir().join(format!(
        "watchdog-{label}-{}-{n}",
        std::process::id()
    ))
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
    let script = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../scripts/fixture-relay.mjs");
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

#[test]
fn helper_message_decrypts_in_an_official_runtime_and_survives_restart() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .thread_stack_size(8 * 1024 * 1024)
        .enable_all()
        .build()
        .expect("runtime");
    runtime.block_on(exchange());
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
    post_json(&format!("{}/event", http_base(&relay.url)), &serde_json::to_value(&decoy).expect("decoy json"));
    let baseline = max_seq(&relay.url);

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
    assert!(first.get("push_event_id").is_none() || first.get("push_event_id") == Some(&Value::Null));
    let trigger = wait_for_trigger(&relay.url, &server, &decoy.id.to_string(), baseline)
        .expect("kind 446 trigger");
    assert_message_precedes_trigger(&relay.url, baseline, trigger.seq);
    assert_routed_token(&runtime, &recipient_hex, &group_id, &server_hex, b"fixture-token").await;

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
    assert_eq!(second.get("operation_id").and_then(Value::as_str), Some(alert));

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
    let expected =
        marmot_app::push_token_fingerprint(PushPlatform::Fcm, b"fixture-token-replaced");
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
    let replaced_trigger = wait_for_new_trigger(&relay.url, &server, &before_replace)
        .expect("replacement trigger");
    assert_ne!(replaced_trigger.id, trigger.id, "replacement reused the gift-wrap id");
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
            .any(|(_seq, event)| p_tag(&event).eq_ignore_ascii_case(&unrelated.public_key().to_hex())),
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
    assert_ne!(
        rejected.get("push").and_then(Value::as_str),
        Some("relay_accepted")
    );
    assert!(wait_plaintext(&runtime, &recipient_hex, &group, "watchdog rejected trigger").await);
    tokio::time::sleep(Duration::from_millis(800)).await;
    assert_eq!(max_seq_kind(&relay.url, 1059), before_reject);
    if rejected.get("push").and_then(Value::as_str) != Some("rejected") {
        panic!(
            "relay rejection was not observed as a push failure ({})",
            rejected.get("push").and_then(Value::as_str).unwrap_or("")
        );
    }
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
            .send_once(
                &alert_id,
                &account,
                &group,
                &body,
                &[recipient_hex.clone()],
            )
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
    let Ok(raw) = base64::engine::general_purpose::STANDARD.decode(unwrapped.rumor.content.as_bytes())
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

fn assert_message_precedes_trigger(url: &str, baseline: u64, trigger_seq: u64) {
    let order = get_json(&format!("{}/order", http_base(url)));
    let preceded = order.as_array().is_some_and(|items| {
        items.iter().any(|item| {
            let seq = item.get("seq").and_then(Value::as_u64).unwrap_or(0);
            let kind = item.get("kind").and_then(Value::as_u64).unwrap_or(0);
            kind != 1059 && seq > baseline && seq < trigger_seq
        })
    });
    assert!(
        preceded,
        "no application event was stored before the gift wrap"
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
        if ready
            .get("active_recipient_tokens")
            .and_then(Value::as_i64)
            == Some(expected)
        {
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
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .thread_stack_size(8 * 1024 * 1024)
        .enable_all()
        .build()
        .expect("runtime");
    runtime.block_on(public_import());
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
fn packaged_binaries_deliver_reconcile_and_send_again() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .thread_stack_size(8 * 1024 * 1024)
        .enable_all()
        .build()
        .expect("runtime");
    runtime.block_on(executable_exchange());
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
    let root = temp_root("exec-sender");
    let recipient_root = temp_root("exec-recipient");
    let db_dir = temp_root("exec-db");
    let db = db_dir.join("watchdog.sqlite");
    let socket = root.join("watchdog.sock");
    let log = db_dir.join("watchdog.log");
    let helper_bin = PathBuf::from(env!("CARGO_BIN_EXE_watchdog-marmot"));
    let watchdog_bin = watchdog_binary();
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

    let mut helper = start_helper(&helper_bin, &root, &socket, &relay.url);
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
    assert_eq!(account, sender_hex, "the packaged helper imported a different sender");
    assert!(!group.is_empty(), "the packaged helper did not establish a conversation");
    let group_id = GroupId::new(hex::decode(&group).expect("group hex"));
    let mut welcomed = false;
    for _ in 0..20 {
        let _ = runtime.catch_up_accounts().await;
        if runtime.group_members(&recipient_hex, &group_id).await.is_ok() {
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
    let first = post_alert(&listen, operator);
    let alert = first
        .get("alertId")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    assert!(
        alert.starts_with("alt_"),
        "alert was not accepted ({})",
        first.get("error").and_then(Value::as_str).unwrap_or("no_alert")
    );
    let text = sql_value(
        &db,
        &format!("select payload_text from alert_outbox where id = '{}'", sql_id(&alert)),
    );
    assert!(!text.is_empty(), "the queued alert has no text");
    assert!(
        wait_plaintext(&runtime, &recipient_hex, &group, &text).await,
        "packaged alert was not decrypted ({})",
        sql_value(
            &db,
            &format!(
                "select ifnull(state,'') || ' ' || ifnull(last_error,'') from alert_outbox where id = '{}'",
                sql_id(&alert)
            ),
        )
    );
    let trigger = wait_for_trigger(&relay.url, &server, &decoy.id.to_string(), baseline)
        .expect("packaged kind 446 trigger");
    assert_message_precedes_trigger(&relay.url, baseline, trigger.seq);
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

    watchdog.stop();
    helper.stop();
    sql_exec(
        &db,
        &format!(
            "update alert_outbox set next_attempt_at = 0 where id = '{}'",
            sql_id(&alert)
        ),
    );
    helper = start_helper(&helper_bin, &root, &socket, &relay.url);
    wait_health(&root.join("health.sock"));
    watchdog = start_watchdog(
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
    assert!(reconciled, "restart changed the original application message");
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

    let second = post_alert(&listen, operator);
    let second_alert = second
        .get("alertId")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    assert!(second_alert.starts_with("alt_") && second_alert != alert);
    let second_text = sql_value(
        &db,
        &format!(
            "select payload_text from alert_outbox where id = '{}'",
            sql_id(&second_alert)
        ),
    );
    assert_ne!(second_text, text);
    assert!(wait_plaintext(&runtime, &recipient_hex, &group, &second_text).await);
    assert_eq!(
        plaintext_count(&runtime, &recipient_hex, &group, &text).await,
        1
    );
    assert_ne!(journal_ids(&root, &second_alert), ids);

    watchdog.stop();
    helper.stop();
    let _ = runtime.shutdown_and_close().await;
    let _ = std::fs::remove_dir_all(&root);
    let _ = std::fs::remove_dir_all(&recipient_root);
    let _ = std::fs::remove_dir_all(&db_dir);
}

fn watchdog_binary() -> PathBuf {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target/debug/nostr-watchdog");
    if path.exists() {
        return path;
    }
    let status = Command::new("cargo")
        .args(["build", "-p", "watchdog-native", "--bin", "nostr-watchdog"])
        .current_dir(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../.."))
        .status()
        .expect("cargo");
    assert!(status.success(), "nostr-watchdog did not build");
    path
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

fn start_helper(binary: &Path, root: &Path, socket: &Path, relay: &str) -> OwnedProc {
    let child = Command::new(binary)
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
    let child = Command::new(binary)
        .env_clear()
        .env(
            "PATH",
            std::env::var("PATH").unwrap_or_else(|_| "/usr/bin:/bin".to_string()),
        )
        .env(
            "HOME",
            std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string()),
        )
        .env(
            "TMPDIR",
            std::env::var("TMPDIR").unwrap_or_else(|_| "/tmp".to_string()),
        )
        .env("OPERATOR_TOKEN", operator)
        .env("DATABASE_PATH", db)
        .env("LISTEN_ADDR", listen)
        .env("MARMOT_ROOT", root)
        .env("MARMOT_SOCKET", socket)
        .env("MARMOT_HELPER", helper)
        .env("ENABLE_MARMOT", "true")
        .env("ENABLE_NIP17", "false")
        .env("ALERTS_ENABLED", "true")
        .env("WATCHDOG_ENABLED", "true")
        .env("BOOTSTRAP_RELAYS", relay)
        .env("SFS_BOT_NSEC", sender_nsec)
        .env("ADMIN_NPUB", recipient)
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
    let mut stream = UnixStream::connect(socket).expect("helper socket");
    let _ = stream.set_read_timeout(Some(Duration::from_secs(120)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(10)));
    let mut bytes = serde_json::to_vec(&request).expect("ipc");
    bytes.push(b'\n');
    stream.write_all(&bytes).expect("ipc write");
    let mut line = String::new();
    BufReader::new(stream).read_line(&mut line).expect("ipc read");
    serde_json::from_str(&line).expect("ipc json")
}

fn post_alert(listen: &str, operator: &str) -> Value {
    let output = Command::new("curl")
        .args([
            "-sS",
            "--max-time",
            "120",
            "-X",
            "POST",
            "-H",
            &format!("authorization: Bearer {operator}"),
            "-H",
            "content-type: application/json",
            "-d",
            r#"{"projectId":"smartflowsocial","transport":"marmot"}"#,
            &format!("http://{listen}/v1/diagnostics/test-alert"),
        ])
        .output()
        .expect("curl");
    serde_json::from_slice(&output.stdout).unwrap_or(Value::Null)
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
