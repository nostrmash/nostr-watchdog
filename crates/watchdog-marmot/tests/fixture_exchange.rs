//! Sender path is the watchdog helper. The recipient is an official
//! `MarmotApp` runtime, not a second helper. Both talk to the loopback
//! fixture relay. The test prints no keys.

use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use cgka_traits::GroupId;
use marmot_app::{AccountSetupRequest, AppMessageQuery, MarmotApp, MarmotAppConfig};
use nostr::prelude::{Keys, ToBech32};
use zeroize::Zeroizing;

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
    let sender_root = std::env::temp_dir().join(format!("watchdog-sender-{}", std::process::id()));
    let recipient_root =
        std::env::temp_dir().join(format!("watchdog-recipient-{}", std::process::id()));
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

    let alert = "alt_fixture_exchange";
    let text = "watchdog fixture alert";
    let first = session
        .send_once(alert, &account, &group, text, &[recipient_hex.clone()])
        .await
        .expect("send");
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

    session.shutdown().await.expect("shutdown");
    drop(session);
    let resumed = watchdog_marmot::open(&sender_root, &relays, true).expect("reopen");
    let second = resumed
        .send_once(alert, &account, &group, text, &[recipient_hex.clone()])
        .await
        .expect("resend");
    let second_ids = second
        .get("message_ids")
        .and_then(|value| value.as_array())
        .cloned()
        .unwrap_or_default();
    assert_eq!(first_ids, second_ids);
    let _ = resumed.shutdown().await;
    let _ = std::fs::remove_dir_all(&sender_root);
    let _ = std::fs::remove_dir_all(&recipient_root);
}
