use cgka_traits::{KeyPackageSource, MessageId};
use marmot_worker_interop::OfficialRecipient;
use marmot_worker_runtime::Session;
use storage_sqlite::SqliteAccountStorage;

#[tokio::test]
async fn cloud_sender_exchanges_marmot_chats_with_official_sqlite_mdk() {
    let key = [11u8; 32];
    let cloud = Session::generate().expect("cloud account");
    let native = OfficialRecipient::generate().expect("official recipient");
    assert_sqlite(native.storage());

    let mut package = native.fresh_key_package().await.expect("recipient key package");
    assert_eq!(
        package.protocol_profile,
        cgka_traits::group::ProtocolProfile::Current
    );
    package.source = Some(KeyPackageSource {
        event_id: MessageId::new(vec![0x44; 32]),
    });
    cloud
        .configure("watchdog", &native.public_key_hex(), &[], false)
        .expect("bind recipient");
    let (group_id, welcomes) = cloud
        .create_group(
            "create-1",
            "watchdog",
            vec![package],
            vec!["wss://relay.example".into()],
        )
        .await
        .expect("create group");
    assert_eq!(welcomes.len(), 1);
    native
        .join_welcome(welcomes[0].clone())
        .await
        .expect("process welcome");

    let first = cloud
        .send_chat("alert-1", &group_id, "relay down")
        .await
        .expect("first alert");
    let stored = cloud.storage().publication("alert-1").unwrap().unwrap();
    assert_eq!(stored.message_phase, "accepted_pending");
    assert!(!stored.confirmed);
    assert!(cloud.stage_push("alert-1", b"trigger-bytes").is_err());
    assert!(cloud
        .send_chat("alert-1", &cgka_traits::GroupId::new(vec![9; 16]), "relay down")
        .await
        .is_err());
    cloud
        .note_publication("alert-1", true)
        .await
        .expect("record message acceptance");
    let staged = cloud.stage_push("alert-1", b"trigger-bytes").unwrap();
    cloud.note_push("alert-1", "rejected", None).unwrap();
    assert_eq!(cloud.stage_push("alert-1", b"other-trigger").unwrap(), staged);
    assert_eq!(
        native.ingest(first.clone()).await.expect("decrypt first"),
        vec!["relay down".to_owned()]
    );

    let reply = native
        .send_chat(&group_id, "ack")
        .await
        .expect("native reply");
    assert_eq!(
        cloud.ingest(reply).await.expect("decrypt reply"),
        vec!["ack".to_owned()]
    );

    let account = cloud.public_key_hex();
    let sealed = cloud.seal(&key, "watchdog").expect("seal");
    drop(cloud);
    let cloud = Session::open(&key, "watchdog", &account, &sealed).expect("restore");
    let second = cloud
        .send_chat("alert-2", &group_id, "after restart")
        .await
        .expect("send after restore");
    assert_eq!(
        native.ingest(second.clone()).await.expect("decrypt restored"),
        vec!["after restart".to_owned()]
    );
    let repeated = cloud
        .send_chat("alert-2", &group_id, "after restart")
        .await
        .expect("retry");
    assert_eq!(repeated, second);
    assert!(
        cloud
            .send_chat("alert-2", &group_id, "different")
            .await
            .is_err()
    );

    let before = cloud.epoch(&group_id).expect("epoch");
    let (commit, pending) = cloud
        .self_update("rotate-1", &group_id)
        .await
        .expect("stage update");
    let account = cloud.public_key_hex();
    let sealed = cloud.seal(&key, "watchdog").expect("seal staged update");
    drop(cloud);
    let cloud = Session::open(&key, "watchdog", &account, &sealed).expect("restore staged update");
    let (again, again_pending) = cloud
        .self_update("rotate-1", &group_id)
        .await
        .expect("reuse staged update");
    assert_eq!(again, commit);
    assert_eq!(again_pending, pending);
    cloud.confirm("rotate-1").await.expect("confirm update");
    assert!(cloud.epoch(&group_id).expect("new epoch") > before);
    let recipient_before = native.epoch(&group_id).expect("recipient epoch");
    native.ingest(commit).await.expect("accept remote commit");
    native.settle(&group_id).await.expect("apply remote commit");
    assert!(native.epoch(&group_id).expect("recipient epoch") > recipient_before);
    let third = cloud
        .send_chat("alert-3", &group_id, "new epoch")
        .await
        .expect("send in new epoch");
    assert_eq!(
        native.ingest(third).await.expect("decrypt new epoch"),
        vec!["new epoch".to_owned()]
    );
}

#[tokio::test]
async fn recipient_token_gossip_is_admitted_for_the_sender() {
    use marmot_worker_runtime::push::{self, Platform, TokenRecord};
    use nostr::key::{Keys, SecretKey};
    let cloud = Session::generate().expect("cloud");
    let native = OfficialRecipient::generate().expect("native");
    let mut package = native.fresh_key_package().await.expect("package");
    package.source = Some(KeyPackageSource {
        event_id: MessageId::new(vec![0x45; 32]),
    });
    cloud
        .configure("watchdog", &native.public_key_hex(), &["wss://relay.example".into()], false)
        .unwrap();
    let (group_id, welcomes) = cloud
        .create_group("create-1", "watchdog", vec![package], vec!["wss://relay.example".into()])
        .await
        .unwrap();
    native.join_welcome(welcomes[0].clone()).await.unwrap();
    let leaf = native.own_leaf(&group_id).unwrap();
    let server = Keys::new(SecretKey::from_slice(&[9u8; 32]).unwrap());
    let server_hex = hex::encode(server.public_key().to_bytes());
    let encrypted = push::encrypt_token(Platform::Fcm, b"fcm-device-token", &server_hex).unwrap();
    let mut record = TokenRecord {
        group_id_hex: hex::encode(group_id.as_slice()),
        member_id_hex: native.public_key_hex(),
        leaf_index: leaf,
        platform: Platform::Fcm,
        token_fingerprint: push::token_fingerprint(Platform::Fcm, b"fcm-device-token"),
        server_pubkey_hex: server_hex,
        relay_hint: Some("wss://relay.example".into()),
        owner_ts: 10,
        encrypted_token: encrypted,
        owner_sig: String::new(),
        removed: false,
    };
    record.owner_sig = push::sign_owner_proof(native.keys(), &record, false).unwrap();
    let content = serde_json::json!({
        "v": "marmot-push-v1",
        "tokens": [{
            "member_id_hex": record.member_id_hex,
            "leaf_index": record.leaf_index,
            "platform": "fcm",
            "token_fingerprint": record.token_fingerprint,
            "server_pubkey_hex": record.server_pubkey_hex,
            "relay_hint": record.relay_hint,
            "encrypted_token": base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &record.encrypted_token),
            "owner_ts": record.owner_ts,
            "owner_sig": record.owner_sig
        }]
    })
    .to_string();
    let message = native.send_app(&group_id, 447, &content).await.unwrap();
    cloud.ingest(message).await.unwrap();
    let wakes = cloud.storage().wakes().unwrap();
    let selected = cloud.select_push_tokens(&group_id).unwrap();
    assert!(
        !selected.is_empty(),
        "leaf={leaf} wakes={} selected={}",
        wakes.len(),
        selected.len()
    );
    assert!(selected.iter().all(|wake| wake.leaf_index == leaf));
}

#[tokio::test]
async fn an_unobserved_leaf_is_not_authorized_and_a_second_device_is_not_a_new_account() {
    use marmot_worker_runtime::push::{self, Platform, TokenRecord};
    use nostr::key::{Keys, SecretKey};
    let cloud = Session::generate().unwrap();
    let native = OfficialRecipient::generate().unwrap();
    let mut package = native.fresh_key_package().await.unwrap();
    package.source = Some(KeyPackageSource {
        event_id: MessageId::new(vec![0x46; 32]),
    });
    cloud
        .configure("watchdog", &native.public_key_hex(), &["wss://relay.example".into()], false)
        .unwrap();
    let (group_id, welcomes) = cloud
        .create_group("create-1", "watchdog", vec![package], vec!["wss://relay.example".into()])
        .await
        .unwrap();
    native.join_welcome(welcomes[0].clone()).await.unwrap();
    let leaf = native.own_leaf(&group_id).unwrap();
    let members = cloud.member_ids(&group_id).unwrap();
    assert_eq!(members.len(), 2);
    let server = Keys::new(SecretKey::from_slice(&[8u8; 32]).unwrap());
    let server_hex = hex::encode(server.public_key().to_bytes());
    let mut records = Vec::new();
    for (index, token) in [(leaf, &b"device-a"[..]), (leaf + 9, &b"device-b"[..])] {
        let encrypted = push::encrypt_token(Platform::Fcm, token, &server_hex).unwrap();
        let mut record = TokenRecord {
            group_id_hex: hex::encode(group_id.as_slice()),
            member_id_hex: native.public_key_hex(),
            leaf_index: index,
            platform: Platform::Fcm,
            token_fingerprint: push::token_fingerprint(Platform::Fcm, token),
            server_pubkey_hex: server_hex.clone(),
            relay_hint: Some("wss://relay.example".into()),
            owner_ts: 11,
            encrypted_token: encrypted,
            owner_sig: String::new(),
            removed: false,
        };
        record.owner_sig = push::sign_owner_proof(native.keys(), &record, false).unwrap();
        records.push(record);
    }
    let content = serde_json::json!({
        "v": "marmot-push-v1",
        "tokens": records.iter().map(|record| serde_json::json!({
            "member_id_hex": record.member_id_hex,
            "leaf_index": record.leaf_index,
            "platform": "fcm",
            "token_fingerprint": record.token_fingerprint,
            "server_pubkey_hex": record.server_pubkey_hex,
            "relay_hint": record.relay_hint,
            "encrypted_token": base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &record.encrypted_token),
            "owner_ts": record.owner_ts,
            "owner_sig": record.owner_sig
        })).collect::<Vec<_>>()
    })
    .to_string();
    cloud
        .ingest(native.send_app(&group_id, 447, &content).await.unwrap())
        .await
        .unwrap();
    let selected = cloud.select_push_tokens(&group_id).unwrap();
    assert_eq!(selected.len(), 1);
    assert_eq!(selected[0].leaf_index, leaf);
    cloud
        .storage()
        .observe_leaf(
            &hex::encode(group_id.as_slice()),
            &native.public_key_hex(),
            leaf + 9,
            cloud.epoch(&group_id).unwrap(),
        )
        .unwrap();
    let mut second = records.clone();
    for record in second.iter_mut() {
        record.owner_ts = 12;
        record.owner_sig = push::sign_owner_proof(native.keys(), record, false).unwrap();
    }
    let second_content = serde_json::json!({
        "v": "marmot-push-v1",
        "tokens": second.iter().map(|record| serde_json::json!({
            "member_id_hex": record.member_id_hex,
            "leaf_index": record.leaf_index,
            "platform": "fcm",
            "token_fingerprint": record.token_fingerprint,
            "server_pubkey_hex": record.server_pubkey_hex,
            "relay_hint": record.relay_hint,
            "encrypted_token": base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &record.encrypted_token),
            "owner_ts": record.owner_ts,
            "owner_sig": record.owner_sig
        })).collect::<Vec<_>>()
    })
    .to_string();
    cloud
        .ingest(native.send_app(&group_id, 447, &second_content).await.unwrap())
        .await
        .unwrap();
    let selected = cloud.select_push_tokens(&group_id).unwrap();
    assert_eq!(selected.len(), 2);
    assert!(selected.iter().all(|wake| wake.member_id_hex == native.public_key_hex()));
    assert_eq!(cloud.member_ids(&group_id).unwrap().len(), 2);
    cloud
        .storage()
        .retire_leaf(&hex::encode(group_id.as_slice()), leaf)
        .unwrap();
    let selected = cloud.select_push_tokens(&group_id).unwrap();
    assert!(selected.iter().all(|wake| wake.leaf_index != leaf));
    assert_eq!(selected.len(), 1);
}

#[tokio::test]
async fn a_persisted_group_is_not_onboarded_until_the_welcome_is_accepted() {
    let key = [12u8; 32];
    let cloud = Session::generate().unwrap();
    let native = OfficialRecipient::generate().unwrap();
    let mut package = native.fresh_key_package().await.unwrap();
    package.source = Some(KeyPackageSource {
        event_id: MessageId::new(vec![0x47; 32]),
    });
    let replacement = native.fresh_key_package().await.unwrap();
    cloud
        .configure("watchdog", &native.public_key_hex(), &["wss://relay.example".into()], false)
        .unwrap();
    let (_group, welcomes) = cloud
        .create_group(
            "onboard-1",
            "watchdog",
            vec![package],
            vec!["wss://relay.example".into()],
        )
        .await
        .unwrap();
    let pending = cloud.onboarding_view().unwrap();
    assert_eq!(pending["groupPersisted"], true);
    assert_eq!(pending["welcomePublicationPending"], true);
    assert_eq!(pending["welcomeAccepted"], false);
    assert_eq!(pending["conversationReady"], false);
    assert_eq!(pending["completion"], "pending");
    let account = cloud.public_key_hex();
    let sealed = cloud.seal(&key, "watchdog").unwrap();
    drop(cloud);
    let cloud = Session::open(&key, "watchdog", &account, &sealed).unwrap();
    let stored = cloud.storage().welcome_publication().unwrap().unwrap();
    assert_eq!(stored.welcomes[0], welcomes[0]);
    assert_eq!(stored.message_phase, "accepted_pending");
    let again = cloud
        .create_group(
            "onboard-2",
            "watchdog",
            vec![replacement],
            vec!["wss://other.example".into()],
        )
        .await
        .expect_err("a new operation must not replace the group");
    assert!(again.to_string().contains("conversation already exists"), "{again}");
    assert_eq!(
        cloud.storage().welcome_publication().unwrap().unwrap().welcomes[0],
        welcomes[0]
    );
    let event_id = marmot_worker_runtime::Session::transport_json(&welcomes[0])
        .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned();
    cloud
        .note_message_outcome("onboard-1", "rejected", &event_id, "wss://relay.example", "attempt-1")
        .await
        .unwrap();
    assert_eq!(
        cloud.storage().welcome_publication().unwrap().unwrap().message_phase,
        "rejected"
    );
    assert_eq!(cloud.onboarding_view().unwrap()["welcomeAccepted"], false);
    cloud
        .note_message_outcome(
            "onboard-1",
            "relay_accepted",
            &event_id,
            "wss://relay.example",
            "attempt-2",
        )
        .await
        .unwrap();
    let ready = cloud.onboarding_view().unwrap();
    assert_eq!(ready["welcomeAccepted"], true);
    assert_eq!(ready["recipientParticipationObserved"], false);
    assert_eq!(ready["conversationReady"], false);
    let other = Session::generate().unwrap();
    assert!(Session::open(&key, "watchdog", &other.public_key_hex(), &sealed).is_err());
}

fn assert_sqlite(storage: &SqliteAccountStorage) {
    let _ = storage;
}
