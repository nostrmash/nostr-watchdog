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
    let (group_id, welcomes) = cloud
        .create_group(
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

    let sealed = cloud.seal(&key).expect("seal");
    drop(cloud);
    let cloud = Session::open(&key, &sealed).expect("restore");
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
    let sealed = cloud.seal(&key).expect("seal staged update");
    drop(cloud);
    let cloud = Session::open(&key, &sealed).expect("restore staged update");
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

fn assert_sqlite(storage: &SqliteAccountStorage) {
    let _ = storage;
}
