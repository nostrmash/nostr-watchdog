//! One Marmot account-device backed by [`mdk_do_storage::MemoryMdkStorage`].
//!
//! Each call builds an official [`cgka_engine::Engine`], hydrates stored groups,
//! and drops the engine before the caller seals the snapshot. The engine is
//! the only MLS implementation. This crate does not publish to relays.

pub mod clock;
pub mod inbox;
pub mod publication;
pub mod push;

pub use mdk_do_storage::{OperationTombstone, ServerRelays, StoredWake};

use std::sync::Arc;

use cgka_engine::account_identity_proof::{
    AccountIdentityProofRequest, AccountIdentityProofSigner,
};
use cgka_engine::{Engine, EngineBuilder, FeatureRegistry};
use cgka_traits::app_event::{MARMOT_APP_EVENT_KIND_CHAT, MarmotAppEvent};
use cgka_traits::app_components::{
    AppComponentData, NOSTR_ROUTING_COMPONENT_ID, NostrRoutingV1, default_group_components,
    encode_nostr_routing_v1,
};
use cgka_traits::group::ProtocolProfile;
use cgka_traits::maintenance::PeriodicMaintenancePolicy;
use cgka_traits::storage::{GroupStorage, MaintenanceStorage, MessageStorage};
use cgka_traits::{
    CgkaEngine, CreateGroupRequest, EpochId, GroupEvent, GroupId, KeyPackage, MemberId,
    PendingStateRef, SendIntent, SendResult, TransportMessage,
};
use k256::schnorr::SigningKey;
use k256::schnorr::signature::hazmat::PrehashSigner;
use mdk_do_storage::{
    AccountBinding, MemoryMdkStorage, PersistError, PreparedPublication, PublicationRecord, SealBinding,
};
use nostr::key::{Keys, SecretKey};
use sha2::{Digest, Sha256};
use transport_nostr_peeler::NostrMlsPeeler;

#[derive(Debug, thiserror::Error)]
pub enum SessionError {
    #[error("storage: {0}")]
    Storage(String),
    #[error("engine: {0}")]
    Engine(String),
    #[error("alert {alert_id} is already bound to a different payload")]
    AlertConflict { alert_id: String },
    #[error("publication {0} is missing")]
    MissingPublication(String),
    #[error("randomness failed")]
    Random,
    #[error("account secret does not match the Nostr identity")]
    IdentityMismatch,
    #[error("operation {operation_id} is already bound to a different group or kind")]
    OperationConflict { operation_id: String },
    #[error("operation {0} is retired and cannot be encrypted again")]
    Retired(String),
    #[error("push requires an accepted application message")]
    PushBeforeAcceptance,
    #[error("recipient is not a current group member")]
    RecipientAbsent,
    #[error("group contains a member outside the authorized set")]
    UnauthorizedMember,
}

pub struct Session {
    storage: MemoryMdkStorage,
    keys: Keys,
    proof: Arc<ProofSigner>,
}

impl Session {
    pub fn generate() -> Result<Self, SessionError> {
        let mut secret = [0u8; 32];
        for _ in 0..8 {
            getrandom::getrandom(&mut secret).map_err(|_| SessionError::Random)?;
            if let Ok(session) = Self::bind(MemoryMdkStorage::empty(), secret) {
                return Ok(session);
            }
        }
        Err(SessionError::IdentityMismatch)
    }

    /// Import an existing project sender secret. The public key must match the
    /// Nostr identity derived from those 32 bytes.
    pub fn import(secret: [u8; 32]) -> Result<Self, SessionError> {
        Self::bind(MemoryMdkStorage::empty(), secret)
    }

    pub fn open(
        storage_key: &[u8; 32],
        project_id: &str,
        account_hex: &str,
        sealed: &[u8],
    ) -> Result<Self, SessionError> {
        let document = mdk_do_storage::open_sealed(
            storage_key,
            SealBinding {
                project_id,
                account_hex,
            },
            sealed,
        )
        .map_err(persist)?;
        let storage = MemoryMdkStorage::from_document(document).map_err(persist)?;
        let secret = storage
            .account_secret()
            .ok_or_else(|| SessionError::Storage("account secret is missing".into()))?;
        let session = Self::bind(storage, secret)?;
        if session.public_key_hex() != account_hex.to_ascii_lowercase() {
            return Err(SessionError::IdentityMismatch);
        }
        Ok(session)
    }

    pub fn seal(&self, storage_key: &[u8; 32], project_id: &str) -> Result<Vec<u8>, SessionError> {
        let document = self.storage.to_document().map_err(persist)?;
        mdk_do_storage::seal(
            storage_key,
            SealBinding {
                project_id,
                account_hex: &self.public_key_hex(),
            },
            &document,
        )
        .map_err(persist)
    }

    /// Observers queued by MDK. Run them only after the Durable Object
    /// compare-and-swap commits. A losing writer drops them unrun.
    pub fn take_commit_hooks(&self) -> Vec<Box<dyn FnOnce() + Send + 'static>> {
        self.storage.drain_commit_hooks()
    }

    pub fn public_key_hex(&self) -> String {
        hex::encode(self.keys.public_key().to_bytes())
    }

    pub fn storage(&self) -> &MemoryMdkStorage {
        &self.storage
    }

    pub fn revision(&self) -> Result<u64, SessionError> {
        self.storage.revision().map_err(map_storage)
    }

    pub fn binding(&self) -> Result<AccountBinding, SessionError> {
        self.storage.binding().map_err(map_storage)
    }

    /// Bind this Durable Object to one project, recipient, and relay set.
    /// A different recipient is refused once a group exists.
    pub fn configure(
        &self,
        project_id: &str,
        recipient_hex: &str,
        relays: &[String],
        replace: bool,
    ) -> Result<bool, SessionError> {
        let existing = self.binding()?;
        let reused = !existing.project_id.is_empty();
        self.storage
            .set_binding(
                AccountBinding {
                    project_id: project_id.to_owned(),
                    recipient_hex: recipient_hex.to_ascii_lowercase(),
                    extra_recipients: existing.extra_recipients,
                    relays: if relays.is_empty() {
                        existing.relays
                    } else {
                        relays.to_vec()
                    },
                    welcome_relays: existing.welcome_relays,
                    nostr_group_hex: existing.nostr_group_hex,
                    group_id_hex: existing.group_id_hex,
                },
                replace,
            )
            .map_err(map_storage)?;
        Ok(reused)
    }

    pub async fn fresh_key_package(&self) -> Result<KeyPackage, SessionError> {
        let mut engine = self.engine()?;
        let package = engine.fresh_key_package().await.map_err(map_engine)?;
        self.note_epochs()?;
        Ok(package)
    }

    pub async fn create_group(
        &self,
        operation_id: &str,
        name: &str,
        members: Vec<KeyPackage>,
        relays: Vec<String>,
    ) -> Result<(GroupId, Vec<TransportMessage>), SessionError> {
        if let Some(existing) = self.storage.publication(operation_id).map_err(map_storage)? {
            if existing.operation_kind != "welcome" {
                return Err(SessionError::OperationConflict {
                    operation_id: operation_id.to_owned(),
                });
            }
            let welcomes = if existing.welcomes.is_empty() {
                vec![existing.message.clone()]
            } else {
                existing.welcomes.clone()
            };
            return Ok((existing.group_id, welcomes));
        }
        if self
            .binding()?
            .group_id_hex
            .as_deref()
            .is_some_and(|value| !value.is_empty())
        {
            return Err(SessionError::Engine(
                "conversation already exists".into(),
            ));
        }
        let mut nostr_group_id = [0u8; 32];
        getrandom::getrandom(&mut nostr_group_id).map_err(|_| SessionError::Random)?;
        let routing = NostrRoutingV1::new(nostr_group_id, relays.clone())
            .map_err(|error| SessionError::Engine(error))?;
        let routing_bytes = encode_nostr_routing_v1(&routing)
            .map_err(|error| SessionError::Engine(error))?;
        let mut engine = self.engine()?;
        let (group_id, result) = engine
            .create_group(CreateGroupRequest {
                name: name.to_owned(),
                description: "watchdog marmot sender".into(),
                members,
                required_features: Vec::new(),
                app_components: vec![AppComponentData {
                    component_id: NOSTR_ROUTING_COMPONENT_ID,
                    data: routing_bytes,
                }],
                initial_admins: Vec::new(),
            })
            .await
            .map_err(map_engine)?;
        let (welcomes, pending, needs_confirm) = match result {
            SendResult::FoundingGroupCreated { welcomes } => (welcomes, None, false),
            SendResult::GroupCreated { welcomes, pending } => {
                (welcomes, Some(pending.as_u64()), true)
            }
            other => {
                return Err(SessionError::Engine(format!(
                    "group creation returned {other:?}"
                )));
            }
        };
        drop(engine);
        let welcome = welcomes
            .first()
            .cloned()
            .ok_or_else(|| SessionError::Engine("group creation produced no welcome".into()))?;
        self.storage
            .note_group_route(
                &hex::encode(group_id.as_slice()),
                &hex::encode(nostr_group_id),
                &relays,
            )
            .map_err(map_storage)?;
        let mut binding = self.binding()?;
        binding.group_id_hex = Some(hex::encode(group_id.as_slice()));
        binding.nostr_group_hex = Some(hex::encode(nostr_group_id));
        binding.welcome_relays = relays;
        self.storage.set_binding(binding, false).map_err(map_storage)?;
        self.storage
            .put_publication(blank_publication(
                operation_id,
                "welcome",
                hash_text(operation_id),
                group_id.clone(),
                welcome,
                pending,
                needs_confirm,
                welcomes.clone(),
                "not_required",
            ))
            .map_err(map_storage)?;
        self.note_epochs()?;
        let _ = self.storage.bump_revision().map_err(map_storage)?;
        Ok((group_id, welcomes))
    }

    pub async fn join_welcome(&self, welcome: TransportMessage) -> Result<(), SessionError> {
        let mut engine = self.engine()?;
        let _joined = engine.join_welcome(welcome).await.map_err(map_engine)?;
        self.note_epochs()?;
        let _ = self.storage.bump_revision().map_err(map_storage)?;
        Ok(())
    }

    pub async fn ingest_event(&self, event: serde_json::Value) -> Result<Vec<String>, SessionError> {
        let parsed: transport_nostr_peeler::NostrTransportEvent = serde_json::from_value(event)
            .map_err(|error| SessionError::Engine(error.to_string()))?;
        let message = parsed
            .to_transport_message()
            .map_err(|error| SessionError::Engine(error.to_string()))?;
        self.ingest(message).await
    }

    pub async fn ingest(&self, message: TransportMessage) -> Result<Vec<String>, SessionError> {
        let mut engine = self.engine()?;
        let prior = engine.drain_events();
        self.storage
            .delete_pending_application_events(&application_event_ids(&prior))
            .map_err(map_storage)?;
        engine.ingest(message).await.map_err(map_engine)?;
        let events = engine.drain_events();
        let ids = application_event_ids(&events);
        drop(engine);
        self.storage
            .delete_pending_application_events(&ids)
            .map_err(map_storage)?;
        let mut chats = Vec::new();
        for event in events {
            match event {
                GroupEvent::GroupMemberLeavesRemoved {
                    group_id, leaves, ..
                } => {
                    let group_hex = hex::encode(group_id.as_slice());
                    for leaf in leaves {
                        self.storage
                            .retire_leaf(&group_hex, leaf.leaf_index)
                            .map_err(map_storage)?;
                    }
                }
                GroupEvent::MessageReceived {
                    payload,
                    group_id,
                    sender_leaf_index,
                    sender,
                    epoch,
                    ..
                } => {
                    let sender_hex = hex::encode(sender.as_slice());
                    if let Some(leaf) = sender_leaf_index {
                        self.storage
                            .observe_leaf(
                                &hex::encode(group_id.as_slice()),
                                &sender_hex,
                                leaf,
                                epoch.0,
                            )
                            .map_err(map_storage)?;
                    }
                    if let Ok(app) = MarmotAppEvent::decode(&payload) {
                        if app.kind == MARMOT_APP_EVENT_KIND_CHAT {
                            chats.push(app.content.clone());
                        }
                        if matches!(app.kind, 447 | 448 | 449) {
                            self.observe_gossip(
                                &group_id,
                                app.kind,
                                &app.content,
                                sender_leaf_index,
                                &sender_hex,
                            )?;
                        }
                    }
                }
                _ => {}
            }
        }
        self.note_epochs()?;
        let _ = self.storage.bump_revision().map_err(map_storage)?;
        Ok(chats)
    }

    /// Encrypt one chat alert. The same alert id and text returns the original
    /// ciphertext. A different text for that id fails closed.
    pub async fn send_chat(
        &self,
        alert_id: &str,
        group_id: &GroupId,
        text: &str,
    ) -> Result<TransportMessage, SessionError> {
        let payload_sha256 = hash_text(text);
        if let Some(retired) = self.storage.tombstone(alert_id).map_err(map_storage)? {
            if retired.payload_sha256 != payload_sha256
                || retired.group_id != *group_id
                || retired.operation_kind != "chat"
            {
                return Err(SessionError::OperationConflict {
                    operation_id: alert_id.to_owned(),
                });
            }
            return Err(SessionError::Retired(alert_id.to_owned()));
        }
        if let Some(existing) = self.storage.publication(alert_id).map_err(map_storage)? {
            if existing.payload_sha256 != payload_sha256 {
                return Err(SessionError::AlertConflict {
                    alert_id: alert_id.to_owned(),
                });
            }
            if existing.group_id != *group_id || existing.operation_kind != "chat" {
                return Err(SessionError::OperationConflict {
                    operation_id: alert_id.to_owned(),
                });
            }
            return Ok(existing.message);
        }
        let binding = self.binding()?;
        if binding.recipient_hex.len() != 64 {
            return Err(SessionError::RecipientAbsent);
        }
        let mut engine = self.engine()?;
        let members = engine.members(group_id).map_err(map_engine)?;
        let allowed = authorized_members(&self.public_key_hex(), &binding);
        if !members.iter().any(|member| member_hex(member) == binding.recipient_hex) {
            return Err(SessionError::RecipientAbsent);
        }
        if members.iter().any(|member| !allowed.iter().any(|id| id == &member.id)) {
            return Err(SessionError::UnauthorizedMember);
        }
        let pin = engine.epoch_pin(group_id).map_err(map_engine)?;
        let app = MarmotAppEvent::new(
            self.public_key_hex(),
            unix_now(),
            MARMOT_APP_EVENT_KIND_CHAT,
            Vec::new(),
            text,
        );
        let payload = app.encode().map_err(|error| SessionError::Engine(error.to_string()))?;
        let result = engine
            .send(SendIntent::AppMessage {
                group_id: group_id.clone(),
                payload,
                expected_epoch: Some(pin),
                only_to_members: Some(allowed),
            })
            .await
            .map_err(map_engine)?;
        let SendResult::ApplicationMessage { msg, .. } = result else {
            return Err(SessionError::Engine(format!(
                "chat send returned {result:?}"
            )));
        };
        drop(engine);
        self.storage
            .put_publication(blank_publication(
                alert_id,
                "chat",
                payload_sha256,
                group_id.clone(),
                msg.clone(),
                None,
                false,
                Vec::new(),
                "not_attempted",
            ))
            .map_err(map_storage)?;
        self.note_epochs()?;
        let _ = self.storage.bump_revision().map_err(map_storage)?;
        Ok(msg)
    }

    pub async fn self_update(
        &self,
        operation_id: &str,
        group_id: &GroupId,
    ) -> Result<(TransportMessage, u64), SessionError> {
        let payload_sha256 = hash_text(operation_id);
        if let Some(existing) = self.storage.publication(operation_id).map_err(map_storage)? {
            if existing.group_id != *group_id || existing.operation_kind != "self_update" {
                return Err(SessionError::OperationConflict {
                    operation_id: operation_id.to_owned(),
                });
            }
            let pending = existing.pending_ref.ok_or_else(|| {
                SessionError::Engine("stored update has no pending reference".into())
            })?;
            return Ok((existing.message, pending));
        }
        let mut engine = self.engine()?;
        let result = engine
            .send(SendIntent::SelfUpdate {
                group_id: group_id.clone(),
            })
            .await
            .map_err(map_engine)?;
        let SendResult::GroupEvolution {
            msg,
            pending,
            welcomes,
        } = result
        else {
            return Err(SessionError::Engine(format!(
                "self-update returned {result:?}"
            )));
        };
        if !welcomes.is_empty() {
            return Err(SessionError::Engine(
                "self-update produced unexpected welcomes".into(),
            ));
        }
        self.storage
            .put_publication(blank_publication(
                operation_id,
                "self_update",
                payload_sha256,
                group_id.clone(),
                msg.clone(),
                Some(pending.as_u64()),
                true,
                Vec::new(),
                "not_required",
            ))
            .map_err(map_storage)?;
        self.note_epochs()?;
        let _ = self.storage.bump_revision().map_err(map_storage)?;
        Ok((msg, pending.as_u64()))
    }

    pub async fn confirm(&self, operation_id: &str) -> Result<(), SessionError> {
        let Some(mut existing) = self.storage.publication(operation_id).map_err(map_storage)? else {
            return Err(SessionError::MissingPublication(operation_id.to_owned()));
        };
        if existing.confirmed {
            return Ok(());
        }
        let stored_pending = existing.pending_ref.ok_or_else(|| {
            SessionError::Engine("publication has no pending reference".into())
        })?;
        let mut engine = self.engine()?;
        // A restarted engine restores a staged evolution under a new pending
        // reference and queues the original ciphertext on the auto-publish
        // buffer. Confirm that reference. The ciphertext does not change.
        let pending = engine
            .drain_auto_publish()
            .into_iter()
            .find(|item| item.msg == existing.message)
            .map(|item| item.pending.as_u64())
            .unwrap_or(stored_pending);
        engine
            .confirm_published(PendingStateRef::new(pending))
            .await
            .map_err(map_engine)?;
        existing.pending_ref = Some(pending);
        existing.confirmed = true;
        if existing.message_phase != "relay_accepted" {
            existing.message_reconcile_attempts = existing.message_reconcile_attempts.saturating_add(1);
        }
        existing.message_phase = "relay_accepted".into();
        existing.updated_at_ms = clock::unix_ms();
        self.storage.put_publication(existing).map_err(map_storage)?;
        self.note_epochs()?;
        let _ = self.storage.bump_revision().map_err(map_storage)?;
        Ok(())
    }

    pub fn signed_key_package_event(
        &self,
        package: &KeyPackage,
    ) -> Result<serde_json::Value, SessionError> {
        use base64::Engine as _;
        use base64::engine::general_purpose::STANDARD;
        use nostr::event::FinalizeEvent;
        use nostr::prelude::{EventBuilder, Kind, Tag, Timestamp};
        let digest = hex::encode(sha2::Sha256::digest(&package.bytes));
        let event = EventBuilder::new(Kind::Custom(30443), STANDARD.encode(&package.bytes))
            .tags([
                Tag::custom("d", ["watchdog".to_owned()]),
                Tag::custom("client", ["nostr-watchdog".to_owned()]),
                Tag::custom("mls_protocol_version", ["1.0".to_owned()]),
                Tag::custom("i", [digest]),
            ])
            .custom_created_at(Timestamp::from_secs(unix_now()))
            .finalize(&self.keys)
            .map_err(|error| SessionError::Engine(error.to_string()))?;
        serde_json::to_value(&event).map_err(|error| SessionError::Engine(error.to_string()))
    }

    pub fn encoded_package_hex(event: &serde_json::Value) -> Result<String, SessionError> {
        use base64::Engine as _;
        let content = event.get("content").and_then(|value| value.as_str()).unwrap_or("");
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(content)
            .map_err(|error| SessionError::Engine(error.to_string()))?;
        Ok(hex::encode(bytes))
    }

    /// Accept a relay key-package event only when it is signed by the configured recipient.
    pub fn key_package_from_relay_event(
        value: &serde_json::Value,
        recipient_hex: &str,
    ) -> Result<KeyPackage, SessionError> {
        use base64::Engine as _;
        use base64::engine::general_purpose::STANDARD;
        let event: nostr::event::Event = serde_json::from_value(value.clone())
            .map_err(|error| SessionError::Engine(error.to_string()))?;
        if event.kind != nostr::event::Kind::Custom(30443) {
            return Err(SessionError::Engine(
                "key package kind is not 30443".into(),
            ));
        }
        if hex::encode(event.pubkey.to_bytes()) != recipient_hex.to_ascii_lowercase() {
            return Err(SessionError::Engine(
                "key package belongs to a different account".into(),
            ));
        }
        event
            .verify()
            .map_err(|error| SessionError::Engine(error.to_string()))?;
        let bytes = STANDARD
            .decode(event.content.as_str())
            .map_err(|error| SessionError::Engine(error.to_string()))?;
        let mut package = KeyPackage::new(bytes).with_protocol_profile(ProtocolProfile::Current);
        package.source = Some(cgka_traits::KeyPackageSource {
            event_id: cgka_traits::MessageId::new(event.id.to_bytes().to_vec()),
        });
        Ok(package)
    }

    pub fn transport_json(message: &TransportMessage) -> Result<serde_json::Value, SessionError> {
        serde_json::from_slice(&message.payload).map_err(|error| SessionError::Engine(error.to_string()))
    }

    pub fn message_id_hex(message: &TransportMessage) -> String {
        hex::encode(message.id.as_slice())
    }

    pub fn member_ids(&self, group_id: &GroupId) -> Result<Vec<String>, SessionError> {
        let engine = self.engine()?;
        Ok(engine
            .members(group_id)
            .map_err(map_engine)?
            .iter()
            .map(member_hex)
            .collect())
    }

    pub fn epoch(&self, group_id: &GroupId) -> Result<u64, SessionError> {
        Ok(self.storage.get_group(group_id).map_err(map_storage)?.epoch.0)
    }

    /// Record relay acceptance without encrypting again.
    ///
    /// Official MDK confirmation runs only after `accepted` and only when the
    /// stored operation still needs it. An ambiguous or failed publication
    /// keeps the original ciphertext.
    pub async fn note_publication(&self, operation_id: &str, accepted: bool) -> Result<(), SessionError> {
        let Some(existing) = self.storage.publication(operation_id).map_err(map_storage)? else {
            return Err(SessionError::MissingPublication(operation_id.to_owned()));
        };
        if existing.message_phase == "relay_accepted" {
            return Ok(());
        }
        if existing.needs_mdk_confirm {
            if !accepted {
                let mut held = existing;
                held.message_phase = "completion_unknown".into();
                held.unknown_attempts = held.unknown_attempts.saturating_add(1);
                held.updated_at_ms = clock::unix_ms();
                self.storage.put_publication(held).map_err(map_storage)?;
                let _ = self.storage.bump_revision().map_err(map_storage)?;
                return Ok(());
            }
            return self.confirm(operation_id).await;
        }
        let mut held = existing;
        if accepted {
            held.message_phase = "relay_accepted".into();
            held.message_reconcile_attempts = held.message_reconcile_attempts.saturating_add(1);
        } else {
            held.message_phase = "completion_unknown".into();
            held.unknown_attempts = held.unknown_attempts.saturating_add(1);
        }
        held.updated_at_ms = clock::unix_ms();
        self.storage.put_publication(held).map_err(map_storage)?;
        let _ = self.storage.bump_revision().map_err(map_storage)?;
        Ok(())
    }

    /// Attach a push trigger to an already prepared application message.
    /// A second call returns the original trigger bytes.
    pub fn stage_push(&self, alert_id: &str, trigger: &[u8]) -> Result<Vec<u8>, SessionError> {
        let Some(mut existing) = self.storage.publication(alert_id).map_err(map_storage)? else {
            return Err(SessionError::MissingPublication(alert_id.to_owned()));
        };
        if existing.message_phase != "relay_accepted" {
            return Err(SessionError::PushBeforeAcceptance);
        }
        if let Some(stored) = existing.push_trigger.clone() {
            return Ok(stored);
        }
        let message = existing.message.clone();
        existing.push_trigger = Some(trigger.to_vec());
        existing.push_phase = "prepared".into();
        existing.push_published = false;
        existing.updated_at_ms = clock::unix_ms();
        self.storage.put_publication(existing).map_err(map_storage)?;
        let stored = self.storage.publication(alert_id).map_err(map_storage)?;
        if stored.as_ref().and_then(|row| row.push_trigger.clone()).as_deref() != Some(trigger) {
            return Err(SessionError::Engine("push trigger was not stored".into()));
        }
        if stored.unwrap().message != message {
            return Err(SessionError::Engine(
                "push staging changed the application message".into(),
            ));
        }
        Ok(trigger.to_vec())
    }

    /// Replace the stored trigger envelope without counting a publication attempt.
    /// Signed event bytes inside an accepted item are left to the caller.
    pub fn replace_push_envelope(&self, alert_id: &str, trigger: &[u8]) -> Result<(), SessionError> {
        let Some(mut existing) = self.storage.publication(alert_id).map_err(map_storage)? else {
            return Err(SessionError::MissingPublication(alert_id.to_owned()));
        };
        if existing.message_phase != "relay_accepted" {
            return Err(SessionError::PushBeforeAcceptance);
        }
        let message = existing.message.clone();
        existing.push_trigger = Some(trigger.to_vec());
        existing.updated_at_ms = clock::unix_ms();
        self.storage.put_publication(existing).map_err(map_storage)?;
        let stored = self.storage.publication(alert_id).map_err(map_storage)?.unwrap();
        if stored.message != message {
            return Err(SessionError::Engine(
                "push staging changed the application message".into(),
            ));
        }
        Ok(())
    }

    pub fn note_push(
        &self,
        alert_id: &str,
        phase: &str,
        event_id: Option<String>,
    ) -> Result<(), SessionError> {
        let Some(mut existing) = self.storage.publication(alert_id).map_err(map_storage)? else {
            return Err(SessionError::MissingPublication(alert_id.to_owned()));
        };
        if existing.push_phase == "relay_accepted" {
            return Ok(());
        }
        let message = existing.message.clone();
        let message_phase = existing.message_phase.clone();
        if existing.push_phase != phase {
            if phase == "publication_attempted" {
                existing.push_publication_attempts = existing.push_publication_attempts.saturating_add(1);
            }
            if phase == "unobservable" {
                existing.unobservable_attempts = existing.unobservable_attempts.saturating_add(1);
            }
            if phase == "token_unavailable" {
                existing.token_wait_attempts = existing.token_wait_attempts.saturating_add(1);
            }
            if matches!(phase, "relay_accepted" | "rejected" | "unobservable") {
                existing.push_attempts = existing.push_attempts.saturating_add(1);
            }
        }
        existing.push_phase = phase.to_owned();
        existing.push_published = phase == "relay_accepted";
        if event_id.is_some() {
            existing.push_event_id = event_id;
        }
        existing.updated_at_ms = clock::unix_ms();
        self.storage.put_publication(existing).map_err(map_storage)?;
        let stored = self.storage.publication(alert_id).map_err(map_storage)?.unwrap();
        if stored.message != message || stored.message_phase != message_phase {
            return Err(SessionError::Engine(
                "push result changed the application message".into(),
            ));
        }
        Ok(())
    }

    pub fn mark_message_publication(&self, operation_id: &str) -> Result<(), SessionError> {
        let Some(mut existing) = self.storage.publication(operation_id).map_err(map_storage)? else {
            return Err(SessionError::MissingPublication(operation_id.to_owned()));
        };
        existing.message_publication_attempts = existing.message_publication_attempts.saturating_add(1);
        existing.updated_at_ms = clock::unix_ms();
        self.storage.put_publication(existing).map_err(map_storage)?;
        Ok(())
    }

    /// Record a relay result for the exact prepared event. A later failure cannot
    /// downgrade an acceptance, and an unrelated event id is refused.
    pub async fn note_message_outcome(
        &self,
        operation_id: &str,
        outcome: &str,
        event_id: &str,
        destination: &str,
        attempt_id: &str,
    ) -> Result<(), SessionError> {
        let Some(mut existing) = self.storage.publication(operation_id).map_err(map_storage)? else {
            return Err(SessionError::MissingPublication(operation_id.to_owned()));
        };
        if !event_matches_publication(&existing, event_id) {
            return Err(SessionError::Engine(
                "acknowledgement does not match the prepared event".into(),
            ));
        }
        if existing
            .publications
            .iter()
            .any(|record| record.event_id == event_id && record.phase == "relay_accepted")
        {
            return Ok(());
        }
        let now = clock::unix_ms();
        if let Some(record) = existing
            .publications
            .iter_mut()
            .find(|record| record.attempt_id == attempt_id)
        {
            if record.phase == outcome {
                return Ok(());
            }
            record.phase = outcome.to_owned();
            record.destination = destination.to_owned();
            record.finished_at_ms = now;
        } else {
            existing.publications.push(PublicationRecord {
                attempt_id: attempt_id.to_owned(),
                event_id: event_id.to_owned(),
                role: existing.operation_kind.clone(),
                destination: destination.to_owned(),
                phase: outcome.to_owned(),
                server: String::new(),
                reason: String::new(),
                started_at_ms: now,
                finished_at_ms: now,
            });
        }
        let welcome_ids = existing
            .welcomes
            .iter()
            .filter_map(transport_event_id)
            .collect::<Vec<_>>();
        if existing.operation_kind == "welcome" && !welcome_ids.is_empty() {
            let all_accepted = welcome_ids.iter().all(|id| {
                existing
                    .publications
                    .iter()
                    .any(|record| record.event_id == *id && record.phase == "relay_accepted")
            });
            if all_accepted && existing.message_phase != "relay_accepted" {
                existing.message_phase = "relay_accepted".into();
                existing.message_reconcile_attempts =
                    existing.message_reconcile_attempts.saturating_add(1);
            } else if outcome == "completion_unknown" && existing.message_phase != "relay_accepted" {
                existing.message_phase = "completion_unknown".into();
                existing.unknown_attempts = existing.unknown_attempts.saturating_add(1);
            } else if outcome == "rejected" && existing.message_phase != "relay_accepted" {
                existing.message_phase = "rejected".into();
            }
        } else if existing.message_phase != "relay_accepted" {
            match outcome {
                "relay_accepted" => {
                    existing.message_phase = "relay_accepted".into();
                    existing.message_reconcile_attempts =
                        existing.message_reconcile_attempts.saturating_add(1);
                }
                "rejected" => existing.message_phase = "rejected".into(),
                "completion_unknown" => {
                    existing.message_phase = "completion_unknown".into();
                    existing.unknown_attempts = existing.unknown_attempts.saturating_add(1);
                }
                _ => {
                    return Err(SessionError::Engine(
                        "publication outcome is not recognized".into(),
                    ))
                }
            }
        }
        existing.updated_at_ms = clock::unix_ms();
        let needs_confirm = existing.needs_mdk_confirm && existing.message_phase == "relay_accepted";
        self.storage.put_publication(existing).map_err(map_storage)?;
        if needs_confirm {
            self.confirm(operation_id).await?;
        }
        Ok(())
    }

    /// Persist one network attempt before any socket is opened.
    /// Returns false when that event already has a verified acceptance.
    pub fn begin_network_attempt(
        &self,
        operation_id: &str,
        role: &str,
        attempt_id: &str,
        event_id: &str,
        destination: &str,
    ) -> Result<bool, SessionError> {
        let Some(mut existing) = self.storage.publication(operation_id).map_err(map_storage)? else {
            return Err(SessionError::MissingPublication(operation_id.to_owned()));
        };
        if existing.publications.iter().any(|record| {
            record.event_id == event_id && record.phase == "relay_accepted"
        }) {
            return Ok(false);
        }
        if existing
            .publications
            .iter()
            .any(|record| record.attempt_id == attempt_id)
        {
            return Ok(true);
        }
        let now = clock::unix_ms();
        if role == "push" {
            existing.push_publication_attempts =
                existing.push_publication_attempts.saturating_add(1);
        } else {
            existing.message_publication_attempts =
                existing.message_publication_attempts.saturating_add(1);
        }
        existing.publications.push(PublicationRecord {
            attempt_id: attempt_id.to_owned(),
            event_id: event_id.to_owned(),
            role: role.to_owned(),
            destination: destination.to_owned(),
            phase: "publication_attempted".into(),
            server: String::new(),
            reason: String::new(),
            started_at_ms: now,
            finished_at_ms: 0,
        });
        existing.updated_at_ms = now;
        self.storage.put_publication(existing).map_err(map_storage)?;
        Ok(true)
    }

    /// Record one trigger without hiding another trigger's result.
    pub fn note_trigger(
        &self,
        operation_id: &str,
        outcome: &str,
        event_id: &str,
        destination: &str,
        attempt_id: &str,
        reason: &str,
        server: &str,
    ) -> Result<String, SessionError> {
        let Some(mut existing) = self.storage.publication(operation_id).map_err(map_storage)? else {
            return Err(SessionError::MissingPublication(operation_id.to_owned()));
        };
        let message = existing.message.clone();
        let message_phase = existing.message_phase.clone();
        if existing.publications.iter().any(|record| {
            record.role == "push" && record.event_id == event_id && record.phase == "relay_accepted"
        }) {
            return Ok(aggregate_push(&existing.publications));
        }
        let now = clock::unix_ms();
        let mut count_outcome = true;
        if let Some(record) = existing
            .publications
            .iter_mut()
            .find(|record| record.attempt_id == attempt_id)
        {
            if record.phase == outcome {
                count_outcome = false;
            } else {
                record.phase = outcome.to_owned();
                record.destination = destination.to_owned();
                record.reason = reason.to_owned();
                record.server = server.to_owned();
                record.finished_at_ms = now;
            }
        } else {
            existing.publications.push(PublicationRecord {
                attempt_id: attempt_id.to_owned(),
                event_id: event_id.to_owned(),
                role: "push".into(),
                destination: destination.to_owned(),
                phase: outcome.to_owned(),
                server: server.to_owned(),
                reason: reason.to_owned(),
                started_at_ms: now,
                finished_at_ms: now,
            });
        }
        if count_outcome && outcome == "unobservable" {
            existing.unobservable_attempts = existing.unobservable_attempts.saturating_add(1);
        }
        if count_outcome && matches!(outcome, "relay_accepted" | "rejected" | "unobservable") {
            existing.push_attempts = existing.push_attempts.saturating_add(1);
        }
        if let Some(bytes) = existing.push_trigger.clone() {
            if let Ok(mut value) = serde_json::from_slice::<serde_json::Value>(&bytes) {
                if let Some(items) = value.as_array_mut() {
                    for item in items.iter_mut() {
                        let id = item
                            .pointer("/event/id")
                            .and_then(|entry| entry.as_str())
                            .unwrap_or("");
                        if id == event_id {
                            if let Some(map) = item.as_object_mut() {
                                map.insert(
                                    "phase".into(),
                                    serde_json::Value::String(outcome.to_owned()),
                                );
                            }
                        }
                    }
                }
                if let Ok(encoded) = serde_json::to_vec(&value) {
                    existing.push_trigger = Some(encoded);
                }
            }
        }
        let phase = aggregate_push(&existing.publications);
        existing.push_phase = phase.clone();
        existing.push_published = phase == "relay_accepted";
        let mut ids = Vec::new();
        for record in existing.publications.iter().filter(|record| record.role == "push") {
            if !ids.iter().any(|id| id == &record.event_id) {
                ids.push(record.event_id.clone());
            }
        }
        existing.push_event_id = if ids.len() == 1 {
            ids.pop()
        } else {
            None
        };
        existing.updated_at_ms = now;
        self.storage.put_publication(existing).map_err(map_storage)?;
        let stored = self.storage.publication(operation_id).map_err(map_storage)?.unwrap();
        if stored.message != message || stored.message_phase != message_phase {
            return Err(SessionError::Engine(
                "push result changed the application message".into(),
            ));
        }
        Ok(phase)
    }

    pub fn select_push_tokens(&self, group_id: &GroupId) -> Result<Vec<StoredWake>, SessionError> {
        let binding = self.binding()?;
        let leaves = self.active_leaves(group_id)?;
        let sender = self.public_key_hex();
        let allowed = std::iter::once(binding.recipient_hex.clone())
            .chain(binding.extra_recipients.into_iter())
            .collect::<Vec<_>>();
        let group_hex = hex::encode(group_id.as_slice());
        let mut selected = Vec::new();
        for wake in self.storage.wakes().map_err(map_storage)? {
            if wake.removed || wake.group_id_hex != group_hex || wake.member_id_hex == sender {
                continue;
            }
            if !allowed.iter().any(|member| member == &wake.member_id_hex) {
                continue;
            }
            if !leaves
                .iter()
                .any(|(member, leaf)| member == &wake.member_id_hex && *leaf == wake.leaf_index)
            {
                continue;
            }
            selected.push(wake);
        }
        Ok(selected)
    }

    pub fn note_token_wait(&self, alert_id: &str) -> Result<(), SessionError> {
        let Some(mut existing) = self.storage.publication(alert_id).map_err(map_storage)? else {
            return Err(SessionError::MissingPublication(alert_id.to_owned()));
        };
        if existing.push_phase == "relay_accepted" {
            return Ok(());
        }
        existing.token_wait_attempts = existing.token_wait_attempts.saturating_add(1);
        if !existing
            .publications
            .iter()
            .any(|record| record.role == "push" && record.phase == "relay_accepted")
        {
            existing.push_phase = "token_unavailable".into();
        }
        existing.updated_at_ms = clock::unix_ms();
        self.storage.put_publication(existing).map_err(map_storage)?;
        Ok(())
    }

    fn observe_gossip(
        &self,
        group_id: &GroupId,
        kind: u64,
        content: &str,
        sender_leaf: Option<u32>,
        sender_hex: &str,
    ) -> Result<(), SessionError> {
        let group_hex = hex::encode(group_id.as_slice());
        let records = push::records_from_gossip(kind, &group_hex, content)
            .map_err(|error| SessionError::Engine(error))?;
        let mut leaves = self.active_leaves(group_id)?;
        if let Some(leaf) = sender_leaf {
            leaves.push((sender_hex.to_owned(), leaf));
        }
        let mut directory = directory_from_wakes(&self.storage.wakes().map_err(map_storage)?);
        for record in records {
            if record.member_id_hex == self.public_key_hex() {
                continue;
            }
            let _ = directory.admit(record, &leaves);
        }
        self.storage
            .put_wakes(wakes_from_directory(&directory))
            .map_err(map_storage)?;
        Ok(())
    }

    fn active_leaves(&self, group_id: &GroupId) -> Result<Vec<(String, u32)>, SessionError> {
        let engine = self.engine()?;
        let own = engine.own_leaf_index(group_id).map_err(map_engine)?;
        let members = engine.members(group_id).map_err(map_engine)?;
        let member_ids = members.iter().map(member_hex).collect::<Vec<_>>();
        drop(engine);
        let group_hex = hex::encode(group_id.as_slice());
        let mut leaves = vec![(self.public_key_hex(), own)];
        for observed in self.storage.observed_leaves().map_err(map_storage)? {
            if observed.removed || observed.group_id_hex != group_hex {
                continue;
            }
            if !member_ids.iter().any(|member| member == &observed.member_id_hex) {
                continue;
            }
            if leaves.iter().any(|(member, leaf)| {
                member == &observed.member_id_hex && *leaf == observed.leaf_index
            }) {
                continue;
            }
            leaves.push((observed.member_id_hex, observed.leaf_index));
        }
        Ok(leaves)
    }

    pub fn onboarding_view(&self) -> Result<serde_json::Value, SessionError> {
        let binding = self.binding()?;
        let welcome = self.storage.welcome_publication().map_err(map_storage)?;
        let group_hex = binding.group_id_hex.clone().unwrap_or_default();
        let recipient_seen = self
            .storage
            .observed_leaves()
            .map_err(map_storage)?
            .iter()
            .any(|leaf| {
                !leaf.removed
                    && leaf.member_id_hex == binding.recipient_hex
                    && leaf.group_id_hex == group_hex
            });
        let welcome_accepted = welcome
            .as_ref()
            .map(|row| row.message_phase == "relay_accepted")
            .unwrap_or(false);
        let welcome_prepared = welcome.is_some();
        let group_persisted = !group_hex.is_empty();
        let ready = welcome_accepted && recipient_seen;
        let completion = if ready {
            "ready"
        } else if welcome_prepared && !welcome_accepted {
            "pending"
        } else if group_persisted {
            "unknown"
        } else {
            "not_started"
        };
        Ok(serde_json::json!({
            "accountInitialized": !binding.project_id.is_empty(),
            "recipientDiscovered": binding.recipient_hex.len() == 64,
            "groupAdmitted": welcome_prepared,
            "groupPersisted": group_persisted,
            "welcomePrepared": welcome_prepared,
            "welcomePublicationPending": welcome_prepared && !welcome_accepted,
            "welcomeAccepted": welcome_accepted,
            "recipientParticipationObserved": recipient_seen,
            "conversationReady": ready,
            "completion": completion,
            "welcomeOperationId": welcome.as_ref().map(|row| row.alert_id.clone()),
        }))
    }

    pub fn project_operation(&self, operation_id: &str) -> Result<serde_json::Value, SessionError> {
        let Some(row) = self.storage.publication(operation_id).map_err(map_storage)? else {
            let Some(stone) = self.storage.tombstone(operation_id).map_err(map_storage)? else {
                return Err(SessionError::MissingPublication(operation_id.to_owned()));
            };
            return Ok(serde_json::json!({
                "operationId": operation_id,
                "messagePhase": stone.message_phase,
                "messageState": stone.message_phase,
                "messageEventId": stone.message_event_id,
                "pushPhase": stone.push_phase,
                "pushState": stone.push_phase,
                "pushEventId": stone.push_event_id,
                "evidence": "retired",
                "error": null,
                "settled": true,
                "disposition": "settled",
                "retryAfterMs": 0,
                "retryAtMs": 0,
                "reconcileAfterMs": 0,
                "phoneDelivery": false,
                "resubmittable": false,
                "pushRetryable": false,
                "startedAtMs": stone.started_at_ms,
                "updatedAtMs": stone.updated_at_ms,
            }));
        };
        let error = push_error(&row);
        let push_retryable = push_is_retryable(&row.push_phase, error.as_deref());
        let message_terminal = matches!(row.message_phase.as_str(), "relay_accepted" | "rejected");
        let push_closed = matches!(
            row.push_phase.as_str(),
            "relay_accepted" | "rejected" | "not_required" | "not_attempted" | "expired" | "terminal_failure"
        );
        let settled = message_terminal && push_closed && !push_retryable;
        let retry_after = if settled { 0 } else { 15_000 };
        let mut body = publication_counters(&row);
        let map = body.as_object_mut().expect("counters");
        map.insert("operationId".into(), serde_json::json!(operation_id));
        map.insert("messagePhase".into(), serde_json::json!(row.message_phase));
        map.insert("messageState".into(), serde_json::json!(row.message_phase));
        map.insert(
            "messageEventId".into(),
            serde_json::json!(Self::message_id_hex(&row.message)),
        );
        map.insert("pushPhase".into(), serde_json::json!(row.push_phase));
        map.insert("pushState".into(), serde_json::json!(row.push_phase));
        map.insert("pushEventId".into(), serde_json::json!(row.push_event_id));
        map.insert("triggers".into(), trigger_evidence(&row));
        map.insert(
            "evidence".into(),
            serde_json::json!(if trigger_evidence(&row).as_array().map(|items| items.len() > 1).unwrap_or(false) {
                "partial_push"
            } else if settled {
                "settled"
            } else {
                "reconcile"
            }),
        );
        map.insert("error".into(), serde_json::json!(error));
        map.insert("settled".into(), serde_json::json!(settled));
        map.insert(
            "disposition".into(),
            serde_json::json!(if settled { "settled" } else { "reconcile" }),
        );
        map.insert("retryAfterMs".into(), serde_json::json!(retry_after));
        map.insert("retryAtMs".into(), serde_json::json!(retry_after));
        map.insert("reconcileAfterMs".into(), serde_json::json!(retry_after));
        map.insert("phoneDelivery".into(), serde_json::json!(false));
        map.insert("pushRetryable".into(), serde_json::json!(push_retryable));
        map.insert("ok".into(), serde_json::json!(true));
        Ok(body)
    }

    pub async fn ensure_key_package_event(&self) -> Result<serde_json::Value, SessionError> {
        if let Some(existing) = self.storage.publication("key-package").map_err(map_storage)? {
            if existing.operation_kind == "key_package" {
                if let Ok(value) = serde_json::from_slice::<serde_json::Value>(&existing.message.payload) {
                    return Ok(value);
                }
            }
        }
        let package = self.fresh_key_package().await?;
        let event = self.signed_key_package_event(&package)?;
        let payload = serde_json::to_vec(&event).map_err(|error| SessionError::Engine(error.to_string()))?;
        let message = cgka_traits::TransportMessage {
            id: cgka_traits::MessageId::new(vec![1, 2, 3, 4]),
            payload,
            timestamp: cgka_traits::Timestamp(unix_now()),
            causal_deps: Vec::new(),
            source: cgka_traits::TransportSource("nostr".into()),
            envelope: cgka_traits::TransportEnvelope::GroupMessage {
                transport_group_id: vec![0],
            },
        };
        self.storage
            .put_publication(blank_publication(
                "key-package",
                "key_package",
                hash_text("key-package"),
                GroupId::new(vec![0; 16]),
                message,
                None,
                false,
                Vec::new(),
                "not_required",
            ))
            .map_err(map_storage)?;
        Ok(event)
    }

    pub fn note_sync_page(
        &self,
        stream: &str,
        created: &[u64],
        page_limit: usize,
        complete: bool,
    ) -> Result<(), SessionError> {
        let cursors = self.storage.sync_cursors().map_err(map_storage)?;
        let existing = cursors.iter().find(|cursor| cursor.stream == stream);
        let mut since = existing.map(|cursor| cursor.since).unwrap_or(0);
        let mut until = existing.and_then(|cursor| cursor.until);
        let mut caught_up = existing.map(|cursor| cursor.caught_up).unwrap_or(false);
        if !complete {
            caught_up = false;
            if let Some(oldest) = created.iter().copied().min() {
                until = Some(oldest);
            }
        } else if created.len() >= page_limit && !created.is_empty() {
            let oldest = created.iter().copied().min().unwrap_or(0);
            until = Some(oldest.saturating_sub(1));
            caught_up = false;
        } else if let Some(newest) = created.iter().copied().max() {
            since = newest;
            until = None;
            caught_up = true;
        } else if until.is_some() {
            until = None;
            caught_up = true;
        }
        self.storage
            .put_sync_cursor(mdk_do_storage::SyncCursor {
                stream: stream.to_owned(),
                since,
                until,
                caught_up,
                updated_at_ms: clock::unix_ms(),
            })
            .map_err(map_storage)?;
        Ok(())
    }

    fn bind(storage: MemoryMdkStorage, secret: [u8; 32]) -> Result<Self, SessionError> {
        let keys = Keys::new(
            SecretKey::from_slice(&secret).map_err(|error| SessionError::Engine(error.to_string()))?,
        );
        let proof = ProofSigner::new(&secret)?;
        if proof.public_bytes() != keys.public_key().to_bytes() {
            return Err(SessionError::IdentityMismatch);
        }
        storage.set_account_secret(&secret).map_err(map_storage)?;
        storage
            .put_periodic_maintenance_policy(PeriodicMaintenancePolicy::Disabled)
            .map_err(map_storage)?;
        Ok(Self {
            storage,
            keys,
            proof: Arc::new(proof),
        })
    }

    fn engine(&self) -> Result<Engine<MemoryMdkStorage>, SessionError> {
        let mut engine = EngineBuilder::new(self.storage.clone())
            .identity(self.keys.public_key().to_bytes().to_vec())
            .account_identity_proof_signer(self.proof.clone())
            .feature_registry(FeatureRegistry::new())
            .supported_app_components(supported_components())
            .protocol_profile(ProtocolProfile::Current)
            .peeler(Box::new(
                NostrMlsPeeler::new().with_welcome_signer(self.keys.clone()),
            ))
            .maintenance_sources(Arc::new(clock::PortableWallClock), Arc::new(clock::PortableRandom))
            .monotonic_clock(Arc::new(clock::PortableMonotonic::new()))
            .convergence_clock(Arc::new(clock::PortableConvergence::new()))
            .build()
            .map_err(map_engine)?;
        engine.hydrate_all_stored_groups().map_err(map_engine)?;
        Ok(engine)
    }

    fn note_epochs(&self) -> Result<(), SessionError> {
        for group_id in self.storage.list_groups().map_err(map_storage)? {
            let epoch = self.storage.get_group(&group_id).map_err(map_storage)?.epoch.0;
            self.storage.note_epoch(&group_id, epoch).map_err(map_storage)?;
        }
        Ok(())
    }
}

struct ProofSigner {
    key: SigningKey,
}

impl ProofSigner {
    fn new(secret: &[u8; 32]) -> Result<Self, SessionError> {
        let key = SigningKey::from_slice(secret)
            .map_err(|error| SessionError::Engine(error.to_string()))?;
        Ok(Self { key })
    }

    fn public_bytes(&self) -> [u8; 32] {
        self.key.verifying_key().to_bytes().into()
    }
}

impl AccountIdentityProofSigner for ProofSigner {
    fn sign_account_identity_proof(
        &self,
        request: &AccountIdentityProofRequest,
    ) -> Result<[u8; 64], String> {
        if self.key.verifying_key().to_bytes().as_slice() != request.account_identity.as_slice() {
            return Err("account identity does not match the Nostr key".into());
        }
        let signature = self
            .key
            .sign_prehash(&request.proof_event_id()?)
            .map_err(|error| error.to_string())?;
        Ok(signature.to_bytes())
    }
}

fn supported_components() -> Vec<cgka_traits::app_components::AppComponentId> {
    let mut components = default_group_components();
    components.insert(NOSTR_ROUTING_COMPONENT_ID);
    components.into_iter().collect()
}

fn application_event_ids(events: &[GroupEvent]) -> Vec<cgka_traits::MessageId> {
    events
        .iter()
        .filter_map(|event| match event {
            GroupEvent::MessageReceived { message_id, .. } => Some(message_id.clone()),
            GroupEvent::GroupJoined { via_welcome, .. } => Some(via_welcome.clone()),
            _ => None,
        })
        .collect()
}

fn hash_text(text: &str) -> [u8; 32] {
    Sha256::digest(text.as_bytes()).into()
}

fn unix_now() -> u64 {
    clock::unix_secs()
}

fn event_matches_publication(row: &PreparedPublication, event_id: &str) -> bool {
    transport_event_id(&row.message).as_deref() == Some(event_id)
        || row
            .welcomes
            .iter()
            .any(|welcome| transport_event_id(welcome).as_deref() == Some(event_id))
}

fn transport_event_id(message: &TransportMessage) -> Option<String> {
    let value: serde_json::Value = serde_json::from_slice(&message.payload).ok()?;
    value
        .get("id")
        .and_then(|item| item.as_str())
        .map(str::to_owned)
}

fn directory_from_wakes(wakes: &[StoredWake]) -> push::PushDirectory {
    let mut directory = push::PushDirectory::default();
    for wake in wakes {
        let Ok(platform) = push::Platform::from_name(&wake.platform) else {
            continue;
        };
        let record = push::TokenRecord {
            group_id_hex: wake.group_id_hex.clone(),
            member_id_hex: wake.member_id_hex.clone(),
            leaf_index: wake.leaf_index,
            platform,
            token_fingerprint: wake.token_fingerprint.clone(),
            server_pubkey_hex: wake.server_pubkey_hex.clone(),
            relay_hint: wake.relay_hint.clone(),
            owner_ts: wake.owner_ts,
            encrypted_token: wake.encrypted_token.clone(),
            owner_sig: wake.owner_sig.clone(),
            removed: wake.removed,
        };
        let leaves = [(record.member_id_hex.clone(), record.leaf_index)];
        let _ = directory.admit(record, &leaves);
    }
    directory
}

fn wakes_from_directory(directory: &push::PushDirectory) -> Vec<StoredWake> {
    directory
        .records()
        .iter()
        .map(|record| StoredWake {
            group_id_hex: record.group_id_hex.clone(),
            member_id_hex: record.member_id_hex.clone(),
            leaf_index: record.leaf_index,
            platform: record.platform.name().to_owned(),
            token_fingerprint: record.token_fingerprint.clone(),
            server_pubkey_hex: record.server_pubkey_hex.clone(),
            relay_hint: record.relay_hint.clone(),
            owner_ts: record.owner_ts,
            encrypted_token: record.encrypted_token.clone(),
            owner_sig: record.owner_sig.clone(),
            removed: record.removed,
        })
        .collect()
}

fn aggregate_push(records: &[PublicationRecord]) -> String {
    let mut by_event: Vec<(String, String)> = Vec::new();
    for record in records.iter().filter(|record| record.role == "push") {
        if let Some(slot) = by_event.iter_mut().find(|(id, _)| id == &record.event_id) {
            if slot.1 != "relay_accepted" {
                slot.1 = record.phase.clone();
            }
        } else {
            by_event.push((record.event_id.clone(), record.phase.clone()));
        }
    }
    if by_event.is_empty() {
        return "not_attempted".into();
    }
    let phases = by_event
        .iter()
        .map(|(_, phase)| phase.as_str())
        .collect::<Vec<_>>();
    if phases.iter().all(|phase| *phase == "relay_accepted") {
        return "relay_accepted".into();
    }
    if phases.iter().any(|phase| *phase == "unobservable") {
        return "unobservable".into();
    }
    if phases
        .iter()
        .any(|phase| *phase == "rejected")
        && phases.iter().all(|phase| *phase == "rejected")
    {
        return "rejected".into();
    }
    if phases.iter().any(|phase| {
        matches!(
            *phase,
            "publication_attempted" | "prepared" | "pending" | "rejected" | "token_unavailable"
        )
    }) {
        return "publication_attempted".into();
    }
    "publication_attempted".into()
}

fn trigger_evidence(row: &PreparedPublication) -> serde_json::Value {
    let mut items: Vec<serde_json::Value> = Vec::new();
    let mut seen = Vec::new();
    for record in row.publications.iter().filter(|record| record.role == "push") {
        if seen.iter().any(|id| id == &record.event_id) {
            if let Some(item) = items.iter_mut().find(|item| {
                item.get("eventId").and_then(|value| value.as_str()) == Some(record.event_id.as_str())
            }) {
                if item.get("phase").and_then(|value| value.as_str()) != Some("relay_accepted") {
                    *item = trigger_item(record);
                }
            }
            continue;
        }
        seen.push(record.event_id.clone());
        items.push(trigger_item(record));
    }
    serde_json::Value::Array(items)
}

fn trigger_item(record: &PublicationRecord) -> serde_json::Value {
    serde_json::json!({
        "eventId": record.event_id,
        "phase": record.phase,
        "relay": record.destination,
        "server": record.server,
        "attemptId": record.attempt_id,
        "retryable": record.phase != "relay_accepted" && record.phase != "rejected" && record.phase != "retired",
    })
}

fn push_error(row: &PreparedPublication) -> Option<String> {
    let mut timeout = false;
    let mut permanent = false;
    for record in row.publications.iter().filter(|record| record.role == "push") {
        if record.phase == "relay_accepted" {
            continue;
        }
        if record.reason == "publication_timeout" {
            timeout = true;
        }
        if record.reason == "push_unobservable" {
            permanent = true;
        }
    }
    if timeout {
        Some("publication_timeout".into())
    } else if permanent {
        Some("push_unobservable".into())
    } else {
        None
    }
}

fn push_is_retryable(phase: &str, error: Option<&str>) -> bool {
    if error == Some("push_unobservable") {
        return false;
    }
    matches!(
        phase,
        "unobservable"
            | "publication_attempted"
            | "prepared"
            | "pending"
            | "token_unavailable"
            | "accepted_pending"
            | "completion_unknown"
    )
}

pub fn publication_counters(row: &PreparedPublication) -> serde_json::Value {
    serde_json::json!({
        "messageAttempts": row.message_attempts,
        "messagePublicationAttempts": row.message_publication_attempts,
        "messageReconcileAttempts": row.message_reconcile_attempts,
        "unknownAttempts": row.unknown_attempts,
        "tokenWaitAttempts": row.token_wait_attempts,
        "pushPublicationAttempts": row.push_publication_attempts,
        "unobservableAttempts": row.unobservable_attempts,
        "pushAttempts": row.push_attempts,
        "operationAgeMs": clock::unix_ms().saturating_sub(row.started_at_ms),
        "startedAtMs": row.started_at_ms,
        "updatedAtMs": row.updated_at_ms,
    })
}

fn member_hex(member: &cgka_traits::group::Member) -> String {
    hex::encode(member.id.as_slice())
}

fn authorized_members(sender_hex: &str, binding: &AccountBinding) -> Vec<MemberId> {
    let mut ids = Vec::new();
    for hex_id in std::iter::once(sender_hex.to_owned())
        .chain(std::iter::once(binding.recipient_hex.clone()))
        .chain(binding.extra_recipients.iter().cloned())
    {
        if let Ok(bytes) = hex::decode(hex_id) {
            if bytes.len() == 32 {
                ids.push(MemberId::new(bytes));
            }
        }
    }
    ids
}

#[allow(clippy::too_many_arguments)]
fn blank_publication(
    alert_id: &str,
    kind: &str,
    payload_sha256: [u8; 32],
    group_id: GroupId,
    message: TransportMessage,
    pending_ref: Option<u64>,
    needs_mdk_confirm: bool,
    welcomes: Vec<TransportMessage>,
    push_phase: &str,
) -> PreparedPublication {
    PreparedPublication {
        alert_id: alert_id.to_owned(),
        operation_kind: kind.to_owned(),
        payload_sha256,
        group_id,
        message,
        confirmed: false,
        message_phase: "accepted_pending".into(),
        pending_ref,
        needs_mdk_confirm,
        welcomes,
        push_trigger: None,
        push_published: false,
        push_phase: push_phase.to_owned(),
        push_event_id: None,
        started_at_ms: clock::unix_ms(),
        updated_at_ms: clock::unix_ms(),
        message_attempts: 1,
        message_publication_attempts: 0,
        message_reconcile_attempts: 0,
        unknown_attempts: 0,
        token_wait_attempts: 0,
        push_publication_attempts: 0,
        unobservable_attempts: 0,
        push_attempts: 0,
        publications: Vec::new(),
    }
}

fn map_storage(error: cgka_traits::StorageError) -> SessionError {
    SessionError::Storage(error.to_string())
}

fn map_engine(error: impl ToString) -> SessionError {
    SessionError::Engine(error.to_string())
}

fn persist(error: PersistError) -> SessionError {
    SessionError::Storage(error.to_string())
}

#[allow(dead_code)]
fn _epoch(epoch: EpochId) -> u64 {
    epoch.0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn an_empty_account_generates_a_key_package_and_restores() {
        let session = Session::generate().unwrap();
        let package = session.fresh_key_package().await.unwrap();
        assert!(!package.bytes.is_empty());
        assert_eq!(package.protocol_profile, ProtocolProfile::Current);
        let key = [4u8; 32];
        let sealed = session.seal(&key, "watchdog").unwrap();
        let restored = Session::open(&key, "watchdog", &session.public_key_hex(), &sealed).unwrap();
        assert_eq!(restored.public_key_hex(), session.public_key_hex());
        let again = restored.fresh_key_package().await.unwrap();
        assert!(!again.bytes.is_empty());
    }

    fn stored_chat(id: &str, event_id: &str) -> mdk_do_storage::PreparedPublication {
        use cgka_traits::{Timestamp, TransportEnvelope, TransportMessage, TransportSource};
        mdk_do_storage::PreparedPublication {
            alert_id: id.to_owned(),
            operation_kind: "chat".into(),
            payload_sha256: [7u8; 32],
            group_id: cgka_traits::GroupId::new(vec![1, 2, 3, 4]),
            message: TransportMessage {
                id: cgka_traits::MessageId::new(b"message-id".to_vec()),
                payload: format!(r#"{{"id":"{event_id}"}}"#).into_bytes(),
                timestamp: Timestamp(1),
                causal_deps: Vec::new(),
                source: TransportSource("nostr".into()),
                envelope: TransportEnvelope::GroupMessage {
                    transport_group_id: vec![1],
                },
            },
            confirmed: true,
            message_phase: "relay_accepted".into(),
            pending_ref: None,
            needs_mdk_confirm: false,
            welcomes: Vec::new(),
            push_trigger: None,
            push_published: false,
            push_phase: "not_attempted".into(),
            push_event_id: None,
            started_at_ms: 10,
            updated_at_ms: 10,
            message_attempts: 1,
            message_publication_attempts: 1,
            message_reconcile_attempts: 1,
            unknown_attempts: 0,
            token_wait_attempts: 0,
            push_publication_attempts: 0,
            unobservable_attempts: 0,
            push_attempts: 0,
            publications: Vec::new(),
        }
    }

    #[tokio::test]
    async fn a_later_success_is_not_erased_by_a_stale_acknowledgement() {
        let session = Session::generate().unwrap();
        session
            .storage()
            .put_publication(stored_chat("alert-1", "event-1"))
            .unwrap();
        session
            .note_message_outcome("alert-1", "relay_accepted", "event-1", "wss://later.example", "attempt-2")
            .await
            .unwrap();
        session
            .note_message_outcome(
                "alert-1",
                "completion_unknown",
                "event-1",
                "wss://earlier.example",
                "attempt-1",
            )
            .await
            .unwrap();
        let row = session.storage().publication("alert-1").unwrap().unwrap();
        assert_eq!(row.message_phase, "relay_accepted");
        assert!(session
            .note_message_outcome("alert-1", "relay_accepted", "other-event", "wss://x.example", "attempt-3")
            .await
            .is_err());
    }

    #[tokio::test]
    async fn one_accepted_trigger_does_not_hide_an_unresolved_trigger() {
        let session = Session::generate().unwrap();
        let mut row = stored_chat("alert-1", "event-1");
        row.push_trigger = Some(
            serde_json::to_vec(&serde_json::json!([
                {"event": {"id": "trigger-a"}, "relays": ["wss://a.example"], "server": "s1", "fingerprints": ["sha256:aaa"], "phase": "prepared"},
                {"event": {"id": "trigger-b"}, "relays": ["wss://b.example"], "server": "s2", "fingerprints": ["sha256:bbb"], "phase": "prepared"}
            ]))
            .unwrap(),
        );
        session.storage().put_publication(row).unwrap();
        let before = session.storage().publication("alert-1").unwrap().unwrap().push_publication_attempts;
        session
            .stage_push("alert-1", br#"{"id":"ignored"}"#)
            .unwrap();
        let staged = session.storage().publication("alert-1").unwrap().unwrap();
        assert_eq!(staged.push_publication_attempts, before);
        session
            .note_trigger("alert-1", "relay_accepted", "trigger-a", "wss://a.example", "a1", "", "s1")
            .unwrap();
        let phase = session
            .note_trigger(
                "alert-1",
                "unobservable",
                "trigger-b",
                "wss://b.example",
                "b1",
                "publication_timeout",
                "s2",
            )
            .unwrap();
        assert_eq!(phase, "unobservable");
        let view = session.project_operation("alert-1").unwrap();
        assert_eq!(view["disposition"], "reconcile");
        assert_eq!(view["pushRetryable"], true);
        assert_eq!(view["error"], "publication_timeout");
        assert_eq!(view["messageAttempts"], 1);
        let triggers = view["triggers"].as_array().unwrap();
        assert_eq!(triggers.len(), 2);
        assert!(triggers.iter().any(|item| item["phase"] == "relay_accepted"));
        assert!(triggers.iter().any(|item| item["phase"] == "unobservable"));
        session
            .note_token_wait("alert-1")
            .unwrap();
        session
            .note_token_wait("alert-1")
            .unwrap();
        let waits = session.storage().publication("alert-1").unwrap().unwrap().token_wait_attempts;
        assert_eq!(waits, 2);
    }

    #[tokio::test]
    async fn a_failed_key_package_publication_is_reused() {
        let session = Session::generate().unwrap();
        let first = session.ensure_key_package_event().await.unwrap();
        session
            .note_message_outcome(
                "key-package",
                "rejected",
                first["id"].as_str().unwrap(),
                "wss://relay.example",
                "attempt-1",
            )
            .await
            .unwrap();
        let second = session.ensure_key_package_event().await.unwrap();
        assert_eq!(first["id"], second["id"]);
    }
}
