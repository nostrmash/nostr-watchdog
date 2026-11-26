//! One Marmot account-device backed by [`mdk_do_storage::MemoryMdkStorage`].
//!
//! Each call builds an official [`cgka_engine::Engine`], hydrates stored groups,
//! and drops the engine before the caller seals the snapshot. The engine is
//! the only MLS implementation. This crate does not publish to relays.

pub mod clock;
pub mod push;

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
use mdk_do_storage::{AccountBinding, MemoryMdkStorage, PersistError, PreparedPublication, SealBinding};
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
            if let GroupEvent::MessageReceived { payload, .. } = event {
                if let Ok(app) = MarmotAppEvent::decode(&payload) {
                    if app.kind == MARMOT_APP_EVENT_KIND_CHAT {
                        chats.push(app.content);
                    }
                }
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
        if let Some(mut existing) = self.storage.publication(alert_id).map_err(map_storage)? {
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
            existing.message_attempts = existing.message_attempts.saturating_add(1);
            let message = existing.message.clone();
            self.storage.put_publication(existing).map_err(map_storage)?;
            return Ok(message);
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
        existing.message_phase = "relay_accepted".into();
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

    pub fn transport_json(message: &TransportMessage) -> Result<serde_json::Value, SessionError> {
        serde_json::from_slice(&message.payload).map_err(|error| SessionError::Engine(error.to_string()))
    }

    pub fn message_id_hex(message: &TransportMessage) -> String {
        hex::encode(message.id.as_slice())
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
                self.storage.put_publication(held).map_err(map_storage)?;
                let _ = self.storage.bump_revision().map_err(map_storage)?;
                return Ok(());
            }
            return self.confirm(operation_id).await;
        }
        let mut held = existing;
        held.message_phase = if accepted {
            "relay_accepted"
        } else {
            "completion_unknown"
        }
        .into();
        held.confirmed = accepted;
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
        if let Some(stored) = existing.push_trigger.clone() {
            return Ok(stored);
        }
        let message = existing.message.clone();
        existing.push_trigger = Some(trigger.to_vec());
        existing.push_phase = "prepared".into();
        existing.push_published = false;
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

    pub fn note_push(
        &self,
        alert_id: &str,
        phase: &str,
        event_id: Option<String>,
    ) -> Result<(), SessionError> {
        let Some(mut existing) = self.storage.publication(alert_id).map_err(map_storage)? else {
            return Err(SessionError::MissingPublication(alert_id.to_owned()));
        };
        let message = existing.message.clone();
        let message_phase = existing.message_phase.clone();
        existing.push_phase = phase.to_owned();
        existing.push_published = phase == "relay_accepted";
        existing.push_attempts = existing.push_attempts.saturating_add(1);
        existing.push_event_id = event_id;
        self.storage.put_publication(existing).map_err(map_storage)?;
        let stored = self.storage.publication(alert_id).map_err(map_storage)?.unwrap();
        if stored.message != message || stored.message_phase != message_phase {
            return Err(SessionError::Engine(
                "push result changed the application message".into(),
            ));
        }
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
        message_attempts: 1,
        push_attempts: 0,
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
}
