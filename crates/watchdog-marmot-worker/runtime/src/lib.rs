//! One Marmot account-device backed by [`mdk_do_storage::MemoryMdkStorage`].
//!
//! Each call builds an official [`cgka_engine::Engine`], hydrates stored groups,
//! and drops the engine before the caller seals the snapshot. The engine is
//! the only MLS implementation. This crate does not publish to relays.

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
    CgkaEngine, CreateGroupRequest, EpochId, GroupEvent, GroupId, KeyPackage, PendingStateRef,
    SendIntent, SendResult, TransportMessage,
};
use k256::schnorr::SigningKey;
use k256::schnorr::signature::hazmat::PrehashSigner;
use mdk_do_storage::{MemoryMdkStorage, PersistError, PreparedPublication};
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

    pub fn open(storage_key: &[u8; 32], sealed: &[u8]) -> Result<Self, SessionError> {
        let document = mdk_do_storage::open_sealed(storage_key, sealed).map_err(persist)?;
        let storage = MemoryMdkStorage::from_document(document).map_err(persist)?;
        let secret = storage
            .account_secret()
            .ok_or_else(|| SessionError::Storage("account secret is missing".into()))?;
        Self::bind(storage, secret)
    }

    pub fn seal(&self, storage_key: &[u8; 32]) -> Result<Vec<u8>, SessionError> {
        if !self.storage.drain_commit_hooks().is_empty() {
            // Hooks are observers. They were drained so a later seal cannot
            // replay them. Nothing in the sealed document depends on them.
        }
        let document = self.storage.to_document().map_err(persist)?;
        mdk_do_storage::seal(storage_key, &document).map_err(persist)
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

    pub async fn fresh_key_package(&self) -> Result<KeyPackage, SessionError> {
        let mut engine = self.engine()?;
        let package = engine.fresh_key_package().await.map_err(map_engine)?;
        self.note_epochs()?;
        Ok(package)
    }

    pub async fn create_group(
        &self,
        name: &str,
        members: Vec<KeyPackage>,
        relays: Vec<String>,
    ) -> Result<(GroupId, Vec<TransportMessage>), SessionError> {
        let mut nostr_group_id = [0u8; 32];
        getrandom::getrandom(&mut nostr_group_id).map_err(|_| SessionError::Random)?;
        let routing = NostrRoutingV1::new(nostr_group_id, relays)
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
        let welcomes = match result {
            SendResult::FoundingGroupCreated { welcomes } => welcomes,
            SendResult::GroupCreated { welcomes, pending } => {
                engine.confirm_published(pending).await.map_err(map_engine)?;
                welcomes
            }
            other => {
                return Err(SessionError::Engine(format!(
                    "group creation returned {other:?}"
                )));
            }
        };
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
        if let Some(existing) = self.storage.publication(alert_id).map_err(map_storage)? {
            if existing.payload_sha256 != payload_sha256 {
                return Err(SessionError::AlertConflict {
                    alert_id: alert_id.to_owned(),
                });
            }
            return Ok(existing.message);
        }
        let mut engine = self.engine()?;
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
                expected_epoch: None,
                only_to_members: None,
            })
            .await
            .map_err(map_engine)?;
        let SendResult::ApplicationMessage { msg, .. } = result else {
            return Err(SessionError::Engine(format!(
                "chat send returned {result:?}"
            )));
        };
        self.storage
            .put_publication(PreparedPublication {
                alert_id: alert_id.to_owned(),
                payload_sha256,
                group_id: group_id.clone(),
                message: msg.clone(),
                confirmed: true,
                pending_ref: None,
                push_trigger: None,
                push_published: false,
            })
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
            .put_publication(PreparedPublication {
                alert_id: operation_id.to_owned(),
                payload_sha256,
                group_id: group_id.clone(),
                message: msg.clone(),
                confirmed: false,
                pending_ref: Some(pending.as_u64()),
                push_trigger: None,
                push_published: false,
            })
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
        self.storage.put_publication(existing).map_err(map_storage)?;
        self.note_epochs()?;
        let _ = self.storage.bump_revision().map_err(map_storage)?;
        Ok(())
    }

    pub fn epoch(&self, group_id: &GroupId) -> Result<u64, SessionError> {
        Ok(self.storage.get_group(group_id).map_err(map_storage)?.epoch.0)
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
    web_time_now()
}

fn web_time_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
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
        let sealed = session.seal(&key).unwrap();
        let restored = Session::open(&key, &sealed).unwrap();
        assert_eq!(restored.public_key_hex(), session.public_key_hex());
        let again = restored.fresh_key_package().await.unwrap();
        assert!(!again.bytes.is_empty());
    }
}
