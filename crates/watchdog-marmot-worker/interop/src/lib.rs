//! Official native MDK client. Storage is `SqliteAccountStorage`, not the
//! Durable Object adapter.

use std::sync::Arc;

use cgka_engine::account_identity_proof::{
    AccountIdentityProofRequest, AccountIdentityProofSigner,
};
use cgka_engine::{Engine, EngineBuilder, FeatureRegistry};
use cgka_traits::app_components::{NOSTR_ROUTING_COMPONENT_ID, default_group_components};
use cgka_traits::app_event::{MARMOT_APP_EVENT_KIND_CHAT, MarmotAppEvent};
use cgka_traits::group::ProtocolProfile;
use cgka_traits::storage::MessageStorage;
use cgka_traits::{
    CgkaEngine, EpochId, GroupEvent, GroupId, KeyPackage, MessageId, SendIntent, SendResult,
    TransportMessage,
};
use k256::schnorr::SigningKey;
use k256::schnorr::signature::hazmat::PrehashSigner;
use nostr::key::{Keys, SecretKey};
use storage_sqlite::SqliteAccountStorage;
use transport_nostr_peeler::NostrMlsPeeler;

pub struct OfficialRecipient {
    storage: SqliteAccountStorage,
    keys: Keys,
    proof: Arc<ProofSigner>,
    extra_components: Vec<u16>,
    features: FeatureRegistry,
}

impl OfficialRecipient {
    pub fn generate() -> Result<Self, String> {
        let mut secret = [0u8; 32];
        for _ in 0..8 {
            getrandom::getrandom(&mut secret).map_err(|error| error.to_string())?;
            if let Ok(keys) = keys_from(&secret) {
                let proof = ProofSigner::new(&secret)?;
                if proof.public_bytes() != keys.public_key().to_bytes() {
                    continue;
                }
                return Ok(Self {
                    storage: SqliteAccountStorage::in_memory_for_test()
                        .map_err(|error| error.to_string())?,
                    keys,
                    proof: Arc::new(proof),
                    extra_components: Vec::new(),
                    features: FeatureRegistry::new(),
                });
            }
        }
        Err("could not derive a Nostr identity".into())
    }

    pub fn with_app_capabilities(
        mut self,
        features: FeatureRegistry,
        extra_components: Vec<u16>,
    ) -> Self {
        self.features = features;
        self.extra_components = extra_components;
        self
    }

    pub fn storage(&self) -> &SqliteAccountStorage {
        &self.storage
    }

    pub fn public_key_hex(&self) -> String {
        hex::encode(self.keys.public_key().to_bytes())
    }

    pub async fn fresh_key_package(&self) -> Result<KeyPackage, String> {
        self.engine()?.fresh_key_package().await.map_err(|error| error.to_string())
    }

    pub async fn join_welcome(&self, welcome: TransportMessage) -> Result<GroupId, String> {
        self.engine()?
            .join_welcome(welcome)
            .await
            .map_err(|error| error.to_string())
    }

    /// Run the official convergence pass for a commit that ingest parked.
    /// Marmot waits one second before a single commit may become canonical.
    pub async fn settle(&self, group_id: &GroupId) -> Result<(), String> {
        let mut engine = self.engine()?;
        let delay = engine
            .prepare_convergence_cutoff_delay_ms(group_id)
            .map_err(|error| error.to_string())?
            .unwrap_or(0);
        if delay > 0 {
            tokio::time::sleep(std::time::Duration::from_millis(delay.saturating_add(50))).await;
        }
        engine
            .advance_convergence(group_id)
            .await
            .map_err(|error| error.to_string())?;
        let events = engine.drain_events();
        let ids = application_event_ids(&events);
        drop(engine);
        self.storage
            .delete_pending_application_events(&ids)
            .map_err(|error| error.to_string())?;
        Ok(())
    }

    pub async fn ingest(&self, message: TransportMessage) -> Result<Vec<String>, String> {
        let mut engine = self.engine()?;
        // Opening the engine reloads every unacknowledged application output.
        // Those belong to earlier calls. Acknowledge them before this message
        // so the returned chats are only what this transport message produced.
        let prior = engine.drain_events();
        self.storage
            .delete_pending_application_events(&application_event_ids(&prior))
            .map_err(|error| error.to_string())?;
        engine.ingest(message).await.map_err(|error| error.to_string())?;
        let events = engine.drain_events();
        let ids = application_event_ids(&events);
        drop(engine);
        self.storage
            .delete_pending_application_events(&ids)
            .map_err(|error| error.to_string())?;
        Ok(chats(events))
    }

    pub async fn send_app(
        &self,
        group_id: &GroupId,
        kind: u64,
        content: &str,
    ) -> Result<TransportMessage, String> {
        let mut engine = self.engine()?;
        let app = MarmotAppEvent::new(self.public_key_hex(), unix_now(), kind, Vec::new(), content);
        let payload = app.encode().map_err(|error| error.to_string())?;
        let result = engine
            .send(SendIntent::AppMessage {
                group_id: group_id.clone(),
                payload,
                expected_epoch: None,
                only_to_members: None,
            })
            .await
            .map_err(|error| error.to_string())?;
        match result {
            SendResult::ApplicationMessage { msg, .. } => Ok(msg),
            other => Err(format!("official client application message returned {other:?}")),
        }
    }

    pub fn own_leaf(&self, group_id: &GroupId) -> Result<u32, String> {
        self.engine()?
            .own_leaf_index(group_id)
            .map_err(|error| error.to_string())
    }

    pub fn keys(&self) -> &Keys {
        &self.keys
    }

    pub async fn send_chat(&self, group_id: &GroupId, text: &str) -> Result<TransportMessage, String> {
        let mut engine = self.engine()?;
        let app = MarmotAppEvent::new(self.public_key_hex(), unix_now(), MARMOT_APP_EVENT_KIND_CHAT, Vec::new(), text);
        let payload = app.encode().map_err(|error| error.to_string())?;
        let result = engine
            .send(SendIntent::AppMessage {
                group_id: group_id.clone(),
                payload,
                expected_epoch: None,
                only_to_members: None,
            })
            .await
            .map_err(|error| error.to_string())?;
        match result {
            SendResult::ApplicationMessage { msg, .. } => Ok(msg),
            other => Err(format!("official client chat returned {other:?}")),
        }
    }

    pub fn epoch(&self, group_id: &GroupId) -> Result<u64, String> {
        Ok(self
            .engine()?
            .group_record(group_id)
            .map_err(|error| error.to_string())?
            .epoch
            .0)
    }

    fn engine(&self) -> Result<Engine<SqliteAccountStorage>, String> {
        let mut engine = EngineBuilder::new(self.storage.clone())
            .identity(self.keys.public_key().to_bytes().to_vec())
            .account_identity_proof_signer(self.proof.clone())
            .feature_registry(self.features.clone())
            .supported_app_components({
                let mut components = default_group_components();
                components.insert(NOSTR_ROUTING_COMPONENT_ID);
                components.extend(self.extra_components.iter().copied());
                components
            })
            .protocol_profile(ProtocolProfile::Current)
            .peeler(Box::new(NostrMlsPeeler::new().with_welcome_signer(self.keys.clone())))
            .build()
            .map_err(|error| error.to_string())?;
        engine
            .hydrate_all_stored_groups()
            .map_err(|error| error.to_string())?;
        Ok(engine)
    }
}

fn keys_from(secret: &[u8; 32]) -> Result<Keys, String> {
    Ok(Keys::new(SecretKey::from_slice(secret).map_err(|error| error.to_string())?))
}

fn application_event_ids(events: &[GroupEvent]) -> Vec<MessageId> {
    events
        .iter()
        .filter_map(|event| match event {
            GroupEvent::MessageReceived { message_id, .. } => Some(message_id.clone()),
            GroupEvent::GroupJoined { via_welcome, .. } => Some(via_welcome.clone()),
            _ => None,
        })
        .collect()
}

fn chats(events: Vec<GroupEvent>) -> Vec<String> {
    events
        .into_iter()
        .filter_map(|event| match event {
            GroupEvent::MessageReceived { payload, .. } => MarmotAppEvent::decode(&payload).ok(),
            _ => None,
        })
        .filter(|event| event.kind == MARMOT_APP_EVENT_KIND_CHAT)
        .map(|event| event.content)
        .collect()
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

struct ProofSigner {
    key: SigningKey,
}

impl ProofSigner {
    fn new(secret: &[u8; 32]) -> Result<Self, String> {
        Ok(Self {
            key: SigningKey::from_slice(secret).map_err(|error| error.to_string())?,
        })
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

#[allow(dead_code)]
fn _epoch(epoch: EpochId) -> u64 {
    epoch.0
}
