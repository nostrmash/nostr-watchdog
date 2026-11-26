//! Official OpenMLS state, snapshotted after each completed operation.
//!
//! This is not the MDK `StorageProvider`. That trait is implemented by the
//! SQLCipher crate, which does not build for Workers. The snapshot is the
//! OpenMLS `MemoryStorage` map plus the group id and signature public key
//! needed to load it. The private signature key lives inside that map because
//! `SignatureKeyPair::store` writes it there before the snapshot is taken.
//!
//! A snapshot is taken only after OpenMLS returns. It is not a mid-operation
//! journal, and it must be persisted before the ciphertext is treated as sent.

use std::collections::HashMap;
use std::sync::RwLock;

use openmls::prelude::tls_codec::Serialize as TlsSerialize;
use openmls::prelude::{
    BasicCredential, Ciphersuite, CredentialWithKey, GroupId, LeafNodeParameters, MlsGroup,
    MlsGroupCreateConfig, OpenMlsProvider,
};
use openmls_basic_credential::SignatureKeyPair;
use openmls_memory_storage::MemoryStorage;
use openmls_rust_crypto::RustCrypto;
use openmls_traits::types::SignatureScheme;
use serde::{Deserialize, Serialize};

const SUITE: Ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

struct Provider {
    crypto: RustCrypto,
    storage: MemoryStorage,
}

impl OpenMlsProvider for Provider {
    type CryptoProvider = RustCrypto;
    type RandProvider = RustCrypto;
    type StorageProvider = MemoryStorage;

    fn storage(&self) -> &Self::StorageProvider {
        &self.storage
    }

    fn crypto(&self) -> &Self::CryptoProvider {
        &self.crypto
    }

    fn rand(&self) -> &Self::RandProvider {
        &self.crypto
    }
}

#[derive(Serialize, Deserialize)]
struct Snapshot {
    public_key: String,
    group_id: String,
    entries: Vec<(String, String)>,
}

pub struct Step {
    pub created: bool,
    pub epoch: u64,
    pub message_bytes: usize,
    pub storage_entries: usize,
    pub snapshot: Vec<u8>,
}

/// Create a group, or restore one and advance its epoch with a self-update.
pub fn step(previous: Option<&[u8]>) -> Result<Step, String> {
    match previous {
        None => create_group(),
        Some(bytes) => restore_and_update(bytes),
    }
}

fn create_group() -> Result<Step, String> {
    let provider = Provider {
        crypto: RustCrypto::default(),
        storage: MemoryStorage::default(),
    };
    let signer = SignatureKeyPair::new(SignatureScheme::ED25519).map_err(|_| "mls_signer")?;
    signer
        .store(provider.storage())
        .map_err(|_| "mls_signer_store")?;
    let credential = BasicCredential::new(b"watchdog-mls-probe".to_vec());
    let credential_with_key = CredentialWithKey {
        credential: credential.into(),
        signature_key: signer.to_public_vec().into(),
    };
    let config = MlsGroupCreateConfig::builder().ciphersuite(SUITE).build();
    let group = MlsGroup::new(&provider, &signer, &config, credential_with_key)
        .map_err(|_| "mls_group_create")?;
    let snapshot = encode(&provider.storage, signer.public(), group.group_id())?;
    Ok(Step {
        created: true,
        epoch: group.epoch().as_u64(),
        message_bytes: 0,
        storage_entries: entry_count(&provider.storage),
        snapshot,
    })
}

fn restore_and_update(bytes: &[u8]) -> Result<Step, String> {
    let snapshot: Snapshot = serde_json::from_slice(bytes).map_err(|_| "mls_snapshot")?;
    let provider = Provider {
        crypto: RustCrypto::default(),
        storage: decode_storage(&snapshot)?,
    };
    let public = hex::decode(&snapshot.public_key).map_err(|_| "mls_snapshot")?;
    let signer = SignatureKeyPair::read(provider.storage(), &public, SignatureScheme::ED25519)
        .ok_or("mls_signer_missing")?;
    let group_id =
        GroupId::from_slice(&hex::decode(&snapshot.group_id).map_err(|_| "mls_snapshot")?);
    let mut group = MlsGroup::load(provider.storage(), &group_id)
        .map_err(|_| "mls_group_load")?
        .ok_or("mls_group_missing")?;
    let epoch_before = group.epoch().as_u64();
    group
        .self_update(&provider, &signer, LeafNodeParameters::default())
        .map_err(|_| "mls_self_update")?;
    group
        .merge_pending_commit(&provider)
        .map_err(|_| "mls_merge")?;
    let message = group
        .create_message(&provider, &signer, b"watchdog")
        .map_err(|_| "mls_message")?;
    let epoch = group.epoch().as_u64();
    if epoch <= epoch_before {
        return Err("mls_epoch_did_not_advance".to_string());
    }
    let snapshot = encode(&provider.storage, signer.public(), group.group_id())?;
    Ok(Step {
        created: false,
        epoch,
        message_bytes: TlsSerialize::tls_serialize_detached(&message)
            .map(|bytes| bytes.len())
            .unwrap_or(0),
        storage_entries: entry_count(&provider.storage),
        snapshot,
    })
}

fn encode(
    storage: &MemoryStorage,
    public_key: &[u8],
    group_id: &GroupId,
) -> Result<Vec<u8>, String> {
    let snapshot = Snapshot {
        public_key: hex::encode(public_key),
        group_id: hex::encode(group_id.as_slice()),
        entries: export_entries(storage)?,
    };
    serde_json::to_vec(&snapshot).map_err(|_| "mls_snapshot".to_string())
}

fn export_entries(storage: &MemoryStorage) -> Result<Vec<(String, String)>, String> {
    let guard = storage
        .values
        .read()
        .map_err(|_| "mls_storage_lock".to_string())?;
    Ok(guard
        .iter()
        .map(|(key, value)| (hex::encode(key), hex::encode(value)))
        .collect())
}

fn decode_storage(snapshot: &Snapshot) -> Result<MemoryStorage, String> {
    let mut values = HashMap::new();
    for (key, value) in &snapshot.entries {
        values.insert(
            hex::decode(key).map_err(|_| "mls_snapshot".to_string())?,
            hex::decode(value).map_err(|_| "mls_snapshot".to_string())?,
        );
    }
    Ok(MemoryStorage {
        values: RwLock::new(values),
    })
}

fn entry_count(storage: &MemoryStorage) -> usize {
    storage.values.read().map(|guard| guard.len()).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_group_survives_a_storage_snapshot_and_then_advances() {
        let created = step(None).expect("create");
        assert!(created.created);
        assert!(created.storage_entries > 0);
        let restored = step(Some(&created.snapshot)).expect("restore");
        assert!(!restored.created);
        assert!(restored.epoch > created.epoch);
        assert!(restored.message_bytes > 0);
        assert!(restored.storage_entries >= created.storage_entries);
    }
}

#[cfg(target_arch = "wasm32")]
mod durable;
