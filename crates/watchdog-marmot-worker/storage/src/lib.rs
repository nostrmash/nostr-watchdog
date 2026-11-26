//! In-memory [`cgka_traits::StorageProvider`] with a sealed snapshot.
//!
//! Official MDK storage is SQLCipher. That stack does not build for
//! `wasm32-unknown-unknown`. This provider implements the same synchronous
//! contract in memory. A Durable Object commits the sealed snapshot only after
//! an operation returns, and only before the ciphertext is published.
//!
//! `StorageProvider::backend` returns [`cgka_traits::Backend::Sqlite`] because
//! that enum has no other variant. The engine does not choose behavior from it.
//! This store is not SQLCipher.

mod persist;
mod state;

use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard};

use cgka_traits::app_event::PendingAppMessageAuthority;
use cgka_traits::convergence_pass::DurableConvergencePass;
use cgka_traits::engine::GroupEvent;
use cgka_traits::group::{DisbandTombstone, Group, InvitationAdmission};
use cgka_traits::maintenance::{
    DurableGroupEvolution, DurableTransportFanout, GroupMaintenanceState, KeyPackageLifecycleState,
    MaintenanceObligation, PeriodicMaintenancePolicy,
};
use cgka_traits::message::{MessageRecord, MessageState};
use cgka_traits::storage::{
    AccountDeviceHistoryKey, AccountDeviceSignerBinding, ChangeNotDelivered, CommittedMembers,
    CommittedRoster, CommittedRosterStorage, CommittedRosterWrite, ConvergencePassStorage,
    ConvergencePolicyStorage, DeferredPeelGeneration, DeferredPeelGenerationStorage,
    DeviceGroupWelcomeExpectation, DeviceGroupWelcomeStorage, DisbandCandidate,
    DisbandCandidateStorage, DisbandRequest, DisbandRequestStorage, DisbandTombstoneStorage,
    GroupStateCheckpointRef, GroupStorage, KeyPackageBundleStorage, LeaveRequest,
    LeaveRequestStorage, MaintenanceStorage, MemberValidationCacheStorage, MessageStorage,
    OpenMlsContentFilter, OutboundFanoutStorage, OutboundIntentStorage, OwnCommitIntent,
    QueuedOutboundIntent, StorageError, StorageProvider, StorageResult, StoredKeyPackageBundle,
    TransportGroupRoute, WelcomeStorage,
};
use cgka_traits::welcome::PendingWelcome;
use cgka_traits::{Backend, CapabilityRequirement, EpochId, Feature, GroupId, MemberId, MessageId};
use openmls_memory_storage::MemoryStorage;
use openmls_traits::storage::CURRENT_VERSION;
use openmls_traits::storage::StorageProvider as OpenMlsStorageProvider;
use zeroize::Zeroizing;

pub use persist::{Document, PersistError, SealBinding, open_sealed, seal};

use state::{
    Forgotten, GroupImage, SnapKey, State, export_mls, import_mls, is_key_package_storage_key,
};

pub use state::{AccountBinding, PreparedPublication};

const KEY_PACKAGE_LABEL: &[u8] = b"KeyPackage";

struct Frame {
    state: State,
    mls: Vec<(Vec<u8>, Vec<u8>)>,
    hooks_len: usize,
}

struct Bag {
    state: State,
    frames: Vec<Frame>,
    hooks: Vec<Box<dyn FnOnce() + Send + 'static>>,
}

struct Shared {
    bag: Mutex<Bag>,
    mls: MemoryStorage,
}

/// Account-device store shared by an engine and the code that seals it.
#[derive(Clone)]
pub struct MemoryMdkStorage {
    shared: Arc<Shared>,
}

impl MemoryMdkStorage {
    pub fn empty() -> Self {
        Self {
            shared: Arc::new(Shared {
                bag: Mutex::new(Bag {
                    state: State::new(),
                    frames: Vec::new(),
                    hooks: Vec::new(),
                }),
                mls: MemoryStorage::default(),
            }),
        }
    }

    pub fn from_document(document: Document) -> Result<Self, PersistError> {
        let (state, mls) = State::load(document.state)?;
        let storage = Self::empty();
        {
            let mut bag = storage.lock().map_err(|_| PersistError::Busy)?;
            bag.state = state;
        }
        import_mls(&storage.shared.mls, mls).map_err(|_| PersistError::Corrupt)?;
        Ok(storage)
    }

    pub fn to_document(&self) -> Result<Document, PersistError> {
        let bag = self.lock().map_err(|_| PersistError::Busy)?;
        if !bag.frames.is_empty() {
            return Err(PersistError::Busy);
        }
        let mls = export_mls(&self.shared.mls).map_err(|_| PersistError::Capacity)?;
        Ok(Document {
            format: persist::FORMAT_VERSION,
            state: bag.state.save(&mls)?,
        })
    }

    pub fn account_secret(&self) -> Option<[u8; 32]> {
        self.lock().ok().and_then(|bag| {
            bag.state.account_secret.as_ref().and_then(|secret| {
                secret.as_slice().try_into().ok()
            })
        })
    }

    pub fn set_account_secret(&self, secret: &[u8; 32]) -> StorageResult<()> {
        self.mutate(|state| {
            if let Some(existing) = &state.account_secret {
                if existing.as_slice() != secret {
                    return Err(StorageError::Backend(
                        "account secret is already bound".into(),
                    ));
                }
                return Ok(());
            }
            state.account_secret = Some(Zeroizing::new(secret.to_vec()));
            Ok(())
        })
    }

    pub fn revision(&self) -> StorageResult<u64> {
        Ok(self.lock()?.state.revision)
    }

    pub fn bump_revision(&self) -> StorageResult<u64> {
        self.mutate(|state| {
            state.revision = state.revision.saturating_add(1);
            Ok(state.revision)
        })
    }

    pub fn publication(&self, alert_id: &str) -> StorageResult<Option<PreparedPublication>> {
        Ok(self
            .lock()?
            .state
            .journal
            .iter()
            .find(|row| row.alert_id == alert_id)
            .cloned())
    }

    pub fn put_publication(&self, publication: PreparedPublication) -> StorageResult<()> {
        self.mutate(|state| {
            if let Some(existing) = state
                .journal
                .iter()
                .find(|row| row.alert_id == publication.alert_id)
            {
                if existing.payload_sha256 != publication.payload_sha256
                    || existing.group_id != publication.group_id
                    || existing.operation_kind != publication.operation_kind
                    || existing.message != publication.message
                {
                    return Err(StorageError::Backend(
                        "operation id is already bound to a different group, payload, or ciphertext"
                            .into(),
                    ));
                }
            }
            upsert_alert(&mut state.journal, publication);
            trim_journal(&mut state.journal)?;
            Ok(())
        })
    }

    pub fn binding(&self) -> StorageResult<AccountBinding> {
        Ok(self.lock()?.state.binding.clone())
    }

    pub fn set_binding(&self, binding: AccountBinding, replace: bool) -> StorageResult<()> {
        if binding.project_id.is_empty() || binding.recipient_hex.len() != 64 {
            return Err(StorageError::Backend(
                "project and recipient are required".into(),
            ));
        }
        self.mutate(|state| {
            if !state.binding.project_id.is_empty()
                && state.binding.project_id != binding.project_id
            {
                return Err(StorageError::Backend(
                    "project id does not match the stored account".into(),
                ));
            }
            if !state.binding.recipient_hex.is_empty()
                && state.binding.recipient_hex != binding.recipient_hex
                && !replace
            {
                return Err(StorageError::Backend(
                    "operation identity does not match the stored recipient".into(),
                ));
            }
            if replace && !state.groups.is_empty() && state.binding.recipient_hex != binding.recipient_hex
            {
                return Err(StorageError::Backend(
                    "recipient replacement requires a new sender object once a group exists".into(),
                ));
            }
            state.binding = binding;
            Ok(())
        })
    }

    pub fn note_group_route(
        &self,
        group_id_hex: &str,
        nostr_group_hex: &str,
        relays: &[String],
    ) -> StorageResult<()> {
        self.mutate(|state| {
            state.binding.group_id_hex = Some(group_id_hex.to_owned());
            state.binding.nostr_group_hex = Some(nostr_group_hex.to_owned());
            if !relays.is_empty() {
                state.binding.relays = relays.to_vec();
            }
            Ok(())
        })
    }

    pub fn note_epoch(&self, group_id: &GroupId, epoch: u64) -> StorageResult<()> {
        self.mutate(|state| {
            let floor = state.floors.get(group_id).copied().unwrap_or(0);
            if epoch < floor {
                return Err(StorageError::Backend(
                    "refusing to persist an earlier MLS epoch".into(),
                ));
            }
            state.floors.insert(group_id.clone(), epoch);
            Ok(())
        })
    }

    pub fn epoch_floor(&self, group_id: &GroupId) -> StorageResult<u64> {
        Ok(self
            .lock()?
            .state
            .floors
            .get(group_id)
            .copied()
            .unwrap_or(0))
    }

    /// Audit callbacks queued by MDK. Run them only after the sealed snapshot
    /// is durable. Dropping them drops the callback without running it.
    pub fn drain_commit_hooks(&self) -> Vec<Box<dyn FnOnce() + Send + 'static>> {
        self.lock()
            .map(|mut bag| std::mem::take(&mut bag.hooks))
            .unwrap_or_default()
    }

    fn lock(&self) -> StorageResult<MutexGuard<'_, Bag>> {
        self.shared
            .bag
            .lock()
            .map_err(|_| StorageError::Backend("storage lock poisoned".into()))
    }

    fn begin(&self) -> StorageResult<()> {
        let mls = export_mls(&self.shared.mls)?;
        let mut bag = self.lock()?;
        let hooks_len = bag.hooks.len();
        let state = bag.state.clone();
        bag.frames.push(Frame {
            state,
            mls,
            hooks_len,
        });
        Ok(())
    }

    fn commit_frame(&self) -> StorageResult<()> {
        let mut bag = self.lock()?;
        bag.frames
            .pop()
            .ok_or_else(|| StorageError::Backend("no storage transaction is open".into()))?;
        Ok(())
    }

    fn rollback_frame(&self) -> StorageResult<()> {
        let mut bag = self.lock()?;
        let frame = bag
            .frames
            .pop()
            .ok_or_else(|| StorageError::Backend("no storage transaction is open".into()))?;
        let high_water = bag.state.pending_high_water.max(frame.state.pending_high_water);
        let roster_next = bag.state.roster_next.max(frame.state.roster_next);
        bag.hooks.truncate(frame.hooks_len);
        bag.state = frame.state;
        bag.state.pending_high_water = high_water;
        bag.state.roster_next = roster_next;
        let mls = frame.mls;
        drop(bag);
        import_mls(&self.shared.mls, mls)
    }

    fn mutate<T>(&self, f: impl FnOnce(&mut State) -> StorageResult<T>) -> StorageResult<T> {
        let mut bag = self.lock()?;
        f(&mut bag.state)
    }
}

impl GroupStorage for MemoryMdkStorage {
    fn invitation_admission(&self, id: &GroupId) -> StorageResult<Option<InvitationAdmission>> {
        Ok(self.lock()?.state.admissions.get(id).cloned())
    }

    fn put_invitation_admission(
        &self,
        id: &GroupId,
        admission: Option<&InvitationAdmission>,
    ) -> StorageResult<()> {
        self.mutate(|state| {
            match admission {
                Some(admission) => {
                    state.admissions.insert(id.clone(), admission.clone());
                }
                None => {
                    state.admissions.remove(id);
                }
            }
            Ok(())
        })
    }

    fn put_group_with_roster(
        &self,
        group: &Group,
        committed: &CommittedMembers,
    ) -> StorageResult<()> {
        self.mutate(|state| state.put_group_with_roster(group, committed))
    }

    fn put_group_keeping_roster(&self, group: &Group) -> StorageResult<()> {
        self.mutate(|state| {
            state.ensure_group_capacity(&group.id)?;
            state.groups.insert(group.id.clone(), group.clone());
            Ok(())
        })
    }

    fn get_group(&self, id: &GroupId) -> StorageResult<Group> {
        self.lock()?
            .state
            .groups
            .get(id)
            .cloned()
            .ok_or(StorageError::NotFound)
    }

    fn delete_group(&self, id: &GroupId) -> StorageResult<()> {
        let mut bag = self.lock()?;
        if !bag.state.groups.contains_key(id) {
            return Err(StorageError::NotFound);
        }
        bag.state.wipe_group(&self.shared.mls, id)
    }

    fn forget_group_local(&self, id: &GroupId, at: cgka_traits::Timestamp) -> StorageResult<bool> {
        let mut bag = self.lock()?;
        if bag
            .state
            .forgotten
            .get(id)
            .is_some_and(|row| row.awaiting)
        {
            return Ok(false);
        }
        let at = bag
            .state
            .forgotten
            .get(id)
            .map(|row| row.at)
            .unwrap_or(at);
        bag.state.wipe_group(&self.shared.mls, id)?;
        bag.state.forgotten.insert(
            id.clone(),
            Forgotten {
                at,
                awaiting: true,
            },
        );
        Ok(true)
    }

    fn is_group_forgotten(&self, id: &GroupId) -> StorageResult<bool> {
        Ok(self
            .lock()?
            .state
            .forgotten
            .get(id)
            .is_some_and(|row| row.awaiting))
    }

    fn group_local_reset_cutoff(
        &self,
        id: &GroupId,
    ) -> StorageResult<Option<cgka_traits::Timestamp>> {
        Ok(self.lock()?.state.forgotten.get(id).map(|row| row.at))
    }

    fn complete_group_local_reset(&self, id: &GroupId) -> StorageResult<()> {
        self.mutate(|state| {
            if let Some(row) = state.forgotten.get_mut(id) {
                row.awaiting = false;
            }
            Ok(())
        })
    }

    fn list_groups(&self) -> StorageResult<Vec<GroupId>> {
        let mut ids: Vec<_> = self.lock()?.state.groups.keys().cloned().collect();
        ids.sort_by(|left, right| left.as_slice().cmp(right.as_slice()));
        Ok(ids)
    }

    fn put_transport_group_route(
        &self,
        transport_group_id: &[u8],
        group_id: &GroupId,
        source_epoch: EpochId,
    ) -> StorageResult<()> {
        self.mutate(|state| {
            state.routes.insert(
                transport_group_id.to_vec(),
                TransportGroupRoute {
                    transport_group_id: transport_group_id.to_vec(),
                    group_id: group_id.clone(),
                    source_epoch,
                },
            );
            Ok(())
        })
    }

    fn list_transport_group_routes(&self) -> StorageResult<Vec<TransportGroupRoute>> {
        Ok(self.lock()?.state.routes.values().cloned().collect())
    }

    fn delete_transport_group_route(&self, transport_group_id: &[u8]) -> StorageResult<()> {
        self.mutate(|state| {
            state.routes.remove(transport_group_id);
            Ok(())
        })
    }

    fn delete_transport_group_routes_below_epoch(
        &self,
        group_id: &GroupId,
        cutoff: EpochId,
    ) -> StorageResult<()> {
        self.mutate(|state| {
            state.routes.retain(|_, route| {
                &route.group_id != group_id || route.source_epoch >= cutoff
            });
            Ok(())
        })
    }

    fn delete_transport_group_routes_for_group(&self, group_id: &GroupId) -> StorageResult<()> {
        self.mutate(|state| {
            state.routes.retain(|_, route| &route.group_id != group_id);
            Ok(())
        })
    }
}

impl CommittedRosterStorage for MemoryMdkStorage {
    fn committed_roster(&self, group_id: &GroupId) -> StorageResult<Option<CommittedRoster>> {
        Ok(self.lock()?.state.rosters.get(group_id).cloned())
    }

    fn committed_roster_revision(
        &self,
        group_id: &GroupId,
    ) -> StorageResult<Option<cgka_traits::storage::RosterRevision>> {
        Ok(self
            .lock()?
            .state
            .rosters
            .get(group_id)
            .map(|roster| roster.revision))
    }

    fn put_committed_roster(
        &self,
        group_id: &GroupId,
        members: &CommittedMembers,
    ) -> StorageResult<CommittedRosterWrite> {
        self.mutate(|state| state.put_committed_roster(group_id, members))
    }
}

impl MessageStorage for MemoryMdkStorage {
    fn put_message(&self, record: &MessageRecord) -> StorageResult<()> {
        self.mutate(|state| state.put_message(record))
    }

    fn get_message(&self, id: &MessageId) -> StorageResult<MessageRecord> {
        self.lock()?
            .state
            .messages
            .iter()
            .find(|record| &record.id == id)
            .cloned()
            .ok_or(StorageError::NotFound)
    }

    fn delete_message(&self, id: &MessageId) -> StorageResult<()> {
        self.mutate(|state| {
            let before = state.messages.len();
            state.messages.retain(|record| &record.id != id);
            if state.messages.len() == before {
                Err(StorageError::NotFound)
            } else {
                Ok(())
            }
        })
    }

    fn update_message_state(&self, id: &MessageId, new_state: MessageState) -> StorageResult<()> {
        self.mutate(|state| {
            let record = state
                .messages
                .iter_mut()
                .find(|record| &record.id == id)
                .ok_or(StorageError::NotFound)?;
            record.state = new_state;
            Ok(())
        })
    }

    fn list_messages(
        &self,
        group_id: &GroupId,
        at_or_after_epoch: EpochId,
    ) -> StorageResult<Vec<MessageRecord>> {
        Ok(self
            .lock()?
            .state
            .messages_for(group_id, at_or_after_epoch))
    }

    fn list_openmls_messages_in_states(
        &self,
        group_id: &GroupId,
        states: &[MessageState],
        at_or_after_epoch: EpochId,
        _filter: OpenMlsContentFilter,
    ) -> StorageResult<Vec<MessageRecord>> {
        self.list_messages_in_states(group_id, states, at_or_after_epoch)
    }

    fn put_pending_application_event(&self, event: &GroupEvent) -> StorageResult<()> {
        self.mutate(|state| state.put_pending_event(event))
    }

    fn list_pending_application_events(&self) -> StorageResult<Vec<GroupEvent>> {
        Ok(self.lock()?.state.pending_events.clone())
    }

    fn pending_application_authority_batch(
        &self,
        after: Option<&MessageId>,
        limit: usize,
    ) -> StorageResult<Vec<PendingAppMessageAuthority>> {
        let bag = self.lock()?;
        let mut rows = bag.state.authorities.iter().cloned();
        if let Some(after) = after {
            rows.find(|item| &item.message_id == after);
        }
        Ok(rows.take(limit).collect())
    }

    fn delete_pending_application_events(&self, ids: &[MessageId]) -> StorageResult<()> {
        self.mutate(|state| {
            state
                .pending_events
                .retain(|event| !event_matches(event, ids));
            state
                .authorities
                .retain(|item| !ids.iter().any(|id| id == &item.message_id));
            Ok(())
        })
    }

    fn put_ingress_dedup_marker(&self, id: &MessageId) -> StorageResult<()> {
        self.mutate(|state| {
            if state.ingress.iter().any(|existing| existing == id) {
                return Ok(());
            }
            state.ingress.push_back(id.clone());
            while state.ingress.len() > state::MAX_INGRESS_MARKERS {
                state.ingress.pop_front();
            }
            Ok(())
        })
    }

    fn has_ingress_dedup_marker(&self, id: &MessageId) -> StorageResult<bool> {
        Ok(self.lock()?.state.ingress.iter().any(|existing| existing == id))
    }

    fn put_processed_transport_id(
        &self,
        group_id: &GroupId,
        transport_id: &MessageId,
    ) -> StorageResult<()> {
        self.mutate(|state| {
            if let Some(existing) = state.processed.get(transport_id) {
                if existing != group_id {
                    return Err(StorageError::Backend(
                        "processed transport id is already assigned to another group".into(),
                    ));
                }
            }
            state
                .processed
                .insert(transport_id.clone(), group_id.clone());
            Ok(())
        })
    }

    fn has_processed_transport_id(&self, transport_id: &MessageId) -> StorageResult<bool> {
        Ok(self.lock()?.state.processed.contains_key(transport_id))
    }

    fn create_group_snapshot(&self, group_id: &GroupId, name: &str) -> StorageResult<()> {
        self.store_image(group_id, name, true, true, false)
    }

    fn create_group_state_snapshot(&self, group_id: &GroupId, name: &str) -> StorageResult<()> {
        self.store_image(group_id, name, false, true, false)
    }

    fn list_group_snapshots(&self, group_id: &GroupId) -> StorageResult<Vec<String>> {
        let mut names: Vec<_> = self
            .lock()?
            .state
            .snapshots
            .keys()
            .filter(|key| &key.group == group_id)
            .map(|key| key.name.clone())
            .collect();
        names.sort();
        Ok(names)
    }

    fn rollback_group_to_snapshot(&self, group_id: &GroupId, name: &str) -> StorageResult<()> {
        self.restore_named(group_id, name, true, false)
    }

    fn rollback_group_state_to_snapshot(
        &self,
        group_id: &GroupId,
        name: &str,
    ) -> StorageResult<()> {
        self.restore_named(group_id, name, false, false)
    }

    fn release_group_snapshot(&self, group_id: &GroupId, name: &str) -> StorageResult<()> {
        self.mutate(|state| {
            state.snapshots.remove(&SnapKey {
                group: group_id.clone(),
                name: name.to_owned(),
            });
            Ok(())
        })
    }

    fn create_group_state_checkpoint(
        &self,
        group_id: &GroupId,
        checkpoint: &GroupStateCheckpointRef,
    ) -> StorageResult<()> {
        let mut image = {
            let bag = self.lock()?;
            bag.state
                .capture_image(&self.shared.mls, group_id, false, false)?
        };
        image.checkpoint_epoch = Some(checkpoint.resulting_epoch);
        let key = SnapKey {
            group: group_id.clone(),
            name: checkpoint.id.clone(),
        };
        self.mutate(|state| {
            if let Some(existing) = state.checkpoints.get(&key) {
                if !checkpoint_same(existing, &image) {
                    return Err(StorageError::AlreadyExists);
                }
                return Ok(());
            }
            let count = state
                .checkpoints
                .keys()
                .filter(|item| item.group == key.group)
                .count();
            if count >= state::MAX_SNAPSHOTS_PER_GROUP {
                return Err(StorageError::Capacity(
                    "group checkpoint limit reached".into(),
                ));
            }
            state.checkpoints.insert(key, image);
            Ok(())
        })
    }

    fn restore_group_state_checkpoint(
        &self,
        group_id: &GroupId,
        checkpoint_id: &str,
    ) -> StorageResult<()> {
        self.restore_named(group_id, checkpoint_id, false, true)
    }

    fn list_group_state_checkpoints(
        &self,
        group_id: &GroupId,
    ) -> StorageResult<Vec<GroupStateCheckpointRef>> {
        Ok(self
            .lock()?
            .state
            .checkpoints
            .iter()
            .filter(|(key, _)| &key.group == group_id)
            .map(|(key, image)| GroupStateCheckpointRef {
                id: key.name.clone(),
                resulting_epoch: image.checkpoint_epoch.unwrap_or(image.group.epoch),
            })
            .collect())
    }

    fn release_group_state_checkpoint(
        &self,
        group_id: &GroupId,
        checkpoint_id: &str,
    ) -> StorageResult<()> {
        self.mutate(|state| {
            state.checkpoints.remove(&SnapKey {
                group: group_id.clone(),
                name: checkpoint_id.to_owned(),
            });
            Ok(())
        })
    }
}

impl MemoryMdkStorage {
    fn store_image(
        &self,
        group_id: &GroupId,
        name: &str,
        full_messages: bool,
        include_policy: bool,
        _checkpoint: bool,
    ) -> StorageResult<()> {
        let image = {
            let bag = self.lock()?;
            bag.state.capture_image(
                &self.shared.mls,
                group_id,
                full_messages,
                include_policy,
            )?
        };
        let key = SnapKey {
            group: group_id.clone(),
            name: name.to_owned(),
        };
        self.mutate(|state| {
            if !state.snapshots.contains_key(&key) {
                let count = state
                    .snapshots
                    .keys()
                    .filter(|item| item.group == key.group)
                    .count();
                if count >= state::MAX_SNAPSHOTS_PER_GROUP {
                    return Err(StorageError::Capacity(
                        "group snapshot limit reached".into(),
                    ));
                }
            }
            state.snapshots.insert(key, image);
            Ok(())
        })
    }

    fn restore_named(
        &self,
        group_id: &GroupId,
        name: &str,
        messages: bool,
        checkpoint: bool,
    ) -> StorageResult<()> {
        let key = SnapKey {
            group: group_id.clone(),
            name: name.to_owned(),
        };
        let mut bag = self.lock()?;
        let image = if checkpoint {
            bag.state.checkpoints.get(&key)
        } else {
            bag.state.snapshots.get(&key)
        }
        .cloned()
        .ok_or_else(|| StorageError::SnapshotMissing(name.to_owned()))?;
        bag.state
            .restore_image(&self.shared.mls, group_id, &image, messages)
    }
}

impl OutboundIntentStorage for MemoryMdkStorage {
    fn put_queued_outbound_intent(&self, record: &QueuedOutboundIntent) -> StorageResult<()> {
        self.mutate(|state| {
            upsert(&mut state.queued, &record.id, record.clone(), |item| &item.id);
            Ok(())
        })
    }

    fn list_queued_outbound_intents(
        &self,
        group_id: &GroupId,
    ) -> StorageResult<Vec<QueuedOutboundIntent>> {
        Ok(self
            .lock()?
            .state
            .queued
            .iter()
            .filter(|item| &item.group_id == group_id)
            .cloned()
            .collect())
    }

    fn delete_queued_outbound_intent(&self, id: &MessageId) -> StorageResult<()> {
        self.mutate(|state| {
            state.queued.retain(|item| &item.id != id);
            Ok(())
        })
    }

    fn put_own_commit_intent(&self, record: &OwnCommitIntent) -> StorageResult<()> {
        self.mutate(|state| {
            upsert(
                &mut state.own_commits,
                &record.commit_id,
                record.clone(),
                |item| &item.commit_id,
            );
            Ok(())
        })
    }

    fn own_commit_intent(&self, commit_id: &MessageId) -> StorageResult<Option<OwnCommitIntent>> {
        Ok(self
            .lock()?
            .state
            .own_commits
            .iter()
            .find(|item| &item.commit_id == commit_id)
            .cloned())
    }

    fn list_own_commit_intents(
        &self,
        group_id: Option<&GroupId>,
    ) -> StorageResult<Vec<OwnCommitIntent>> {
        Ok(self
            .lock()?
            .state
            .own_commits
            .iter()
            .filter(|item| group_id.is_none_or(|id| &item.group_id == id))
            .cloned()
            .collect())
    }

    fn delete_own_commit_intent(&self, commit_id: &MessageId) -> StorageResult<()> {
        self.mutate(|state| {
            state
                .own_commits
                .retain(|item| &item.commit_id != commit_id);
            Ok(())
        })
    }

    fn put_change_not_delivered(&self, record: &ChangeNotDelivered) -> StorageResult<()> {
        self.mutate(|state| {
            if state.changes.iter().any(|item| {
                item.group_id == record.group_id && item.commit_id == record.commit_id
            }) {
                return Ok(());
            }
            state.changes.push(record.clone());
            Ok(())
        })
    }

    fn changes_not_delivered(&self, group_id: &GroupId) -> StorageResult<Vec<ChangeNotDelivered>> {
        Ok(self
            .lock()?
            .state
            .changes
            .iter()
            .filter(|item| &item.group_id == group_id)
            .cloned()
            .collect())
    }

    fn delete_change_not_delivered(
        &self,
        group_id: &GroupId,
        commit_id: &MessageId,
    ) -> StorageResult<bool> {
        self.mutate(|state| {
            let before = state.changes.len();
            state
                .changes
                .retain(|item| &item.group_id != group_id || &item.commit_id != commit_id);
            Ok(state.changes.len() != before)
        })
    }
}

impl OutboundFanoutStorage for MemoryMdkStorage {
    fn put_outbound_fanout(&self, fanout: &cgka_traits::OutboundFanout) -> StorageResult<()> {
        self.mutate(|state| {
            if let Some(previous) = state
                .fanouts
                .iter()
                .find(|item| item.message_id() == fanout.message_id())
            {
                fanout.validate_successor_of(previous).map_err(|_| {
                    StorageError::Backend(
                        "outbound fanout update would alter or regress durable state".into(),
                    )
                })?;
            }
            if let Some(pending) = fanout.pending_ref() {
                state.raise_high_water(pending.as_u64());
            }
            upsert(
                &mut state.fanouts,
                fanout.message_id(),
                fanout.clone(),
                |item| item.message_id(),
            );
            Ok(())
        })
    }

    fn outbound_fanout(
        &self,
        message_id: &MessageId,
    ) -> StorageResult<Option<cgka_traits::OutboundFanout>> {
        Ok(self
            .lock()?
            .state
            .fanouts
            .iter()
            .find(|item| item.message_id() == message_id)
            .cloned())
    }

    fn list_outbound_fanouts(&self) -> StorageResult<Vec<cgka_traits::OutboundFanout>> {
        Ok(self.lock()?.state.fanouts.clone())
    }

    fn list_outbound_fanouts_for_group(
        &self,
        group_id: &GroupId,
    ) -> StorageResult<Vec<cgka_traits::OutboundFanout>> {
        Ok(self
            .lock()?
            .state
            .fanouts
            .iter()
            .filter(|item| item.group_id() == Some(group_id))
            .cloned()
            .collect())
    }

    fn delete_outbound_fanout(&self, message_id: &MessageId) -> StorageResult<()> {
        self.mutate(|state| {
            state
                .fanouts
                .retain(|item| item.message_id() != message_id);
            Ok(())
        })
    }
}

impl LeaveRequestStorage for MemoryMdkStorage {
    fn put_leave_request(&self, request: &LeaveRequest) -> StorageResult<()> {
        self.mutate(|state| {
            state
                .leaves
                .insert(request.group_id.clone(), request.clone());
            Ok(())
        })
    }

    fn leave_request(&self, group_id: &GroupId) -> StorageResult<Option<LeaveRequest>> {
        Ok(self.lock()?.state.leaves.get(group_id).cloned())
    }

    fn clear_leave_request(&self, group_id: &GroupId) -> StorageResult<()> {
        self.mutate(|state| {
            state.leaves.remove(group_id);
            Ok(())
        })
    }
}

impl DisbandRequestStorage for MemoryMdkStorage {
    fn put_disband_request(&self, request: &DisbandRequest) -> StorageResult<()> {
        self.mutate(|state| {
            state
                .disband_requests
                .insert(request.group_id.clone(), request.clone());
            Ok(())
        })
    }

    fn disband_request(&self, group_id: &GroupId) -> StorageResult<Option<DisbandRequest>> {
        Ok(self.lock()?.state.disband_requests.get(group_id).cloned())
    }

    fn clear_disband_request(&self, group_id: &GroupId) -> StorageResult<()> {
        self.mutate(|state| {
            state.disband_requests.remove(group_id);
            Ok(())
        })
    }
}

impl DisbandCandidateStorage for MemoryMdkStorage {
    fn put_disband_candidate(&self, candidate: &DisbandCandidate) -> StorageResult<()> {
        self.mutate(|state| {
            if let Some(slot) = state.disband_candidates.iter_mut().find(|item| {
                item.group_id == candidate.group_id && item.commit_id == candidate.commit_id
            }) {
                *slot = candidate.clone();
            } else {
                state.disband_candidates.push(candidate.clone());
            }
            Ok(())
        })
    }

    fn disband_candidate(
        &self,
        group_id: &GroupId,
        commit_id: &MessageId,
    ) -> StorageResult<Option<DisbandCandidate>> {
        Ok(self
            .lock()?
            .state
            .disband_candidates
            .iter()
            .find(|item| &item.group_id == group_id && &item.commit_id == commit_id)
            .cloned())
    }

    fn list_disband_candidates(&self, group_id: &GroupId) -> StorageResult<Vec<DisbandCandidate>> {
        Ok(self
            .lock()?
            .state
            .disband_candidates
            .iter()
            .filter(|item| &item.group_id == group_id)
            .cloned()
            .collect())
    }

    fn clear_disband_candidates(&self, group_id: &GroupId) -> StorageResult<()> {
        self.mutate(|state| {
            state
                .disband_candidates
                .retain(|item| &item.group_id != group_id);
            Ok(())
        })
    }
}

impl DisbandTombstoneStorage for MemoryMdkStorage {
    fn put_disband_tombstone(
        &self,
        group_id: &GroupId,
        tombstone: &DisbandTombstone,
    ) -> StorageResult<()> {
        self.mutate(|state| {
            let mut stored = tombstone.clone();
            if state
                .tombstones
                .get(group_id)
                .is_some_and(|existing| existing.announced)
            {
                stored.announced = true;
            }
            state.tombstones.insert(group_id.clone(), stored);
            Ok(())
        })
    }

    fn disband_tombstone(
        &self,
        group_id: &GroupId,
    ) -> StorageResult<Option<DisbandTombstone>> {
        Ok(self.lock()?.state.tombstones.get(group_id).cloned())
    }

    fn list_disband_tombstones(&self) -> StorageResult<Vec<(GroupId, DisbandTombstone)>> {
        Ok(self
            .lock()?
            .state
            .tombstones
            .iter()
            .map(|(id, tombstone)| (id.clone(), tombstone.clone()))
            .collect())
    }

    fn mark_disband_tombstone_announced(&self, group_id: &GroupId) -> StorageResult<()> {
        self.mutate(|state| {
            if let Some(tombstone) = state.tombstones.get_mut(group_id) {
                tombstone.announced = true;
            }
            Ok(())
        })
    }
}

impl WelcomeStorage for MemoryMdkStorage {
    fn put_welcome(&self, welcome: &PendingWelcome) -> StorageResult<()> {
        self.mutate(|state| {
            upsert(
                &mut state.welcomes,
                &welcome.message_id,
                welcome.clone(),
                |item| &item.message_id,
            );
            Ok(())
        })
    }

    fn take_welcome(&self, id: &MessageId) -> StorageResult<PendingWelcome> {
        self.mutate(|state| {
            let index = state
                .welcomes
                .iter()
                .position(|item| &item.message_id == id)
                .ok_or(StorageError::NotFound)?;
            Ok(state.welcomes.remove(index))
        })
    }

    fn list_welcomes(&self) -> StorageResult<Vec<PendingWelcome>> {
        Ok(self.lock()?.state.welcomes.clone())
    }
}

impl cgka_traits::storage::CapabilityStorage for MemoryMdkStorage {
    fn register_feature(
        &self,
        feature: Feature,
        requirement: CapabilityRequirement,
    ) -> StorageResult<()> {
        self.mutate(|state| {
            state.features.insert(feature.0.to_owned(), requirement);
            Ok(())
        })
    }

    fn feature_requirement(
        &self,
        feature: &Feature,
    ) -> StorageResult<Option<CapabilityRequirement>> {
        Ok(self.lock()?.state.features.get(feature.0).cloned())
    }
}

impl ConvergencePolicyStorage for MemoryMdkStorage {
    fn put_convergence_policy(&self, group_id: &GroupId, policy: &[u8]) -> StorageResult<()> {
        self.mutate(|state| {
            state.policies.insert(group_id.clone(), policy.to_vec());
            Ok(())
        })
    }

    fn convergence_policy(&self, group_id: &GroupId) -> StorageResult<Option<Vec<u8>>> {
        Ok(self.lock()?.state.policies.get(group_id).cloned())
    }
}

impl MemberValidationCacheStorage for MemoryMdkStorage {
    fn put_validated_tree_marker(&self, group_id: &GroupId, marker: &[u8]) -> StorageResult<()> {
        self.mutate(|state| {
            state.markers.insert(group_id.clone(), marker.to_vec());
            Ok(())
        })
    }

    fn validated_tree_marker(&self, group_id: &GroupId) -> StorageResult<Option<Vec<u8>>> {
        Ok(self.lock()?.state.markers.get(group_id).cloned())
    }
}

impl cgka_traits::storage::AccountDeviceSignerStorage for MemoryMdkStorage {
    fn put_account_device_signer(&self, binding: &AccountDeviceSignerBinding) -> StorageResult<()> {
        self.mutate(|state| {
            state
                .signers
                .insert(binding.marmot_identity.clone(), binding.clone());
            Ok(())
        })
    }

    fn account_device_signer(
        &self,
        marmot_identity: &MemberId,
    ) -> StorageResult<Option<AccountDeviceSignerBinding>> {
        Ok(self.lock()?.state.signers.get(marmot_identity).cloned())
    }
}

impl cgka_traits::storage::AccountDeviceHistoryKeyStorage for MemoryMdkStorage {
    fn put_account_device_history_key_if_absent(
        &self,
        key: &AccountDeviceHistoryKey,
    ) -> StorageResult<AccountDeviceHistoryKey> {
        self.mutate(|state| {
            if let Some(existing) = state.history_keys.get(&key.marmot_identity) {
                return Ok(existing.clone());
            }
            state
                .history_keys
                .insert(key.marmot_identity.clone(), key.clone());
            Ok(key.clone())
        })
    }

    fn account_device_history_key(
        &self,
        marmot_identity: &MemberId,
    ) -> StorageResult<Option<AccountDeviceHistoryKey>> {
        Ok(self
            .lock()?
            .state
            .history_keys
            .get(marmot_identity)
            .cloned())
    }
}

impl DeviceGroupWelcomeStorage for MemoryMdkStorage {
    fn put_device_group_welcome_expectation(
        &self,
        expectation: &DeviceGroupWelcomeExpectation,
    ) -> StorageResult<()> {
        self.mutate(|state| {
            state
                .expectations
                .insert(expectation.group_id.clone(), expectation.clone());
            Ok(())
        })
    }

    fn device_group_welcome_expectation(
        &self,
        group_id: &GroupId,
    ) -> StorageResult<Option<DeviceGroupWelcomeExpectation>> {
        Ok(self.lock()?.state.expectations.get(group_id).cloned())
    }

    fn device_group_welcome_expectations(
        &self,
    ) -> StorageResult<Vec<DeviceGroupWelcomeExpectation>> {
        Ok(self.lock()?.state.expectations.values().cloned().collect())
    }

    fn delete_device_group_welcome_expectation(&self, group_id: &GroupId) -> StorageResult<bool> {
        self.mutate(|state| Ok(state.expectations.remove(group_id).is_some()))
    }
}

impl KeyPackageBundleStorage for MemoryMdkStorage {
    fn stored_key_package_bundles(&self) -> StorageResult<Vec<StoredKeyPackageBundle>> {
        let guard = self
            .shared
            .mls
            .values
            .read()
            .map_err(|_| StorageError::Backend("openmls storage lock failed".into()))?;
        let mut rows: Vec<_> = guard
            .iter()
            .filter(|(key, _)| is_key_package_storage_key(key))
            .map(|(key, value)| StoredKeyPackageBundle {
                storage_key: key.clone(),
                value: Zeroizing::new(value.clone()),
            })
            .collect();
        rows.sort_by(|left, right| left.storage_key.cmp(&right.storage_key));
        let _ = (CURRENT_VERSION, KEY_PACKAGE_LABEL);
        Ok(rows)
    }

    fn delete_stored_key_package_bundle(&self, storage_key: &[u8]) -> StorageResult<()> {
        if !is_key_package_storage_key(storage_key) {
            return Err(StorageError::Backend(
                "refusing to delete a non-key-package OpenMLS row".into(),
            ));
        }
        let mut guard = self
            .shared
            .mls
            .values
            .write()
            .map_err(|_| StorageError::Backend("openmls storage lock failed".into()))?;
        guard.remove(storage_key);
        Ok(())
    }
}

impl ConvergencePassStorage for MemoryMdkStorage {
    fn convergence_pass(
        &self,
        group_id: &GroupId,
    ) -> StorageResult<Option<DurableConvergencePass>> {
        Ok(self.lock()?.state.passes.get(group_id).cloned())
    }

    fn put_convergence_pass(&self, pass: &DurableConvergencePass) -> StorageResult<()> {
        self.mutate(|state| {
            state.passes.insert(pass.group_id.clone(), pass.clone());
            Ok(())
        })
    }

    fn list_convergence_passes(&self) -> StorageResult<Vec<DurableConvergencePass>> {
        Ok(self.lock()?.state.passes.values().cloned().collect())
    }

    fn delete_convergence_pass(&self, group_id: &GroupId) -> StorageResult<()> {
        self.mutate(|state| {
            state.passes.remove(group_id);
            Ok(())
        })
    }
}

impl DeferredPeelGenerationStorage for MemoryMdkStorage {
    fn deferred_peel_generation(
        &self,
        group_id: &GroupId,
    ) -> StorageResult<Option<DeferredPeelGeneration>> {
        Ok(self.lock()?.state.deferred.get(group_id).cloned())
    }

    fn put_deferred_peel_generation(
        &self,
        generation: &DeferredPeelGeneration,
    ) -> StorageResult<()> {
        self.mutate(|state| {
            state
                .deferred
                .insert(generation.group_id.clone(), generation.clone());
            Ok(())
        })
    }

    fn delete_deferred_peel_generation(&self, group_id: &GroupId) -> StorageResult<()> {
        self.mutate(|state| {
            state.deferred.remove(group_id);
            Ok(())
        })
    }
}

impl MaintenanceStorage for MemoryMdkStorage {
    fn key_package_lifecycle(&self) -> StorageResult<Option<KeyPackageLifecycleState>> {
        Ok(self.lock()?.state.key_package_lifecycle.clone())
    }

    fn put_key_package_lifecycle(&self, lifecycle: &KeyPackageLifecycleState) -> StorageResult<()> {
        self.mutate(|state| {
            state.key_package_lifecycle = Some(lifecycle.clone());
            Ok(())
        })
    }

    fn group_maintenance(
        &self,
        group_id: &GroupId,
    ) -> StorageResult<Option<GroupMaintenanceState>> {
        Ok(self.lock()?.state.group_maintenance.get(group_id).cloned())
    }

    fn put_group_maintenance(&self, maintenance: &GroupMaintenanceState) -> StorageResult<()> {
        self.mutate(|state| {
            state
                .group_maintenance
                .insert(maintenance.group_id.clone(), maintenance.clone());
            Ok(())
        })
    }

    fn delete_group_maintenance(&self, group_id: &GroupId) -> StorageResult<()> {
        self.mutate(|state| {
            state.group_maintenance.remove(group_id);
            Ok(())
        })
    }

    fn put_maintenance_obligation(&self, record: &MaintenanceObligation) -> StorageResult<()> {
        self.mutate(|state| {
            upsert(
                &mut state.obligations,
                &record.id,
                record.clone(),
                |item| &item.id,
            );
            Ok(())
        })
    }

    fn maintenance_obligation(
        &self,
        id: &MessageId,
    ) -> StorageResult<Option<MaintenanceObligation>> {
        Ok(self
            .lock()?
            .state
            .obligations
            .iter()
            .find(|item| &item.id == id)
            .cloned())
    }

    fn list_maintenance_obligations(&self) -> StorageResult<Vec<MaintenanceObligation>> {
        Ok(self.lock()?.state.obligations.clone())
    }

    fn list_maintenance_obligations_for_group(
        &self,
        group_id: &GroupId,
    ) -> StorageResult<Vec<MaintenanceObligation>> {
        Ok(self
            .lock()?
            .state
            .obligations
            .iter()
            .filter(|item| &item.group_id == group_id)
            .cloned()
            .collect())
    }

    fn delete_maintenance_obligation(&self, id: &MessageId) -> StorageResult<()> {
        self.mutate(|state| {
            state.obligations.retain(|item| &item.id != id);
            Ok(())
        })
    }

    fn put_group_evolution(&self, record: &DurableGroupEvolution) -> StorageResult<()> {
        self.mutate(|state| {
            if let Some(pending) = record.pending_ref {
                state.raise_high_water(pending.as_u64());
            }
            upsert(
                &mut state.evolutions,
                &record.id,
                record.clone(),
                |item| &item.id,
            );
            Ok(())
        })
    }

    fn group_evolution(&self, id: &MessageId) -> StorageResult<Option<DurableGroupEvolution>> {
        Ok(self
            .lock()?
            .state
            .evolutions
            .iter()
            .find(|item| &item.id == id)
            .cloned())
    }

    fn list_group_evolutions(&self) -> StorageResult<Vec<DurableGroupEvolution>> {
        Ok(self.lock()?.state.evolutions.clone())
    }

    fn list_group_evolutions_for_group(
        &self,
        group_id: &GroupId,
    ) -> StorageResult<Vec<DurableGroupEvolution>> {
        Ok(self
            .lock()?
            .state
            .evolutions
            .iter()
            .filter(|item| &item.group_id == group_id)
            .cloned()
            .collect())
    }

    fn delete_group_evolution(&self, id: &MessageId) -> StorageResult<()> {
        self.mutate(|state| {
            state.evolutions.retain(|item| &item.id != id);
            Ok(())
        })
    }

    fn put_transport_fanout(&self, record: &DurableTransportFanout) -> StorageResult<()> {
        self.mutate(|state| {
            upsert(
                &mut state.transport_fanouts,
                &record.id,
                record.clone(),
                |item| &item.id,
            );
            Ok(())
        })
    }

    fn transport_fanout(
        &self,
        id: &MessageId,
    ) -> StorageResult<Option<DurableTransportFanout>> {
        Ok(self
            .lock()?
            .state
            .transport_fanouts
            .iter()
            .find(|item| &item.id == id)
            .cloned())
    }

    fn list_transport_fanouts(&self) -> StorageResult<Vec<DurableTransportFanout>> {
        Ok(self.lock()?.state.transport_fanouts.clone())
    }

    fn delete_transport_fanout(&self, id: &MessageId) -> StorageResult<()> {
        self.mutate(|state| {
            state.transport_fanouts.retain(|item| &item.id != id);
            Ok(())
        })
    }

    fn periodic_maintenance_policy(&self) -> StorageResult<PeriodicMaintenancePolicy> {
        Ok(self.lock()?.state.periodic)
    }

    fn put_periodic_maintenance_policy(
        &self,
        policy: PeriodicMaintenancePolicy,
    ) -> StorageResult<()> {
        self.mutate(|state| {
            state.periodic = policy;
            Ok(())
        })
    }
}

impl StorageProvider for MemoryMdkStorage {
    type Mls = MemoryStorage;

    fn mls_storage(&self) -> &Self::Mls {
        &self.shared.mls
    }

    fn pending_ref_high_water(&self) -> StorageResult<u64> {
        Ok(self.lock()?.state.pending_high_water)
    }

    fn maintenance_storage(&self) -> Option<&dyn MaintenanceStorage> {
        Some(self)
    }

    fn with_transaction<T, E, F>(&self, f: F) -> Result<T, E>
    where
        E: From<StorageError>,
        F: FnOnce(&Self) -> Result<T, E>,
    {
        self.begin().map_err(E::from)?;
        match f(self) {
            Ok(value) => {
                self.commit_frame().map_err(E::from)?;
                Ok(value)
            }
            Err(error) => {
                let _ = self.rollback_frame();
                Err(error)
            }
        }
    }

    fn after_commit(&self, callback: Box<dyn FnOnce() + Send + 'static>) {
        if let Ok(mut bag) = self.lock() {
            bag.hooks.push(callback);
        }
    }

    fn with_group_savepoint<T, E, F>(
        &self,
        _group_id: &GroupId,
        _fallback_snapshot: &str,
        f: F,
    ) -> Result<T, E>
    where
        E: From<StorageError>,
        F: FnOnce(&Self) -> Result<T, E>,
    {
        self.with_transaction(f)
    }

    fn has_atomic_group_savepoints(&self) -> bool {
        true
    }

    fn backend(&self) -> Backend {
        Backend::Sqlite
    }
}

fn trim_journal(rows: &mut Vec<PreparedPublication>) -> StorageResult<()> {
    if rows.len() <= state::MAX_JOURNAL {
        return Ok(());
    }
    let mut index = 0;
    while rows.len() > state::MAX_JOURNAL && index < rows.len() {
        let phase = rows[index].message_phase.as_str();
        if phase == "relay_accepted" || phase == "rejected" {
            rows.remove(index);
        } else {
            index += 1;
        }
    }
    if rows.len() > state::MAX_JOURNAL.saturating_mul(2) {
        return Err(StorageError::Backend(
            "publication journal exceeded its bound".into(),
        ));
    }
    Ok(())
}

fn upsert_alert(rows: &mut Vec<PreparedPublication>, row: PreparedPublication) {
    if let Some(slot) = rows.iter_mut().find(|item| item.alert_id == row.alert_id) {
        *slot = row;
    } else {
        rows.push(row);
    }
}

fn upsert<T>(rows: &mut Vec<T>, id: &MessageId, row: T, id_of: impl Fn(&T) -> &MessageId) {
    if let Some(slot) = rows.iter_mut().find(|item| id_of(item) == id) {
        *slot = row;
    } else {
        rows.push(row);
    }
}

fn event_matches(event: &GroupEvent, ids: &[MessageId]) -> bool {
    let id = match event {
        GroupEvent::MessageReceived { message_id, .. } => message_id,
        GroupEvent::GroupJoined { via_welcome, .. } => via_welcome,
        _ => return false,
    };
    ids.iter().any(|candidate| candidate == id)
}

fn checkpoint_same(left: &GroupImage, right: &GroupImage) -> bool {
    left.group == right.group
        && left.marker == right.marker
        && left.mls == right.mls
        && left.checkpoint_epoch == right.checkpoint_epoch
}

#[allow(dead_code)]
fn _assert_openmls_provider(storage: &MemoryStorage) {
    fn assert_provider<T: OpenMlsStorageProvider<CURRENT_VERSION>>() {}
    assert_provider::<MemoryStorage>();
    let _ = storage;
}

#[allow(dead_code)]
fn _hashmap_anchor<T>(value: HashMap<u8, T>) -> usize {
    value.len()
}

#[cfg(test)]
mod tests {
    use super::*;
    use cgka_traits::message::MessageState;

    fn message(id: u8, epoch: u64) -> MessageRecord {
        MessageRecord {
            id: MessageId::new(vec![id]),
            group_id: GroupId::new(vec![9, 9]),
            epoch: EpochId(epoch),
            state: MessageState::Created,
            payload: vec![id],
            deferred_peel: None,
        }
    }

    #[test]
    fn a_failed_transaction_restores_records_and_keeps_the_high_water() {
        let storage = MemoryMdkStorage::empty();
        storage.put_message(&message(1, 0)).unwrap();
        storage
            .mutate(|state| {
                state.raise_high_water(4);
                Ok(())
            })
            .unwrap();
        let result: Result<(), StorageError> = storage.with_transaction(|storage| {
            storage.put_message(&message(2, 1))?;
            storage.mutate(|state| {
                state.raise_high_water(9);
                Ok(())
            })?;
            Err(StorageError::Backend("boom".into()))
        });
        assert!(result.is_err());
        assert!(storage.get_message(&MessageId::new(vec![2])).is_err());
        assert!(storage.get_message(&MessageId::new(vec![1])).is_ok());
        assert_eq!(storage.pending_ref_high_water().unwrap(), 9);
    }

    #[test]
    fn a_sealed_snapshot_round_trips_and_rejects_tampering() {
        let storage = MemoryMdkStorage::empty();
        storage.put_message(&message(7, 3)).unwrap();
        let document = storage.to_document().unwrap();
        let key = [7u8; 32];
        let binding = SealBinding {
            project_id: "smartflowsocial",
            account_hex: &"ab".repeat(32),
        };
        let sealed = seal(&key, binding, &document).unwrap();
        let opened =
            MemoryMdkStorage::from_document(open_sealed(&key, binding, &sealed).unwrap()).unwrap();
        let restored = opened.get_message(&MessageId::new(vec![7])).unwrap();
        assert_eq!(restored.epoch, EpochId(3));
        let mut tampered = sealed.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 0xff;
        assert!(open_sealed(&key, binding, &tampered).is_err());
        assert!(open_sealed(&[8u8; 32], binding, &sealed).is_err());
        let other = SealBinding {
            project_id: "other-project",
            account_hex: binding.account_hex,
        };
        assert!(open_sealed(&key, other, &sealed).is_err());
    }

    #[test]
    fn a_rolled_back_commit_callback_is_not_kept() {
        use cgka_traits::StorageProvider;
        let storage = MemoryMdkStorage::empty();
        let failed: Result<(), StorageError> = storage.with_transaction(|storage| {
            storage.after_commit(Box::new(|| {}));
            Err(StorageError::Backend("boom".into()))
        });
        assert!(failed.is_err());
        assert!(storage.drain_commit_hooks().is_empty());
        storage
            .with_transaction(|storage| {
                storage.after_commit(Box::new(|| {}));
                Ok::<(), StorageError>(())
            })
            .unwrap();
        assert_eq!(storage.drain_commit_hooks().len(), 1);
    }
}
