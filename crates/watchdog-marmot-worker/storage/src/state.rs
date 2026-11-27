//! Live MDK records. Snapshots and the sealed document are projections of this.

use std::collections::{HashMap, VecDeque};

use cgka_traits::app_event::PendingAppMessageAuthority;
use cgka_traits::convergence_pass::DurableConvergencePass;
use cgka_traits::engine::GroupEvent;
use cgka_traits::group::{DisbandTombstone, Group, InvitationAdmission};
use cgka_traits::maintenance::{
    DurableGroupEvolution, DurableTransportFanout, GroupMaintenanceState, KeyPackageLifecycleState,
    MaintenanceObligation, PeriodicMaintenancePolicy,
};
use cgka_traits::message::MessageRecord;
use cgka_traits::storage::{
    AccountDeviceHistoryKey, AccountDeviceSignerBinding, ChangeNotDelivered, CommittedMembers,
    CommittedRoster, CommittedRosterWrite, DeferredPeelGeneration, DeviceGroupWelcomeExpectation,
    DisbandCandidate, DisbandRequest, LeaveRequest, OwnCommitIntent, QueuedOutboundIntent,
    RosterRevision, StorageError, StorageResult, TransportGroupRoute,
};
use cgka_traits::transport::TransportMessage;
use cgka_traits::welcome::PendingWelcome;
use cgka_traits::{
    CapabilityRequirement, EpochId, GroupId, MemberId, MessageId, Timestamp,
};
use openmls_memory_storage::MemoryStorage;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::persist::PersistError;

pub(crate) const MAX_GROUPS: usize = 64;
pub(crate) const MAX_MESSAGES_PER_GROUP: usize = 4_096;
pub(crate) const MAX_MLS_ENTRIES: usize = 20_000;
pub(crate) const MAX_SNAPSHOTS_PER_GROUP: usize = 32;
pub(crate) const MAX_INGRESS_MARKERS: usize = 4_096;
pub(crate) const MAX_JOURNAL: usize = 64;
pub(crate) const SNAPSHOT_TOMBSTONE_LIMIT: usize = 4_096;

#[derive(Clone)]
pub(crate) struct State {
    pub pending_high_water: u64,
    pub roster_next: u64,
    pub groups: HashMap<GroupId, Group>,
    pub admissions: HashMap<GroupId, InvitationAdmission>,
    pub forgotten: HashMap<GroupId, Forgotten>,
    pub routes: HashMap<Vec<u8>, TransportGroupRoute>,
    pub rosters: HashMap<GroupId, CommittedRoster>,
    pub messages: Vec<MessageRecord>,
    pub queued: Vec<QueuedOutboundIntent>,
    pub own_commits: Vec<OwnCommitIntent>,
    pub changes: Vec<ChangeNotDelivered>,
    pub fanouts: Vec<cgka_traits::OutboundFanout>,
    pub leaves: HashMap<GroupId, LeaveRequest>,
    pub disband_requests: HashMap<GroupId, DisbandRequest>,
    pub disband_candidates: Vec<DisbandCandidate>,
    pub tombstones: HashMap<GroupId, DisbandTombstone>,
    pub welcomes: Vec<PendingWelcome>,
    pub features: HashMap<String, CapabilityRequirement>,
    pub policies: HashMap<GroupId, Vec<u8>>,
    pub markers: HashMap<GroupId, Vec<u8>>,
    pub signers: HashMap<MemberId, AccountDeviceSignerBinding>,
    pub history_keys: HashMap<MemberId, AccountDeviceHistoryKey>,
    pub expectations: HashMap<GroupId, DeviceGroupWelcomeExpectation>,
    pub passes: HashMap<GroupId, DurableConvergencePass>,
    pub deferred: HashMap<GroupId, DeferredPeelGeneration>,
    pub pending_events: Vec<GroupEvent>,
    pub authorities: Vec<PendingAppMessageAuthority>,
    pub ingress: VecDeque<MessageId>,
    pub processed: HashMap<MessageId, GroupId>,
    pub snapshots: HashMap<SnapKey, GroupImage>,
    pub checkpoints: HashMap<SnapKey, GroupImage>,
    pub key_package_lifecycle: Option<KeyPackageLifecycleState>,
    pub group_maintenance: HashMap<GroupId, GroupMaintenanceState>,
    pub obligations: Vec<MaintenanceObligation>,
    pub evolutions: Vec<DurableGroupEvolution>,
    pub transport_fanouts: Vec<DurableTransportFanout>,
    pub periodic: PeriodicMaintenancePolicy,
    pub journal: Vec<PreparedPublication>,
    pub operation_tombstones: Vec<OperationTombstone>,
    /// Number of retired identities. A sealed snapshot may omit the rows once
    /// they live in the Durable Object operation index.
    pub tombstone_high_water: u64,
    /// Set after the SQL operation index has been loaded into this process.
    pub tombstones_indexed: bool,
    pub observed_leaves: Vec<ObservedLeaf>,
    pub sync_cursors: Vec<SyncCursor>,
    pub wakes: Vec<StoredWake>,
    pub server_relays: Vec<ServerRelays>,
    pub floors: HashMap<GroupId, u64>,
    pub account_secret: Option<Zeroizing<Vec<u8>>>,
    pub revision: u64,
    pub binding: AccountBinding,
}

#[derive(Clone)]
pub(crate) struct Forgotten {
    pub at: Timestamp,
    pub awaiting: bool,
}

#[derive(Clone, PartialEq, Eq, Hash)]
pub(crate) struct SnapKey {
    pub group: GroupId,
    pub name: String,
}

#[derive(Clone)]
pub(crate) struct GroupImage {
    pub full_messages: bool,
    pub policy: Option<Option<Vec<u8>>>,
    pub marker: Option<Option<Vec<u8>>>,
    pub group: Group,
    pub messages: Option<Vec<MessageRecord>>,
    pub queued: Option<Vec<QueuedOutboundIntent>>,
    pub mls: Vec<(Vec<u8>, Vec<u8>)>,
    pub checkpoint_epoch: Option<EpochId>,
}

impl State {
    pub(crate) fn new() -> Self {
        Self {
            pending_high_water: 0,
            roster_next: 1,
            groups: HashMap::new(),
            admissions: HashMap::new(),
            forgotten: HashMap::new(),
            routes: HashMap::new(),
            rosters: HashMap::new(),
            messages: Vec::new(),
            queued: Vec::new(),
            own_commits: Vec::new(),
            changes: Vec::new(),
            fanouts: Vec::new(),
            leaves: HashMap::new(),
            disband_requests: HashMap::new(),
            disband_candidates: Vec::new(),
            tombstones: HashMap::new(),
            welcomes: Vec::new(),
            features: HashMap::new(),
            policies: HashMap::new(),
            markers: HashMap::new(),
            signers: HashMap::new(),
            history_keys: HashMap::new(),
            expectations: HashMap::new(),
            passes: HashMap::new(),
            deferred: HashMap::new(),
            pending_events: Vec::new(),
            authorities: Vec::new(),
            ingress: VecDeque::new(),
            processed: HashMap::new(),
            snapshots: HashMap::new(),
            checkpoints: HashMap::new(),
            key_package_lifecycle: None,
            group_maintenance: HashMap::new(),
            obligations: Vec::new(),
            evolutions: Vec::new(),
            transport_fanouts: Vec::new(),
            periodic: PeriodicMaintenancePolicy::Disabled,
            journal: Vec::new(),
            operation_tombstones: Vec::new(),
            tombstone_high_water: 0,
            tombstones_indexed: false,
            observed_leaves: Vec::new(),
            sync_cursors: Vec::new(),
            wakes: Vec::new(),
            server_relays: Vec::new(),
            floors: HashMap::new(),
            account_secret: None,
            revision: 0,
            binding: AccountBinding::default(),
        }
    }

    pub(crate) fn raise_high_water(&mut self, pending: u64) {
        if pending > self.pending_high_water {
            self.pending_high_water = pending;
        }
    }

    fn alloc_revision(&mut self) -> StorageResult<RosterRevision> {
        if self.roster_next == u64::MAX {
            return Err(StorageError::Capacity(
                "roster revision space is exhausted".into(),
            ));
        }
        let revision = RosterRevision(self.roster_next);
        self.roster_next += 1;
        Ok(revision)
    }

    pub(crate) fn put_group_with_roster(
        &mut self,
        group: &Group,
        committed: &CommittedMembers,
    ) -> StorageResult<()> {
        self.ensure_group_capacity(&group.id)?;
        self.groups.insert(group.id.clone(), group.clone());
        self.put_committed_roster(&group.id, committed)?;
        Ok(())
    }

    pub(crate) fn put_committed_roster(
        &mut self,
        group_id: &GroupId,
        members: &CommittedMembers,
    ) -> StorageResult<CommittedRosterWrite> {
        if !self.groups.contains_key(group_id) {
            return Err(StorageError::NotFound);
        }
        if let Some(existing) = self.rosters.get(group_id) {
            if &existing.members == members {
                return Ok(CommittedRosterWrite::Unchanged(existing.revision));
            }
        }
        let revision = self.alloc_revision()?;
        let write = if self.rosters.contains_key(group_id) {
            CommittedRosterWrite::Replaced(revision)
        } else {
            CommittedRosterWrite::Recorded(revision)
        };
        self.rosters.insert(
            group_id.clone(),
            CommittedRoster {
                revision,
                members: members.clone(),
            },
        );
        Ok(write)
    }

    pub(crate) fn ensure_group_capacity(&self, id: &GroupId) -> StorageResult<()> {
        if self.groups.contains_key(id) || self.groups.len() < MAX_GROUPS {
            Ok(())
        } else {
            Err(StorageError::Capacity(
                "account group limit reached".into(),
            ))
        }
    }

    pub(crate) fn wipe_group(&mut self, mls: &MemoryStorage, id: &GroupId) -> StorageResult<()> {
        self.groups.remove(id);
        self.admissions.remove(id);
        self.rosters.remove(id);
        self.policies.remove(id);
        self.markers.remove(id);
        self.leaves.remove(id);
        self.disband_requests.remove(id);
        self.expectations.remove(id);
        self.passes.remove(id);
        self.deferred.remove(id);
        self.group_maintenance.remove(id);
        self.routes.retain(|_, route| &route.group_id != id);
        self.messages.retain(|record| &record.group_id != id);
        self.queued.retain(|record| &record.group_id != id);
        self.own_commits.retain(|record| &record.group_id != id);
        self.changes.retain(|record| &record.group_id != id);
        self.fanouts.retain(|fanout| fanout.group_id() != Some(id));
        self.disband_candidates
            .retain(|candidate| &candidate.group_id != id);
        self.welcomes.retain(|welcome| &welcome.group_id != id);
        self.pending_events.retain(|event| event_group(event) != Some(id));
        self.authorities.retain(|item| &item.group_id != id);
        self.processed.retain(|_, group| group != id);
        self.obligations.retain(|item| &item.group_id != id);
        self.evolutions.retain(|item| &item.group_id != id);
        self.transport_fanouts
            .retain(|item| item.group_id.as_ref() != Some(id));
        self.snapshots.retain(|key, _| &key.group != id);
        self.checkpoints.retain(|key, _| &key.group != id);
        remove_group_mls(mls, id)?;
        Ok(())
    }

    pub(crate) fn put_message(&mut self, record: &MessageRecord) -> StorageResult<()> {
        if let Some(slot) = self
            .messages
            .iter_mut()
            .find(|item| item.id == record.id)
        {
            *slot = record.clone();
            return Ok(());
        }
        let count = self
            .messages
            .iter()
            .filter(|item| item.group_id == record.group_id)
            .count();
        if count >= MAX_MESSAGES_PER_GROUP {
            return Err(StorageError::Capacity(
                "group message limit reached".into(),
            ));
        }
        self.messages.push(record.clone());
        Ok(())
    }

    pub(crate) fn messages_for(
        &self,
        group_id: &GroupId,
        at_or_after: EpochId,
    ) -> Vec<MessageRecord> {
        self.messages
            .iter()
            .filter(|record| &record.group_id == group_id && record.epoch >= at_or_after)
            .cloned()
            .collect()
    }

    pub(crate) fn capture_image(
        &self,
        mls: &MemoryStorage,
        group_id: &GroupId,
        full_messages: bool,
        include_policy: bool,
    ) -> StorageResult<GroupImage> {
        let group = self
            .groups
            .get(group_id)
            .cloned()
            .ok_or(StorageError::NotFound)?;
        Ok(GroupImage {
            full_messages,
            policy: include_policy.then(|| self.policies.get(group_id).cloned()),
            marker: Some(self.markers.get(group_id).cloned()),
            group,
            messages: full_messages.then(|| self.messages_for(group_id, EpochId(0))),
            queued: full_messages.then(|| {
                self.queued
                    .iter()
                    .filter(|item| &item.group_id == group_id)
                    .cloned()
                    .collect()
            }),
            mls: group_mls_rows(mls, group_id)?,
            checkpoint_epoch: None,
        })
    }

    pub(crate) fn restore_image(
        &mut self,
        mls: &MemoryStorage,
        group_id: &GroupId,
        image: &GroupImage,
        messages: bool,
    ) -> StorageResult<()> {
        self.ensure_group_capacity(group_id)?;
        self.groups.insert(group_id.clone(), image.group.clone());
        if let Some(marker) = &image.marker {
            match marker {
                Some(bytes) => {
                    self.markers.insert(group_id.clone(), bytes.clone());
                }
                None => {
                    self.markers.remove(group_id);
                }
            }
        }
        if let Some(policy) = &image.policy {
            match policy {
                Some(bytes) => {
                    self.policies.insert(group_id.clone(), bytes.clone());
                }
                None => {
                    self.policies.remove(group_id);
                }
            }
        }
        replace_group_mls(mls, group_id, &image.mls)?;
        if messages && image.full_messages {
            if let Some(records) = &image.messages {
                self.messages.retain(|record| &record.group_id != group_id);
                self.messages.extend(records.iter().cloned());
            }
            if let Some(queued) = &image.queued {
                self.queued.retain(|record| &record.group_id != group_id);
                self.queued.extend(queued.iter().cloned());
            }
        }
        Ok(())
    }

    pub(crate) fn put_pending_event(&mut self, event: &GroupEvent) -> StorageResult<()> {
        let (group_id, message_id) = event_ids(event)?;
        if let GroupEvent::MessageReceived {
            epoch,
            sender,
            payload,
            authority,
            retention,
            ..
        } = event
        {
            if authority.is_none()
                && cgka_traits::MarmotAppEvent::decode(payload).is_ok_and(|decoded| {
                    cgka_traits::reporting::requires_source_authority(decoded.kind)
                })
            {
                if !self
                    .authorities
                    .iter()
                    .any(|item| item.message_id == message_id)
                {
                    self.authorities.push(PendingAppMessageAuthority {
                        group_id: group_id.clone(),
                        message_id: message_id.clone(),
                        epoch: *epoch,
                        sender: sender.clone(),
                        payload_digest: Sha256::digest(payload).into(),
                        retention: *retention,
                    });
                }
            } else {
                self.authorities
                    .retain(|item| item.message_id != message_id);
            }
        }
        if let Some(slot) = self.pending_events.iter_mut().find(|existing| {
            event_ids(existing).ok().map(|(_, id)| id) == Some(message_id.clone())
        }) {
            if pending_authority_upgrade(slot, event)? {
                *slot = event.clone();
                return Ok(());
            }
            if slot == event {
                return Ok(());
            }
            return Err(StorageError::Backend(
                "pending application event id reused with different content".into(),
            ));
        }
        let known = self.messages.iter().any(|record| {
            record.id == message_id && record.group_id == group_id
        });
        if !known {
            return Err(StorageError::NotFound);
        }
        self.pending_events.push(event.clone());
        Ok(())
    }

    pub(crate) fn save(&self, mls: &[(Vec<u8>, Vec<u8>)]) -> Result<SavedState, PersistError> {
        if mls.len() > MAX_MLS_ENTRIES {
            return Err(PersistError::Capacity);
        }
        Ok(SavedState {
            pending_high_water: self.pending_high_water,
            roster_next: self.roster_next,
            groups: sorted_values(self.groups.values().cloned()),
            admissions: self
                .admissions
                .iter()
                .map(|(id, admission)| SavedAdmission {
                    group_id: id.clone(),
                    generation: admission.generation,
                    created_locally: admission.created_locally,
                    via_welcome: admission.via_welcome.clone(),
                })
                .collect(),
            forgotten: self
                .forgotten
                .iter()
                .map(|(id, row)| SavedForgotten {
                    group_id: id.clone(),
                    at: row.at.0,
                    awaiting: row.awaiting,
                })
                .collect(),
            routes: self
                .routes
                .values()
                .map(|route| SavedRoute {
                    transport_group_id: route.transport_group_id.clone(),
                    group_id: route.group_id.clone(),
                    source_epoch: route.source_epoch,
                })
                .collect(),
            rosters: self
                .rosters
                .iter()
                .map(|(id, roster)| SavedRoster {
                    group_id: id.clone(),
                    revision: roster.revision.0,
                    members: roster.members.ids().to_vec(),
                })
                .collect(),
            messages: self.messages.clone(),
            queued: self.queued.clone(),
            own_commits: self.own_commits.clone(),
            changes: self.changes.clone(),
            fanouts: self.fanouts.clone(),
            leaves: self.leaves.values().cloned().collect(),
            disband_requests: self.disband_requests.values().cloned().collect(),
            disband_candidates: self.disband_candidates.clone(),
            tombstones: self
                .tombstones
                .iter()
                .map(|(id, tombstone)| SavedTombstone {
                    group_id: id.clone(),
                    tombstone: tombstone.clone(),
                })
                .collect(),
            welcomes: self.welcomes.clone(),
            features: self
                .features
                .iter()
                .map(|(name, requirement)| SavedFeature {
                    name: name.clone(),
                    requires: requirement.requires.clone(),
                    level: requirement.level.clone(),
                    description: requirement.description.to_owned(),
                })
                .collect(),
            policies: map_bytes(&self.policies),
            markers: map_bytes(&self.markers),
            signers: self.signers.values().cloned().collect(),
            history_keys: self
                .history_keys
                .values()
                .map(|key| SavedHistoryKey {
                    marmot_identity: key.marmot_identity.clone(),
                    ciphersuite: key.ciphersuite,
                    public_key: key.public_key.clone(),
                    private_key: key.private_key.to_vec(),
                })
                .collect(),
            expectations: self.expectations.values().cloned().collect(),
            passes: self.passes.values().cloned().collect(),
            deferred: self.deferred.values().cloned().collect(),
            pending_events: self.pending_events.clone(),
            authorities: self.authorities.clone(),
            ingress: self.ingress.iter().cloned().collect(),
            processed: self
                .processed
                .iter()
                .map(|(message, group)| SavedProcessed {
                    message_id: message.clone(),
                    group_id: group.clone(),
                })
                .collect(),
            snapshots: self
                .snapshots
                .iter()
                .map(|(key, image)| image.save(&key.group, &key.name))
                .collect::<Result<Vec<_>, _>>()?,
            checkpoints: self
                .checkpoints
                .iter()
                .map(|(key, image)| image.save(&key.group, &key.name))
                .collect::<Result<Vec<_>, _>>()?,
            key_package_lifecycle: self.key_package_lifecycle.clone(),
            group_maintenance: self.group_maintenance.values().cloned().collect(),
            obligations: self.obligations.clone(),
            evolutions: self.evolutions.clone(),
            transport_fanouts: self.transport_fanouts.clone(),
            periodic: self.periodic,
            mls: encode_pairs(mls),
            journal: self.journal.clone(),
            operation_tombstones: if self.tombstones_indexed {
                Vec::new()
            } else {
                self.operation_tombstones.clone()
            },
            tombstone_high_water: if self.tombstones_indexed {
                self.operation_tombstones.len() as u64
            } else {
                self.operation_tombstones.len() as u64
            },
            observed_leaves: self.observed_leaves.clone(),
            sync_cursors: self.sync_cursors.clone(),
            wakes: self.wakes.clone(),
            server_relays: self.server_relays.clone(),
            floors: self
                .floors
                .iter()
                .map(|(group_id, epoch)| SavedFloor {
                    group_id: group_id.clone(),
                    epoch: *epoch,
                })
                .collect(),
            account_secret_hex: self
                .account_secret
                .as_ref()
                .map(|secret| hex::encode(secret.as_slice())),
            revision: self.revision,
            binding: self.binding.clone(),
        })
    }

    pub(crate) fn load(saved: SavedState) -> Result<(Self, Vec<(Vec<u8>, Vec<u8>)>), PersistError> {
        if saved.roster_next == 0 || saved.mls.len() > MAX_MLS_ENTRIES {
            return Err(if saved.mls.len() > MAX_MLS_ENTRIES {
                PersistError::Capacity
            } else {
                PersistError::Corrupt
            });
        }
        let mut state = Self::new();
        state.pending_high_water = saved.pending_high_water;
        state.roster_next = saved.roster_next;
        for group in saved.groups {
            state.groups.insert(group.id.clone(), group);
        }
        for admission in saved.admissions {
            state.admissions.insert(
                admission.group_id,
                InvitationAdmission {
                    generation: admission.generation,
                    created_locally: admission.created_locally,
                    via_welcome: admission.via_welcome,
                },
            );
        }
        for row in saved.forgotten {
            state.forgotten.insert(
                row.group_id,
                Forgotten {
                    at: Timestamp(row.at),
                    awaiting: row.awaiting,
                },
            );
        }
        for route in saved.routes {
            state.routes.insert(
                route.transport_group_id.clone(),
                TransportGroupRoute {
                    transport_group_id: route.transport_group_id,
                    group_id: route.group_id,
                    source_epoch: route.source_epoch,
                },
            );
        }
        for roster in saved.rosters {
            state.rosters.insert(
                roster.group_id,
                CommittedRoster {
                    revision: RosterRevision(roster.revision),
                    members: CommittedMembers::from_ids(roster.members),
                },
            );
        }
        state.messages = saved.messages;
        state.queued = saved.queued;
        state.own_commits = saved.own_commits;
        state.changes = saved.changes;
        state.fanouts = saved.fanouts;
        for leave in saved.leaves {
            state.leaves.insert(leave.group_id.clone(), leave);
        }
        for request in saved.disband_requests {
            state
                .disband_requests
                .insert(request.group_id.clone(), request);
        }
        state.disband_candidates = saved.disband_candidates;
        for tombstone in saved.tombstones {
            state
                .tombstones
                .insert(tombstone.group_id, tombstone.tombstone);
        }
        state.welcomes = saved.welcomes;
        for feature in saved.features {
            state.features.insert(
                feature.name,
                CapabilityRequirement {
                    requires: feature.requires,
                    level: feature.level,
                    description: intern(&feature.description),
                },
            );
        }
        state.policies = unmap_bytes(saved.policies);
        state.markers = unmap_bytes(saved.markers);
        for signer in saved.signers {
            state
                .signers
                .insert(signer.marmot_identity.clone(), signer);
        }
        for key in saved.history_keys {
            state.history_keys.insert(
                key.marmot_identity.clone(),
                AccountDeviceHistoryKey {
                    marmot_identity: key.marmot_identity,
                    ciphersuite: key.ciphersuite,
                    public_key: key.public_key,
                    private_key: Zeroizing::new(key.private_key),
                },
            );
        }
        for expectation in saved.expectations {
            state
                .expectations
                .insert(expectation.group_id.clone(), expectation);
        }
        for pass in saved.passes {
            state.passes.insert(pass.group_id.clone(), pass);
        }
        for generation in saved.deferred {
            state
                .deferred
                .insert(generation.group_id.clone(), generation);
        }
        state.pending_events = saved.pending_events;
        state.authorities = saved.authorities;
        state.ingress = saved.ingress.into();
        for processed in saved.processed {
            state
                .processed
                .insert(processed.message_id, processed.group_id);
        }
        for image in saved.snapshots {
            let (key, decoded) = image.load()?;
            state.snapshots.insert(key, decoded);
        }
        for image in saved.checkpoints {
            let (key, decoded) = image.load()?;
            state.checkpoints.insert(key, decoded);
        }
        state.key_package_lifecycle = saved.key_package_lifecycle;
        for maintenance in saved.group_maintenance {
            state
                .group_maintenance
                .insert(maintenance.group_id.clone(), maintenance);
        }
        state.obligations = saved.obligations;
        state.evolutions = saved.evolutions;
        state.transport_fanouts = saved.transport_fanouts;
        state.periodic = saved.periodic;
        state.journal = saved.journal;
        state.operation_tombstones = saved.operation_tombstones;
        state.tombstone_high_water = saved.tombstone_high_water;
        state.tombstones_indexed = false;
        state.observed_leaves = saved.observed_leaves;
        state.sync_cursors = saved.sync_cursors;
        state.wakes = saved.wakes;
        state.server_relays = saved.server_relays;
        for floor in saved.floors {
            state.floors.insert(floor.group_id, floor.epoch);
        }
        if let Some(secret) = saved.account_secret_hex {
            let bytes = hex::decode(secret).map_err(|_| PersistError::Corrupt)?;
            if bytes.len() != 32 {
                return Err(PersistError::Corrupt);
            }
            state.account_secret = Some(Zeroizing::new(bytes));
        }
        state.revision = saved.revision;
        state.binding = saved.binding;
        if state.journal.len() > MAX_JOURNAL.saturating_mul(2) {
            return Err(PersistError::Capacity);
        }
        for group in state.groups.values() {
            if let Some(floor) = state.floors.get(&group.id) {
                if group.epoch.0 < *floor {
                    return Err(PersistError::Corrupt);
                }
            }
        }
        let mls = decode_pairs(&saved.mls)?;
        Ok((state, mls))
    }
}

impl GroupImage {
    fn save(&self, group_id: &GroupId, name: &str) -> Result<SavedImage, PersistError> {
        Ok(SavedImage {
            group_id: group_id.clone(),
            name: name.to_owned(),
            full_messages: self.full_messages,
            policy: tri_save(&self.policy),
            marker: tri_save(&self.marker),
            group: serde_json::to_value(&self.group).map_err(|_| PersistError::Corrupt)?,
            messages: optional_json(&self.messages)?,
            queued: optional_json(&self.queued)?,
            mls: encode_pairs(&self.mls),
            checkpoint_epoch: self.checkpoint_epoch,
        })
    }
}

fn optional_json<T: Serialize>(
    value: &Option<T>,
) -> Result<Option<Value>, PersistError> {
    value
        .as_ref()
        .map(|item| serde_json::to_value(item).map_err(|_| PersistError::Corrupt))
        .transpose()
}

fn tri_save(value: &Option<Option<Vec<u8>>>) -> SavedTri {
    match value {
        None => SavedTri::Omit,
        Some(None) => SavedTri::Absent,
        Some(Some(bytes)) => SavedTri::Present(bytes.clone()),
    }
}

fn tri_load(value: &SavedTri) -> Option<Option<Vec<u8>>> {
    match value {
        SavedTri::Omit => None,
        SavedTri::Absent => Some(None),
        SavedTri::Present(bytes) => Some(Some(bytes.clone())),
    }
}

fn pending_authority_upgrade(existing: &GroupEvent, incoming: &GroupEvent) -> StorageResult<bool> {
    let GroupEvent::MessageReceived {
        authority: Some(new),
        retention: new_retention,
        ..
    } = incoming
    else {
        return Ok(false);
    };
    let mut upgraded = existing.clone();
    let GroupEvent::MessageReceived {
        authority: old,
        retention: old_retention,
        ..
    } = &mut upgraded
    else {
        return Ok(false);
    };
    if old.is_some() {
        return Ok(false);
    }
    *old = Some(*new);
    if old_retention.is_none() {
        *old_retention = *new_retention;
    }
    Ok(&upgraded == incoming)
}

fn event_ids(event: &GroupEvent) -> StorageResult<(GroupId, MessageId)> {
    match event {
        GroupEvent::MessageReceived {
            group_id,
            message_id,
            ..
        } => Ok((group_id.clone(), message_id.clone())),
        GroupEvent::GroupJoined {
            group_id,
            via_welcome,
            ..
        } => Ok((group_id.clone(), via_welcome.clone())),
        _ => Err(StorageError::Backend(
            "pending application outbox accepts only MessageReceived and GroupJoined events"
                .into(),
        )),
    }
}

fn event_group(event: &GroupEvent) -> Option<&GroupId> {
    match event {
        GroupEvent::MessageReceived { group_id, .. }
        | GroupEvent::GroupJoined { group_id, .. } => Some(group_id),
        _ => None,
    }
}

pub(crate) fn group_needle(group_id: &GroupId) -> StorageResult<Vec<u8>> {
    let mls_id = openmls::group::GroupId::from_slice(group_id.as_slice());
    serde_json::to_vec(&mls_id).map_err(|error| StorageError::Serialization(error.to_string()))
}

pub(crate) fn export_mls(storage: &MemoryStorage) -> StorageResult<Vec<(Vec<u8>, Vec<u8>)>> {
    let guard = storage
        .values
        .read()
        .map_err(|_| StorageError::Backend("openmls storage lock failed".into()))?;
    if guard.len() > MAX_MLS_ENTRIES {
        return Err(StorageError::Capacity(
            "openmls storage limit reached".into(),
        ));
    }
    let mut rows: Vec<_> = guard
        .iter()
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect();
    rows.sort_by(|left, right| left.0.cmp(&right.0));
    Ok(rows)
}

pub(crate) fn import_mls(
    storage: &MemoryStorage,
    rows: Vec<(Vec<u8>, Vec<u8>)>,
) -> StorageResult<()> {
    if rows.len() > MAX_MLS_ENTRIES {
        return Err(StorageError::Capacity(
            "openmls storage limit reached".into(),
        ));
    }
    let mut guard = storage
        .values
        .write()
        .map_err(|_| StorageError::Backend("openmls storage lock failed".into()))?;
    guard.clear();
    guard.extend(rows);
    Ok(())
}

pub(crate) fn group_mls_rows(
    storage: &MemoryStorage,
    group_id: &GroupId,
) -> StorageResult<Vec<(Vec<u8>, Vec<u8>)>> {
    let needle = group_needle(group_id)?;
    let guard = storage
        .values
        .read()
        .map_err(|_| StorageError::Backend("openmls storage lock failed".into()))?;
    Ok(guard
        .iter()
        .filter(|(key, _)| key_matches(key, &needle))
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect())
}

pub(crate) fn replace_group_mls(
    storage: &MemoryStorage,
    group_id: &GroupId,
    rows: &[(Vec<u8>, Vec<u8>)],
) -> StorageResult<()> {
    let needle = group_needle(group_id)?;
    let mut guard = storage
        .values
        .write()
        .map_err(|_| StorageError::Backend("openmls storage lock failed".into()))?;
    guard.retain(|key, _| !key_matches(key, &needle));
    for (key, value) in rows {
        guard.insert(key.clone(), value.clone());
    }
    Ok(())
}

fn remove_group_mls(storage: &MemoryStorage, group_id: &GroupId) -> StorageResult<()> {
    replace_group_mls(storage, group_id, &[])
}

fn key_matches(key: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && key.windows(needle.len()).any(|window| window == needle)
}

pub(crate) fn is_key_package_storage_key(key: &[u8]) -> bool {
    const LABEL: &[u8] = b"KeyPackage";
    key.starts_with(LABEL)
        && key
            .get(LABEL.len())
            .is_some_and(|byte| !byte.is_ascii_alphabetic())
}

fn sorted_values<T>(values: impl Iterator<Item = T>) -> Vec<T> {
    values.collect()
}

fn map_bytes(map: &HashMap<GroupId, Vec<u8>>) -> Vec<SavedBytes> {
    map.iter()
        .map(|(id, bytes)| SavedBytes {
            group_id: id.clone(),
            bytes: bytes.clone(),
        })
        .collect()
}

fn unmap_bytes(rows: Vec<SavedBytes>) -> HashMap<GroupId, Vec<u8>> {
    rows.into_iter()
        .map(|row| (row.group_id, row.bytes))
        .collect()
}

fn encode_pairs(rows: &[(Vec<u8>, Vec<u8>)]) -> Vec<SavedPair> {
    rows.iter()
        .map(|(key, value)| SavedPair {
            key_hex: hex::encode(key),
            value_hex: hex::encode(value),
        })
        .collect()
}

fn decode_pairs(rows: &[SavedPair]) -> Result<Vec<(Vec<u8>, Vec<u8>)>, PersistError> {
    rows.iter()
        .map(|row| {
            Ok((
                hex::decode(&row.key_hex).map_err(|_| PersistError::Corrupt)?,
                hex::decode(&row.value_hex).map_err(|_| PersistError::Corrupt)?,
            ))
        })
        .collect()
}

fn intern(value: &str) -> &'static str {
    use std::sync::Mutex;
    static CACHE: Mutex<Vec<&'static str>> = Mutex::new(Vec::new());
    let mut cache = CACHE.lock().unwrap_or_else(|poison| poison.into_inner());
    if let Some(found) = cache.iter().copied().find(|item| *item == value) {
        return found;
    }
    let leaked: &'static str = Box::leak(value.to_owned().into_boxed_str());
    cache.push(leaked);
    leaked
}

#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct SavedState {
    pub pending_high_water: u64,
    pub roster_next: u64,
    pub groups: Vec<Group>,
    pub admissions: Vec<SavedAdmission>,
    pub forgotten: Vec<SavedForgotten>,
    pub routes: Vec<SavedRoute>,
    pub rosters: Vec<SavedRoster>,
    pub messages: Vec<MessageRecord>,
    pub queued: Vec<QueuedOutboundIntent>,
    pub own_commits: Vec<OwnCommitIntent>,
    pub changes: Vec<ChangeNotDelivered>,
    pub fanouts: Vec<cgka_traits::OutboundFanout>,
    pub leaves: Vec<LeaveRequest>,
    pub disband_requests: Vec<DisbandRequest>,
    pub disband_candidates: Vec<DisbandCandidate>,
    pub tombstones: Vec<SavedTombstone>,
    pub welcomes: Vec<PendingWelcome>,
    pub features: Vec<SavedFeature>,
    pub policies: Vec<SavedBytes>,
    pub markers: Vec<SavedBytes>,
    pub signers: Vec<AccountDeviceSignerBinding>,
    pub history_keys: Vec<SavedHistoryKey>,
    pub expectations: Vec<DeviceGroupWelcomeExpectation>,
    pub passes: Vec<DurableConvergencePass>,
    pub deferred: Vec<DeferredPeelGeneration>,
    pub pending_events: Vec<GroupEvent>,
    pub authorities: Vec<PendingAppMessageAuthority>,
    pub ingress: Vec<MessageId>,
    pub processed: Vec<SavedProcessed>,
    pub snapshots: Vec<SavedImage>,
    pub checkpoints: Vec<SavedImage>,
    pub key_package_lifecycle: Option<KeyPackageLifecycleState>,
    pub group_maintenance: Vec<GroupMaintenanceState>,
    pub obligations: Vec<MaintenanceObligation>,
    pub evolutions: Vec<DurableGroupEvolution>,
    pub transport_fanouts: Vec<DurableTransportFanout>,
    pub periodic: PeriodicMaintenancePolicy,
    pub mls: Vec<SavedPair>,
    #[serde(default)]
    pub journal: Vec<PreparedPublication>,
    #[serde(default)]
    pub operation_tombstones: Vec<OperationTombstone>,
    #[serde(default)]
    pub tombstone_high_water: u64,
    #[serde(default)]
    pub observed_leaves: Vec<ObservedLeaf>,
    #[serde(default)]
    pub sync_cursors: Vec<SyncCursor>,
    #[serde(default)]
    pub wakes: Vec<StoredWake>,
    #[serde(default)]
    pub server_relays: Vec<ServerRelays>,
    #[serde(default)]
    pub floors: Vec<SavedFloor>,
    #[serde(default)]
    pub account_secret_hex: Option<String>,
    #[serde(default)]
    pub revision: u64,
    #[serde(default)]
    pub binding: AccountBinding,
}

/// Project sender binding stored inside the sealed account.
///
/// Revision 0 means the account has not been committed to a Durable Object.
/// Row absence is a missing SQL row, never this value.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountBinding {
    #[serde(default)]
    pub project_id: String,
    #[serde(default)]
    pub recipient_hex: String,
    #[serde(default)]
    pub extra_recipients: Vec<String>,
    #[serde(default)]
    pub relays: Vec<String>,
    /// Relays used for the original Welcome. Recovery republishes there.
    #[serde(default)]
    pub welcome_relays: Vec<String>,
    #[serde(default)]
    pub nostr_group_hex: Option<String>,
    #[serde(default)]
    pub group_id_hex: Option<String>,
}

/// One prepared publication. A retry with the same operation id returns this
/// message instead of encrypting again.
#[derive(Clone, Serialize, Deserialize)]
pub struct PreparedPublication {
    pub alert_id: String,
    #[serde(default = "default_operation_kind")]
    pub operation_kind: String,
    pub payload_sha256: [u8; 32],
    pub group_id: GroupId,
    pub message: TransportMessage,
    /// Local MDK confirmation. This is not relay acceptance.
    pub confirmed: bool,
    #[serde(default = "default_message_phase")]
    pub message_phase: String,
    pub pending_ref: Option<u64>,
    #[serde(default)]
    pub needs_mdk_confirm: bool,
    #[serde(default)]
    pub welcomes: Vec<TransportMessage>,
    pub push_trigger: Option<Vec<u8>>,
    pub push_published: bool,
    #[serde(default = "default_push_phase")]
    pub push_phase: String,
    #[serde(default)]
    pub push_event_id: Option<String>,
    #[serde(default)]
    pub started_at_ms: u64,
    #[serde(default)]
    pub updated_at_ms: u64,
    #[serde(default)]
    pub message_attempts: u64,
    #[serde(default)]
    pub message_publication_attempts: u64,
    #[serde(default)]
    pub message_reconcile_attempts: u64,
    #[serde(default)]
    pub unknown_attempts: u64,
    #[serde(default)]
    pub token_wait_attempts: u64,
    #[serde(default)]
    pub push_publication_attempts: u64,
    #[serde(default)]
    pub unobservable_attempts: u64,
    #[serde(default)]
    pub push_attempts: u64,
    #[serde(default)]
    pub publications: Vec<PublicationRecord>,
}

/// One correlated relay attempt. Acceptance of a different event cannot confirm this one.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PublicationRecord {
    pub attempt_id: String,
    pub event_id: String,
    pub role: String,
    pub destination: String,
    pub phase: String,
    #[serde(default)]
    pub server: String,
    #[serde(default)]
    pub reason: String,
    #[serde(default)]
    pub started_at_ms: u64,
    #[serde(default)]
    pub finished_at_ms: u64,
}

/// Compact identity kept after the ciphertext journal drops a terminal row.
/// It carries no ciphertext, so a later retry cannot encrypt again.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct OperationTombstone {
    pub alert_id: String,
    pub operation_kind: String,
    pub payload_sha256: [u8; 32],
    pub group_id: GroupId,
    pub message_phase: String,
    pub message_event_id: String,
    pub push_phase: String,
    pub push_event_id: Option<String>,
    pub started_at_ms: u64,
    pub updated_at_ms: u64,
    pub message_attempts: u64,
    pub message_publication_attempts: u64,
    pub message_reconcile_attempts: u64,
    pub unknown_attempts: u64,
    pub token_wait_attempts: u64,
    pub push_publication_attempts: u64,
    pub unobservable_attempts: u64,
    pub push_attempts: u64,
}

/// Encrypted wake capability. The raw device token is not stored.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct StoredWake {
    pub group_id_hex: String,
    pub member_id_hex: String,
    pub leaf_index: u32,
    pub platform: String,
    pub token_fingerprint: String,
    pub server_pubkey_hex: String,
    #[serde(default)]
    pub relay_hint: Option<String>,
    pub owner_ts: i64,
    pub encrypted_token: Vec<u8>,
    pub owner_sig: String,
    pub removed: bool,
}

/// Engine-reported device leaf. Positions are not inferred from member count.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ObservedLeaf {
    pub group_id_hex: String,
    pub member_id_hex: String,
    pub leaf_index: u32,
    pub epoch: u64,
    pub removed: bool,
}

/// Catch-up checkpoint for one relay query stream.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SyncCursor {
    pub stream: String,
    pub since: u64,
    pub until: Option<u64>,
    pub caught_up: bool,
    pub updated_at_ms: u64,
}

/// Kind 10050 inbox relays observed for a notification server.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ServerRelays {
    pub server_pubkey_hex: String,
    pub relays: Vec<String>,
    pub observed_at_ms: u64,
    pub negative: bool,
}

fn default_operation_kind() -> String {
    "chat".into()
}

fn default_message_phase() -> String {
    "prepared".into()
}

fn default_push_phase() -> String {
    "not_required".into()
}

#[derive(Clone, Serialize, Deserialize)]
pub struct SavedFloor {
    pub group_id: GroupId,
    pub epoch: u64,
}

#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct SavedAdmission {
    pub group_id: GroupId,
    pub generation: [u8; 32],
    pub created_locally: bool,
    pub via_welcome: Option<MessageId>,
}

#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct SavedForgotten {
    pub group_id: GroupId,
    pub at: u64,
    pub awaiting: bool,
}

#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct SavedRoute {
    pub transport_group_id: Vec<u8>,
    pub group_id: GroupId,
    pub source_epoch: EpochId,
}

#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct SavedRoster {
    pub group_id: GroupId,
    pub revision: u64,
    pub members: Vec<MemberId>,
}

#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct SavedTombstone {
    pub group_id: GroupId,
    pub tombstone: DisbandTombstone,
}

#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct SavedFeature {
    pub name: String,
    pub requires: cgka_traits::Capability,
    pub level: cgka_traits::RequirementLevel,
    pub description: String,
}

#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct SavedBytes {
    pub group_id: GroupId,
    pub bytes: Vec<u8>,
}

#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct SavedHistoryKey {
    pub marmot_identity: MemberId,
    pub ciphersuite: u16,
    pub public_key: Vec<u8>,
    pub private_key: Vec<u8>,
}

#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct SavedProcessed {
    pub message_id: MessageId,
    pub group_id: GroupId,
}

#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct SavedPair {
    pub key_hex: String,
    pub value_hex: String,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum SavedTri {
    Omit,
    Absent,
    Present(Vec<u8>),
}

#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct SavedImage {
    pub group_id: GroupId,
    pub name: String,
    pub full_messages: bool,
    pub policy: SavedTri,
    pub marker: SavedTri,
    pub group: Value,
    pub messages: Option<Value>,
    pub queued: Option<Value>,
    pub mls: Vec<SavedPair>,
    #[serde(default)]
    pub checkpoint_epoch: Option<EpochId>,
}

impl SavedImage {
    fn load(self) -> Result<(SnapKey, GroupImage), PersistError> {
        let group: Group =
            serde_json::from_value(self.group).map_err(|_| PersistError::Corrupt)?;
        let messages = self
            .messages
            .map(|value| serde_json::from_value(value).map_err(|_| PersistError::Corrupt))
            .transpose()?;
        let queued = self
            .queued
            .map(|value| serde_json::from_value(value).map_err(|_| PersistError::Corrupt))
            .transpose()?;
        let image = GroupImage {
            full_messages: self.full_messages,
            policy: tri_load(&self.policy),
            marker: tri_load(&self.marker),
            group,
            messages,
            queued,
            mls: decode_pairs(&self.mls)?,
            checkpoint_epoch: self.checkpoint_epoch,
        };
        Ok((
            SnapKey {
                group: self.group_id,
                name: self.name,
            },
            image,
        ))
    }
}
