//! Native Marmot session.
//!
//! This process embeds the official `marmot-app` runtime (MDK `ca52a04`).
//! It is a separate executable because that runtime links SQLCipher, while the
//! watchdog's operational database links a different SQLite. Cargo allows only
//! one `links = "sqlite3"` package in a binary. Cloudflare does not use this
//! process.
//!
//! MDK local submissions are the send journal. The files under `outbox-boundary`
//! are a projection of that journal plus the direct-conversation id. A pending
//! projection is refreshed from MDK on every retry. It is not a terminal result.
//! `consumed.json` is the durable operation index. Journal files may be pruned.
//! Entries in that index are not.

mod push_trace;
mod relays;

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use cgka_traits::{GroupId, SendAcceptDisposition};
use marmot_app::{
    AccountSetupRequest, GroupPushDebugInfo, LocalSendStatus, ManagedAccount, MarmotApp,
    MarmotAppConfig, MarmotAppRuntime,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use watchdog_core::group_auth::authorize_group_members;
use watchdog_core::marmot_recovery::{
    active_recipient_tokens, advance_phase, bind_stored_identity, classify_push,
    reconcile_conversation_record, reconcile_send, ConversationLookup, ConversationRecord,
    ConversationStep, IdentityEvidence, IdentityStep, PhaseAttempts, SendStep, StoredSend,
    TokenObservation, UpstreamSend,
};
use zeroize::Zeroizing;

const JOURNAL_KEEP: usize = 64;

pub struct Session {
    runtime: MarmotAppRuntime,
    boundary: PathBuf,
    allow_loopback: bool,
    _lock: File,
}

pub fn open(root: &Path, relays: &[String], allow_loopback: bool) -> Result<Session, String> {
    push_trace::install();
    relays::validate_configured_relays(relays, allow_loopback)?;
    fs::create_dir_all(root).map_err(|error| format!("marmot_root: {error}"))?;
    restrict_dir(root)?;
    let lock_path = root.join("helper.lock");
    let lock = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(&lock_path)
        .map_err(|error| format!("marmot_lock: {error}"))?;
    restrict(&lock_path)?;
    if !exclusive_lock(&lock) {
        return Err("helper_already_running".to_string());
    }
    let mut config = MarmotAppConfig::white_noise();
    if allow_loopback {
        config = config.with_allow_loopback_relay_endpoints(true);
    }
    let app = MarmotApp::with_relays_and_config(root, relays.to_vec(), config);
    let boundary = root.join("outbox-boundary");
    fs::create_dir_all(&boundary).map_err(|error| format!("marmot_boundary: {error}"))?;
    restrict_dir(&boundary)?;
    fs::create_dir_all(boundary.join("onboard")).map_err(|error| format!("marmot_boundary: {error}"))?;
    restrict_dir(&boundary.join("onboard"))?;
    Ok(Session {
        runtime: app.runtime(),
        boundary,
        allow_loopback,
        _lock: lock,
    })
}

impl Session {
    pub async fn import_sender(&self, nsec: String, relays: &[String]) -> Result<String, String> {
        relays::validate_configured_relays(relays, self.allow_loopback)?;
        let secret = Zeroizing::new(nsec);
        let endpoints: Vec<cgka_traits::TransportEndpoint> = relays
            .iter()
            .map(|relay| cgka_traits::TransportEndpoint(relay.clone()))
            .collect();
        let request = AccountSetupRequest {
            import_nsec: Some(secret),
            default_relays: endpoints.clone(),
            bootstrap_relays: endpoints.clone(),
            inbox_relays: endpoints,
            publish_missing_relay_lists: true,
            publish_initial_key_package: true,
            ..AccountSetupRequest::default()
        };
        let result = self
            .runtime
            .create_or_import_account(request)
            .await
            .map_err(safe_error)?;
        let account = result.account.account_id_hex;
        self.adopt_account(&account)?;
        Ok(account)
    }

    /// Idempotent onboarding. The same operation id returns the recorded
    /// account and group. It does not mint a second conversation.
    pub async fn onboard(
        &self,
        operation_id: &str,
        nsec: String,
        relays: &[String],
        recipient: &str,
        replace: bool,
    ) -> Result<Value, String> {
        if !operation_token(operation_id) {
            return Err("operation_id_invalid".to_string());
        }
        let recipient = account_hex(recipient)?;
        if let Some(existing) = self.read_onboard(operation_id)? {
            if existing
                .get("recipient")
                .and_then(Value::as_str)
                != Some(recipient.as_str())
                || existing.get("replace").and_then(Value::as_bool) != Some(replace)
            {
                return Err("operation_identity_mismatch".to_string());
            }
            if existing.get("phase").and_then(Value::as_str) == Some("established") {
                let account = existing
                    .get("account")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string();
                if !self.account_in_storage(&account) {
                    return Err("mdk_storage_missing".to_string());
                }
                let mut value = existing;
                if let Some(object) = value.as_object_mut() {
                    object.insert("reused".to_string(), Value::Bool(true));
                }
                return Ok(value);
            }
        }
        self.write_onboard(&json!({
            "operation_id": operation_id,
            "recipient": recipient,
            "replace": replace,
            "phase": "importing"
        }))?;
        let account = self.import_sender(nsec, relays).await?;
        self.write_onboard(&json!({
            "operation_id": operation_id,
            "account": account,
            "recipient": recipient,
            "replace": replace,
            "phase": "intending"
        }))?;
        let group = self.establish_direct(&account, &recipient, replace).await?;
        let value = json!({
            "operation_id": operation_id,
            "account": account,
            "recipient": recipient,
            "group": group,
            "replace": replace,
            "phase": "established",
            "reused": false
        });
        self.write_onboard(&value)?;
        Ok(value)
    }

    pub fn onboard_status(&self, operation_id: &str) -> Result<Value, String> {
        if !operation_token(operation_id) {
            return Err("operation_id_invalid".to_string());
        }
        Ok(self
            .read_onboard(operation_id)?
            .unwrap_or_else(|| json!({"operation_id": operation_id, "phase": "absent"})))
    }

    pub async fn identity(
        &self,
        account: &str,
        recipient: &str,
        group: &str,
    ) -> Result<Value, String> {
        let account = account_hex(account)?;
        let recipient = account_hex(recipient)?;
        let evidence = self.evidence(&account, &recipient, group).await?;
        let step = bind_stored_identity(
            Some(&account),
            Some(&account),
            Some(&recipient),
            if group.is_empty() { None } else { Some(group) },
            &recipient,
            false,
            evidence,
        );
        Ok(json!({
            "step": identity_name(step),
            "account_present": evidence.account_in_storage,
            "device_valid": evidence.device_can_sign,
            "storage_matches": evidence.storage_matches,
            "group_available": evidence.group_available,
        }))
    }

    pub async fn readiness(
        &self,
        account: &str,
        recipient: &str,
        group: &str,
    ) -> Result<Value, String> {
        let identity = self.identity(account, recipient, group).await?;
        let account = account_hex(account)?;
        let recipient = account_hex(recipient)?;
        let mut devices = 0_u32;
        let mut tokens = 0_i64;
        if !group.is_empty() {
            if let Ok(members) = self.member_accounts(&account, group).await {
                devices = members
                    .iter()
                    .find(|(id, _)| id == &recipient)
                    .map(|(_, count)| *count)
                    .unwrap_or(0);
            }
            if let Ok(group_id) = group_id(group) {
                if let Ok(count) = self.recipient_token_count(&account, &group_id, &recipient).await
                {
                    tokens = count;
                }
            }
        }
        Ok(json!({
            "identity": identity,
            "recipient_devices": devices,
            "active_recipient_tokens": tokens,
        }))
    }

    pub async fn create_group(
        &self,
        account: &str,
        _name: &str,
        members: &[String],
    ) -> Result<String, String> {
        let account = account_hex(account)?;
        let Some(peer) = members.first() else {
            return Err("recipient_missing".to_string());
        };
        let peer = account_hex(peer)?;
        self.establish_direct(&account, &peer, false).await
    }

    pub async fn reonboard(&self, account: &str, members: &[String]) -> Result<String, String> {
        let account = account_hex(account)?;
        let Some(peer) = members.first() else {
            return Err("recipient_missing".to_string());
        };
        let peer = account_hex(peer)?;
        self.establish_direct(&account, &peer, true).await
    }

    async fn establish_direct(
        &self,
        account: &str,
        peer: &str,
        replace: bool,
    ) -> Result<String, String> {
        let saved = self.conversation_state(account, peer)?;
        let (lookup, existing_id) = self.lookup_direct(account, peer).await?;
        if let ConversationState::Established(saved_id) = &saved {
            return match lookup {
                ConversationLookup::Reusable => {
                    let Some(found) = existing_id else {
                        return Err("marmot_group_missing".to_string());
                    };
                    if found.eq_ignore_ascii_case(saved_id) {
                        Ok(saved_id.clone())
                    } else if replace {
                        self.remember_group(account, peer, &found)?;
                        Ok(found)
                    } else {
                        Err("conversation_mismatch".to_string())
                    }
                }
                ConversationLookup::NotReady => Ok(saved_id.clone()),
                ConversationLookup::NotReusable => Err("conversation_not_reusable".to_string()),
                ConversationLookup::None => Ok(saved_id.clone()),
            };
        }
        let now = unix_ms();
        let record = match &saved {
            ConversationState::Absent => ConversationRecord::Absent,
            ConversationState::Intending {
                empty_lookups,
                started_at_ms,
            } => ConversationRecord::Intending {
                empty_lookups: *empty_lookups,
                age_ms: now.saturating_sub(*started_at_ms),
            },
            ConversationState::Established(_) => ConversationRecord::Established,
        };
        match reconcile_conversation_record(record, lookup) {
            ConversationStep::UseSaved => Err("marmot_group_missing".to_string()),
            ConversationStep::RetryIndex => {
                if matches!(lookup, ConversationLookup::None) {
                    self.note_empty_lookup(account, peer)?;
                }
                Err("conversation_index_not_ready".to_string())
            }
            ConversationStep::NotReusable => Err("conversation_not_reusable".to_string()),
            ConversationStep::UseExisting => {
                let id = existing_id.ok_or_else(|| "marmot_group_missing".to_string())?;
                self.remember_group(account, peer, &id)?;
                Ok(id)
            }
            ConversationStep::Create => {
                self.mark_intending(account, peer)?;
                let members = vec![peer.to_string()];
                let created = self
                    .runtime
                    .create_group_detailed(account, "", &members, None)
                    .await
                    .map_err(safe_error)?;
                let group = created
                    .operation
                    .ok_or_else(|| "no_eligible_member".to_string())?;
                let id = group.group_id.to_string();
                self.remember_group(account, peer, &id)?;
                Ok(id)
            }
        }
    }

    async fn lookup_direct(
        &self,
        account: &str,
        peer: &str,
    ) -> Result<(ConversationLookup, Option<String>), String> {
        match self
            .runtime
            .existing_direct_conversation(account, peer)
            .await
        {
            Ok(Some(existing)) if existing.reusable => {
                Ok((ConversationLookup::Reusable, Some(existing.group_id_hex)))
            }
            Ok(Some(_)) => Ok((ConversationLookup::NotReusable, None)),
            Ok(None) => Ok((ConversationLookup::None, None)),
            Err(error) => {
                let text = safe_error(error);
                if text.contains("direct_conversation_index_not_ready")
                    || text.contains("IndexNotReady")
                    || text.contains("not ready")
                {
                    Ok((ConversationLookup::NotReady, None))
                } else {
                    Err(text)
                }
            }
        }
    }

    pub async fn member_ids(&self, account: &str, group_hex: &str) -> Result<Vec<String>, String> {
        Ok(self
            .member_accounts(account, group_hex)
            .await?
            .into_iter()
            .map(|(id, _)| id)
            .collect())
    }

    async fn member_accounts(
        &self,
        account: &str,
        group_hex: &str,
    ) -> Result<Vec<(String, u32)>, String> {
        let group = group_id(group_hex)?;
        let members = self
            .runtime
            .group_members(account, &group)
            .await
            .map_err(safe_error)?;
        Ok(members
            .into_iter()
            .map(|member| (member.member_id_hex.to_ascii_lowercase(), member.device_count))
            .collect())
    }

    pub async fn send_once(
        &self,
        alert_id: &str,
        account: &str,
        group_hex: &str,
        text: &str,
        allow: &[String],
    ) -> Result<Value, String> {
        if !operation_token(alert_id) {
            return Err("alert_id_invalid".to_string());
        }
        let account = account_hex(account)?;
        let group_hex = normalize_group(group_hex)?;
        let group = group_id(&group_hex)?;
        let Some(recipient) = allow.iter().find(|item| !item.is_empty()) else {
            return Err("recipient_missing".to_string());
        };
        let recipient = account_hex(recipient)?;
        let payload = payload_hash(text);
        let stored = self.read_record(alert_id)?;
        let legacy_started = stored.is_none() && self.started(alert_id)?;
        let stored_phase = stored
            .as_ref()
            .and_then(stored_phase)
            .or(legacy_started.then_some(StoredSend::Submitting));
        let identity_matches = stored
            .as_ref()
            .map(|value| journal_identity_matches(value, &account, &group_hex, &payload))
            .unwrap_or(true);
        if stored.is_some() && !identity_matches {
            return Err("alert_identity_mismatch".to_string());
        }
        let prior = stored
            .as_ref()
            .map(read_attempts)
            .unwrap_or_default();
        let refresh = !matches!(
            stored_phase,
            None | Some(StoredSend::Published | StoredSend::Rejected)
        );
        if refresh {
            let _ = self.runtime.catch_up_accounts().await;
        }
        let status = self
            .runtime
            .local_send_status(&account, &group, alert_id)
            .map_err(safe_error)?;
        match reconcile_send(stored_phase, identity_matches, upstream_of(status.as_ref())) {
            SendStep::IdentityMismatch => Err("alert_identity_mismatch".to_string()),
            SendStep::ProjectUpstream => {
                let status = status.ok_or_else(|| "completion_unknown".to_string())?;
                let value = self
                    .project_status(
                        alert_id,
                        &account,
                        &group,
                        &recipient,
                        &payload,
                        status,
                        false,
                        prior,
                        stored.as_ref(),
                    )
                    .await?;
                self.write_record(alert_id, &value)?;
                Ok(value)
            }
            SendStep::KeepStoredTerminal => {
                let stored = stored.ok_or_else(|| "completion_unknown".to_string())?;
                let value = self.finish_record(stored, prior)?;
                self.write_record(alert_id, &value)?;
                Ok(value)
            }
            SendStep::CompletionUnknown => {
                let mut value = unknown_value(alert_id, &account, &group_hex, &payload);
                value = self.finish_record(value, prior)?;
                self.write_record(alert_id, &value)?;
                Ok(value)
            }
            SendStep::Submit => {
                if stored_phase.is_some() {
                    return Err("operation_already_recorded".to_string());
                }
                self.authorize_send(&account, &group_hex, &recipient).await?;
                let mut intent = json!({
                    "operation_id": alert_id,
                    "account": account,
                    "group": group_hex,
                    "payload_sha256": payload,
                    "disposition": "submitting",
                    "message_phase": "accepted_pending",
                    "published": 0,
                    "message_ids": [],
                    "message_event_id": Value::Null,
                    "push": "prepared",
                    "push_event_id": Value::Null,
                    "push_evidence": "not_attempted",
                    "push_error": Value::Null,
                    "hold": true,
                    "preserve_message": true,
                    "terminal": false
                });
                let generation = push_trace::begin_submit();
                if let Some(object) = intent.as_object_mut() {
                    object.insert("push_trace_generation".to_string(), json!(generation));
                }
                self.write_record(alert_id, &intent)?;
                crash_after("intent")?;
                if let Err(error) = self
                    .runtime
                    .submit_text(&account, &group, text.to_string(), alert_id.to_string())
                    .await
                {
                    let admitted = self
                        .runtime
                        .local_send_status(&account, &group, alert_id)
                        .map_err(safe_error)?;
                    if admitted.is_none() {
                        self.forget_unadmitted(alert_id)?;
                        return Err(safe_error(error));
                    }
                }
                crash_after("submitted")?;
                let status = self
                    .runtime
                    .local_send_status(&account, &group, alert_id)
                    .map_err(safe_error)?
                    .ok_or_else(|| "completion_unknown".to_string())?;
                crash_after("pending")?;
                let value = self
                    .project_status(
                        alert_id,
                        &account,
                        &group,
                        &recipient,
                        &payload,
                        status,
                        true,
                        prior,
                        Some(&intent),
                    )
                    .await?;
                crash_after("accepted")?;
                self.write_record(alert_id, &value)?;
                crash_after("persisted")?;
                crash_after("push")?;
                Ok(value)
            }
        }
    }

    async fn authorize_send(
        &self,
        account: &str,
        group_hex: &str,
        recipient: &str,
    ) -> Result<(), String> {
        let members = self.member_accounts(account, group_hex).await?;
        let ids: Vec<String> = members
            .into_iter()
            .filter(|(_, devices)| *devices > 0)
            .map(|(id, _)| id)
            .collect();
        authorize_group_members(&ids, account, recipient)?;
        match self.lookup_direct(account, recipient).await? {
            (ConversationLookup::Reusable, Some(found)) if !found.eq_ignore_ascii_case(group_hex) => {
                Err("conversation_mismatch".to_string())
            }
            (ConversationLookup::NotReusable, _) => Err("conversation_not_reusable".to_string()),
            _ => Ok(()),
        }
    }

    async fn project_status(
        &self,
        alert_id: &str,
        account: &str,
        group: &GroupId,
        recipient: &str,
        payload: &str,
        status: LocalSendStatus,
        fresh_submit: bool,
        prior: PhaseAttempts,
        previous: Option<&Value>,
    ) -> Result<Value, String> {
        let group_hex = group.to_string();
        let (disposition, published, message_ids, detail) = match status {
            LocalSendStatus::Queued { message_id_hex }
            | LocalSendStatus::EngineOwned { message_id_hex } => {
                ("accepted_pending", 0, vec![message_id_hex], None)
            }
            LocalSendStatus::Completed(summary) => {
                let disposition = match summary.accept_disposition {
                    SendAcceptDisposition::Published => "published",
                    SendAcceptDisposition::AcceptedPending => "accepted_pending",
                    SendAcceptDisposition::CompletionUnknown => "completion_unknown",
                };
                (disposition, summary.published, summary.message_ids, None)
            }
            LocalSendStatus::Rejected => ("rejected", 0, Vec::new(), None),
            LocalSendStatus::RefusedNewMembers => {
                ("rejected", 0, Vec::new(), Some("refused_new_members"))
            }
        };
        let message_published = disposition == "published";
        let tokens = if message_published {
            self.recipient_token_count(account, group, recipient)
                .await
                .unwrap_or(0)
        } else {
            0
        };
        let generation = previous
            .and_then(|value| value.get("push_trace_generation"))
            .and_then(Value::as_u64)
            .unwrap_or(0);
        let observed = push_trace::observed_for(generation).or_else(|| {
            previous
                .and_then(|value| value.get("push_error"))
                .and_then(Value::as_str)
                .map(str::to_string)
        });
        let _ = fresh_submit;
        let (push, evidence) = classify_push(message_published, tokens, observed.is_some());
        let mut value = json!({
            "operation_id": alert_id,
            "account": account,
            "group": group_hex,
            "payload_sha256": payload,
            "disposition": disposition,
            "message_phase": message_phase_name(disposition),
            "published": published,
            "message_ids": message_ids,
            "push": push,
            "push_evidence": evidence,
            "push_error": observed,
            "push_event_id": Value::Null,
            "status_detail": detail,
        });
        if let Some(object) = value.as_object_mut() {
            let ids = object.get("message_ids").cloned().unwrap_or(Value::Null);
            let first = ids
                .as_array()
                .and_then(|items| items.first())
                .cloned()
                .unwrap_or(Value::Null);
            object.insert("message_event_id".to_string(), first);
        }
        if let Some(generation) = previous.and_then(|item| item.get("push_trace_generation")) {
            if let Some(object) = value.as_object_mut() {
                object.insert("push_trace_generation".to_string(), generation.clone());
            }
        }
        self.finish_record(value, prior)
    }

    fn finish_record(&self, mut value: Value, prior: PhaseAttempts) -> Result<Value, String> {
        let message = value
            .get("message_phase")
            .and_then(Value::as_str)
            .unwrap_or("completion_unknown")
            .to_string();
        let push = value
            .get("push")
            .and_then(Value::as_str)
            .unwrap_or("not_attempted")
            .to_string();
        let (attempts, decision) = advance_phase(&message, &push, prior, unix_ms());
        if let Some(object) = value.as_object_mut() {
            object.insert("push".to_string(), json!(decision.push_phase));
            object.insert("hold".to_string(), json!(decision.hold));
            object.insert("retry_after_ms".to_string(), json!(decision.delay_ms));
            object.insert(
                "preserve_message".to_string(),
                json!(decision.preserve_message),
            );
            object.insert("terminal".to_string(), json!(decision.terminal));
            object.insert("message_attempts".to_string(), json!(attempts.message));
            object.insert("unknown_attempts".to_string(), json!(attempts.unknown));
            object.insert("token_wait_attempts".to_string(), json!(attempts.token_wait));
            object.insert(
                "unobservable_attempts".to_string(),
                json!(attempts.unobservable),
            );
            object.insert("started_at_ms".to_string(), json!(attempts.started_at_ms));
            if !object.contains_key("push_event_id") {
                object.insert("push_event_id".to_string(), Value::Null);
            }
        }
        Ok(value)
    }

    pub async fn sees_recipient_token(
        &self,
        account: &str,
        group_hex: &str,
        recipient: &str,
        fingerprint: &str,
    ) -> Result<bool, String> {
        let account = account_hex(account)?;
        let recipient = account_hex(recipient)?;
        let group = group_id(group_hex)?;
        let info = self
            .runtime
            .group_push_debug_info(&account, &group)
            .await
            .map_err(safe_error)?;
        Ok(info.tokens.iter().any(|token| {
            token.member_id_hex.eq_ignore_ascii_case(&recipient)
                && token.member_matches_active_leaf
                && token.token_fingerprint == fingerprint
        }))
    }

    async fn recipient_token_count(
        &self,
        account: &str,
        group: &GroupId,
        recipient: &str,
    ) -> Result<i64, String> {
        let info: GroupPushDebugInfo = self
            .runtime
            .group_push_debug_info(account, group)
            .await
            .map_err(safe_error)?;
        let observations: Vec<TokenObservation<'_>> = info
            .tokens
            .iter()
            .map(|token| TokenObservation {
                member_id_hex: token.member_id_hex.as_str(),
                active_leaf: token.active_leaf,
                member_matches_active_leaf: token.member_matches_active_leaf,
            })
            .collect();
        Ok(active_recipient_tokens(&observations, recipient))
    }

    pub async fn sync(&self) -> Result<(), String> {
        self.runtime.catch_up_accounts().await.map_err(safe_error)
    }

    /// One explicit history repair. This is the same ingest path as catch-up,
    /// queried from the beginning of the account's relay history.
    pub async fn repair_history(&self, account: &str) -> Result<(), String> {
        let account = account_hex(account)?;
        self.runtime
            .repair_full_history(&account)
            .await
            .map_err(safe_error)
    }

    pub async fn shutdown(&self) -> Result<(), String> {
        self.runtime.shutdown_and_close().await.map_err(safe_error)
    }

    fn journal_path(&self, alert_id: &str) -> PathBuf {
        self.boundary.join(format!("{alert_id}.json"))
    }

    fn started_path(&self, alert_id: &str) -> PathBuf {
        self.boundary.join(format!("{alert_id}.started"))
    }

    fn consumed_path(&self) -> PathBuf {
        self.boundary.join("consumed.json")
    }

    fn read_record(&self, alert_id: &str) -> Result<Option<Value>, String> {
        let path = self.journal_path(alert_id);
        if path.exists() {
            let bytes = fs::read(&path).map_err(|error| format!("boundary_read: {error}"))?;
            return serde_json::from_slice(&bytes)
                .map(Some)
                .map_err(|_| "boundary_corrupt".to_string());
        }
        let consumed = self.consumed_index()?;
        Ok(consumed.get(alert_id).cloned())
    }

    fn consumed_index(&self) -> Result<Value, String> {
        let path = self.consumed_path();
        if !path.exists() {
            return Ok(json!({}));
        }
        let bytes = fs::read(&path).map_err(|error| format!("boundary_read: {error}"))?;
        serde_json::from_slice(&bytes).map_err(|_| "boundary_corrupt".to_string())
    }

    fn write_record(&self, alert_id: &str, value: &Value) -> Result<(), String> {
        let mut consumed = self.consumed_index()?;
        if let Some(object) = consumed.as_object_mut() {
            object.insert(alert_id.to_string(), value.clone());
        }
        atomic_json(&self.consumed_path(), &consumed)?;
        atomic_json(&self.journal_path(alert_id), value)?;
        let _ = fs::remove_file(self.started_path(alert_id));
        self.prune_journals()
    }

    fn forget_unadmitted(&self, alert_id: &str) -> Result<(), String> {
        let _ = fs::remove_file(self.journal_path(alert_id));
        let mut consumed = self.consumed_index()?;
        let drop_entry = consumed
            .get(alert_id)
            .and_then(|value| value.get("disposition"))
            .and_then(Value::as_str)
            == Some("submitting");
        if drop_entry {
            if let Some(object) = consumed.as_object_mut() {
                object.remove(alert_id);
            }
            atomic_json(&self.consumed_path(), &consumed)?;
        }
        Ok(())
    }

    fn prune_journals(&self) -> Result<(), String> {
        let consumed = self.consumed_index()?;
        let mut terminal = Vec::new();
        let entries = fs::read_dir(&self.boundary).map_err(|error| format!("boundary_read: {error}"))?;
        for entry in entries.flatten() {
            let name = entry.file_name();
            let Some(name) = name.to_str() else { continue };
            if !name.ends_with(".json") || name == "consumed.json" || name == "conversations.json" || name == "storage-epoch.json" {
                continue;
            }
            let id = name.trim_end_matches(".json");
            let disposition = consumed
                .get(id)
                .and_then(|value| value.get("disposition"))
                .and_then(Value::as_str);
            if matches!(disposition, Some("published" | "rejected")) {
                let modified = entry
                    .metadata()
                    .and_then(|metadata| metadata.modified())
                    .ok();
                terminal.push((modified, entry.path()));
            }
        }
        terminal.sort_by(|left, right| right.0.cmp(&left.0));
        for (_, path) in terminal.into_iter().skip(JOURNAL_KEEP) {
            let _ = fs::remove_file(path);
        }
        Ok(())
    }

    fn started(&self, alert_id: &str) -> Result<bool, String> {
        Ok(self.started_path(alert_id).exists())
    }

    fn conversation_path(&self) -> PathBuf {
        self.boundary.join("conversations.json")
    }

    fn conversations(&self) -> Result<Value, String> {
        let path = self.conversation_path();
        if !path.exists() {
            return Ok(json!({}));
        }
        let bytes = fs::read(&path).map_err(|error| format!("boundary_read: {error}"))?;
        serde_json::from_slice(&bytes).map_err(|_| "boundary_corrupt".to_string())
    }

    fn conversation_state(&self, account: &str, peer: &str) -> Result<ConversationState, String> {
        let value = self.conversations()?;
        Ok(match value.get(conversation_key(account, peer)) {
            Some(Value::String(group)) if !group.is_empty() => {
                ConversationState::Established(group.clone())
            }
            Some(Value::Object(object)) => {
                let group = object
                    .get("group_id")
                    .and_then(Value::as_str)
                    .filter(|group| !group.is_empty())
                    .map(str::to_string);
                if let Some(group) = group {
                    ConversationState::Established(group)
                } else if object.get("phase").and_then(Value::as_str) == Some("intending") {
                    ConversationState::Intending {
                        empty_lookups: object
                            .get("empty_lookups")
                            .and_then(Value::as_i64)
                            .unwrap_or(0),
                        started_at_ms: object
                            .get("started_at_ms")
                            .and_then(Value::as_i64)
                            .unwrap_or_else(unix_ms),
                    }
                } else {
                    ConversationState::Absent
                }
            }
            _ => ConversationState::Absent,
        })
    }

    fn remember_group(&self, account: &str, peer: &str, group: &str) -> Result<(), String> {
        let mut value = self.conversations()?;
        if let Some(object) = value.as_object_mut() {
            object.insert(
                conversation_key(account, peer),
                json!({"group_id": group, "phase": "established"}),
            );
        }
        atomic_json(&self.conversation_path(), &value)
    }

    fn mark_intending(&self, account: &str, peer: &str) -> Result<(), String> {
        if matches!(
            self.conversation_state(account, peer)?,
            ConversationState::Established(_) | ConversationState::Intending { .. }
        ) {
            return Ok(());
        }
        let mut value = self.conversations()?;
        if let Some(object) = value.as_object_mut() {
            object.insert(
                conversation_key(account, peer),
                json!({"phase": "intending", "started_at_ms": unix_ms(), "empty_lookups": 0}),
            );
        }
        atomic_json(&self.conversation_path(), &value)
    }

    fn note_empty_lookup(&self, account: &str, peer: &str) -> Result<(), String> {
        let ConversationState::Intending {
            empty_lookups,
            started_at_ms,
        } = self.conversation_state(account, peer)?
        else {
            return Ok(());
        };
        let mut value = self.conversations()?;
        if let Some(object) = value.as_object_mut() {
            object.insert(
                conversation_key(account, peer),
                json!({
                    "phase": "intending",
                    "started_at_ms": started_at_ms,
                    "empty_lookups": empty_lookups.saturating_add(1)
                }),
            );
        }
        atomic_json(&self.conversation_path(), &value)
    }

    fn onboard_path(&self, operation_id: &str) -> PathBuf {
        self.boundary
            .join("onboard")
            .join(format!("{operation_id}.json"))
    }

    fn read_onboard(&self, operation_id: &str) -> Result<Option<Value>, String> {
        let path = self.onboard_path(operation_id);
        if !path.exists() {
            return Ok(None);
        }
        let bytes = fs::read(&path).map_err(|error| format!("boundary_read: {error}"))?;
        serde_json::from_slice(&bytes)
            .map(Some)
            .map_err(|_| "boundary_corrupt".to_string())
    }

    fn write_onboard(&self, value: &Value) -> Result<(), String> {
        let operation_id = value
            .get("operation_id")
            .and_then(Value::as_str)
            .ok_or_else(|| "operation_id_invalid".to_string())?;
        atomic_json(&self.onboard_path(operation_id), value)
    }

    fn epoch_path(&self) -> PathBuf {
        self.boundary.join("storage-epoch.json")
    }

    fn adopted_accounts(&self) -> Result<Vec<String>, String> {
        let path = self.epoch_path();
        if !path.exists() {
            return Ok(Vec::new());
        }
        let bytes = fs::read(&path).map_err(|error| format!("boundary_read: {error}"))?;
        let value: Value = serde_json::from_slice(&bytes).map_err(|_| "boundary_corrupt".to_string())?;
        Ok(value
            .get("accounts")
            .and_then(Value::as_array)
            .map(|items| {
                items
                    .iter()
                    .filter_map(Value::as_str)
                    .map(|item| item.to_ascii_lowercase())
                    .collect()
            })
            .unwrap_or_default())
    }

    fn adopt_account(&self, account: &str) -> Result<(), String> {
        let mut accounts = self.adopted_accounts()?;
        if !accounts.iter().any(|item| item == account) {
            accounts.push(account.to_string());
            accounts.sort();
        }
        atomic_json(&self.epoch_path(), &json!({"accounts": accounts}))
    }

    fn managed_accounts(&self) -> Result<Vec<ManagedAccount>, String> {
        self.runtime
            .accounts()
            .managed_accounts()
            .map_err(safe_error)
    }

    fn account_in_storage(&self, account: &str) -> bool {
        self.managed_accounts()
            .ok()
            .into_iter()
            .flatten()
            .any(|item| item.account_id_hex.eq_ignore_ascii_case(account))
    }

    async fn evidence(
        &self,
        account: &str,
        recipient: &str,
        group: &str,
    ) -> Result<IdentityEvidence, String> {
        let managed = self.managed_accounts()?;
        let current: Vec<String> = managed
            .iter()
            .map(|item| item.account_id_hex.to_ascii_lowercase())
            .collect();
        let adopted = self.adopted_accounts()?;
        let account_in_storage = current.iter().any(|item| item == account);
        let device_can_sign = managed.iter().any(|item| {
            item.account_id_hex.eq_ignore_ascii_case(account)
                && item.local_signing
                && !item.signed_out
                && !item.unlinked
        });
        let storage_matches = if adopted.is_empty() {
            true
        } else if current.is_empty() {
            false
        } else {
            adopted.iter().all(|id| current.iter().any(|item| item == id))
        };
        let group_available = if group.is_empty() {
            None
        } else {
            match self.member_accounts(account, group).await {
                Ok(members) => {
                    let ids: Vec<String> = members
                        .into_iter()
                        .filter(|(_, devices)| *devices > 0)
                        .map(|(id, _)| id)
                        .collect();
                    Some(authorize_group_members(&ids, account, recipient).is_ok())
                }
                Err(_) => Some(false),
            }
        };
        Ok(IdentityEvidence {
            account_in_storage,
            device_can_sign,
            storage_matches,
            group_available,
        })
    }
}

enum ConversationState {
    Absent,
    Intending { empty_lookups: i64, started_at_ms: i64 },
    Established(String),
}

fn upstream_of(status: Option<&LocalSendStatus>) -> UpstreamSend {
    match status {
        None => UpstreamSend::Absent,
        Some(LocalSendStatus::Queued { .. }) => UpstreamSend::Queued,
        Some(LocalSendStatus::EngineOwned { .. }) => UpstreamSend::EngineOwned,
        Some(LocalSendStatus::Completed(summary)) => match summary.accept_disposition {
            SendAcceptDisposition::Published => UpstreamSend::Published,
            SendAcceptDisposition::AcceptedPending => UpstreamSend::AcceptedPending,
            SendAcceptDisposition::CompletionUnknown => UpstreamSend::CompletionUnknown,
        },
        Some(LocalSendStatus::Rejected | LocalSendStatus::RefusedNewMembers) => {
            UpstreamSend::Rejected
        }
    }
}

fn stored_phase(value: &Value) -> Option<StoredSend> {
    Some(match value.get("disposition").and_then(Value::as_str)? {
        "submitting" => StoredSend::Submitting,
        "accepted_pending" => StoredSend::Pending,
        "published" => StoredSend::Published,
        "rejected" => StoredSend::Rejected,
        "completion_unknown" => StoredSend::CompletionUnknown,
        _ => return None,
    })
}

fn read_attempts(value: &Value) -> PhaseAttempts {
    PhaseAttempts {
        message: value.get("message_attempts").and_then(Value::as_i64).unwrap_or(0),
        unknown: value.get("unknown_attempts").and_then(Value::as_i64).unwrap_or(0),
        token_wait: value
            .get("token_wait_attempts")
            .and_then(Value::as_i64)
            .unwrap_or(0),
        unobservable: value
            .get("unobservable_attempts")
            .and_then(Value::as_i64)
            .unwrap_or(0),
        started_at_ms: value.get("started_at_ms").and_then(Value::as_i64).unwrap_or(0),
    }
}

fn journal_identity_matches(value: &Value, account: &str, group: &str, payload: &str) -> bool {
    match (
        value.get("account").and_then(Value::as_str),
        value.get("group").and_then(Value::as_str),
        value.get("payload_sha256").and_then(Value::as_str),
    ) {
        (None, None, None) => true,
        (Some(stored_account), Some(stored_group), Some(stored_payload)) => {
            stored_account.eq_ignore_ascii_case(account)
                && stored_group.eq_ignore_ascii_case(group)
                && stored_payload == payload
        }
        _ => false,
    }
}

fn unknown_value(alert_id: &str, account: &str, group: &str, payload: &str) -> Value {
    json!({
        "operation_id": alert_id,
        "account": account,
        "group": group,
        "payload_sha256": payload,
        "disposition": "completion_unknown",
        "message_phase": "completion_unknown",
        "published": 0,
        "message_ids": [],
        "message_event_id": Value::Null,
        "push": "not_attempted",
        "push_event_id": Value::Null,
        "push_evidence": "not_attempted",
        "push_error": Value::Null
    })
}

fn message_phase_name(disposition: &str) -> &'static str {
    match disposition {
        "published" => "relay_accepted",
        "accepted_pending" | "submitting" => "accepted_pending",
        "rejected" => "rejected",
        _ => "completion_unknown",
    }
}

fn identity_name(step: IdentityStep) -> &'static str {
    match step {
        IdentityStep::UseCached => "use_cached",
        IdentityStep::Import => "import",
        IdentityStep::ExplicitOnboard => "explicit_onboard",
        IdentityStep::SenderMismatch => "sender_identity_mismatch",
        IdentityStep::RecipientMismatch => "recipient_identity_mismatch",
        IdentityStep::RecipientUnbound => "recipient_identity_unbound",
        IdentityStep::StorageMissing => "mdk_storage_missing",
        IdentityStep::DeviceInvalid => "device_identity_invalid",
        IdentityStep::StorageReplaced => "mdk_storage_replaced",
        IdentityStep::GroupUnavailable => "conversation_unavailable",
    }
}

fn group_id(hex_id: &str) -> Result<GroupId, String> {
    let bytes = hex::decode(hex_id.trim()).map_err(|_| "group_id_invalid".to_string())?;
    if bytes.is_empty() {
        return Err("group_id_invalid".to_string());
    }
    Ok(GroupId::new(bytes))
}

fn normalize_group(value: &str) -> Result<String, String> {
    let bytes = hex::decode(value.trim()).map_err(|_| "group_id_invalid".to_string())?;
    if bytes.is_empty() {
        return Err("group_id_invalid".to_string());
    }
    Ok(hex::encode(bytes))
}

fn account_hex(value: &str) -> Result<String, String> {
    let trimmed = value.trim();
    if trimmed.starts_with("nsec") {
        return Err("account_invalid".to_string());
    }
    nostr::prelude::PublicKey::parse(trimmed)
        .map(|key| key.to_hex())
        .map_err(|_| "account_invalid".to_string())
}

fn payload_hash(text: &str) -> String {
    hex::encode(Sha256::digest(text.as_bytes()))
}

fn operation_token(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 80
        && value
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' || ch == ':')
}

fn conversation_key(account: &str, peer: &str) -> String {
    format!("{account}:{peer}")
}

fn unix_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as i64)
        .unwrap_or(0)
}

fn crash_after(point: &str) -> Result<(), String> {
    if std::env::var("WATCHDOG_MARMOT_CRASH_AT").ok().as_deref() == Some(point) {
        Err(format!("crash_injected:{point}"))
    } else {
        Ok(())
    }
}

fn atomic_json(path: &Path, value: &Value) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|error| format!("boundary_write: {error}"))?;
    }
    let bytes = serde_json::to_vec(value).map_err(|_| "boundary_encode".to_string())?;
    let tmp = path.with_extension("tmp");
    let _ = fs::remove_file(&tmp);
    {
        let mut options = OpenOptions::new();
        options.create_new(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options
            .open(&tmp)
            .map_err(|error| format!("boundary_write: {error}"))?;
        file.write_all(&bytes)
            .map_err(|error| format!("boundary_write: {error}"))?;
        file.sync_all()
            .map_err(|error| format!("boundary_write: {error}"))?;
    }
    fs::rename(&tmp, path).map_err(|error| format!("boundary_write: {error}"))?;
    if let Some(parent) = path.parent() {
        if let Ok(dir) = File::open(parent) {
            let _ = dir.sync_all();
        }
    }
    restrict(path)
}

fn safe_error(error: impl ToString) -> String {
    let text = error.to_string();
    let lower = text.to_ascii_lowercase();
    if lower.contains("nsec")
        || text.contains("nsec1")
        || lower.contains("token")
        || lower.contains("bearer")
    {
        return "marmot_app_error".to_string();
    }
    if lower.contains("direct_conversation_index_not_ready") {
        return "direct_conversation_index_not_ready".to_string();
    }
    let mut cleaned = String::new();
    let mut hex_run = String::new();
    for ch in text.chars() {
        if ch.is_ascii_hexdigit() {
            hex_run.push(ch);
            continue;
        }
        push_redacted(&mut cleaned, &hex_run);
        hex_run.clear();
        cleaned.push(ch);
    }
    push_redacted(&mut cleaned, &hex_run);
    let trimmed: String = cleaned.chars().take(180).collect();
    if trimmed.is_empty() {
        "marmot_app_error".to_string()
    } else {
        trimmed
    }
}

fn push_redacted(out: &mut String, hex_run: &str) {
    if hex_run.len() >= 32 {
        out.push_str("[redacted]");
    } else {
        out.push_str(hex_run);
    }
}

fn restrict(path: &Path) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .map_err(|error| format!("boundary_mode: {error}"))?;
    }
    let _ = path;
    Ok(())
}

fn restrict_dir(path: &Path) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))
            .map_err(|error| format!("marmot_root: {error}"))?;
    }
    let _ = path;
    Ok(())
}

fn exclusive_lock(file: &File) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::io::AsRawFd;
        extern "C" {
            fn flock(fd: i32, operation: i32) -> i32;
        }
        const LOCK_EX: i32 = 2;
        const LOCK_NB: i32 = 4;
        unsafe { flock(file.as_raw_fd(), LOCK_EX | LOCK_NB) == 0 }
    }
    #[cfg(not(unix))]
    {
        let _ = file;
        true
    }
}
