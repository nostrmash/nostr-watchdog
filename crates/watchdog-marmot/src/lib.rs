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
//! `operations.log` is a write-ahead log. Per-alert files keep every operation id.

mod egress;
mod journal;
mod push_trace;
mod relays;

pub use egress::install_egress;

use std::fs::{self, File, OpenOptions};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
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

fn public_key_hex(nsec: &str) -> Result<String, String> {
    nostr::prelude::Keys::parse(nsec)
        .map(|keys| keys.public_key().to_hex())
        .map_err(|_| "sender_secret_invalid".to_string())
}

fn transport_evidence(value: &str) -> &'static str {
    match value {
        "token_availability_only" => "token_availability_only",
        "helper_journal" => "helper_journal",
        _ => "not_observed",
    }
}

pub struct Session {
    runtime: MarmotAppRuntime,
    boundary: PathBuf,
    journal: Mutex<journal::Journal>,
    allow_loopback: bool,
    _lock: File,
}

pub fn open(root: &Path, relays: &[String], allow_loopback: bool) -> Result<Session, String> {
    install_egress(allow_loopback)?;
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
    fs::create_dir_all(boundary.join("onboard"))
        .map_err(|error| format!("marmot_boundary: {error}"))?;
    restrict_dir(&boundary.join("onboard"))?;
    let operations = journal::Journal::open(&boundary)?;
    Ok(Session {
        runtime: app.runtime(),
        boundary,
        journal: Mutex::new(operations),
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
        let existing = self.read_onboard(operation_id)?;
        if let Some(record) = existing.as_ref() {
            if record.get("recipient").and_then(Value::as_str) != Some(recipient.as_str())
                || record.get("replace").and_then(Value::as_bool) != Some(replace)
            {
                return Err("operation_identity_mismatch".to_string());
            }
            if record.get("phase").and_then(Value::as_str) == Some("established") {
                let account = record
                    .get("account")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string();
                if !self.account_in_storage(&account) {
                    return Err("mdk_storage_missing".to_string());
                }
                let mut value = record.clone();
                if let Some(object) = value.as_object_mut() {
                    object.insert("reused".to_string(), Value::Bool(true));
                }
                return Ok(value);
            }
        }
        let expected = public_key_hex(&nsec)?;
        let saved_account = existing
            .as_ref()
            .and_then(|value| value.get("account"))
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .map(str::to_string);
        let account = if let Some(saved) = saved_account {
            if !saved.eq_ignore_ascii_case(&expected) {
                return Err("operation_identity_mismatch".to_string());
            }
            if !self.account_in_storage(&saved) {
                return Err("mdk_storage_missing".to_string());
            }
            saved
        } else {
            self.write_onboard(&json!({
                "operation_id": operation_id,
                "recipient": recipient,
                "replace": replace,
                "phase": "importing"
            }))?;
            match self.import_sender(nsec, relays).await {
                Ok(account) => account,
                Err(error)
                    if error.contains("account already exists")
                        && self.account_in_storage(&expected) =>
                {
                    self.adopt_account(&expected)?;
                    expected
                }
                Err(error) => return Err(error),
            }
        };
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
                if let Ok(count) = self
                    .recipient_token_count(&account, &group_id, &recipient)
                    .await
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
            .map(|member| {
                (
                    member.member_id_hex.to_ascii_lowercase(),
                    member.device_count,
                )
            })
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
        self.send_in_project(alert_id, "", account, group_hex, text, allow)
            .await
    }

    pub async fn send_in_project(
        &self,
        alert_id: &str,
        project: &str,
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
        let binding = self.read_binding(alert_id)?;
        if let Some(value) = binding.as_ref() {
            if !journal_identity_matches(value, project, &account, &recipient, &group_hex, &payload)
            {
                return Err("alert_identity_mismatch".to_string());
            }
        }
        let stored = binding
            .filter(|value| value.get("disposition").and_then(Value::as_str) != Some("released"));
        let legacy_started = stored.is_none() && self.started(alert_id)?;
        let stored_phase = stored
            .as_ref()
            .and_then(stored_phase)
            .or(legacy_started.then_some(StoredSend::Submitting));
        let prior = stored.as_ref().map(read_attempts).unwrap_or_default();
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
        match reconcile_send(stored_phase, true, upstream_of(status.as_ref())) {
            SendStep::IdentityMismatch => Err("alert_identity_mismatch".to_string()),
            SendStep::ProjectUpstream => {
                let status = status.ok_or_else(|| "completion_unknown".to_string())?;
                let value = self
                    .project_status(
                        alert_id,
                        project,
                        &account,
                        &group,
                        &recipient,
                        &payload,
                        status,
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
            SendStep::CompletionUnknown => self.mark_unknown(
                alert_id,
                project,
                &account,
                &recipient,
                &group_hex,
                &payload,
                prior,
                "completion_unknown",
            ),
            SendStep::Submit => {
                if stored_phase.is_some() {
                    return Err("operation_already_recorded".to_string());
                }
                self.authorize_send(&account, &group_hex, &recipient)
                    .await?;
                let intent = json!({
                    "operation_id": alert_id,
                    "project": project,
                    "account": account,
                    "recipient": recipient,
                    "group": group_hex,
                    "operation_type": "application_message",
                    "payload_sha256": payload,
                    "disposition": "submitting",
                    "message_phase": "prepared",
                    "message_state": "prepared",
                    "published": 0,
                    "message_ids": [],
                    "message_event_id": Value::Null,
                    "push": "unknown",
                    "push_state": "unknown",
                    "push_event_id": Value::Null,
                    "push_evidence": "intent_recorded",
                    "push_error": Value::Null,
                    "push_attempts": Value::Null,
                    "hold": true,
                    "preserve_message": true,
                    "terminal": false
                });
                self.write_record(alert_id, &intent)?;
                crash_after("intent")?;
                if let Err(error) = self
                    .runtime
                    .submit_text(&account, &group, text.to_string(), alert_id.to_string())
                    .await
                {
                    return self
                        .recover_submit_error(
                            alert_id, project, &account, &group, &recipient, &group_hex, &payload,
                            prior, &intent, error,
                        )
                        .await;
                }
                crash_after("submitted")?;
                let status = match self.runtime.local_send_status(&account, &group, alert_id) {
                    Ok(Some(status)) => status,
                    Ok(None) | Err(_) => {
                        return self.mark_unknown(
                            alert_id,
                            project,
                            &account,
                            &recipient,
                            &group_hex,
                            &payload,
                            prior,
                            "status_not_visible",
                        );
                    }
                };
                crash_after("pending")?;
                let value = self
                    .project_status(
                        alert_id,
                        project,
                        &account,
                        &group,
                        &recipient,
                        &payload,
                        status,
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
        // This read is not held across submit_text. MDK has no API that admits
        // the kind-9 message and the current member set in one transaction.
        // A failed or unusable roster refuses the send. A roster that passes
        // can still change before the worker encrypts.
        authorize_group_members(&ids, account, recipient)?;
        match self.lookup_direct(account, recipient).await? {
            (ConversationLookup::Reusable, Some(found))
                if !found.eq_ignore_ascii_case(group_hex) =>
            {
                Err("conversation_mismatch".to_string())
            }
            (ConversationLookup::NotReusable, _) => Err("conversation_not_reusable".to_string()),
            _ => Ok(()),
        }
    }

    async fn project_status(
        &self,
        alert_id: &str,
        project: &str,
        account: &str,
        group: &GroupId,
        recipient: &str,
        payload: &str,
        status: LocalSendStatus,
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
        let previous_message = previous
            .and_then(|value| {
                value
                    .get("message_state")
                    .or_else(|| value.get("message_phase"))
            })
            .and_then(Value::as_str);
        let (disposition, message_ids) = if previous_message == Some("relay_accepted") {
            let ids = if message_ids.is_empty() {
                previous
                    .and_then(|value| value.get("message_ids"))
                    .and_then(Value::as_array)
                    .map(|items| {
                        items
                            .iter()
                            .filter_map(|item| item.as_str().map(str::to_string))
                            .collect()
                    })
                    .unwrap_or(message_ids)
            } else {
                message_ids
            };
            ("published", ids)
        } else {
            (disposition, message_ids)
        };
        let message_published = disposition == "published";
        let tokens = if message_published {
            match self.recipient_token_count(account, group, recipient).await {
                Ok(count) => count,
                Err(_) => -1,
            }
        } else {
            0
        };
        let _ = push_trace::operation_push_failure();
        let _ = previous;
        let (push, evidence) = classify_push(message_published, tokens);
        let stored_project = previous
            .and_then(|value| value.get("project"))
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .unwrap_or(project);
        let mut value = json!({
            "operation_id": alert_id,
            "project": stored_project,
            "account": account,
            "recipient": recipient,
            "group": group_hex,
            "operation_type": "application_message",
            "payload_sha256": payload,
            "disposition": disposition,
            "message_phase": message_phase_name(disposition),
            "message_state": message_phase_name(disposition),
            "published": published,
            "message_ids": message_ids,
            "push": push,
            "push_state": push,
            "push_evidence": evidence,
            "push_error": Value::Null,
            "push_event_id": Value::Null,
            "push_attempts": Value::Null,
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
            object.insert(
                "token_wait_attempts".to_string(),
                json!(attempts.token_wait),
            );
            object.insert(
                "unobservable_attempts".to_string(),
                json!(attempts.unobservable),
            );
            object.insert("started_at_ms".to_string(), json!(attempts.started_at_ms));
            let updated_at_ms = unix_ms();
            object.insert("updated_at_ms".to_string(), json!(updated_at_ms));
            object.insert(
                "operation_age_ms".to_string(),
                json!(updated_at_ms.saturating_sub(attempts.started_at_ms)),
            );
            object.insert("settled".to_string(), json!(!decision.hold));
            object.insert("reconcile".to_string(), json!(decision.hold));
            object.insert("message_state".to_string(), json!(message));
            object.insert("push_state".to_string(), json!(decision.push_phase));
            if !object.contains_key("push_event_id") {
                object.insert("push_event_id".to_string(), Value::Null);
            }
            if !object.contains_key("push_attempts") {
                object.insert("push_attempts".to_string(), Value::Null);
            }
            let evidence = object
                .get("push_evidence")
                .and_then(Value::as_str)
                .map(transport_evidence)
                .unwrap_or("not_observed");
            let project = object
                .get("project")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            let operation_id = object
                .get("operation_id")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            let message_event_id = object
                .get("message_event_id")
                .cloned()
                .unwrap_or(Value::Null);
            let detail = object
                .get("status_detail")
                .and_then(Value::as_str)
                .filter(|value| {
                    !value.is_empty()
                        && value.len() <= 80
                        && value
                            .chars()
                            .all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
                })
                .map(str::to_string);
            let contract = operation_contract(
                &project,
                &operation_id,
                &message,
                message_event_id,
                decision.push_phase,
                evidence,
                detail.as_deref(),
                decision.hold,
                decision.delay_ms,
                attempts.started_at_ms,
                updated_at_ms,
                attempts,
            );
            object.insert("operation".to_string(), contract);
        }
        Ok(value)
    }

    /// MDK's view of whether this account's group changes were refused.
    /// `None` from MDK means nothing is owed and nothing was refused.
    pub async fn group_was_accepted(&self, account: &str, group_hex: &str) -> Result<bool, String> {
        let account = account_hex(account)?;
        let group = group_id(group_hex)?;
        match self
            .runtime
            .group_commit_delivery(&account, &group)
            .await
            .map_err(safe_error)?
        {
            None => Ok(true),
            Some(delivery) => Ok(delivery.refused_relays.is_empty()),
        }
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

    fn started_path(&self, alert_id: &str) -> PathBuf {
        self.boundary.join(format!("{alert_id}.started"))
    }

    fn journal(&self) -> Result<std::sync::MutexGuard<'_, journal::Journal>, String> {
        let guard = self
            .journal
            .lock()
            .map_err(|_| "boundary_lock".to_string())?;
        if guard.poisoned() {
            return Err("boundary_durable_failure".to_string());
        }
        Ok(guard)
    }

    fn read_binding(&self, alert_id: &str) -> Result<Option<Value>, String> {
        Ok(self.journal()?.get(alert_id))
    }

    fn write_record(&self, alert_id: &str, value: &Value) -> Result<(), String> {
        self.journal()?.record(alert_id, value)?;
        let _ = fs::remove_file(self.started_path(alert_id));
        self.prune_journals()
    }

    async fn recover_submit_error(
        &self,
        alert_id: &str,
        project: &str,
        account: &str,
        group: &GroupId,
        recipient: &str,
        group_hex: &str,
        payload: &str,
        prior: PhaseAttempts,
        intent: &Value,
        error: marmot_app::AppError,
    ) -> Result<Value, String> {
        let status = self.runtime.local_send_status(account, group, alert_id);
        match (
            failed_submit_decision(
                classify_submit_error(&error),
                status.as_ref().ok().map(|value| value.is_some()),
            ),
            status,
        ) {
            (_, Ok(Some(status))) => {
                let value = self
                    .project_status(
                        alert_id,
                        project,
                        account,
                        group,
                        recipient,
                        payload,
                        status,
                        prior,
                        Some(intent),
                    )
                    .await?;
                self.write_record(alert_id, &value)?;
                Ok(value)
            }
            (FailedSubmit::Resubmit, Ok(None)) => {
                self.forget_unadmitted(alert_id)?;
                Err(safe_error(error))
            }
            _ => self.mark_unknown(
                alert_id,
                project,
                account,
                recipient,
                group_hex,
                payload,
                prior,
                "submit_ambiguous",
            ),
        }
    }

    fn mark_unknown(
        &self,
        alert_id: &str,
        project: &str,
        account: &str,
        recipient: &str,
        group_hex: &str,
        payload: &str,
        prior: PhaseAttempts,
        detail: &str,
    ) -> Result<Value, String> {
        let mut value = unknown_value(alert_id, project, account, recipient, group_hex, payload);
        if let Some(object) = value.as_object_mut() {
            object.insert("status_detail".to_string(), json!(detail));
        }
        let value = self.finish_record(value, prior)?;
        self.write_record(alert_id, &value)?;
        Ok(value)
    }

    fn forget_unadmitted(&self, alert_id: &str) -> Result<(), String> {
        let mut journal = self.journal()?;
        if journal.disposition(alert_id).as_deref() == Some("submitting") {
            journal.release(alert_id)?;
        }
        Ok(())
    }

    fn prune_journals(&self) -> Result<(), String> {
        // Operation files are the deduplication index. They stay after the
        // ciphertext is gone so a retired alert id cannot be encrypted again.
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
        journal::atomic_json(&self.conversation_path(), &value)
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
        journal::atomic_json(&self.conversation_path(), &value)
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
        journal::atomic_json(&self.conversation_path(), &value)
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
        journal::atomic_json(&self.onboard_path(operation_id), value)
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
        let value: Value =
            serde_json::from_slice(&bytes).map_err(|_| "boundary_corrupt".to_string())?;
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
        journal::atomic_json(&self.epoch_path(), &json!({"accounts": accounts}))
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
            adopted
                .iter()
                .all(|id| current.iter().any(|item| item == id))
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
    Intending {
        empty_lookups: i64,
        started_at_ms: i64,
    },
    Established(String),
}

fn operation_contract(
    project: &str,
    operation_id: &str,
    message: &str,
    message_event_id: Value,
    push_phase: &str,
    evidence: &str,
    error: Option<&str>,
    hold: bool,
    delay_ms: i64,
    started_at_ms: i64,
    updated_at_ms: i64,
    attempts: PhaseAttempts,
) -> Value {
    let retry_after_ms = if hold { json!(delay_ms) } else { Value::Null };
    let admitted = matches!(message, "relay_accepted" | "accepted_pending" | "rejected");
    json!({
        "projectId": project,
        "operationId": operation_id,
        "messageState": message,
        "messageEventId": message_event_id,
        "pushState": push_phase,
        "pushEventId": Value::Null,
        "evidence": evidence,
        "error": error,
        "disposition": if hold { "reconcile" } else { "settled" },
        "retryAtMs": retry_after_ms.clone(),
        "retryAfterMs": retry_after_ms,
        "phoneDelivery": false,
        "startedAtMs": started_at_ms,
        "updatedAtMs": updated_at_ms,
        "messageSubmissions": if admitted { json!(1) } else { Value::Null },
        "messagePublications": Value::Null,
        "messageReconciles": if message == "accepted_pending" {
            json!(attempts.message)
        } else {
            Value::Null
        },
        "ambiguousReconciles": if matches!(message, "completion_unknown" | "prepared") {
            json!(attempts.unknown)
        } else {
            Value::Null
        },
        "tokenWaits": if push_phase == "token_unavailable" {
            json!(attempts.token_wait)
        } else {
            Value::Null
        },
        "pushPublications": Value::Null,
        "pushReconciles": if push_phase == "unobservable" {
            json!(attempts.unobservable)
        } else {
            Value::Null
        }
    })
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
        message: value
            .get("message_attempts")
            .and_then(Value::as_i64)
            .unwrap_or(0),
        unknown: value
            .get("unknown_attempts")
            .and_then(Value::as_i64)
            .unwrap_or(0),
        token_wait: value
            .get("token_wait_attempts")
            .and_then(Value::as_i64)
            .unwrap_or(0),
        unobservable: value
            .get("unobservable_attempts")
            .and_then(Value::as_i64)
            .unwrap_or(0),
        started_at_ms: value
            .get("started_at_ms")
            .and_then(Value::as_i64)
            .unwrap_or(0),
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SubmitFailure {
    ProvenNonAdmission,
    Ambiguous,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FailedSubmit {
    Resubmit,
    ProjectExisting,
    KeepUnknown,
}

/// Errors returned before `insert_local_submission`, from MDK `ca52a04`.
/// A timeout, a storage failure, or a panicked admission task can happen
/// after the row exists, so those stay ambiguous even when the lookup is empty.
fn classify_submit_error(error: &marmot_app::AppError) -> SubmitFailure {
    use marmot_app::AppError::*;
    match error {
        InvalidAppMessagePayload(_)
        | GroupRemoved(_)
        | GroupDisbanding(_)
        | UserBlocked
        | UnknownGroup(_)
        | InvalidEditTarget
        | MessageDraftRevisionConflict
        | InvalidMessageDraft(_)
        | MediaReferenceStaleEpoch { .. }
        | MediaReferenceEpochUnsettled { .. } => SubmitFailure::ProvenNonAdmission,
        _ => SubmitFailure::Ambiguous,
    }
}

fn failed_submit_decision(class: SubmitFailure, status_present: Option<bool>) -> FailedSubmit {
    match (class, status_present) {
        (_, Some(true)) => FailedSubmit::ProjectExisting,
        (SubmitFailure::ProvenNonAdmission, Some(false)) => FailedSubmit::Resubmit,
        _ => FailedSubmit::KeepUnknown,
    }
}

fn journal_identity_matches(
    value: &Value,
    project: &str,
    account: &str,
    recipient: &str,
    group: &str,
    payload: &str,
) -> bool {
    if let Some(stored_project) = value.get("project").and_then(Value::as_str) {
        if !stored_project.is_empty() && !project.is_empty() && stored_project != project {
            return false;
        }
    }
    if let Some(kind) = value.get("operation_type").and_then(Value::as_str) {
        if kind != "application_message" {
            return false;
        }
    }
    match (
        value.get("account").and_then(Value::as_str),
        value.get("recipient").and_then(Value::as_str),
        value.get("group").and_then(Value::as_str),
        value.get("payload_sha256").and_then(Value::as_str),
    ) {
        (
            Some(stored_account),
            Some(stored_recipient),
            Some(stored_group),
            Some(stored_payload),
        ) => {
            stored_account.eq_ignore_ascii_case(account)
                && stored_recipient.eq_ignore_ascii_case(recipient)
                && stored_group.eq_ignore_ascii_case(group)
                && stored_payload == payload
        }
        // A legacy row with no recipient is not bound to whoever is configured now.
        _ => false,
    }
}

fn unknown_value(
    alert_id: &str,
    project: &str,
    account: &str,
    recipient: &str,
    group: &str,
    payload: &str,
) -> Value {
    json!({
        "operation_id": alert_id,
        "project": project,
        "account": account,
        "recipient": recipient,
        "group": group,
        "operation_type": "application_message",
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
    if std::env::var("WATCHDOG_MARMOT_CRASH_AT").ok().as_deref() != Some(point) {
        return Ok(());
    }
    if std::env::var("WATCHDOG_MARMOT_CRASH_EXIT").ok().as_deref() == Some("1") {
        eprintln!("watchdog-marmot stopped at {point}");
        std::process::exit(75);
    }
    Err(format!("crash_injected:{point}"))
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

#[cfg(test)]
mod admission_tests {
    use super::{
        classify_submit_error, failed_submit_decision, journal_identity_matches, FailedSubmit,
        SubmitFailure,
    };
    use marmot_app::AppError;
    use serde_json::json;

    fn bound(recipient: &str, payload: &str) -> serde_json::Value {
        json!({
            "project": "smartflowsocial",
            "account": "aa",
            "recipient": recipient,
            "group": "bb",
            "operation_type": "application_message",
            "payload_sha256": payload,
            "disposition": "published"
        })
    }

    #[test]
    fn only_a_pre_admission_validation_error_may_be_submitted_again() {
        let validation = AppError::InvalidAppMessagePayload("empty text".into());
        let timeout = AppError::AccountWorkerResponseTimedOut;
        let panicked = AppError::BlockingTask("admission task panicked".into());
        let disk = AppError::Io(std::io::Error::new(
            std::io::ErrorKind::Other,
            "no space left on device",
        ));
        assert_eq!(
            classify_submit_error(&validation),
            SubmitFailure::ProvenNonAdmission
        );
        assert_eq!(classify_submit_error(&timeout), SubmitFailure::Ambiguous);
        assert_eq!(classify_submit_error(&panicked), SubmitFailure::Ambiguous);
        assert_eq!(classify_submit_error(&disk), SubmitFailure::Ambiguous);
        assert_eq!(
            classify_submit_error(&AppError::GroupRemoved("member left".into())),
            SubmitFailure::ProvenNonAdmission
        );
        assert_eq!(
            classify_submit_error(&AppError::UnknownGroup("missing".into())),
            SubmitFailure::ProvenNonAdmission
        );
        assert_eq!(
            classify_submit_error(&AppError::Publish("relay timeout".into())),
            SubmitFailure::Ambiguous
        );
        assert_eq!(
            classify_submit_error(&AppError::TransportClosed),
            SubmitFailure::Ambiguous
        );
        assert_eq!(
            failed_submit_decision(SubmitFailure::ProvenNonAdmission, None),
            FailedSubmit::KeepUnknown
        );
        assert_eq!(
            failed_submit_decision(SubmitFailure::Ambiguous, Some(false)),
            FailedSubmit::KeepUnknown
        );
        assert_eq!(
            failed_submit_decision(SubmitFailure::ProvenNonAdmission, Some(false)),
            FailedSubmit::Resubmit
        );
        assert_eq!(
            failed_submit_decision(SubmitFailure::Ambiguous, Some(false)),
            FailedSubmit::KeepUnknown
        );
        assert_eq!(
            failed_submit_decision(SubmitFailure::Ambiguous, None),
            FailedSubmit::KeepUnknown
        );
        assert_eq!(
            failed_submit_decision(SubmitFailure::ProvenNonAdmission, Some(true)),
            FailedSubmit::ProjectExisting
        );
        assert_eq!(
            failed_submit_decision(SubmitFailure::Ambiguous, Some(true)),
            FailedSubmit::ProjectExisting
        );
    }

    #[test]
    fn a_different_recipient_does_not_reuse_a_released_operation() {
        let mut released = bound("cc", "payload");
        released["disposition"] = json!("released");
        assert!(journal_identity_matches(
            &released,
            "smartflowsocial",
            "aa",
            "cc",
            "bb",
            "payload"
        ));
        assert!(!journal_identity_matches(
            &released,
            "smartflowsocial",
            "aa",
            "dd",
            "bb",
            "payload"
        ));
        assert!(!journal_identity_matches(
            &bound("cc", "payload"),
            "smartflowsocial",
            "ff",
            "cc",
            "bb",
            "payload"
        ));
        assert!(!journal_identity_matches(
            &bound("cc", "payload"),
            "smartflowsocial",
            "aa",
            "cc",
            "ee",
            "payload"
        ));
        assert!(!journal_identity_matches(
            &bound("cc", "payload"),
            "smartflowsocial",
            "aa",
            "cc",
            "bb",
            "other"
        ));
        assert!(!journal_identity_matches(
            &bound("cc", "payload"),
            "nostrmash",
            "aa",
            "cc",
            "bb",
            "payload"
        ));
        let legacy = json!({
            "project": "smartflowsocial",
            "account": "aa",
            "group": "bb",
            "payload_sha256": "payload",
            "disposition": "published"
        });
        assert!(
            !journal_identity_matches(&legacy, "smartflowsocial", "aa", "cc", "bb", "payload"),
            "a legacy row was bound to a newly configured recipient"
        );
    }
}

#[cfg(test)]
mod contract_tests {
    use super::operation_contract;
    use serde_json::{json, Value};
    use watchdog_core::marmot_recovery::{advance_phase, PhaseAttempts};

    const NOW: i64 = 1_700_000_000_000;
    const EVENT: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    fn view(
        message: &str,
        event: Option<&str>,
        push: &str,
        evidence: &str,
        attempts: PhaseAttempts,
        hold: bool,
        delay_ms: i64,
    ) -> Value {
        operation_contract(
            "smartflowsocial",
            "alert-1",
            message,
            event.map(|value| json!(value)).unwrap_or(Value::Null),
            push,
            evidence,
            None,
            hold,
            delay_ms,
            attempts.started_at_ms,
            NOW,
            attempts,
        )
    }

    fn fixtures() -> Value {
        let (unobservable, unobservable_decision) = advance_phase(
            "relay_accepted",
            "unobservable",
            PhaseAttempts::default(),
            NOW,
        );
        let (pending, pending_decision) = advance_phase(
            "accepted_pending",
            "not_attempted",
            PhaseAttempts::default(),
            NOW,
        );
        let (unknown, unknown_decision) = advance_phase(
            "completion_unknown",
            "not_attempted",
            PhaseAttempts::default(),
            NOW,
        );
        let (waiting, waiting_decision) = advance_phase(
            "relay_accepted",
            "token_unavailable",
            PhaseAttempts::default(),
            NOW,
        );
        let (settled_wait, settled_decision) =
            advance_phase("relay_accepted", "token_unavailable", waiting, NOW);
        json!({
            "permanentUnobservablePush": view(
                "relay_accepted",
                Some(EVENT),
                unobservable_decision.push_phase,
                "not_observed",
                unobservable,
                unobservable_decision.hold,
                unobservable_decision.delay_ms,
            ),
            "messagePublicationUncertain": view(
                "accepted_pending",
                None,
                pending_decision.push_phase,
                "not_observed",
                pending,
                pending_decision.hold,
                pending_decision.delay_ms,
            ),
            "completionUnknown": view(
                "completion_unknown",
                None,
                unknown_decision.push_phase,
                "not_observed",
                unknown,
                unknown_decision.hold,
                unknown_decision.delay_ms,
            ),
            "missingRecipientToken": view(
                "relay_accepted",
                Some(EVENT),
                waiting_decision.push_phase,
                "token_availability_only",
                waiting,
                waiting_decision.hold,
                waiting_decision.delay_ms,
            ),
            "missingRecipientTokenSettled": view(
                "relay_accepted",
                Some(EVENT),
                settled_decision.push_phase,
                "token_availability_only",
                settled_wait,
                settled_decision.hold,
                settled_decision.delay_ms,
            )
        })
    }

    #[test]
    fn native_operation_fixtures_match_the_helper() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../docs/native-operation-fixtures.json");
        let file: Value =
            serde_json::from_str(&std::fs::read_to_string(&path).expect("fixture file")).unwrap();
        let built = fixtures();
        assert_eq!(file, built);
        for value in built.as_object().unwrap().values() {
            assert_eq!(value["projectId"], "smartflowsocial");
            assert_eq!(value["operationId"], "alert-1");
            assert!(value["messagePublications"].is_null());
            assert!(value["pushPublications"].is_null());
            assert!(value.get("messageAttempts").is_none());
            assert!(value["pushEventId"].is_null());
            assert_eq!(value["phoneDelivery"], false);
        }
        assert_eq!(built["permanentUnobservablePush"]["disposition"], "settled");
        assert_eq!(
            built["permanentUnobservablePush"]["messageState"],
            "relay_accepted"
        );
        assert_eq!(
            built["permanentUnobservablePush"]["pushState"],
            "unobservable"
        );
        assert_eq!(built["permanentUnobservablePush"]["messageSubmissions"], 1);
        assert!(built["permanentUnobservablePush"]["messageReconciles"].is_null());
        assert_eq!(built["permanentUnobservablePush"]["pushReconciles"], 1);
        assert!(built["permanentUnobservablePush"]["retryAfterMs"].is_null());
        assert_eq!(
            built["messagePublicationUncertain"]["disposition"],
            "reconcile"
        );
        assert_eq!(
            built["messagePublicationUncertain"]["messageState"],
            "accepted_pending"
        );
        assert_eq!(
            built["messagePublicationUncertain"]["messageSubmissions"],
            1
        );
        assert_eq!(built["messagePublicationUncertain"]["messageReconciles"], 1);
        assert_eq!(built["messagePublicationUncertain"]["retryAfterMs"], 15000);
        assert!(built["completionUnknown"]["messageSubmissions"].is_null());
        assert_eq!(built["completionUnknown"]["ambiguousReconciles"], 1);
        assert_eq!(built["completionUnknown"]["disposition"], "reconcile");
        assert_eq!(
            built["missingRecipientToken"]["messageState"],
            "relay_accepted"
        );
        assert_eq!(built["missingRecipientToken"]["disposition"], "reconcile");
        assert_eq!(built["missingRecipientToken"]["tokenWaits"], 1);
        assert_eq!(
            built["missingRecipientTokenSettled"]["disposition"],
            "settled"
        );
        assert_eq!(
            built["missingRecipientTokenSettled"]["messageState"],
            "relay_accepted"
        );
        assert_eq!(built["missingRecipientTokenSettled"]["tokenWaits"], 2);
        assert!(built["missingRecipientTokenSettled"]["retryAfterMs"].is_null());
    }
}
