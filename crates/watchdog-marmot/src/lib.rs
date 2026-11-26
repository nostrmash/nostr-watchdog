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

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use cgka_traits::{GroupId, SendAcceptDisposition};
use marmot_app::{
    AccountSetupRequest, LocalSendStatus, MarmotApp, MarmotAppConfig, MarmotAppRuntime,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use watchdog_core::group_auth::authorize_group_members;
use watchdog_core::marmot_recovery::{
    reconcile_conversation, reconcile_send, ConversationLookup, ConversationStep, SendStep,
    StoredSend, UpstreamSend,
};
use zeroize::Zeroizing;

pub struct Session {
    runtime: MarmotAppRuntime,
    boundary: PathBuf,
    _lock: File,
}

pub fn open(root: &Path, relays: &[String], allow_loopback: bool) -> Result<Session, String> {
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
    Ok(Session {
        runtime: app.runtime(),
        boundary,
        _lock: lock,
    })
}

impl Session {
    pub async fn import_sender(&self, nsec: String, relays: &[String]) -> Result<String, String> {
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
        Ok(result.account.account_id_hex)
    }

    /// Find or create the direct conversation with one recipient.
    ///
    /// The group name is empty so MDK classifies it as a direct conversation
    /// and can find it again after a restart. An unready peer index is retried
    /// rather than treated as "no conversation".
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

    /// Replace a stale saved group only when MDK reports that no reusable
    /// direct conversation exists. An unready index keeps the saved id.
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
        replace_saved: bool,
    ) -> Result<String, String> {
        let saved = self.saved_group(account, peer)?;
        let (lookup, existing_id) = self.lookup_direct(account, peer).await?;
        let saved_ref = if replace_saved {
            None
        } else {
            saved.as_deref()
        };
        match reconcile_conversation(saved_ref, lookup) {
            ConversationStep::UseSaved => Ok(saved.expect("saved group")),
            ConversationStep::RetryIndex => Err("conversation_index_not_ready".to_string()),
            ConversationStep::NotReusable => Err("conversation_not_reusable".to_string()),
            ConversationStep::UseExisting => {
                let id = existing_id.ok_or_else(|| "marmot_group_missing".to_string())?;
                self.remember_group(account, peer, &id)?;
                Ok(id)
            }
            ConversationStep::Create => {
                if replace_saved {
                    self.forget_group(account, peer)?;
                }
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
        let group = group_id(group_hex)?;
        let members = self
            .runtime
            .group_members(account, &group)
            .await
            .map_err(safe_error)?;
        Ok(members
            .into_iter()
            .map(|member| member.member_id_hex.to_ascii_lowercase())
            .collect())
    }

    /// Publish one alert, or refresh the MDK status of an alert already submitted.
    ///
    /// A cached `accepted_pending` result is not returned until MDK has been
    /// asked again. The same client token is never submitted twice.
    pub async fn send_once(
        &self,
        alert_id: &str,
        account: &str,
        group_hex: &str,
        text: &str,
        allow: &[String],
    ) -> Result<Value, String> {
        if !alert_token(alert_id) {
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
        let stored = self.read_journal(alert_id)?;
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
                    .project_status(&account, &group, &recipient, &payload, status)
                    .await?;
                self.write_journal(alert_id, &value)?;
                Ok(value)
            }
            SendStep::KeepStoredTerminal => stored.ok_or_else(|| "completion_unknown".to_string()),
            SendStep::CompletionUnknown => {
                let value = unknown_value(&account, &group_hex, &payload);
                self.write_journal(alert_id, &value)?;
                Ok(value)
            }
            SendStep::Submit => {
                let members = self.member_ids(&account, &group_hex).await?;
                authorize_group_members(&members, &account, &recipient).map_err(str::to_string)?;
                let intent = json!({
                    "account": account,
                    "group": group_hex,
                    "payload_sha256": payload,
                    "disposition": "submitting",
                    "published": 0,
                    "message_ids": [],
                    "push": "not_attempted"
                });
                self.write_journal(alert_id, &intent)?;
                self.runtime
                    .submit_text(&account, &group, text.to_string(), alert_id.to_string())
                    .await
                    .map_err(safe_error)?;
                let status = self
                    .runtime
                    .local_send_status(&account, &group, alert_id)
                    .map_err(safe_error)?
                    .ok_or_else(|| "completion_unknown".to_string())?;
                let value = self
                    .project_status(&account, &group, &recipient, &payload, status)
                    .await?;
                self.write_journal(alert_id, &value)?;
                Ok(value)
            }
        }
    }

    async fn project_status(
        &self,
        account: &str,
        group: &GroupId,
        recipient: &str,
        payload: &str,
        status: LocalSendStatus,
    ) -> Result<Value, String> {
        let group_hex = group.to_string();
        let (disposition, published, message_ids) = match status {
            LocalSendStatus::Queued { message_id_hex }
            | LocalSendStatus::EngineOwned { message_id_hex } => {
                ("accepted_pending", 0, vec![message_id_hex])
            }
            LocalSendStatus::Completed(summary) => {
                let disposition = match summary.accept_disposition {
                    SendAcceptDisposition::Published => "published",
                    SendAcceptDisposition::AcceptedPending => "accepted_pending",
                    SendAcceptDisposition::CompletionUnknown => "completion_unknown",
                };
                (disposition, summary.published, summary.message_ids)
            }
            LocalSendStatus::Rejected | LocalSendStatus::RefusedNewMembers => {
                ("rejected", 0, Vec::new())
            }
        };
        let push = if disposition == "published" {
            self.push_phase(account, group, recipient).await
        } else {
            "not_attempted"
        };
        Ok(json!({
            "account": account,
            "group": group_hex,
            "payload_sha256": payload,
            "disposition": disposition,
            "published": published,
            "message_ids": message_ids,
            "push": push,
            "push_evidence": if disposition == "published" { "token_availability_only" } else { "not_attempted" }
        }))
    }

    /// Active tokens are those whose member still holds the announcing leaf.
    /// Only the configured recipient's tokens count. MDK does not expose a
    /// separate push-trigger publication result, so a published message with
    /// tokens still reports `push_disposition_unknown`.
    async fn push_phase(&self, account: &str, group: &GroupId, recipient: &str) -> &'static str {
        match self.runtime.group_push_debug_info(account, group).await {
            Ok(info) => {
                let active = info.tokens.iter().any(|token| {
                    token.member_matches_active_leaf
                        && token.member_id_hex.eq_ignore_ascii_case(recipient)
                });
                if active {
                    "push_disposition_unknown"
                } else {
                    "recipient_push_token_unavailable"
                }
            }
            Err(_) => "push_disposition_unknown",
        }
    }

    pub async fn sync(&self) -> Result<(), String> {
        self.runtime.catch_up_accounts().await.map_err(safe_error)
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

    fn read_journal(&self, alert_id: &str) -> Result<Option<Value>, String> {
        let path = self.journal_path(alert_id);
        if !path.exists() {
            return Ok(None);
        }
        let bytes = fs::read(&path).map_err(|error| format!("boundary_read: {error}"))?;
        serde_json::from_slice(&bytes)
            .map(Some)
            .map_err(|_| "boundary_corrupt".to_string())
    }

    fn started(&self, alert_id: &str) -> Result<bool, String> {
        Ok(self.started_path(alert_id).exists())
    }

    fn write_journal(&self, alert_id: &str, value: &Value) -> Result<(), String> {
        atomic_json(&self.journal_path(alert_id), value)?;
        let _ = fs::remove_file(self.started_path(alert_id));
        Ok(())
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

    fn saved_group(&self, account: &str, peer: &str) -> Result<Option<String>, String> {
        let value = self.conversations()?;
        Ok(match value.get(conversation_key(account, peer)) {
            Some(Value::String(group)) if !group.is_empty() => Some(group.clone()),
            Some(Value::Object(object)) => object
                .get("group_id")
                .and_then(Value::as_str)
                .filter(|group| !group.is_empty())
                .map(str::to_string),
            _ => None,
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
        if self.saved_group(account, peer)?.is_some() {
            return Ok(());
        }
        let mut value = self.conversations()?;
        if let Some(object) = value.as_object_mut() {
            object.insert(
                conversation_key(account, peer),
                json!({"phase": "intending"}),
            );
        }
        atomic_json(&self.conversation_path(), &value)
    }

    fn forget_group(&self, account: &str, peer: &str) -> Result<(), String> {
        let mut value = self.conversations()?;
        if let Some(object) = value.as_object_mut() {
            object.remove(&conversation_key(account, peer));
        }
        atomic_json(&self.conversation_path(), &value)
    }
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

fn unknown_value(account: &str, group: &str, payload: &str) -> Value {
    json!({
        "account": account,
        "group": group,
        "payload_sha256": payload,
        "disposition": "completion_unknown",
        "published": 0,
        "message_ids": [],
        "push": "not_attempted",
        "push_evidence": "not_attempted"
    })
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
    if trimmed.len() == 64 && trimmed.chars().all(|ch| ch.is_ascii_hexdigit()) {
        Ok(trimmed.to_ascii_lowercase())
    } else {
        Err("account_invalid".to_string())
    }
}

fn payload_hash(text: &str) -> String {
    hex::encode(Sha256::digest(text.as_bytes()))
}

fn alert_token(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 80
        && value
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '-' || ch == '_')
}

fn conversation_key(account: &str, peer: &str) -> String {
    format!("{account}:{peer}")
}

fn atomic_json(path: &Path, value: &Value) -> Result<(), String> {
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
    if lower.contains("nsec") || text.contains("nsec1") {
        return "marmot_app_error".to_string();
    }
    if lower.contains("direct_conversation_index_not_ready") {
        return "direct_conversation_index_not_ready".to_string();
    }
    let trimmed: String = text.chars().take(180).collect();
    if trimmed.is_empty() {
        "marmot_app_error".to_string()
    } else {
        trimmed
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
