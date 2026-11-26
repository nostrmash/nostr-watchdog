//! Native Marmot session.
//!
//! This process embeds the official `marmot-app` runtime (MDK `ca52a04`).
//! It is a separate executable because that runtime links SQLCipher, while the
//! watchdog's operational database links a different SQLite. Cargo allows only
//! one `links = "sqlite3"` package in a binary. Cloudflare does not use this
//! process.

use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

use cgka_traits::{GroupId, SendAcceptDisposition, TransportEndpoint};
use marmot_app::{AccountSetupRequest, MarmotApp, MarmotAppConfig, MarmotAppRuntime};
use serde_json::{json, Value};
use zeroize::Zeroizing;

pub struct Session {
    runtime: MarmotAppRuntime,
    boundary: PathBuf,
}

pub fn open(root: &Path, relays: &[String]) -> Result<Session, String> {
    fs::create_dir_all(root).map_err(|error| format!("marmot_root: {error}"))?;
    let mut perms = fs::metadata(root)
        .map_err(|error| format!("marmot_root: {error}"))?
        .permissions();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        perms.set_mode(0o700);
        fs::set_permissions(root, perms).map_err(|error| format!("marmot_root: {error}"))?;
    }
    let app =
        MarmotApp::with_relays_and_config(root, relays.to_vec(), MarmotAppConfig::white_noise());
    let boundary = root.join("outbox-boundary");
    fs::create_dir_all(&boundary).map_err(|error| format!("marmot_boundary: {error}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&boundary, fs::Permissions::from_mode(0o700))
            .map_err(|error| format!("marmot_boundary: {error}"))?;
    }
    Ok(Session {
        runtime: app.runtime(),
        boundary,
    })
}

impl Session {
    pub async fn import_sender(&self, nsec: String, relays: &[String]) -> Result<String, String> {
        let secret = Zeroizing::new(nsec);
        let endpoints: Vec<TransportEndpoint> = relays
            .iter()
            .map(|relay| TransportEndpoint(relay.clone()))
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

    pub async fn create_group(
        &self,
        account: &str,
        name: &str,
        members: &[String],
    ) -> Result<String, String> {
        let created = self
            .runtime
            .create_group(account, name, members, Some("Watchdog alerts".to_string()))
            .await
            .map_err(safe_error)?;
        let group = created
            .operation
            .ok_or_else(|| "no_eligible_member".to_string())?;
        Ok(group.to_string())
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

    /// Send one alert, or return the earlier result for the same alert id.
    ///
    /// A crash after the MDK call starts is recorded as completion-unknown.
    /// The helper does not encrypt that alert again.
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
        if let Some(stored) = self.read_result(alert_id)? {
            return Ok(stored);
        }
        if self.started(alert_id)? {
            return Ok(json!({
                "disposition": "completion_unknown",
                "published": 0,
                "message_ids": [],
                "push": "not_attempted"
            }));
        }
        let members = self.member_ids(account, group_hex).await?;
        if members.is_empty() {
            return Err("membership_unknown".to_string());
        }
        let allowed: HashSet<String> = allow
            .iter()
            .map(|item| item.to_ascii_lowercase())
            .chain(std::iter::once(account.to_ascii_lowercase()))
            .collect();
        if members.iter().any(|member| !allowed.contains(member)) {
            return Err("membership_rejected".to_string());
        }
        self.mark_started(alert_id)?;
        let group = group_id(group_hex)?;
        let summary = self
            .runtime
            .send_message(account, &group, text.as_bytes().to_vec())
            .await
            .map_err(safe_error)?;
        let disposition = match summary.accept_disposition {
            SendAcceptDisposition::Published => "published",
            SendAcceptDisposition::AcceptedPending => "accepted_pending",
            SendAcceptDisposition::CompletionUnknown => "completion_unknown",
        };
        let push = if disposition == "published" {
            "trigger_attempted"
        } else {
            "not_attempted"
        };
        let value = json!({
            "disposition": disposition,
            "published": summary.published,
            "message_ids": summary.message_ids,
            "push": push
        });
        self.write_result(alert_id, &value)?;
        Ok(value)
    }

    pub async fn sync(&self) -> Result<(), String> {
        self.runtime.catch_up_accounts().await.map_err(safe_error)
    }

    pub async fn shutdown(&self) -> Result<(), String> {
        self.runtime.shutdown_and_close().await.map_err(safe_error)
    }

    fn result_path(&self, alert_id: &str) -> PathBuf {
        self.boundary.join(format!("{alert_id}.json"))
    }

    fn started_path(&self, alert_id: &str) -> PathBuf {
        self.boundary.join(format!("{alert_id}.started"))
    }

    fn read_result(&self, alert_id: &str) -> Result<Option<Value>, String> {
        let path = self.result_path(alert_id);
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

    fn mark_started(&self, alert_id: &str) -> Result<(), String> {
        let path = self.started_path(alert_id);
        fs::write(&path, b"started").map_err(|error| format!("boundary_write: {error}"))?;
        restrict(&path)
    }

    fn write_result(&self, alert_id: &str, value: &Value) -> Result<(), String> {
        let path = self.result_path(alert_id);
        let bytes = serde_json::to_vec(value).map_err(|_| "boundary_encode".to_string())?;
        fs::write(&path, bytes).map_err(|error| format!("boundary_write: {error}"))?;
        restrict(&path)?;
        let _ = fs::remove_file(self.started_path(alert_id));
        Ok(())
    }
}

fn group_id(hex_id: &str) -> Result<GroupId, String> {
    let bytes = hex::decode(hex_id.trim()).map_err(|_| "group_id_invalid".to_string())?;
    if bytes.is_empty() {
        return Err("group_id_invalid".to_string());
    }
    Ok(GroupId::new(bytes))
}

fn alert_token(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 80
        && value
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '-')
}

fn safe_error(error: impl ToString) -> String {
    let text = error.to_string();
    if text.to_ascii_lowercase().contains("nsec") || text.contains("nsec1") {
        return "marmot_app_error".to_string();
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
    Ok(())
}
