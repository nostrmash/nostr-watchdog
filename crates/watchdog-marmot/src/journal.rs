//! Operation index.
//!
//! Each operation id has one durable file. `operations.log` is a write-ahead
//! log of updates since the last checkpoint. A torn final line is truncated
//! back to the last complete record before another append is allowed.
//!
//! A commit appends and syncs the log, atomically replaces the per-id file,
//! and only then updates the in-memory map. Checkpointing runs against that
//! updated map and clears the log only after those files match it. A checkpoint
//! error leaves the durable record in place. It is not evidence the operation
//! was never written.

use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use serde_json::{json, Value};

const LOG_NAME: &str = "operations.log";
/// Checkpoint after the log holds a full history rewrite's worth of bytes,
/// or after superseded lines dominate. The replacement log is empty.
const CHECKPOINT_AT: u64 = 64 * 1024;

pub struct Journal {
    root: PathBuf,
    records: HashMap<String, Value>,
    wal_lines: u64,
    /// A failed reload after a partial write. No later call may treat memory as durable.
    poisoned: bool,
}

impl Journal {
    pub fn open(root: &Path) -> Result<Self, String> {
        fs::create_dir_all(root).map_err(|error| format!("boundary_write: {error}"))?;
        restrict_dir(root)?;
        ensure_not_symlink(root)?;
        ensure_owned(root)?;
        let mut records = HashMap::new();
        load_files(root, &mut records)?;
        load_consumed(root, &mut records)?;
        let log = root.join(LOG_NAME);
        let wal_lines = if log.exists() {
            repair_log(&log, &mut records)?
        } else {
            0
        };
        materialize_files(root, &records)?;
        Ok(Self {
            root: root.to_path_buf(),
            records,
            wal_lines,
            poisoned: false,
        })
    }

    pub fn poisoned(&self) -> bool {
        self.poisoned
    }

    pub fn get(&self, id: &str) -> Option<Value> {
        self.records.get(id).cloned()
    }

    #[cfg(test)]
    pub fn visible(&self, id: &str) -> Option<Value> {
        self.records
            .get(id)
            .filter(|value| !is_released(value))
            .cloned()
    }

    pub fn disposition(&self, id: &str) -> Option<String> {
        self.records
            .get(id)
            .and_then(|value| value.get("disposition"))
            .and_then(Value::as_str)
            .map(str::to_string)
    }

    pub fn record(&mut self, id: &str, value: &Value) -> Result<(), String> {
        self.commit(id, value)
    }

    /// Keeps the operation id and forgets only an attempt MDK did not admit.
    pub fn release(&mut self, id: &str) -> Result<(), String> {
        let mut value = self
            .records
            .get(id)
            .cloned()
            .unwrap_or_else(|| json!({"operation_id": id}));
        if let Some(object) = value.as_object_mut() {
            object.insert("operation_id".to_string(), json!(id));
            object.insert("disposition".to_string(), json!("released"));
        }
        self.commit(id, &value)
    }

    /// Durable order: WAL, per-id file, memory, then checkpoint.
    /// A failed write reloads disk. Reload failure refuses every later mutation.
    /// A checkpoint failure after a durable file is not treated as a missing operation.
    fn commit(&mut self, id: &str, value: &Value) -> Result<(), String> {
        if self.poisoned {
            return Err("boundary_durable_failure".to_string());
        }
        if let Err(error) = append_log(&self.root, &json!({"operation_id": id, "record": value})) {
            self.reload_after_failure();
            return Err(error);
        }
        self.wal_lines = self.wal_lines.saturating_add(1);
        if let Err(error) = durability_point("after_wal") {
            self.reload_after_failure();
            return Err(error);
        }
        if let Err(error) = atomic_json(&self.root.join(format!("{id}.json")), value) {
            self.reload_after_failure();
            return Err(error);
        }
        if let Err(error) = durability_point("after_record") {
            self.reload_after_failure();
            return Err(error);
        }
        self.records.insert(id.to_string(), value.clone());
        let log = self.root.join(LOG_NAME);
        let length = fs::metadata(&log)
            .map(|metadata| metadata.len())
            .unwrap_or(0);
        if self.should_checkpoint(length) {
            if let Err(error) = self.checkpoint() {
                let expected = value.clone();
                self.reload_after_failure();
                if !self.poisoned && self.records.get(id) != Some(&expected) {
                    self.poisoned = true;
                }
                return Err(error);
            }
        }
        Ok(())
    }

    fn reload_after_failure(&mut self) {
        match Self::open(&self.root) {
            Ok(fresh) => {
                self.records = fresh.records;
                self.wal_lines = fresh.wal_lines;
                self.poisoned = false;
            }
            Err(_) => self.poisoned = true,
        }
    }

    fn should_checkpoint(&self, wal_len: u64) -> bool {
        wal_len > CHECKPOINT_AT
            || (self.wal_lines >= 8
                && self.wal_lines > (self.records.len() as u64).saturating_mul(2))
    }

    /// Drops superseded log lines after the in-memory map has been updated.
    /// The WAL is replaced only once those per-id files match that map.
    fn checkpoint(&mut self) -> Result<(), String> {
        materialize_files(&self.root, &self.records)?;
        replace_wal_empty(&self.root)?;
        self.wal_lines = 0;
        Ok(())
    }
}

fn durability_point(name: &str) -> Result<(), String> {
    if std::env::var("WATCHDOG_MARMOT_CRASH_AT").ok().as_deref() != Some(name) {
        return Ok(());
    }
    if std::env::var("WATCHDOG_MARMOT_CRASH_EXIT").ok().as_deref() == Some("1") {
        crate::exit_at_crash_point(name);
    }
    if std::env::var("WATCHDOG_JOURNAL_FAIL").ok().as_deref() == Some("1") {
        return Err(format!("boundary_injected:{name}"));
    }
    Ok(())
}

pub fn atomic_json(path: &Path, value: &Value) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|error| format!("boundary_write: {error}"))?;
        restrict_dir(parent)?;
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
        sync_dir(parent)?;
    }
    restrict(path)
}

fn append_log(root: &Path, value: &Value) -> Result<(), String> {
    let path = root.join(LOG_NAME);
    ensure_not_symlink(&path)?;
    let mut line = serde_json::to_vec(value).map_err(|_| "boundary_encode".to_string())?;
    line.push(b'\n');
    let mut options = OpenOptions::new();
    options.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(&path)
        .map_err(|error| format!("boundary_write: {error}"))?;
    file.write_all(&line)
        .map_err(|error| format!("boundary_write: {error}"))?;
    file.sync_all()
        .map_err(|error| format!("boundary_write: {error}"))?;
    sync_dir(root)?;
    restrict(&path)
}

fn replace_wal_empty(root: &Path) -> Result<(), String> {
    let tmp = root.join("operations.log.chk");
    let _ = fs::remove_file(&tmp);
    {
        let mut options = OpenOptions::new();
        options.create_new(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let file = options
            .open(&tmp)
            .map_err(|error| format!("boundary_write: {error}"))?;
        file.sync_all()
            .map_err(|error| format!("boundary_write: {error}"))?;
    }
    durability_point("checkpoint")?;
    let path = root.join(LOG_NAME);
    fs::rename(&tmp, &path).map_err(|error| format!("boundary_write: {error}"))?;
    sync_dir(root)?;
    restrict(&path)
}

/// Replays complete lines and truncates a torn tail, including incomplete UTF-8.
fn repair_log(path: &Path, records: &mut HashMap<String, Value>) -> Result<u64, String> {
    ensure_not_symlink(path)?;
    let bytes = fs::read(path).map_err(|error| format!("boundary_read: {error}"))?;
    let mut cursor = 0;
    let mut end = 0;
    let mut lines = 0_u64;
    while cursor < bytes.len() {
        let Some(newline) = bytes[cursor..].iter().position(|byte| *byte == b'\n') else {
            break;
        };
        let line = &bytes[cursor..cursor + newline];
        let text = std::str::from_utf8(line).map_err(|_| "boundary_corrupt".to_string())?;
        let value = serde_json::from_str::<Value>(text.trim_end())
            .map_err(|_| "boundary_corrupt".to_string())?;
        let id = value
            .get("operation_id")
            .and_then(Value::as_str)
            .ok_or_else(|| "boundary_corrupt".to_string())?;
        let record = value
            .get("record")
            .ok_or_else(|| "boundary_corrupt".to_string())?;
        records.insert(id.to_string(), record.clone());
        lines = lines.saturating_add(1);
        cursor += newline + 1;
        end = cursor;
    }
    if end < bytes.len() {
        let file = OpenOptions::new()
            .write(true)
            .open(path)
            .map_err(|error| format!("boundary_write: {error}"))?;
        file.set_len(end as u64)
            .map_err(|error| format!("boundary_write: {error}"))?;
        file.sync_all()
            .map_err(|error| format!("boundary_write: {error}"))?;
        if let Some(parent) = path.parent() {
            sync_dir(parent)?;
        }
    }
    Ok(lines)
}

fn materialize_files(root: &Path, records: &HashMap<String, Value>) -> Result<(), String> {
    for (id, value) in records {
        let path = root.join(format!("{id}.json"));
        let current = fs::read(&path)
            .ok()
            .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok());
        if current.as_ref() != Some(value) {
            atomic_json(&path, value)?;
        }
    }
    Ok(())
}

fn ensure_not_symlink(path: &Path) -> Result<(), String> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => Err("boundary_symlink".to_string()),
        _ => Ok(()),
    }
}

fn ensure_owned(path: &Path) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        extern "C" {
            fn getuid() -> u32;
        }
        let uid = fs::symlink_metadata(path)
            .map_err(|error| format!("boundary_read: {error}"))?
            .uid();
        if uid != unsafe { getuid() } {
            return Err("boundary_owner".to_string());
        }
    }
    let _ = path;
    Ok(())
}

fn load_files(root: &Path, records: &mut HashMap<String, Value>) -> Result<(), String> {
    let entries = fs::read_dir(root).map_err(|error| format!("boundary_read: {error}"))?;
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        if !name.ends_with(".json") || reserved(name) {
            continue;
        }
        let bytes = fs::read(entry.path()).map_err(|error| format!("boundary_read: {error}"))?;
        let value =
            serde_json::from_slice::<Value>(&bytes).map_err(|_| "boundary_corrupt".to_string())?;
        let id = name.trim_end_matches(".json");
        records.insert(id.to_string(), value);
    }
    Ok(())
}

fn load_consumed(root: &Path, records: &mut HashMap<String, Value>) -> Result<(), String> {
    let path = root.join("consumed.json");
    if !path.exists() {
        return Ok(());
    }
    let bytes = fs::read(&path).map_err(|error| format!("boundary_read: {error}"))?;
    let value =
        serde_json::from_slice::<Value>(&bytes).map_err(|_| "boundary_corrupt".to_string())?;
    let Some(object) = value.as_object() else {
        return Ok(());
    };
    for (id, record) in object {
        records.entry(id.clone()).or_insert_with(|| record.clone());
    }
    Ok(())
}

fn reserved(name: &str) -> bool {
    matches!(
        name,
        "consumed.json" | "conversations.json" | "storage-epoch.json"
    )
}

#[cfg(test)]
fn is_released(value: &Value) -> bool {
    value.get("disposition").and_then(Value::as_str) == Some("released")
}

fn sync_dir(path: &Path) -> Result<(), String> {
    let dir = File::open(path).map_err(|error| format!("boundary_sync: {error}"))?;
    dir.sync_all()
        .map_err(|error| format!("boundary_sync: {error}"))
}

fn restrict(path: &Path) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .map_err(|error| format!("boundary_write: {error}"))?;
    }
    let _ = path;
    Ok(())
}

fn restrict_dir(path: &Path) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))
            .map_err(|error| format!("boundary_write: {error}"))?;
    }
    let _ = path;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_partial_line_does_not_drop_earlier_operations() {
        let root = std::env::temp_dir().join(format!("watchdog-journal-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        let first =
            json!({"operation_id": "alt_one", "disposition": "published", "message_ids": ["m1"]});
        let mut journal = Journal::open(&root).unwrap();
        journal.record("alt_one", &first).unwrap();
        let mut raw = fs::read(root.join(LOG_NAME)).unwrap();
        raw.extend_from_slice(br#"{"operation_id":"alt_cut","record":{"disposition":"pub"#);
        fs::write(root.join(LOG_NAME), raw).unwrap();
        let mut reopened = Journal::open(&root).unwrap();
        assert_eq!(
            reopened
                .visible("alt_one")
                .unwrap()
                .get("message_ids")
                .and_then(|value| value.as_array())
                .map(|items| items.len()),
            Some(1)
        );
        assert!(reopened.visible("alt_cut").is_none());
        let repaired = fs::read(root.join(LOG_NAME)).unwrap();
        assert!(
            repaired.ends_with(b"\n") || repaired.is_empty(),
            "a torn tail was left for the next append"
        );
        reopened
            .record(
                "alt_three",
                &json!({"operation_id": "alt_three", "disposition": "published", "message_ids": ["m3"]}),
            )
            .unwrap();
        drop(reopened);
        let again = Journal::open(&root).unwrap();
        assert!(again.visible("alt_one").is_some());
        assert!(again.visible("alt_three").is_some());
        assert!(again.visible("alt_cut").is_none());
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn a_killed_appender_does_not_glue_the_next_record_onto_a_torn_tail() {
        if std::env::var_os("WATCHDOG_JOURNAL_CHILD").is_some() {
            super::torn_child();
            return;
        }
        let root = std::env::temp_dir().join(format!(
            "watchdog-journal-kill-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|duration| duration.as_nanos())
                .unwrap_or(0)
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .arg("a_killed_appender_does_not_glue_the_next_record_onto_a_torn_tail")
            .env("WATCHDOG_JOURNAL_CHILD", "1")
            .env("WATCHDOG_JOURNAL_ROOT", &root)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap();
        let ready = root.join("torn");
        for _ in 0..100 {
            if ready.exists() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        assert!(ready.exists(), "the child did not tear the log");
        let _ = child.kill();
        let status = child.wait().unwrap();
        assert!(!status.success());
        let mut journal = Journal::open(&root).unwrap();
        assert!(journal.visible("alt_a").is_some());
        assert!(
            journal.get("alt_b").is_none(),
            "a torn append became an operation"
        );
        journal
            .record(
                "alt_c",
                &json!({"operation_id": "alt_c", "disposition": "published", "payload_sha256": "c"}),
            )
            .unwrap();
        drop(journal);
        let reopened = Journal::open(&root).unwrap();
        assert_eq!(
            reopened
                .visible("alt_a")
                .unwrap()
                .get("payload_sha256")
                .and_then(Value::as_str),
            Some("a")
        );
        assert!(reopened.visible("alt_c").is_some());
        assert!(reopened.get("alt_b").is_none());
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn checkpoint_drops_the_log_without_dropping_operation_ids() {
        let root = std::env::temp_dir().join(format!(
            "watchdog-journal-checkpoint-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        let mut journal = Journal::open(&root).unwrap();
        let bulky = "x".repeat((CHECKPOINT_AT as usize) + 128);
        journal
            .record(
                "alt_bulk",
                &json!({"operation_id": "alt_bulk", "disposition": "published", "note": bulky}),
            )
            .unwrap();
        journal
            .record(
                "alt_small",
                &json!({"operation_id": "alt_small", "disposition": "published", "payload_sha256": "s"}),
            )
            .unwrap();
        let log = fs::read(root.join(LOG_NAME)).unwrap();
        assert!(
            log.len() < 4_096,
            "checkpoint rewrote the historical record into the log ({} bytes)",
            log.len()
        );
        assert!(!log.windows(8).any(|window| window == b"alt_bulk"));
        drop(journal);
        let reopened = Journal::open(&root).unwrap();
        assert!(reopened.visible("alt_bulk").is_some());
        assert!(reopened.visible("alt_small").is_some());
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn a_checkpoint_killed_before_rename_keeps_the_previous_log() {
        if std::env::var_os("WATCHDOG_JOURNAL_CHECKPOINT_CHILD").is_some() {
            super::checkpoint_child();
            return;
        }
        let root =
            std::env::temp_dir().join(format!("watchdog-journal-chk-kill-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .arg("a_checkpoint_killed_before_rename_keeps_the_previous_log")
            .env("WATCHDOG_JOURNAL_CHECKPOINT_CHILD", "1")
            .env("WATCHDOG_JOURNAL_ROOT", &root)
            .env("WATCHDOG_MARMOT_CRASH_AT", "checkpoint")
            .env("WATCHDOG_MARMOT_CRASH_EXIT", "1")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap();
        let status = child.wait().unwrap();
        assert_eq!(status.code(), Some(75));
        let journal = Journal::open(&root).unwrap();
        assert!(journal.visible("alt_keep").is_some());
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn releasing_an_unadmitted_attempt_keeps_the_operation_id() {
        let root =
            std::env::temp_dir().join(format!("watchdog-journal-release-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let mut journal = Journal::open(&root).unwrap();
        journal
            .record(
                "alt_two",
                &json!({"operation_id": "alt_two", "disposition": "submitting", "payload_sha256": "same"}),
            )
            .unwrap();
        journal.release("alt_two").unwrap();
        assert!(journal.visible("alt_two").is_none());
        let reopened = Journal::open(&root).unwrap();
        assert!(reopened.visible("alt_two").is_none());
        assert_eq!(reopened.disposition("alt_two").as_deref(), Some("released"));
        assert_eq!(
            reopened
                .get("alt_two")
                .unwrap()
                .get("payload_sha256")
                .and_then(Value::as_str),
            Some("same")
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn a_failed_append_does_not_keep_an_unpersisted_record() {
        let root =
            std::env::temp_dir().join(format!("watchdog-journal-fail-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let mut journal = Journal::open(&root).unwrap();
        journal
            .record(
                "alt_ok",
                &json!({"operation_id": "alt_ok", "disposition": "published"}),
            )
            .unwrap();
        let log = root.join(LOG_NAME);
        let mut permissions = fs::metadata(&log).unwrap().permissions();
        permissions.set_readonly(true);
        fs::set_permissions(&log, permissions).unwrap();
        let failed = journal.record(
            "alt_new",
            &json!({"operation_id": "alt_new", "disposition": "submitting"}),
        );
        assert!(failed.is_err(), "a read-only log accepted a record");
        assert!(journal.get("alt_new").is_none());
        assert!(journal.get("alt_ok").is_some());
        let mut permissions = fs::metadata(&log).unwrap().permissions();
        permissions.set_readonly(false);
        fs::set_permissions(&log, permissions).unwrap();
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn ordinary_writes_do_not_rewrite_thousands_of_historical_records() {
        let root =
            std::env::temp_dir().join(format!("watchdog-journal-volume-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let mut journal = Journal::open(&root).unwrap();
        let started = std::time::Instant::now();
        for index in 0..1_500 {
            journal
                .record(
                    &format!("op_{index}"),
                    &json!({
                        "operation_id": format!("op_{index}"),
                        "disposition": "published",
                        "payload_sha256": format!("{index:08x}")
                    }),
                )
                .unwrap();
        }
        let write_ms = started.elapsed().as_millis();
        let log_len = fs::metadata(root.join(LOG_NAME)).unwrap().len();
        assert!(
            log_len < CHECKPOINT_AT + 8_192,
            "the log rewrote history ({log_len} bytes after {write_ms} ms)"
        );
        let reopen_started = std::time::Instant::now();
        let reopened = Journal::open(&root).unwrap();
        let reopen_ms = reopen_started.elapsed().as_millis();
        assert!(reopened.get("op_0").is_some());
        assert!(reopened.get("op_1499").is_some());
        assert_eq!(reopened.records.len(), 1_500);
        eprintln!(
            "journal volume: 1500 writes in {write_ms} ms, log {log_len} bytes, reopen {reopen_ms} ms"
        );
        assert!(
            reopen_ms < 10_000,
            "startup replay of 1500 records took {reopen_ms} ms"
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn pending_becomes_published_when_checkpoint_runs() {
        let root = fresh_root("publish-checkpoint");
        let mut journal = Journal::open(&root).unwrap();
        write_prior(&mut journal, "accepted_pending");
        journal
            .record("op_update", &crossing("published", json!(["m-admitted"])))
            .unwrap();
        let log = fs::read(root.join(LOG_NAME)).unwrap();
        assert!(
            log.len() < 4_096,
            "checkpoint left the superseded pending line in the log"
        );
        drop(journal);
        let reopened = Journal::open(&root).unwrap();
        assert_published(&reopened);
        assert!(!reopened.poisoned());
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn released_becomes_submitting_across_the_checkpoint() {
        let root = fresh_root("release-checkpoint");
        let mut journal = Journal::open(&root).unwrap();
        write_prior(&mut journal, "submitting");
        journal.release("op_update").unwrap();
        journal
            .record("op_update", &crossing("submitting", json!([])))
            .unwrap();
        drop(journal);
        let reopened = Journal::open(&root).unwrap();
        let saved = reopened.get("op_update").unwrap();
        assert_eq!(saved["disposition"], json!("submitting"));
        assert_eq!(saved["recipient"], json!("cc"));
        assert_eq!(saved["payload_sha256"], json!("same"));
        assert_ne!(saved["disposition"], json!("released"));
        let _ = fs::remove_dir_all(&root);
    }

    fn finish_if_boundary_child() -> bool {
        if std::env::var_os("WATCHDOG_JOURNAL_BOUNDARY_CHILD").is_some() {
            super::boundary_child();
            true
        } else {
            false
        }
    }

    #[test]
    fn failure_after_wal_append_keeps_the_updated_operation() {
        if finish_if_boundary_child() {
            return;
        }
        let root = spawn_boundary(
            "failure_after_wal_append_keeps_the_updated_operation",
            "after_wal",
            false,
        );
        let journal = Journal::open(&root).unwrap();
        assert_published(&journal);
        assert!(!journal.poisoned());
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn failure_after_record_replacement_keeps_the_updated_operation() {
        if finish_if_boundary_child() {
            return;
        }
        let root = spawn_boundary(
            "failure_after_record_replacement_keeps_the_updated_operation",
            "after_record",
            false,
        );
        let journal = Journal::open(&root).unwrap();
        assert_published(&journal);
        let log = fs::read(root.join(LOG_NAME)).unwrap();
        assert!(
            log.windows(10).any(|window| window == b"m-admitted"),
            "the WAL was cleared before the failure point"
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn failure_before_wal_truncation_keeps_the_updated_operation() {
        if finish_if_boundary_child() {
            return;
        }
        let root = spawn_boundary(
            "failure_before_wal_truncation_keeps_the_updated_operation",
            "checkpoint",
            false,
        );
        let journal = Journal::open(&root).unwrap();
        assert_published(&journal);
        let log = fs::read(root.join(LOG_NAME)).unwrap();
        assert!(
            log.windows(10).any(|window| window == b"m-admitted"),
            "the WAL was truncated even though the checkpoint did not finish"
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn process_stop_after_wal_append_keeps_the_updated_operation() {
        if finish_if_boundary_child() {
            return;
        }
        let root = spawn_boundary(
            "process_stop_after_wal_append_keeps_the_updated_operation",
            "after_wal",
            true,
        );
        let journal = Journal::open(&root).unwrap();
        assert_published(&journal);
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn process_stop_after_record_replacement_keeps_the_updated_operation() {
        if finish_if_boundary_child() {
            return;
        }
        let root = spawn_boundary(
            "process_stop_after_record_replacement_keeps_the_updated_operation",
            "after_record",
            true,
        );
        let journal = Journal::open(&root).unwrap();
        assert_published(&journal);
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn process_stop_during_checkpoint_keeps_the_updated_operation() {
        if finish_if_boundary_child() {
            return;
        }
        let root = spawn_boundary(
            "process_stop_during_checkpoint_keeps_the_updated_operation",
            "checkpoint",
            true,
        );
        let journal = Journal::open(&root).unwrap();
        assert_published(&journal);
        let _ = fs::remove_dir_all(&root);
    }
}

#[cfg(test)]
fn torn_child() {
    let root = PathBuf::from(std::env::var("WATCHDOG_JOURNAL_ROOT").unwrap());
    let mut journal = Journal::open(&root).unwrap();
    journal
        .record(
            "alt_a",
            &json!({"operation_id": "alt_a", "disposition": "published", "payload_sha256": "a"}),
        )
        .unwrap();
    drop(journal);
    let mut file = OpenOptions::new()
        .append(true)
        .open(root.join(LOG_NAME))
        .unwrap();
    file.write_all(
        br#"{"operation_id":"alt_b","record":{"disposition":"submitting","payload_sha256":"b""#,
    )
    .unwrap();
    file.write_all(&[0xff, 0xfe]).unwrap();
    file.sync_all().unwrap();
    fs::write(root.join("torn"), b"1").unwrap();
    std::thread::sleep(std::time::Duration::from_secs(30));
}

#[cfg(test)]
fn fresh_root(label: &str) -> PathBuf {
    let root = std::env::temp_dir().join(format!(
        "watchdog-journal-{label}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or(0)
    ));
    let _ = fs::remove_dir_all(&root);
    root
}

#[cfg(test)]
fn write_prior(journal: &mut Journal, disposition: &str) {
    journal
        .record(
            "op_update",
            &json!({
                "operation_id": "op_update",
                "disposition": disposition,
                "recipient": "cc",
                "payload_sha256": "same",
                "message_ids": []
            }),
        )
        .unwrap();
}

#[cfg(test)]
fn crossing(disposition: &str, message_ids: Value) -> Value {
    json!({
        "operation_id": "op_update",
        "disposition": disposition,
        "recipient": "cc",
        "payload_sha256": "same",
        "message_ids": message_ids,
        "note": "n".repeat((CHECKPOINT_AT as usize) + 128)
    })
}

#[cfg(test)]
fn assert_published(journal: &Journal) {
    let saved = journal.get("op_update").expect("updated operation missing");
    assert_eq!(saved["disposition"], json!("published"));
    assert_eq!(saved["message_ids"][0], json!("m-admitted"));
    assert_eq!(saved["payload_sha256"], json!("same"));
    assert_ne!(
        saved["disposition"],
        json!("accepted_pending"),
        "checkpoint restored the previous state"
    );
}

#[cfg(test)]
fn spawn_boundary(test_name: &str, point: &str, exit_process: bool) -> PathBuf {
    let root = fresh_root(point);
    let mut command = std::process::Command::new(std::env::current_exe().unwrap());
    command
        .arg(test_name)
        .env("WATCHDOG_JOURNAL_BOUNDARY_CHILD", "1")
        .env("WATCHDOG_JOURNAL_ROOT", &root)
        .env("WATCHDOG_MARMOT_CRASH_AT", point)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped());
    if exit_process {
        command.env("WATCHDOG_MARMOT_CRASH_EXIT", "1");
    } else {
        command.env("WATCHDOG_JOURNAL_FAIL", "1");
    }
    let child = command.spawn().unwrap();
    let output = child.wait_with_output().unwrap();
    if exit_process {
        assert_eq!(
            output.status.code(),
            Some(75),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    } else {
        assert!(
            output.status.success(),
            "injected failure child failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    root
}

#[cfg(test)]
fn boundary_child() {
    let root = PathBuf::from(std::env::var("WATCHDOG_JOURNAL_ROOT").unwrap());
    let point = std::env::var("WATCHDOG_MARMOT_CRASH_AT").unwrap();
    // The prior record has to land. The injected failure applies to the update.
    unsafe {
        std::env::remove_var("WATCHDOG_MARMOT_CRASH_AT");
    }
    let mut journal = Journal::open(&root).unwrap();
    write_prior(&mut journal, "accepted_pending");
    unsafe {
        std::env::set_var("WATCHDOG_MARMOT_CRASH_AT", &point);
    }
    let updated = crossing("published", json!(["m-admitted"]));
    let result = journal.record("op_update", &updated);
    if std::env::var("WATCHDOG_JOURNAL_FAIL").ok().as_deref() == Some("1") {
        let error = result.expect_err("the injected failure did not fail the commit");
        assert!(error.starts_with("boundary_injected:"));
        assert_published(&journal);
        assert!(!journal.poisoned());
        return;
    }
    result.expect("boundary child commit");
}

#[cfg(test)]
fn checkpoint_child() {
    let root = PathBuf::from(std::env::var("WATCHDOG_JOURNAL_ROOT").unwrap());
    let mut journal = Journal::open(&root).unwrap();
    journal
        .record(
            "alt_keep",
            &json!({"operation_id": "alt_keep", "disposition": "published", "payload_sha256": "k"}),
        )
        .unwrap();
    let bulky = "y".repeat((CHECKPOINT_AT as usize) + 64);
    let _ = journal.record(
        "alt_grow",
        &json!({"operation_id": "alt_grow", "disposition": "published", "note": bulky}),
    );
}
