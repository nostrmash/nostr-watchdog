//! Append-only operation index.
//!
//! Each alert keeps its own file for direct reads. `operations.log` is the
//! durable index: one JSON line per update, fsynced before the per-alert file
//! is replaced. A crashed rewrite leaves a partial final line, which is
//! ignored. Compaction keeps the latest line for every operation id, including
//! ids whose per-alert file has been removed.

use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

use serde_json::{json, Value};

const LOG_NAME: &str = "operations.log";
const COMPACT_AT: u64 = 256 * 1024;

pub struct Journal {
    root: PathBuf,
    records: HashMap<String, Value>,
}

impl Journal {
    pub fn open(root: &Path) -> Result<Self, String> {
        fs::create_dir_all(root).map_err(|error| format!("boundary_write: {error}"))?;
        restrict_dir(root)?;
        let mut records = HashMap::new();
        load_files(root, &mut records)?;
        load_consumed(root, &mut records)?;
        let log = root.join(LOG_NAME);
        if log.exists() {
            replay_log(&log, &mut records)?;
        } else if !records.is_empty() {
            rewrite_log(root, &records)?;
        }
        for (id, value) in &records {
            if is_released(value) {
                let _ = fs::remove_file(root.join(format!("{id}.json")));
            }
        }
        Ok(Self {
            root: root.to_path_buf(),
            records,
        })
    }

    pub fn visible(&self, id: &str) -> Option<Value> {
        self.records.get(id).filter(|value| !is_released(value)).cloned()
    }

    pub fn disposition(&self, id: &str) -> Option<String> {
        self.records
            .get(id)
            .and_then(|value| value.get("disposition"))
            .and_then(Value::as_str)
            .map(str::to_string)
    }

    pub fn record(&mut self, id: &str, value: &Value) -> Result<(), String> {
        self.records.insert(id.to_string(), value.clone());
        self.persist(id, value)
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
        self.records.insert(id.to_string(), value.clone());
        self.persist(id, &value)?;
        let _ = fs::remove_file(self.root.join(format!("{id}.json")));
        Ok(())
    }

    fn persist(&mut self, id: &str, value: &Value) -> Result<(), String> {
        append_log(
            &self.root,
            &json!({"operation_id": id, "record": value}),
        )?;
        if !is_released(value) {
            atomic_json(&self.root.join(format!("{id}.json")), value)?;
        }
        let log = self.root.join(LOG_NAME);
        let length = fs::metadata(&log).map(|metadata| metadata.len()).unwrap_or(0);
        if length > COMPACT_AT {
            rewrite_log(&self.root, &self.records)?;
        }
        Ok(())
    }
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
    let mut line = serde_json::to_vec(value).map_err(|_| "boundary_encode".to_string())?;
    line.push(b'\n');
    let path = root.join(LOG_NAME);
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

fn rewrite_log(root: &Path, records: &HashMap<String, Value>) -> Result<(), String> {
    let mut lines = Vec::new();
    let mut ids: Vec<&String> = records.keys().collect();
    ids.sort();
    for id in ids {
        let record = &records[id];
        let mut line = serde_json::to_vec(&json!({"operation_id": id, "record": record}))
            .map_err(|_| "boundary_encode".to_string())?;
        line.push(b'\n');
        lines.extend(line);
    }
    let path = root.join(LOG_NAME);
    let tmp = root.join("operations.log.tmp");
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
        file.write_all(&lines)
            .map_err(|error| format!("boundary_write: {error}"))?;
        file.sync_all()
            .map_err(|error| format!("boundary_write: {error}"))?;
    }
    fs::rename(&tmp, &path).map_err(|error| format!("boundary_write: {error}"))?;
    sync_dir(root)?;
    restrict(&path)
}

fn replay_log(path: &Path, records: &mut HashMap<String, Value>) -> Result<(), String> {
    let file = File::open(path).map_err(|error| format!("boundary_read: {error}"))?;
    let mut reader = BufReader::new(file);
    let mut line = String::new();
    loop {
        line.clear();
        let read = reader
            .read_line(&mut line)
            .map_err(|error| format!("boundary_read: {error}"))?;
        if read == 0 {
            break;
        }
        if !line.ends_with('\n') {
            break;
        }
        let value = serde_json::from_str::<Value>(line.trim_end())
            .map_err(|_| "boundary_corrupt".to_string())?;
        let id = value
            .get("operation_id")
            .and_then(Value::as_str)
            .ok_or_else(|| "boundary_corrupt".to_string())?;
        let record = value
            .get("record")
            .ok_or_else(|| "boundary_corrupt".to_string())?;
        records.insert(id.to_string(), record.clone());
    }
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
        let value = serde_json::from_slice::<Value>(&bytes)
            .map_err(|_| "boundary_corrupt".to_string())?;
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
    let value = serde_json::from_slice::<Value>(&bytes)
        .map_err(|_| "boundary_corrupt".to_string())?;
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
        let first = json!({"operation_id": "alt_one", "disposition": "published", "message_ids": ["m1"]});
        let mut journal = Journal::open(&root).unwrap();
        journal.record("alt_one", &first).unwrap();
        let mut raw = fs::read(root.join(LOG_NAME)).unwrap();
        raw.extend_from_slice(br#"{"operation_id":"alt_cut","record":{"disposition":"pub"#);
        fs::write(root.join(LOG_NAME), raw).unwrap();
        let reopened = Journal::open(&root).unwrap();
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
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn releasing_an_unadmitted_attempt_keeps_the_operation_id() {
        let root = std::env::temp_dir().join(format!("watchdog-journal-release-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let mut journal = Journal::open(&root).unwrap();
        journal
            .record("alt_two", &json!({"operation_id": "alt_two", "disposition": "submitting"}))
            .unwrap();
        journal.release("alt_two").unwrap();
        assert!(journal.visible("alt_two").is_none());
        let reopened = Journal::open(&root).unwrap();
        assert!(reopened.visible("alt_two").is_none());
        assert_eq!(reopened.disposition("alt_two").as_deref(), Some("released"));
        let _ = fs::remove_dir_all(&root);
    }
}
