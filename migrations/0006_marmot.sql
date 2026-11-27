ALTER TABLE alert_outbox ADD COLUMN message_phase TEXT;
ALTER TABLE alert_outbox ADD COLUMN push_phase TEXT;
ALTER TABLE alert_outbox ADD COLUMN push_envelope_json TEXT;
ALTER TABLE alert_outbox ADD COLUMN message_event_id TEXT;

CREATE TABLE marmot_projects (
  project_id TEXT PRIMARY KEY,
  pubkey TEXT,
  conversation_id TEXT,
  group_id_hex TEXT,
  peer_pubkey TEXT,
  last_sync_at INTEGER,
  last_sync_error TEXT,
  key_package_published_at INTEGER,
  engine_status TEXT NOT NULL,
  updated_at INTEGER NOT NULL
);

CREATE TABLE push_token_records (
  project_id TEXT NOT NULL,
  fingerprint TEXT NOT NULL,
  member_id_hex TEXT NOT NULL,
  leaf_index INTEGER NOT NULL,
  platform TEXT NOT NULL,
  server_pubkey_hex TEXT NOT NULL,
  relay_hint TEXT,
  encrypted_token_b64 TEXT NOT NULL,
  owner_ts INTEGER NOT NULL,
  owner_sig TEXT NOT NULL,
  revoked INTEGER NOT NULL DEFAULT 0,
  updated_at INTEGER NOT NULL,
  PRIMARY KEY (project_id, fingerprint)
);
