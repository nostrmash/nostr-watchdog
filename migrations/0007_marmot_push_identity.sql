-- Push-token identity follows the Marmot record tuple. The fingerprint is a
-- replaceable attribute, so it is not part of the primary key. Migration 0006
-- is left unchanged because it may already have been applied. Official MDK
-- storage remains the cryptographic authority; this table is the application
-- projection used to select tokens without logging their contents.

CREATE TABLE marmot_push_records (
  project_id TEXT NOT NULL,
  group_id_hex TEXT NOT NULL,
  member_id_hex TEXT NOT NULL,
  leaf_index INTEGER NOT NULL,
  platform TEXT NOT NULL,
  server_pubkey_hex TEXT NOT NULL,
  fingerprint TEXT,
  owner_ts INTEGER,
  record_digest TEXT,
  tombstone INTEGER NOT NULL DEFAULT 0,
  updated_at INTEGER NOT NULL,
  PRIMARY KEY (
    project_id,
    group_id_hex,
    member_id_hex,
    leaf_index,
    platform,
    server_pubkey_hex
  )
);

CREATE INDEX idx_marmot_push_records_group
  ON marmot_push_records (project_id, group_id_hex, tombstone, owner_ts);
