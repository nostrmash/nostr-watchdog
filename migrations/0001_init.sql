CREATE TABLE monitor_state (
  monitor_id TEXT PRIMARY KEY,
  project_id TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'unknown',
  consecutive_successes INTEGER NOT NULL DEFAULT 0,
  consecutive_failures INTEGER NOT NULL DEFAULT 0,
  failure_kind TEXT,
  last_check_at INTEGER,
  last_success_at INTEGER,
  last_failure_at INTEGER,
  last_error_class TEXT,
  last_latency_ms INTEGER,
  last_summary TEXT,
  observed_version TEXT,
  generation INTEGER NOT NULL DEFAULT 0,
  updated_at INTEGER NOT NULL
);

CREATE TABLE incidents (
  id TEXT PRIMARY KEY,
  monitor_id TEXT NOT NULL,
  project_id TEXT NOT NULL,
  status TEXT NOT NULL,
  kind TEXT NOT NULL,
  severity TEXT NOT NULL,
  opened_at INTEGER NOT NULL,
  closed_at INTEGER,
  open_reason TEXT NOT NULL,
  close_reason TEXT,
  reminder_count INTEGER NOT NULL DEFAULT 0,
  last_reminder_at INTEGER,
  acked_at INTEGER,
  silenced_until INTEGER,
  updated_at INTEGER NOT NULL
);

CREATE UNIQUE INDEX incidents_one_open ON incidents (monitor_id) WHERE status = 'open';
CREATE INDEX incidents_project_status ON incidents (project_id, status);

CREATE TABLE alert_outbox (
  id TEXT PRIMARY KEY,
  alert_class TEXT NOT NULL,
  incident_id TEXT,
  monitor_id TEXT NOT NULL,
  project_id TEXT NOT NULL,
  dedupe_key TEXT NOT NULL UNIQUE,
  destination TEXT NOT NULL,
  severity TEXT NOT NULL,
  state TEXT NOT NULL,
  payload_text TEXT NOT NULL,
  envelope_json TEXT,
  attempt_count INTEGER NOT NULL DEFAULT 0,
  next_attempt_at INTEGER NOT NULL,
  claim_until INTEGER,
  last_error TEXT,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);

CREATE INDEX alert_outbox_due ON alert_outbox (state, next_attempt_at);

CREATE TABLE observed_versions (
  monitor_id TEXT PRIMARY KEY,
  installed_version TEXT,
  latest_version TEXT,
  latest_url TEXT,
  security_status TEXT NOT NULL,
  advisory_fingerprint TEXT,
  notice_fingerprint TEXT,
  updated_at INTEGER NOT NULL
);

CREATE TABLE upstream_cache (
  source_key TEXT PRIMARY KEY,
  etag TEXT,
  payload_json TEXT,
  fetched_at INTEGER NOT NULL,
  rate_limited_until INTEGER
);

CREATE TABLE heartbeats (
  monitor_id TEXT PRIMARY KEY,
  project_id TEXT NOT NULL,
  received_at INTEGER NOT NULL,
  reported_at INTEGER NOT NULL,
  progress_token TEXT,
  progress_changed_at INTEGER NOT NULL,
  idle INTEGER NOT NULL,
  loop_at INTEGER,
  summary TEXT
);

CREATE TABLE heartbeat_nonces (
  monitor_id TEXT NOT NULL,
  nonce TEXT NOT NULL,
  expires_at INTEGER NOT NULL,
  PRIMARY KEY (monitor_id, nonce)
);

CREATE INDEX heartbeat_nonces_expiry ON heartbeat_nonces (expires_at);

CREATE TABLE relay_list_cache (
  pubkey TEXT PRIMARY KEY,
  relays_json TEXT NOT NULL,
  fetched_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  negative INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE scheduler_leases (
  job_name TEXT PRIMARY KEY,
  owner TEXT NOT NULL,
  lease_until INTEGER NOT NULL
);

CREATE TABLE scheduler_runs (
  job_name TEXT PRIMARY KEY,
  last_started_at INTEGER,
  last_finished_at INTEGER,
  last_error TEXT
);
