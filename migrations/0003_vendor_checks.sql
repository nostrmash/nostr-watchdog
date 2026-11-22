ALTER TABLE scheduler_runs ADD COLUMN last_success_at INTEGER;

CREATE TABLE vendor_checks (
  monitor_id TEXT PRIMARY KEY,
  vendor TEXT NOT NULL,
  attempted_at INTEGER,
  succeeded_at INTEGER,
  releases_checked_at INTEGER,
  advisories_checked_at INTEGER,
  releases_stale INTEGER NOT NULL DEFAULT 0,
  advisories_stale INTEGER NOT NULL DEFAULT 0,
  error_code TEXT,
  consecutive_failures INTEGER NOT NULL DEFAULT 0,
  updated_at INTEGER NOT NULL
);
