-- Completion ownership, authoritative counters, and immutable operation age.
-- Existing rows keep unknown counters as NULL. This does not invent acceptance,
-- publication, or a historical attempt count.

ALTER TABLE alert_outbox ADD COLUMN completion_token TEXT;
ALTER TABLE alert_outbox ADD COLUMN operation_started_at INTEGER;
ALTER TABLE alert_outbox ADD COLUMN message_phase_started_at INTEGER;
ALTER TABLE alert_outbox ADD COLUMN push_phase_started_at INTEGER;
ALTER TABLE alert_outbox ADD COLUMN auth_message_submissions INTEGER;
ALTER TABLE alert_outbox ADD COLUMN auth_message_publications INTEGER;
ALTER TABLE alert_outbox ADD COLUMN auth_message_reconciles INTEGER;
ALTER TABLE alert_outbox ADD COLUMN auth_ambiguous_reconciles INTEGER;
ALTER TABLE alert_outbox ADD COLUMN auth_token_waits INTEGER;
ALTER TABLE alert_outbox ADD COLUMN auth_push_publications INTEGER;
ALTER TABLE alert_outbox ADD COLUMN auth_push_reconciles INTEGER;

CREATE INDEX alert_outbox_completion ON alert_outbox (completion_token);

CREATE TABLE marmot_onboard_history (
  project_id TEXT NOT NULL,
  operation_id TEXT NOT NULL,
  replace_requested INTEGER NOT NULL,
  requested_at INTEGER NOT NULL,
  engine_status TEXT NOT NULL,
  PRIMARY KEY (project_id, operation_id)
);
