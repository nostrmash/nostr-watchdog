-- Additive operational projections. This file does not store MLS secrets,
-- push-token plaintext, or private keys. Already-applied files are not edited.

ALTER TABLE alert_outbox ADD COLUMN message_state TEXT;
ALTER TABLE alert_outbox ADD COLUMN push_state TEXT;
ALTER TABLE alert_outbox ADD COLUMN message_attempts INTEGER NOT NULL DEFAULT 0;
ALTER TABLE alert_outbox ADD COLUMN push_attempts INTEGER NOT NULL DEFAULT 0;
ALTER TABLE alert_outbox ADD COLUMN message_updated_at INTEGER;
ALTER TABLE alert_outbox ADD COLUMN push_updated_at INTEGER;
ALTER TABLE alert_outbox ADD COLUMN terminal_reason TEXT;
ALTER TABLE alert_outbox ADD COLUMN operator_ack_at INTEGER;
ALTER TABLE alert_outbox ADD COLUMN logical_id TEXT;
ALTER TABLE alert_outbox ADD COLUMN submission_generation INTEGER NOT NULL DEFAULT 0;

ALTER TABLE scheduler_runs ADD COLUMN run_owner TEXT;

ALTER TABLE observed_versions ADD COLUMN generation INTEGER NOT NULL DEFAULT 0;
ALTER TABLE observed_versions ADD COLUMN commit_token TEXT;
ALTER TABLE vendor_checks ADD COLUMN generation INTEGER NOT NULL DEFAULT 0;
ALTER TABLE vendor_checks ADD COLUMN commit_token TEXT;

ALTER TABLE incidents ADD COLUMN decision_generation INTEGER NOT NULL DEFAULT 0;

ALTER TABLE marmot_projects ADD COLUMN onboard_idempotency_key TEXT;
ALTER TABLE marmot_projects ADD COLUMN onboard_requested_at INTEGER;
ALTER TABLE marmot_projects ADD COLUMN canonical_converged INTEGER;
ALTER TABLE marmot_projects ADD COLUMN key_package_ready INTEGER;
ALTER TABLE marmot_projects ADD COLUMN recipient_token_ready INTEGER;

CREATE INDEX alert_outbox_logical ON alert_outbox (logical_id, destination);
