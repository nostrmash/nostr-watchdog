-- Additive lifecycle projection. Already-applied files are not edited.
-- Null message or push state stays unknown. This migration does not invent
-- relay acceptance or device delivery for historical rows.

ALTER TABLE alert_outbox ADD COLUMN message_reconcile_attempts INTEGER NOT NULL DEFAULT 0;
ALTER TABLE alert_outbox ADD COLUMN unknown_attempts INTEGER NOT NULL DEFAULT 0;
ALTER TABLE alert_outbox ADD COLUMN token_wait_attempts INTEGER NOT NULL DEFAULT 0;
ALTER TABLE alert_outbox ADD COLUMN push_publication_attempts INTEGER NOT NULL DEFAULT 0;
ALTER TABLE alert_outbox ADD COLUMN unobservable_attempts INTEGER NOT NULL DEFAULT 0;
ALTER TABLE alert_outbox ADD COLUMN started_at_ms INTEGER;
ALTER TABLE alert_outbox ADD COLUMN preserve_message INTEGER NOT NULL DEFAULT 0;
ALTER TABLE alert_outbox ADD COLUMN settled_at INTEGER;
ALTER TABLE alert_outbox ADD COLUMN operation_id TEXT;
ALTER TABLE alert_outbox ADD COLUMN claim_owner TEXT;

CREATE INDEX alert_outbox_operation ON alert_outbox (operation_id);
CREATE INDEX alert_outbox_owner ON alert_outbox (claim_owner);
