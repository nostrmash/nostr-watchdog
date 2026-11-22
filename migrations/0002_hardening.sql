ALTER TABLE monitor_state ADD COLUMN consecutive_unknowns INTEGER NOT NULL DEFAULT 0;
ALTER TABLE monitor_state ADD COLUMN unknown_since INTEGER;
ALTER TABLE monitor_state ADD COLUMN last_unknown_reason TEXT;

ALTER TABLE alert_outbox ADD COLUMN claim_token TEXT;
ALTER TABLE alert_outbox ADD COLUMN accepted_relays TEXT;
ALTER TABLE alert_outbox ADD COLUMN failed_relays TEXT;

DROP INDEX incidents_one_open;
CREATE UNIQUE INDEX incidents_one_open_kind ON incidents (monitor_id, kind) WHERE status = 'open';

CREATE INDEX relay_list_cache_expiry ON relay_list_cache (expires_at);
CREATE INDEX alert_outbox_state ON alert_outbox (state, updated_at);
CREATE INDEX incidents_closed ON incidents (status, closed_at);
