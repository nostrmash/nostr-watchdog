-- Sanitized transport evidence. Historical rows stay NULL.
-- This does not store keys, MLS state, device tokens, or ciphertext.

ALTER TABLE alert_outbox ADD COLUMN push_event_id TEXT;
ALTER TABLE alert_outbox ADD COLUMN evidence TEXT;
ALTER TABLE alert_outbox ADD COLUMN transport_disposition TEXT;
ALTER TABLE alert_outbox ADD COLUMN transport_updated_at INTEGER;
