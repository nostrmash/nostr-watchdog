-- Ownership marker for a conditional monitor-state transition.
-- Dependent incident and outbox writes must match this token, not only the
-- next generation. A losing writer can observe the winner's generation and
-- must still be unable to mutate it. Already-applied files are not edited.

ALTER TABLE monitor_state ADD COLUMN commit_token TEXT;
