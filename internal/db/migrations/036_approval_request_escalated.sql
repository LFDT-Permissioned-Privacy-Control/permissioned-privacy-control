-- Add escalated_at column to track when a request was auto-escalated
-- due to exceeding the governance_escalation_timeout_hours threshold.
ALTER TABLE approval_requests ADD COLUMN escalated_at TIMESTAMPTZ;

---- create above / drop below ----

ALTER TABLE approval_requests DROP COLUMN escalated_at;
