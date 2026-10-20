-- RD-869: governance subsystem removed; the customer-side IaC replaces it.
-- Drop allowed by explicit team decision (overrides the expand-only policy
-- documented in CLAUDE.md for this single, intentional removal).
--
-- Removes the in-app N-of-M approval flow:
--   - approval_requests / approval_decisions / approval_notifications
--   - governance_approver_groups
--   - organizations.governance_* columns
--
-- Drop child tables first (FKs reference approval_requests).

DROP TABLE IF EXISTS approval_notifications;
DROP TABLE IF EXISTS approval_decisions;
DROP TABLE IF EXISTS governance_approver_groups;
DROP TABLE IF EXISTS approval_requests;

ALTER TABLE organizations DROP COLUMN IF EXISTS governance_escalation_timeout_hours;
ALTER TABLE organizations DROP COLUMN IF EXISTS governance_webhook_url;
ALTER TABLE organizations DROP COLUMN IF EXISTS approval_threshold;
ALTER TABLE organizations DROP COLUMN IF EXISTS governance_enabled;

---- create above / drop below ----

-- Dev-only rollback. Recreates the schema previously defined by migrations
-- 033, 034 and 036. Not intended for production use.

ALTER TABLE organizations ADD COLUMN governance_enabled BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE organizations ADD COLUMN approval_threshold INTEGER NOT NULL DEFAULT 1;
ALTER TABLE organizations ADD COLUMN governance_webhook_url TEXT;
ALTER TABLE organizations ADD COLUMN governance_escalation_timeout_hours INTEGER DEFAULT 24;

CREATE TABLE approval_requests (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    requester_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    change_type TEXT NOT NULL,
    target_resource_id UUID,
    target_resource_type TEXT,
    payload JSONB NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    approvals_needed INTEGER NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    resolved_at TIMESTAMPTZ,
    escalated_at TIMESTAMPTZ
);

CREATE INDEX idx_approval_requests_org_status ON approval_requests(org_id, status);

CREATE TABLE approval_decisions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    request_id UUID NOT NULL REFERENCES approval_requests(id) ON DELETE CASCADE,
    approver_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    decision TEXT NOT NULL,
    reason TEXT,
    decided_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(request_id, approver_id)
);

CREATE INDEX idx_approval_decisions_request ON approval_decisions(request_id);

CREATE TABLE approval_notifications (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    request_id UUID NOT NULL REFERENCES approval_requests(id) ON DELETE CASCADE,
    approver_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    channel TEXT NOT NULL,
    sent_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    acknowledged_at TIMESTAMPTZ
);

CREATE TABLE governance_approver_groups (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    group_id UUID NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(org_id, group_id)
);

CREATE INDEX idx_governance_approver_groups_org ON governance_approver_groups(org_id);
