-- Governance Approval Flow

-- Add governance fields to organizations
ALTER TABLE organizations ADD COLUMN governance_enabled BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE organizations ADD COLUMN approval_threshold INTEGER NOT NULL DEFAULT 1;
ALTER TABLE organizations ADD COLUMN governance_webhook_url TEXT;
ALTER TABLE organizations ADD COLUMN governance_escalation_timeout_hours INTEGER DEFAULT 24;

-- Provision a strictly typed 'system' user with the nil UUID for automated/API proxy governance requests
INSERT INTO users (id, external_id, banned) 
VALUES ('00000000-0000-0000-0000-000000000000', 'system_admin', false)
ON CONFLICT (id) DO NOTHING;

-- Approval requests table
CREATE TABLE approval_requests (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    requester_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    change_type TEXT NOT NULL,
    target_resource_id UUID,          -- for auditability
    target_resource_type TEXT,        -- 'contract', 'group', 'user'
    payload JSONB NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending', -- 'pending', 'approved', 'rejected'
    approvals_needed INTEGER NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    resolved_at TIMESTAMPTZ
);

CREATE INDEX idx_approval_requests_org_status ON approval_requests(org_id, status);

-- Approval decisions table
CREATE TABLE approval_decisions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    request_id UUID NOT NULL REFERENCES approval_requests(id) ON DELETE CASCADE,
    approver_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    decision TEXT NOT NULL,           -- 'approve' or 'reject'
    reason TEXT,
    decided_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(request_id, approver_id)
);

CREATE INDEX idx_approval_decisions_request ON approval_decisions(request_id);

-- Approval notifications table
CREATE TABLE approval_notifications (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    request_id UUID NOT NULL REFERENCES approval_requests(id) ON DELETE CASCADE,
    approver_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    channel TEXT NOT NULL,            -- 'webhook', 'dashboard'
    sent_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    acknowledged_at TIMESTAMPTZ
);

---- create above / drop below ----

DROP TABLE approval_notifications;
DROP TABLE approval_decisions;
DROP TABLE approval_requests;

ALTER TABLE organizations DROP COLUMN governance_escalation_timeout_hours;
ALTER TABLE organizations DROP COLUMN governance_webhook_url;
ALTER TABLE organizations DROP COLUMN approval_threshold;
ALTER TABLE organizations DROP COLUMN governance_enabled;
