-- Disclosure tables for compliance and audit features
-- Similar to ZkSync Prividium selective disclosure

-- =============================================================================
-- Disclosure Request Tables
-- =============================================================================

-- Disclosure requests from authorized parties (regulators, auditors)
CREATE TABLE IF NOT EXISTS disclosure_requests (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    requester_user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    target_user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    scope JSONB NOT NULL DEFAULT '{}'::jsonb, -- {methods: [], addresses: [], date_range: {start, end}}
    reason TEXT NOT NULL,
    legal_basis VARCHAR(255), -- GDPR article, court order ref, regulatory requirement
    status VARCHAR(50) NOT NULL DEFAULT 'pending',
    requested_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ, -- When the request expires if not acted upon
    decided_at TIMESTAMPTZ,
    decided_by_user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    decision_reason TEXT, -- User's reason for approval/rejection
    CONSTRAINT valid_disclosure_status CHECK (status IN ('pending', 'approved', 'rejected', 'expired', 'revoked'))
);

-- Disclosure grants (active access tokens for approved requests)
CREATE TABLE IF NOT EXISTS disclosure_grants (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    request_id UUID NOT NULL REFERENCES disclosure_requests(id) ON DELETE CASCADE,
    grant_token_hash VARCHAR(64) UNIQUE NOT NULL, -- SHA256 of access token
    scope JSONB NOT NULL, -- Actual granted scope (may be narrower than requested)
    granted_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    revoked_reason TEXT
);

-- Disclosure access events (audit trail of what was accessed)
CREATE TABLE IF NOT EXISTS disclosure_events (
    id BIGSERIAL PRIMARY KEY,
    grant_id UUID NOT NULL REFERENCES disclosure_grants(id) ON DELETE CASCADE,
    viewer_user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    action VARCHAR(50) NOT NULL, -- view_logs, view_transactions, export_report, view_summary
    resource_type VARCHAR(50) NOT NULL, -- access_logs, transactions, summary, report
    data_summary JSONB, -- Metadata about what was accessed (counts, date ranges - not actual data)
    viewer_ip VARCHAR(45),
    accessed_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Disclosure report cache (pre-generated compliance reports)
CREATE TABLE IF NOT EXISTS disclosure_reports (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    grant_id UUID NOT NULL REFERENCES disclosure_grants(id) ON DELETE CASCADE,
    report_type VARCHAR(50) NOT NULL, -- activity_summary, sanctions_check, compliance_report
    report_data JSONB NOT NULL, -- The actual report content
    generated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL
);

-- =============================================================================
-- Indexes
-- =============================================================================

-- Disclosure requests indexes
CREATE INDEX IF NOT EXISTS idx_disclosure_requests_requester ON disclosure_requests(requester_user_id);
CREATE INDEX IF NOT EXISTS idx_disclosure_requests_target ON disclosure_requests(target_user_id);
CREATE INDEX IF NOT EXISTS idx_disclosure_requests_org ON disclosure_requests(org_id);
CREATE INDEX IF NOT EXISTS idx_disclosure_requests_status ON disclosure_requests(status);
CREATE INDEX IF NOT EXISTS idx_disclosure_requests_requested_at ON disclosure_requests(requested_at);
CREATE INDEX IF NOT EXISTS idx_disclosure_requests_pending ON disclosure_requests(target_user_id, status) WHERE status = 'pending';

-- Disclosure grants indexes
CREATE INDEX IF NOT EXISTS idx_disclosure_grants_request ON disclosure_grants(request_id);
CREATE INDEX IF NOT EXISTS idx_disclosure_grants_token ON disclosure_grants(grant_token_hash);
CREATE INDEX IF NOT EXISTS idx_disclosure_grants_expires ON disclosure_grants(expires_at);
CREATE INDEX IF NOT EXISTS idx_disclosure_grants_active ON disclosure_grants(request_id) WHERE revoked_at IS NULL;

-- Disclosure events indexes
CREATE INDEX IF NOT EXISTS idx_disclosure_events_grant ON disclosure_events(grant_id);
CREATE INDEX IF NOT EXISTS idx_disclosure_events_viewer ON disclosure_events(viewer_user_id);
CREATE INDEX IF NOT EXISTS idx_disclosure_events_accessed_at ON disclosure_events(accessed_at);
CREATE INDEX IF NOT EXISTS idx_disclosure_events_action ON disclosure_events(action);

-- Disclosure reports indexes
CREATE INDEX IF NOT EXISTS idx_disclosure_reports_grant ON disclosure_reports(grant_id);
CREATE INDEX IF NOT EXISTS idx_disclosure_reports_type ON disclosure_reports(report_type);
CREATE INDEX IF NOT EXISTS idx_disclosure_reports_expires ON disclosure_reports(expires_at);

---- create above / drop below ----

-- Drop indexes
DROP INDEX IF EXISTS idx_disclosure_reports_expires;
DROP INDEX IF EXISTS idx_disclosure_reports_type;
DROP INDEX IF EXISTS idx_disclosure_reports_grant;
DROP INDEX IF EXISTS idx_disclosure_events_action;
DROP INDEX IF EXISTS idx_disclosure_events_accessed_at;
DROP INDEX IF EXISTS idx_disclosure_events_viewer;
DROP INDEX IF EXISTS idx_disclosure_events_grant;
DROP INDEX IF EXISTS idx_disclosure_grants_active;
DROP INDEX IF EXISTS idx_disclosure_grants_expires;
DROP INDEX IF EXISTS idx_disclosure_grants_token;
DROP INDEX IF EXISTS idx_disclosure_grants_request;
DROP INDEX IF EXISTS idx_disclosure_requests_pending;
DROP INDEX IF EXISTS idx_disclosure_requests_requested_at;
DROP INDEX IF EXISTS idx_disclosure_requests_status;
DROP INDEX IF EXISTS idx_disclosure_requests_org;
DROP INDEX IF EXISTS idx_disclosure_requests_target;
DROP INDEX IF EXISTS idx_disclosure_requests_requester;

-- Drop tables
DROP TABLE IF EXISTS disclosure_reports;
DROP TABLE IF EXISTS disclosure_events;
DROP TABLE IF EXISTS disclosure_grants;
DROP TABLE IF EXISTS disclosure_requests;
