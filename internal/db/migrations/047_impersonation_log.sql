-- RD-872: dedicated audit log for admin "dry-run as user" calls.
--
-- Kept separate from rbac_audit_log so its retention can diverge: rbac
-- audit rows roll over via the RD-871 sweeper, but impersonation rows
-- are evidence for security review walk-throughs and need to live
-- through the full audit period regardless of the access-log row cap.
-- Forwarding to SIEM (internal/audit/siem.go) is layered on top and
-- handles tamper evidence outside the DB.
--
-- Schema choices:
--   * actor_did + impersonated_did kept as plain text. We never trust a
--     mid-stream rename of users; the DID at the time of the call is
--     what the auditor needs.
--   * params_hash, not raw params: we never persist the impersonated
--     payload (could carry private addresses). The hash lets a reviewer
--     correlate against an external request log.
--   * decision/reason: small free-text describing the outcome (allow /
--     deny / error). Reason must be operator-safe — no raw DB errors,
--     no embedded private addresses; the dry-run handler is responsible
--     for sanitising before insert.
--   * correlation_id: lets a reviewer line up dry-run rows with the
--     access_logs entry the same admin produced when triggering the
--     call.

CREATE TABLE impersonation_log (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    actor_did       TEXT        NOT NULL,
    impersonated_did TEXT       NOT NULL,
    org_id          UUID        NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    method          TEXT        NOT NULL,
    params_hash     CHAR(64)    NOT NULL,        -- sha256, hex
    decision        TEXT        NOT NULL,        -- 'allow' | 'deny' | 'error'
    reason          TEXT,
    correlation_id  UUID,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT impersonation_decision_chk CHECK (decision IN ('allow', 'deny', 'error'))
);

-- Browse by admin (who looked at what?)
CREATE INDEX idx_impersonation_log_actor ON impersonation_log (actor_did, created_at DESC);
-- Browse by target (who was impersonated, when?)
CREATE INDEX idx_impersonation_log_target ON impersonation_log (impersonated_did, created_at DESC);
-- Org-scoped queries (an org admin reviewing their own org's activity)
CREATE INDEX idx_impersonation_log_org ON impersonation_log (org_id, created_at DESC);

---- create above / drop below ----

DROP INDEX IF EXISTS idx_impersonation_log_org;
DROP INDEX IF EXISTS idx_impersonation_log_target;
DROP INDEX IF EXISTS idx_impersonation_log_actor;
DROP TABLE IF EXISTS impersonation_log;
