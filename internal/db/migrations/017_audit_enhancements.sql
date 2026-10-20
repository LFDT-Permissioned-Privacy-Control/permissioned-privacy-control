-- 017_audit_enhancements.sql
-- Add correlation IDs, request parameters, and hash chain to audit tables.

-- Add correlation_id, request_params, and entry_hash to access_logs
ALTER TABLE access_logs
    ADD COLUMN IF NOT EXISTS correlation_id VARCHAR(128),
    ADD COLUMN IF NOT EXISTS request_params JSONB,
    ADD COLUMN IF NOT EXISTS entry_hash VARCHAR(128);

CREATE INDEX IF NOT EXISTS idx_access_logs_correlation
    ON access_logs(correlation_id) WHERE correlation_id IS NOT NULL;

-- Add correlation_id to compliance_logs
ALTER TABLE compliance_logs
    ADD COLUMN IF NOT EXISTS correlation_id VARCHAR(128);

CREATE INDEX IF NOT EXISTS idx_compliance_logs_correlation
    ON compliance_logs(correlation_id) WHERE correlation_id IS NOT NULL;

-- Add correlation_id to rbac_audit_log
ALTER TABLE rbac_audit_log
    ADD COLUMN IF NOT EXISTS correlation_id VARCHAR(128);

CREATE INDEX IF NOT EXISTS idx_rbac_audit_correlation
    ON rbac_audit_log(correlation_id) WHERE correlation_id IS NOT NULL;

---- create above / drop below ----

DROP INDEX IF EXISTS idx_rbac_audit_correlation;
ALTER TABLE rbac_audit_log DROP COLUMN IF EXISTS correlation_id;

DROP INDEX IF EXISTS idx_compliance_logs_correlation;
ALTER TABLE compliance_logs DROP COLUMN IF EXISTS correlation_id;

DROP INDEX IF EXISTS idx_access_logs_correlation;
ALTER TABLE access_logs
    DROP COLUMN IF EXISTS entry_hash,
    DROP COLUMN IF EXISTS request_params,
    DROP COLUMN IF EXISTS correlation_id;
