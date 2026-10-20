-- 061_compliance_enforcement_mode.sql
--
-- WHAT: Adds a configurable compliance enforcement mode (RD-1044).
--   1. compliance_config.enforcement_mode TEXT NOT NULL DEFAULT 'enforce'
--      CHECK (enforce|monitor) — per-org selector: 'enforce' (block — the
--      historical fail-closed behaviour) vs 'monitor' (allow the tx but
--      record the violation).
--   2. compliance_logs.would_block BOOLEAN NOT NULL DEFAULT FALSE — marks a
--      monitor-mode row: the transfer was allowed (decision='allowed') but
--      WOULD have been blocked under enforce mode; denial_reason carries the
--      would-have-blocked reason.
--
-- WHY: RD-1044 — operator-selectable monitor / log-only mode for phased
--   rollout and observation periods (compliance visibility without hard
--   enforcement). The compliance_logs sink already exists; monitor reuses it.
--
-- SECURITY / AUDIT (ISO 27001 / Vanta): monitor mode converts a PREVENTIVE
--   control into a DETECTIVE-only one for the affected org — a
--   change-management + control-documentation item:
--     * Default is 'enforce' (the column DEFAULT). Monitor is strictly
--       opt-in, per org, via the audited admin compliance-config endpoint
--       (recordAuditActionScoped) and/or the COMPLIANCE_DEFAULT_MODE env.
--     * Sanctions are NOT monitor-eligible: a transfer touching a sanctioned
--       address stays hard-blocked even under monitor mode. Only
--       threshold-breach, travel-rule-record-required, and unknown-price
--       violations are monitored. Relaxing this is a Legal/Compliance call,
--       not an engineering one.
--     * would_block lets auditors distinguish a monitored violation from a
--       genuinely-compliant allow when reviewing compliance_logs.
--
-- AFFECTED ROWS: none rewritten. Both columns are additive with safe NOT NULL
--   DEFAULTs, so every existing row keeps fail-closed semantics
--   (enforcement_mode='enforce', would_block=FALSE). Detection queries:
--     -- orgs opted into monitor mode:
--     SELECT org_id FROM compliance_config WHERE enforcement_mode = 'monitor';
--     -- monitored (allowed-but-would-block) transfers:
--     SELECT * FROM compliance_logs WHERE would_block = TRUE;
--
-- EXPAND-ONLY: yes — ADD COLUMN only; no DROP, no constraint removal. The
--   compliance_logs.decision CHECK (allowed|denied) is intentionally left
--   untouched: monitored rows use decision='allowed' + would_block=TRUE, not
--   a new decision value, so no constraint surgery is required.
--
-- GRANTS: none needed — both are existing tables already granted to
--   privacy_proxy_app (migration 058); PostgreSQL table grants cover new
--   columns automatically.
--
-- AUTHORITATIVE RECORD: this migration file (git) + PR review + tern
--   schema_version applied-at timestamp. No write to any hash-chained audit
--   table from this migration (per CLAUDE.md).

ALTER TABLE compliance_config
    ADD COLUMN enforcement_mode TEXT NOT NULL DEFAULT 'enforce'
    CHECK (enforcement_mode IN ('enforce', 'monitor'));

ALTER TABLE compliance_logs
    ADD COLUMN would_block BOOLEAN NOT NULL DEFAULT FALSE;

---- create above / drop below ----

-- Down migration is development-only; production is expand-only (CLAUDE.md).
-- ALTER TABLE compliance_logs DROP COLUMN IF EXISTS would_block;
-- ALTER TABLE compliance_config DROP COLUMN IF EXISTS enforcement_mode;
