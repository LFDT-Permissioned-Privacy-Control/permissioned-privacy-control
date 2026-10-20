-- 057_rbac_audit_log_hash_chain.sql
-- RD-858: extend the audit hash chain (currently access_logs only, migration
-- 017) to cover rbac_audit_log. Admin actions on RBAC tables (groups,
-- grants, memberships, contract claim, etc.) are exactly the records SOC 2
-- CC7 / ISO 27001 auditors ask about under "change management evidence",
-- and pre-fix any actor with DB write access could rewrite the table
-- silently — there was no cryptographic linking of rows.
--
-- This migration is additive only (expand-only policy). The new column is
-- nullable so historical rows (created before this migration ran) stay
-- valid; new writes via CreateAuditLog populate it. The verifier (see
-- internal/audit/verifier.go) flags NULL entries on rows written after
-- the writer change shipped, which is what we want — those represent
-- either tampering or a process crash that the writer fix to single-
-- statement INSERT (RD-858 short-term tier item) is meant to prevent.
--
-- Chain seeding follows the same pattern as the access_logs chain:
--   1. Latest non-NULL entry_hash row.
--   2. Otherwise audit_chain_anchor (migration 042) — chain_name will be
--      'rbac_audit_log' once that chain has its first prune cut.
--   3. Otherwise the empty string (fresh chain).
--
-- The hash-format version is intentionally separate from the access_logs
-- format (which is "v2" at the time of this migration). rbac_audit_log
-- starts at v1; future format bumps (e.g. when more fields are added)
-- increment independently.

ALTER TABLE rbac_audit_log
    ADD COLUMN IF NOT EXISTS entry_hash VARCHAR(128),
    ADD COLUMN IF NOT EXISTS hash_format_version SMALLINT NOT NULL DEFAULT 1;

-- old_value / new_value were JSONB. JSONB normalizes the byte
-- representation on round-trip (key reorder, whitespace insertion
-- between colon and value) — fine for query semantics, **fatal** for
-- a hash chain that includes these fields in its canonical content.
-- The writer marshals via Go's encoding/json (compact form) and the
-- verifier reads back the column as text — Postgres returns the
-- JSONB canonical text with a single space after every colon, which
-- never matches the writer's compact form. Every new row would look
-- tampered even when no one tampered.
--
-- Mirror the migration 031 solution for access_logs.request_params:
-- convert to TEXT so the bytes the writer INSERTed come back
-- verbatim. App code that needs to parse the fields still parses on
-- demand — no Go change required, the columns hold the same JSON
-- documents either way.
--
-- USING old_value::text canonicalizes existing JSONB rows to
-- Postgres-pretty text. Those rows have NULL entry_hash (they were
-- written before RD-858), so no chain seed is invalidated.
ALTER TABLE rbac_audit_log
    ALTER COLUMN old_value TYPE TEXT USING old_value::text,
    ALTER COLUMN new_value TYPE TEXT USING new_value::text;

COMMENT ON COLUMN rbac_audit_log.entry_hash IS
    'SHA-256(prev_entry_hash || canonical_row_content) hex. NULL for rows written before RD-858; verifier flags as integrity gap.';

COMMENT ON COLUMN rbac_audit_log.hash_format_version IS
    'Hash content schema version. The verifier picks the matching content builder by this column; new versions must be additive (never rewrite past formats).';

COMMENT ON COLUMN rbac_audit_log.old_value IS
    'Previous value as raw JSON text (RD-858). Migrated from JSONB to TEXT so the hash chain content remains stable across DB read-back; same approach as access_logs.request_params per migration 031.';

COMMENT ON COLUMN rbac_audit_log.new_value IS
    'New value as raw JSON text (RD-858). See old_value comment.';
