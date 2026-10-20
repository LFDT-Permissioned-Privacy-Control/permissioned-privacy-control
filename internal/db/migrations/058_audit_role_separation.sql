-- 058_audit_role_separation.sql
-- RD-858: split Postgres roles so the application identity cannot
-- silently rewrite the audit chain. Pre-fix, a single role had full
-- read/write/delete on every table — an attacker who compromised the
-- proxy host could rewrite rbac_audit_log entries and recompute the
-- chain forward in seconds. Role separation raises that bar to "the
-- attacker must also pop the dedicated admin credential" — defense in
-- depth, not a silver bullet, but the cheapest meaningful step that
-- doesn't require leaving Postgres trust boundaries.
--
-- Roles defined:
--   * privacy_proxy_app   — the runtime identity used by the proxy
--                           process.
--   * privacy_proxy_admin — operator identity for migrations, ad-hoc
--                           queries, incident response. Full DDL/DML
--                           on the entire schema. Used **rarely**,
--                           by a human via a credential that lives
--                           outside the app's secret store.
--
-- ── Permission model: explicit allowlist (NOT deny-list). ───────
--
-- Every table the app needs is enumerated below with the exact perms
-- it requires. Append-forever audit tables get INSERT + SELECT only
-- (no UPDATE / DELETE / TRUNCATE); operational tables get full CRUD.
--
-- Rationale for allowlist over the simpler "GRANT ALL then REVOKE on
-- two tables": a future audit-relevant table created in (say)
-- migration 080 would inherit blanket grants under the deny-list
-- pattern and be silently writable by the app role unless the author
-- remembers to add a REVOKE. With the allowlist pattern, forgetting
-- a GRANT means the runtime fails loudly with "permission denied"
-- the first time it touches the new table — loud-break-on-mistake is
-- the failure mode you want for compliance-sensitive grants.
--
-- ── New-table checklist (for future migration authors) ──────────
--
-- When you CREATE TABLE in a later migration, you MUST also:
--
--   1. Decide whether the table is "append-forever audit" or
--      "operational". If unsure, the safe default is append-only.
--   2. Add a GRANT block to that migration:
--      - Operational:    GRANT SELECT, INSERT, UPDATE, DELETE
--                        ON <table> TO privacy_proxy_app;
--      - Audit:          GRANT SELECT, INSERT
--                        ON <table> TO privacy_proxy_app;
--   3. Sequences for new tables: GRANT USAGE, UPDATE ON SEQUENCE
--      <table>_id_seq TO privacy_proxy_app;  (BIGSERIAL/SERIAL
--      tables only — UUID primary keys have no sequence).
--   4. The admin role automatically gets all perms via ALL TABLES
--      grants below — no per-table action needed for privacy_proxy_admin.
--
-- ── Credential lifecycle ─────────────────────────────────────────
--
-- The migration is intentionally non-prescriptive about credentials:
--   - No passwords are assigned (NOLOGIN is the default).
--   - The infra team picks the lifecycle (AWS Secrets Manager via
--     IRSA, RDS IAM authentication, HashiCorp Vault dynamic secrets,
--     plain ALTER ROLE ... PASSWORD ..., etc.) and applies it via
--     their preferred mechanism after this migration runs.
--   - The operator MUST flip the roles to LOGIN before they can be
--     used.
--   - See docs/security/audit-integrity for the recommended setup
--     (AWS Secrets Manager pattern for canonical deployments).
--
-- IF the operator has NOT separated credentials yet, the migration is
-- still safe — the existing connection role (whatever credential was
-- in DATABASE_URL when migrations ran) remains untouched, with all
-- its current permissions. The new roles sit dormant until the
-- operator chooses to enable them. Non-breaking when role separation
-- is deferred.

-- ---------------------------------------------------------------------------
-- Idempotent role creation. CREATE ROLE doesn't support IF NOT EXISTS.
-- ---------------------------------------------------------------------------

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'privacy_proxy_app') THEN
        CREATE ROLE privacy_proxy_app NOLOGIN;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'privacy_proxy_admin') THEN
        CREATE ROLE privacy_proxy_admin NOLOGIN;
    END IF;
END$$;

-- ---------------------------------------------------------------------------
-- Admin role: full access. Carve-out path for emergency surgery and
-- DDL (migrations). Granted at schema level so future tables / sequences
-- inherit automatically via ALTER DEFAULT PRIVILEGES.
-- ---------------------------------------------------------------------------

GRANT USAGE ON SCHEMA public TO privacy_proxy_admin;
GRANT ALL PRIVILEGES ON ALL TABLES    IN SCHEMA public TO privacy_proxy_admin;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO privacy_proxy_admin;

ALTER DEFAULT PRIVILEGES IN SCHEMA public
    GRANT ALL PRIVILEGES ON TABLES    TO privacy_proxy_admin;
ALTER DEFAULT PRIVILEGES IN SCHEMA public
    GRANT ALL PRIVILEGES ON SEQUENCES TO privacy_proxy_admin;

-- ---------------------------------------------------------------------------
-- App role: explicit per-table allowlist.
-- ---------------------------------------------------------------------------

GRANT USAGE ON SCHEMA public TO privacy_proxy_app;

-- ── Audit / append-forever tables: INSERT + SELECT only ──────────
-- These tables form the cryptographic audit trail. The app role
-- can append (write new rows) but cannot rewrite history. Retention
-- of these tables, when policy-permitted, is the admin role's job.

GRANT SELECT, INSERT ON rbac_audit_log    TO privacy_proxy_app;
GRANT SELECT, INSERT ON compliance_logs   TO privacy_proxy_app;
GRANT SELECT, INSERT ON disclosure_events TO privacy_proxy_app;
GRANT SELECT, INSERT ON price_change_log  TO privacy_proxy_app;
GRANT SELECT, INSERT ON impersonation_log TO privacy_proxy_app;

-- access_logs is special — it IS audit content, but retention prune
-- (90-day TTL + FIFO row cap) is intentional policy on this table.
-- The app role keeps UPDATE/DELETE so the retention worker continues
-- to function under the app credential. The audit_chain_anchor
-- preserves chain verifiability across prune cuts.
GRANT SELECT, INSERT, UPDATE, DELETE ON access_logs TO privacy_proxy_app;

-- audit_chain_anchor: app role writes here when retention prunes the
-- last surviving row in a chain. Read-modify-write required, so
-- INSERT + UPDATE + SELECT (no DELETE — anchor history is itself an
-- integrity signal).
GRANT SELECT, INSERT, UPDATE ON audit_chain_anchor TO privacy_proxy_app;

-- ── Operational tables: full CRUD ────────────────────────────────

GRANT SELECT, INSERT, UPDATE, DELETE ON address_threshold_overrides TO privacy_proxy_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON allowed_azure_tenants       TO privacy_proxy_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON api_keys                    TO privacy_proxy_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON compliance_config           TO privacy_proxy_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON contract_grants             TO privacy_proxy_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON contracts                   TO privacy_proxy_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON disclosure_grants           TO privacy_proxy_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON disclosure_reports          TO privacy_proxy_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON disclosure_requests         TO privacy_proxy_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON effective_permissions_cache TO privacy_proxy_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON eth_address_links           TO privacy_proxy_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON group_access                TO privacy_proxy_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON groups                      TO privacy_proxy_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON organizations               TO privacy_proxy_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON pending_tx_visibility       TO privacy_proxy_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON preregistered_addresses     TO privacy_proxy_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON refresh_tokens              TO privacy_proxy_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON revoked_tokens              TO privacy_proxy_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON sanctioned_addresses        TO privacy_proxy_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON shared_infrastructure       TO privacy_proxy_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON system_settings             TO privacy_proxy_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON system_token_prices         TO privacy_proxy_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON token_prices                TO privacy_proxy_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON travel_rule_records         TO privacy_proxy_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON tx_log_visible_to           TO privacy_proxy_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON tx_visible_to               TO privacy_proxy_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON user_memberships            TO privacy_proxy_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON users                       TO privacy_proxy_app;

-- ── Sequences ────────────────────────────────────────────────────
-- Every BIGSERIAL / SERIAL column needs USAGE + UPDATE on its
-- sequence so the writer can call nextval(). Enumerated explicitly:
-- forgetting one means INSERTs into that table fail with "permission
-- denied for sequence" — loud break, recovery via a single ALTER
-- migration.

GRANT USAGE, UPDATE ON SEQUENCE access_logs_id_seq        TO privacy_proxy_app;
GRANT USAGE, UPDATE ON SEQUENCE rbac_audit_log_id_seq     TO privacy_proxy_app;
GRANT USAGE, UPDATE ON SEQUENCE compliance_logs_id_seq    TO privacy_proxy_app;
GRANT USAGE, UPDATE ON SEQUENCE disclosure_events_id_seq  TO privacy_proxy_app;
GRANT USAGE, UPDATE ON SEQUENCE price_change_log_id_seq   TO privacy_proxy_app;

-- ── Tables NOT granted to app role ──────────────────────────────
-- The following exist in the schema but have ZERO Go code references
-- in the current codebase. They are not granted to privacy_proxy_app
-- so any accidental future write attempt fails loudly:
--   - access_policies   (initial-schema artefact, never used)
--   - managed_proxies   (migration 005 artefact, no Go usage)
-- The admin role still has full access via the schema-wide grant
-- above; a future migration can drop them once confirmed unused.

COMMENT ON ROLE privacy_proxy_app IS
    'Runtime app role (RD-858). Explicit per-table allowlist: INSERT+SELECT on audit-forever tables; full CRUD on operational tables; no grants on dead tables (access_policies, managed_proxies). No password set by migration — infra team configures credential lifecycle.';

COMMENT ON ROLE privacy_proxy_admin IS
    'Admin / operator role (RD-858). Full DDL+DML. Used rarely, via credentials that live outside the app secret store. No password set by migration.';
