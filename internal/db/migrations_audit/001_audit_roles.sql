-- audit/001_audit_roles.sql
--
-- ── WHAT ─────────────────────────────────────────────────────────
-- Creates the two Postgres roles the SEPARATE append-only audit database needs
-- (RD-1147): privacy_proxy_app (runtime, NOLOGIN) and privacy_proxy_admin
-- (operator/owner, NOLOGIN), and grants the admin role full schema access +
-- default privileges. Mirrors the role/grant model of main migration 058, but
-- LEAN: the audit database contains ONLY the access_logs audit trail + its hash
-- chain tables (created in audit/002), NOT the full RBAC/operational schema. So
-- this file defines the roles and admin grants; audit/002 grants the runtime
-- role its per-table append-only allowlist.
--
-- This is the FIRST migration in the audit-only set. It does NOT run the main
-- migration FS: the audit DB never gets users / contracts / groups /
-- rbac_audit_log / compliance_logs etc. It connects to an already-provisioned,
-- EMPTY database (infra creates the DB; the app never runs CREATE DATABASE) and
-- builds exactly the audit schema.
--
-- ── WHY (ticket: RD-1147) ────────────────────────────────────────
-- Role separation in the audit DB is what makes the append-only seal bite: the
-- runtime DSN (AUDIT_DATABASE_URL) connects AS privacy_proxy_app, which holds
-- INSERT+SELECT on access_logs but NOT UPDATE/DELETE. Retention prune runs under
-- the admin/owner DSN (AUDIT_ADMIN_DATABASE_URL / privacy_proxy_admin), which
-- does. A compromised proxy process (or leaked runtime credential) can append
-- new access-log rows but cannot rewrite or delete history. Defense in depth.
--
-- ── CREDENTIAL LIFECYCLE ─────────────────────────────────────────
-- No passwords are assigned here (NOLOGIN default), exactly as in 058. The infra
-- team flips each role to LOGIN with a credential via their chosen mechanism
-- (AWS Secrets Manager / RDS IAM / Vault / ALTER ROLE). The derived-default
-- deployment (AUDIT_*_DATABASE_URL unset) reuses DATABASE_URL's credentials
-- against the <db>_audit database — in that mode the runtime connects as the
-- OWNER, so the INSERT-only seal is NOT enforced (documented in docs/config).
-- The seal bites only when AUDIT_DATABASE_URL connects as privacy_proxy_app.
--
-- ── AUTHORITATIVE-RECORD note ────────────────────────────────────
-- Traceable record = this migration file (git) + PR review + tern
-- schema_version_audit (applied-at timestamp). Writes nothing to a hash-chained
-- audit table.
--
-- ── EXPAND-ONLY / ROLE-SEPARATION status ─────────────────────────
-- Expand-only: COMPLIANT (CREATE ROLE + GRANT only). Role separation: this IS
-- the role separation. Runs ONLY against the audit database (embedded FS applied
-- by the audit-admin pool); never against the main DATABASE_URL.

-- Idempotent role creation. CREATE ROLE has no IF NOT EXISTS.
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'privacy_proxy_app') THEN
        CREATE ROLE privacy_proxy_app NOLOGIN;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'privacy_proxy_admin') THEN
        CREATE ROLE privacy_proxy_admin NOLOGIN;
    END IF;
END$$;

-- Admin/owner role: full access to the (lean) audit schema, incl. future
-- audit-schema tables via ALTER DEFAULT PRIVILEGES. This is the identity that
-- runs these migrations and the retention prune.
GRANT USAGE ON SCHEMA public TO privacy_proxy_admin;
GRANT ALL PRIVILEGES ON ALL TABLES    IN SCHEMA public TO privacy_proxy_admin;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO privacy_proxy_admin;

ALTER DEFAULT PRIVILEGES IN SCHEMA public
    GRANT ALL PRIVILEGES ON TABLES    TO privacy_proxy_admin;
ALTER DEFAULT PRIVILEGES IN SCHEMA public
    GRANT ALL PRIVILEGES ON SEQUENCES TO privacy_proxy_admin;

-- Runtime role: schema usage only here. Per-table append-only grants are in
-- audit/002 (co-located with the CREATE TABLE they apply to).
GRANT USAGE ON SCHEMA public TO privacy_proxy_app;

COMMENT ON ROLE privacy_proxy_app IS
    'Runtime app role in the SEPARATE audit database (RD-1147). Append-only: INSERT+SELECT on access_logs and the audit_chain_* tables; NO UPDATE/DELETE on access_logs. No password set by migration.';

COMMENT ON ROLE privacy_proxy_admin IS
    'Admin/owner role in the SEPARATE audit database (RD-1147). Full DDL+DML: runs audit migrations and retention prune. No password set by migration.';
