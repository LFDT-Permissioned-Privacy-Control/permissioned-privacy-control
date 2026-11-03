-- exec/001_exec_roles.sql
--
-- ── WHAT ─────────────────────────────────────────────────────────
-- Creates the two roles of the SEPARATE execution-tracking database (RD-1410):
-- privacy_proxy_app (runtime, NOLOGIN) and privacy_proxy_admin (owner,
-- NOLOGIN), and grants the admin role full schema access plus default
-- privileges. Same shape as audit/001; per-table runtime grants live with the
-- CREATE TABLE they apply to.
--
-- ── WHY (ticket: RD-1410) ────────────────────────────────────────
-- Per-transaction tracking (bindings, status, history) moves out of the main
-- database so no per-transaction commit stream reaches it. The runtime role
-- reads and writes tracking rows; the owner runs these migrations and the
-- partition maintenance (create ahead, drop expired, truncate expired payload
-- buckets), which the runtime role cannot.
--
-- ── CREDENTIAL LIFECYCLE ─────────────────────────────────────────
-- No passwords are assigned here (NOLOGIN default), as in main 058 and
-- audit/001. Infra enables LOGIN with a credential from its secrets store. The
-- derived default (EXECUTION_*_DATABASE_URL unset) reuses DATABASE_URL's
-- credentials against <db>_exec, so the runtime connects as the owner there.
--
-- ── AUTHORITATIVE-RECORD note ────────────────────────────────────
-- Traceable record = this file (git) + PR review + tern schema_version_exec.
-- Writes nothing to a hash-chained audit table.
--
-- ── EXPAND-ONLY / ROLE-SEPARATION status ─────────────────────────
-- Expand-only: COMPLIANT (CREATE ROLE + GRANT only). Runs ONLY against the
-- tracking database; never against DATABASE_URL or the audit database.

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'privacy_proxy_app') THEN
        CREATE ROLE privacy_proxy_app NOLOGIN;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'privacy_proxy_admin') THEN
        CREATE ROLE privacy_proxy_admin NOLOGIN;
    END IF;
END$$;

GRANT USAGE ON SCHEMA public TO privacy_proxy_admin;
GRANT ALL PRIVILEGES ON ALL TABLES    IN SCHEMA public TO privacy_proxy_admin;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO privacy_proxy_admin;
ALTER DEFAULT PRIVILEGES IN SCHEMA public
    GRANT ALL PRIVILEGES ON TABLES    TO privacy_proxy_admin;
ALTER DEFAULT PRIVILEGES IN SCHEMA public
    GRANT ALL PRIVILEGES ON SEQUENCES TO privacy_proxy_admin;

GRANT USAGE ON SCHEMA public TO privacy_proxy_app;
