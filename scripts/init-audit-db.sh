#!/bin/sh
# init-audit-db.sh — Postgres docker-entrypoint-initdb.d hook (RD-1147).
#
# Runs ONCE, inside the privacy-postgres CONTAINER, the first time its data
# volume is initialised. It provisions the SEPARATE append-only audit database
# and the restricted LOGIN role so the dev stack enforces the append-only seal —
# exactly the shape production infra provisions out of band.
#
# This is the CONTAINER creating the database (mirroring how the main DB is made
# via POSTGRES_DB), NOT the app: the Open Privacy Suite app never runs CREATE
# DATABASE. It connects to the already-provisioned "<main>_audit" DB and runs the
# lean audit migrations against it (as privacy_proxy_admin / the owner).
#
# Env (provided by docker-compose.privacy.dev.yml):
#   POSTGRES_USER            — the owner/superuser (also the audit-admin identity in dev).
#   POSTGRES_DB              — the main database name; the audit DB is "<POSTGRES_DB>_audit".
#   AUDIT_APP_PASSWORD       — password for the restricted runtime role privacy_proxy_app.
#
# The restricted role is created here with LOGIN + a password so AUDIT_DATABASE_URL
# can connect AS privacy_proxy_app. The lean audit migration (run later by the app
# via the owner DSN) creates the role NOLOGIN if it does not exist and then grants
# it the append-only allowlist; creating it here first (with LOGIN) is compatible —
# the migration's CREATE ROLE is guarded by IF NOT EXISTS and its GRANTs apply to
# the already-existing role.
set -eu

AUDIT_DB="${POSTGRES_DB}_audit"

psql -v ON_ERROR_STOP=1 -v app_pw="$AUDIT_APP_PASSWORD" --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<-SQL
    -- The separate audit database. The app connects here and migrates it; it
    -- never issues CREATE DATABASE itself.
    SELECT 'CREATE DATABASE ${AUDIT_DB}'
    WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = '${AUDIT_DB}')\gexec

    -- Restricted runtime role, with LOGIN + password so AUDIT_DATABASE_URL can
    -- connect as it and the append-only seal (INSERT+SELECT on access_logs) bites.
    -- The password is passed as a psql variable, never interpolated into a SQL
    -- string literal: :'app_pw' safely single-quotes it into a session GUC here,
    -- and format(%L) safely quotes it server-side inside the DO block (psql does
    -- not expand :vars inside a \$\$-quoted body).
    SELECT set_config('init_audit.app_pw', :'app_pw', false);
    DO \$\$
    BEGIN
        IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'privacy_proxy_app') THEN
            EXECUTE format('CREATE ROLE privacy_proxy_app LOGIN PASSWORD %L', current_setting('init_audit.app_pw'));
        ELSE
            EXECUTE format('ALTER ROLE privacy_proxy_app WITH LOGIN PASSWORD %L', current_setting('init_audit.app_pw'));
        END IF;
    END\$\$;

    -- Let the restricted role connect to the audit DB. Table-level append-only
    -- grants are applied by the lean audit migration (run by the app as owner).
    GRANT CONNECT ON DATABASE ${AUDIT_DB} TO privacy_proxy_app;
SQL

echo "init-audit-db: provisioned ${AUDIT_DB} + restricted role privacy_proxy_app (RD-1147)"
