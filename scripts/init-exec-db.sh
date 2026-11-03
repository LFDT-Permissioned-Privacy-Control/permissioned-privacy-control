#!/bin/sh
# init-exec-db.sh — Postgres docker-entrypoint-initdb.d hook (RD-1410).
#
# Runs ONCE, inside a Postgres CONTAINER, the first time its data volume is
# initialised. It provisions the execution-tracking database of the Reth
# execution path, "<POSTGRES_DB>_exec", next to the main database — the
# derived default of EXECUTION_DATABASE_URL / EXECUTION_ADMIN_DATABASE_URL.
# Production provisions a SEPARATE Postgres instance instead (see the
# deployment docs); this same-server layout is for development only.
#
# The app never runs CREATE DATABASE: it connects to this database as the
# owner, runs the tracking migrations and records the network.
#
# Env: POSTGRES_USER (owner), POSTGRES_DB (main database name).
set -eu

EXEC_DB="${POSTGRES_DB}_exec"

# The name is passed as a psql variable and quoted server-side (format %I),
# never interpolated into SQL text.
psql -v ON_ERROR_STOP=1 -v exec_db="$EXEC_DB" --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<-'SQL'
    SELECT format('CREATE DATABASE %I', :'exec_db')
    WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = :'exec_db')\gexec
    SELECT format('GRANT CONNECT ON DATABASE %I TO privacy_proxy_app', :'exec_db')
    WHERE EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'privacy_proxy_app')\gexec
SQL

echo "init-exec-db: provisioned ${EXEC_DB} (RD-1410)"
