#!/usr/bin/env bash
# verify-governance-removed.sh — RD-869 manual test §3.4 automation.
#
# RD-869 ripped out the in-app governance-approval subsystem. This script
# pins the removal: the DB no longer carries the governance_* relations, and
# the old API endpoints return 404. Sanity-check unrelated flows (deploy +
# grant) belong in the demo-run-all.sh harness, not here.
#
# Requires the privacy stack running. The DB container name defaults to
# privacy-proxy-privacy-postgres-1; override via $PG_CONTAINER if your
# compose project differs.
set -euo pipefail

PROXY_URL="${PROXY_URL:-http://localhost:8080}"
PG_CONTAINER="${PG_CONTAINER:-privacy-proxy-privacy-postgres-1}"
PG_DB="${PG_DB:-privacy_proxy}"
PG_USER="${PG_USER:-postgres}"

LOG=/tmp/verify-governance-removed.log
: >"$LOG"

red() { printf '\033[0;31m%s\033[0m\n' "$*"; }
green() { printf '\033[0;32m%s\033[0m\n' "$*"; }
fail() { red "FAIL: $1"; echo "      see $LOG"; exit 1; }
ok() { green "OK:   $1"; }

# ----------------------------------------------------------------------------
# 1. No governance_* tables remain
# ----------------------------------------------------------------------------
echo "==> Step 1: no governance_* relations in the DB" | tee -a "$LOG"
if ! docker ps --format '{{.Names}}' | grep -qx "$PG_CONTAINER"; then
  # Fall back to detecting any postgres container in the stack.
  PG_CONTAINER=$(docker ps --format '{{.Names}}' | grep -E '(privacy-postgres|privacy-proxy-postgres)' | head -1 || true)
  [ -n "$PG_CONTAINER" ] || fail "could not find a privacy-stack postgres container"
fi
echo "using $PG_CONTAINER" >>"$LOG"

REL=$(docker exec "$PG_CONTAINER" \
  psql -U "$PG_USER" -d "$PG_DB" -A -t \
  -c "SELECT c.relname FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname='public' AND c.relname LIKE 'governance%';" 2>>"$LOG" || true)
echo "governance% relations: '$REL'" >>"$LOG"
if [ -z "$REL" ]; then
  ok "no governance_* relations exist"
else
  fail "governance_* relations still present: $REL"
fi

# ----------------------------------------------------------------------------
# 2. Old governance API endpoints are gone
# ----------------------------------------------------------------------------
echo "==> Step 2: old governance API endpoints return 404" | tee -a "$LOG"
ADMIN_TOKEN="${ADMIN_API_TOKEN:?ADMIN_API_TOKEN must be set}"

ENDPOINTS=(
  "/api/v1/admin/governance/proposals"
  "/api/v1/admin/governance/approvers"
  "/api/v1/admin/governance/policies"
)
for ep in "${ENDPOINTS[@]}"; do
  CODE=$(curl -s -o /dev/null -w '%{http_code}' \
    -H "X-Admin-Token: $ADMIN_TOKEN" \
    "$PROXY_URL$ep")
  echo "GET $ep -> $CODE" >>"$LOG"
  if [ "$CODE" = "404" ] || [ "$CODE" = "405" ]; then
    ok "$ep -> $CODE (route removed)"
  else
    fail "$ep returned $CODE — expected 404 or 405"
  fi
done

green "RD-869: governance subsystem fully removed."
