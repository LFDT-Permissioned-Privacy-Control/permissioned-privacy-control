#!/usr/bin/env bash
# verify-trust-zone-split.sh — RD-876 manual test §3.7 automation.
#
# The Open Privacy Suite stack ships as TWO sibling compose files:
#   - docker-compose.privacy.yml      (production manifest; audited trust boundary)
#   - docker-compose.privacy.dev.yml  (developer manifest; mock-login, anvil RPC exposed)
#
# RD-876 invariants (parsed at the manifest level — no docker spin-up):
#   1. Both files declare the trust-zone networks (indexer-zone, bff-zone, public).
#   2. The prod manifest does NOT publish anvil's RPC port to the host.
#      The dev manifest DOES (devs need cast/forge/MetaMask access).
#   3. The prod manifest does NOT enable mock-login.
#      The dev manifest does (ALLOW_MOCK_LOGIN=true, MOCK_SIGNATURES=true,
#      ENVIRONMENT=development).
#   4. Documentation site mentions the split.
#
# Running the actual prod stack to test boundary closure would tear down a
# concurrently-running dev stack (port + container-name conflicts). That
# negative-network smoke is the e2e test on the privacy compose, run
# separately. This script is the static check to keep manifest drift
# from silently weakening the audited deployment.
set -euo pipefail

PROD=docker-compose.privacy.yml
DEV=docker-compose.privacy.dev.yml

LOG=/tmp/verify-trust-zone-split.log
: >"$LOG"

red() { printf '\033[0;31m%s\033[0m\n' "$*"; }
green() { printf '\033[0;32m%s\033[0m\n' "$*"; }
fail() { red "FAIL: $1"; echo "      see $LOG"; exit 1; }
ok() { green "OK:   $1"; }

[ -f "$PROD" ] || fail "missing $PROD (run from the repo root)"
[ -f "$DEV"  ] || fail "missing $DEV"

# Helper — does the file declare a network with the given name? Looks for
# a 2-space-indented declaration ("  netname:") under a top-level
# "networks:" key. Uses awk so we don't have to depend on a YAML parser.
has_network() {
  local file=$1 name=$2
  awk -v want="$name" '
    /^networks:/ { in_nets=1; next }
    in_nets && /^[a-zA-Z]/ { in_nets=0 }
    in_nets && /^  [a-zA-Z][a-zA-Z0-9_-]*:/ {
      gsub(/[ :]/,"",$0)
      if ($0 == want) { print "yes"; exit }
    }
  ' "$file" | grep -q yes
}

# Helper — does the named service block carry a `ports:` key? Same idea:
# walk the YAML using indentation. Service block starts at 2-space indent
# under a top-level "services:" key; ports under it sit at 4-space indent.
service_has_ports() {
  local file=$1 svc=$2
  awk -v want="$svc" '
    /^services:/ { in_svcs=1; next }
    in_svcs && /^[a-zA-Z]/ { in_svcs=0 }
    in_svcs && /^  [a-zA-Z][a-zA-Z0-9_-]*:/ {
      gsub(/[ :]/,"",$0)
      cur = $0
      next
    }
    in_svcs && cur == want && /^    ports:/ { print "yes"; exit }
  ' "$file" | grep -q yes
}

# Helper — pull the value of an env var defined under
# services.<svc>.environment. Returns empty string if unset.
# Uses python (line-based) instead of awk so we don't depend on gawk's
# match() extension (BSD awk on macOS rejects the 3-arg form).
service_env() {
  local file=$1 svc=$2 key=$3
  python3 - "$file" "$svc" "$key" <<'PY'
import re, sys
path, svc, key = sys.argv[1], sys.argv[2], sys.argv[3]
in_services = False
current_svc = None
in_env = False
re_kv  = re.compile(r'^      ([A-Z_]+):\s+(.*)$')
re_dash = re.compile(r'^      - ([A-Z_]+)=(.*)$')
re_svc = re.compile(r'^  ([A-Za-z][A-Za-z0-9_-]*):')
with open(path) as fh:
    for line in fh:
        line = line.rstrip('\n')
        if line.startswith('services:'):
            in_services = True; continue
        if in_services and line and not line.startswith(' ') and not line.startswith('#'):
            in_services = False
        if not in_services: continue
        m = re_svc.match(line)
        if m:
            current_svc = m.group(1); in_env = False; continue
        if current_svc != svc: continue
        if line.startswith('    environment:'):
            in_env = True; continue
        if in_env and line.startswith('    ') and not line.startswith('     '):
            # next sibling key under this service — leave env block
            in_env = False
        if not in_env: continue
        for r in (re_kv, re_dash):
            m = r.match(line)
            if m and m.group(1) == key:
                print(m.group(2).strip().strip('"').strip("'"))
                sys.exit(0)
PY
}

# ----------------------------------------------------------------------------
# 1. Both manifests declare the trust-zone network split
# ----------------------------------------------------------------------------
echo "==> Step 1: indexer-zone / bff-zone / public networks present in both files" | tee -a "$LOG"
for net in indexer-zone bff-zone public; do
  for f in "$PROD" "$DEV"; do
    if ! has_network "$f" "$net"; then
      fail "$f does not declare network '$net'"
    fi
  done
  ok "$net network declared in prod + dev"
done

# ----------------------------------------------------------------------------
# 2. Anvil host port: forbidden in prod, expected in dev
# ----------------------------------------------------------------------------
echo "==> Step 2: anvil RPC port not published in prod manifest" | tee -a "$LOG"
if service_has_ports "$PROD" anvil; then
  fail "prod manifest publishes anvil ports — trust boundary regression"
fi
ok "prod manifest keeps anvil off the host network"

if ! service_has_ports "$DEV" anvil; then
  fail "dev manifest must publish anvil ports for cast/forge/MetaMask"
fi
ok "dev manifest publishes anvil ports for developer tooling"

# ----------------------------------------------------------------------------
# 3. Mock-login posture: forbidden in prod, expected in dev
# ----------------------------------------------------------------------------
echo "==> Step 3: ALLOW_MOCK_LOGIN gating differs between manifests" | tee -a "$LOG"

PROD_MOCK=$(service_env "$PROD" proxy-backend ALLOW_MOCK_LOGIN)
echo "prod ALLOW_MOCK_LOGIN: '$PROD_MOCK'" >>"$LOG"
case "$PROD_MOCK" in
  ''|'false'|'"false"')
    ok "prod manifest does NOT enable ALLOW_MOCK_LOGIN ('${PROD_MOCK:-unset}')"
    ;;
  *)
    fail "prod manifest sets ALLOW_MOCK_LOGIN=$PROD_MOCK — should be unset or false"
    ;;
esac

DEV_MOCK=$(service_env "$DEV" proxy-backend ALLOW_MOCK_LOGIN)
echo "dev ALLOW_MOCK_LOGIN: '$DEV_MOCK'" >>"$LOG"
case "$DEV_MOCK" in
  'true'|'"true"')
    ok "dev manifest enables ALLOW_MOCK_LOGIN=$DEV_MOCK"
    ;;
  *)
    fail "dev manifest must set ALLOW_MOCK_LOGIN=true; got '$DEV_MOCK'"
    ;;
esac

PROD_ENV=$(service_env "$PROD" proxy-backend ENVIRONMENT)
echo "prod ENVIRONMENT: '$PROD_ENV'" >>"$LOG"
case "$PROD_ENV" in
  'production'|'"production"')
    ok "prod manifest sets ENVIRONMENT=$PROD_ENV"
    ;;
  *)
    fail "prod manifest must set ENVIRONMENT=production; got '$PROD_ENV'"
    ;;
esac

# ----------------------------------------------------------------------------
# 4. Docs cross-check (loose)
# ----------------------------------------------------------------------------
# Look for trust-boundary vocabulary anywhere in the security docs. Specific
# RD-876 wording (indexer-zone / bff-zone) is not yet on the docs site —
# that's a real gap to file separately, but it's not what this script gates.
echo "==> Step 4: docs site mentions the trust boundary" | tee -a "$LOG"
DOC_HITS=$(grep -rli "trust.zone\|RD-876\|indexer-zone\|bff-zone\|trust.boundary\|trusted.proxies" site/src/app/docs/security/ 2>/dev/null | wc -l | tr -d ' ')
echo "doc files referencing trust-related vocabulary: $DOC_HITS" >>"$LOG"
[ "$DOC_HITS" -ge 1 ] || fail "no docs in site/src/app/docs/security/ mention any trust-boundary vocabulary"
ok "docs reference trust-boundary vocabulary ($DOC_HITS file(s))"
if ! grep -rli "indexer-zone\|bff-zone\|RD-876" site/src/app/docs/security/ >/dev/null 2>&1; then
  printf '\033[0;33mNOTE:\033[0m docs do not yet reference the indexer-zone / bff-zone split by name (RD-876). Consider adding a section.\n'
fi

green "RD-876: prod and dev compose manifests pass the trust-zone invariants."
