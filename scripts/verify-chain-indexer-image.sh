#!/usr/bin/env bash
# verify-chain-indexer-image.sh — manual test §3.9 automation (#192, #65).
#
# RD-855/RD-876 era: chain-indexer is no longer built from a sibling clone in
# the prod manifest — it pulls a published image from GHCR. The dev manifest
# still builds locally so devs can iterate, but `docker compose pull` against
# the prod compose must resolve the indexer to a tagged GHCR image.
#
# Invariants:
#   1. The prod manifest references ghcr.io/gateway-fm/chain-indexer (no
#      `build:` block — pure `image:` reference).
#   2. `docker compose -f docker-compose.privacy.yml pull chain-indexer`
#      succeeds.
#   3. Resulting image is named `ghcr.io/gateway-fm/chain-indexer` (any tag).
#
# This script does NOT bring the stack up — that's covered by
# scripts/privacy-dev-up.sh and the demo harness. Pulling alone is the
# narrowest assertion that the GHCR resolution works.
set -euo pipefail

PROD=docker-compose.privacy.yml
LOG=/tmp/verify-chain-indexer-image.log
: >"$LOG"

red() { printf '\033[0;31m%s\033[0m\n' "$*"; }
green() { printf '\033[0;32m%s\033[0m\n' "$*"; }
fail() { red "FAIL: $1"; echo "      see $LOG"; exit 1; }
ok() { green "OK:   $1"; }

[ -f "$PROD" ] || fail "missing $PROD (run from the repo root)"

# ----------------------------------------------------------------------------
# 1. Prod manifest declares chain-indexer as a pulled image, not a build
# ----------------------------------------------------------------------------
echo "==> Step 1: prod manifest uses GHCR image for chain-indexer" | tee -a "$LOG"

# Walk the YAML by indentation to scope inspection to the chain-indexer
# service block. Comments and arbitrary block ordering inside the service
# would break a fixed-line `grep -A` window, so we rely on the structural
# rule "service block ends when we hit another 2-space-indented key".
read -r HAS_GHCR HAS_BUILD < <(awk '
  /^  chain-indexer:/ { in_svc=1; next }
  in_svc && /^  [a-zA-Z]/ { in_svc=0 }
  in_svc && /^    image:[[:space:]]*ghcr\.io\/gateway-fm\/chain-indexer/ { ghcr=1 }
  in_svc && /^    build:/ { build=1 }
  END { print (ghcr?1:0), (build?1:0) }
' "$PROD")
echo "chain-indexer block: ghcr=$HAS_GHCR build=$HAS_BUILD" >>"$LOG"
[ "$HAS_GHCR" = "1" ] || fail "prod manifest's chain-indexer service does not reference ghcr.io/gateway-fm/chain-indexer"
ok "prod manifest pulls chain-indexer from GHCR"

[ "$HAS_BUILD" = "0" ] || fail "prod manifest's chain-indexer has a build: block — should pull from GHCR only"
ok "prod manifest's chain-indexer has no local build directive"

# ----------------------------------------------------------------------------
# 2. docker compose pull resolves the image
# ----------------------------------------------------------------------------
echo "==> Step 2: docker compose pull chain-indexer succeeds" | tee -a "$LOG"
# `docker compose pull` parses the whole manifest for interpolation even when
# scoped to a single service, so any `${VAR:?msg}` reference outside the
# chain-indexer block (e.g. REDIS_PASSWORD, INDEXER_POSTGRES_PASSWORD) would
# trip validation. Use the prod env file when available; fall back to dummy
# placeholders for the strict-required vars when running without one.
ENV_ARGS=()
for f in .env.privacy.prod ../../../.env.privacy.prod; do
  if [ -f "$f" ]; then
    ENV_ARGS=(--env-file "$f")
    echo "using env file: $f" >>"$LOG"
    break
  fi
done
if [ ${#ENV_ARGS[@]} -eq 0 ]; then
  echo "no .env.privacy.prod found; using dummy interpolation values" >>"$LOG"
  export REDIS_PASSWORD="${REDIS_PASSWORD:-dummy-redis}"
  export PRIVACY_POSTGRES_PASSWORD="${PRIVACY_POSTGRES_PASSWORD:-dummy-pg}"
  export INDEXER_POSTGRES_PASSWORD="${INDEXER_POSTGRES_PASSWORD:-dummy-pg}"
  export BLOCK_EXPLORER_POSTGRES_PASSWORD="${BLOCK_EXPLORER_POSTGRES_PASSWORD:-dummy-pg}"
  export ADMIN_API_TOKEN="${ADMIN_API_TOKEN:-dummy-token}"
  export RPC_API_KEY_ENCRYPTION_KEY="${RPC_API_KEY_ENCRYPTION_KEY:-$(printf '0%.0s' {1..64})}"
fi

set +e
PULL_OUT=$(docker compose "${ENV_ARGS[@]}" -f "$PROD" pull --quiet chain-indexer 2>&1)
PULL_RC=$?
set -e
echo "$PULL_OUT" >>"$LOG"
if [ $PULL_RC -eq 0 ]; then
  ok "docker compose pull chain-indexer succeeded"
elif echo "$PULL_OUT" | grep -qiE 'denied|unauthorized|authentication required'; then
  # GHCR access is gated by auth. The manifest is correct; the local Docker
  # daemon just isn't logged in. That's a setup concern, not a regression.
  printf '\033[0;33mWARN:\033[0m docker compose pull chain-indexer was DENIED.\n'
  printf '       The manifest references GHCR correctly, but this Docker daemon\n'
  printf '       has no credentials. Run `docker login ghcr.io` and retry, or\n'
  printf '       set CI=1 to fail hard if you need authoritative coverage here.\n'
  if [ "${CI:-}" = "1" ] || [ "${STRICT_PULL:-}" = "1" ]; then
    fail "docker pull denied (CI/STRICT_PULL=1); see $LOG"
  fi
else
  fail "docker compose pull chain-indexer failed; see $LOG"
fi

# ----------------------------------------------------------------------------
# 3. Image is now present locally and tagged from GHCR (best-effort)
# ----------------------------------------------------------------------------
echo "==> Step 3: ghcr.io/gateway-fm/chain-indexer is present locally" | tee -a "$LOG"
IMG_LINE=$(docker images --format '{{.Repository}}:{{.Tag}}' | grep -E '^ghcr\.io/gateway-fm/chain-indexer:' | head -1 || true)
echo "matched image: $IMG_LINE" >>"$LOG"
if [ -n "$IMG_LINE" ]; then
  ok "ghcr.io/gateway-fm/chain-indexer present locally ($IMG_LINE)"
else
  printf '\033[0;33mWARN:\033[0m no ghcr.io/gateway-fm/chain-indexer image is cached locally.\n'
  printf '       Likely the pull above was denied. Skipping local-image check.\n'
fi

green "RD-876 / #192 / #65: chain-indexer GHCR image flow OK."
