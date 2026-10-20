#!/usr/bin/env bash
# Bring up the privacy-mode stack in dev mode:
# - resolves sibling-repo paths (BLOCK_EXPLORER_PATH, CHAIN_INDEXER_PATH)
#   with sane defaults and validates them up-front
# - generates all required fail-closed secrets (persisted in .env.privacy.dev)
# - uses docker-compose.privacy.dev.yml (a standalone manifest, NOT an overlay
#   on docker-compose.privacy.yml — the two are siblings)
# - waits for the backend healthcheck and prints access URLs
#
# The proxy-frontend runs the Vite dev server (target: dev) with the
# repo's frontend/ bind-mounted, so VITE_ALLOW_MOCK_LOGIN and other
# import.meta.env.DEV-gated dev tooling work without a rebuild.
#
# Delete .env.privacy.dev to rotate secrets. If you do, also run
# `docker compose ... down -v` first — postgres volumes encrypted
# their contents with the old passwords and will refuse the new ones.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

ENV_FILE=".env.privacy.dev"
COMPOSE_FILE="docker-compose.privacy.dev.yml"
COMPOSE_ARGS=(-f "$COMPOSE_FILE")

color() { printf '\033[%sm%s\033[0m' "$1" "$2"; }
bold()  { color "1"      "$1"; }
green() { color "0;32"   "$1"; }
yellow(){ color "0;33"   "$1"; }
red()   { color "0;31"   "$1"; }

# Resolve sibling-repo paths. Defaults assume the standard layout where
# block-explorer and chain-indexer are checked out next to this repo.
# Override via environment if your layout differs.
BLOCK_EXPLORER_PATH="${BLOCK_EXPLORER_PATH:-../block-explorer}"
CHAIN_INDEXER_PATH="${CHAIN_INDEXER_PATH:-../chain-indexer}"

missing=()
[ -d "$BLOCK_EXPLORER_PATH/backend" ] || missing+=("BLOCK_EXPLORER_PATH ($BLOCK_EXPLORER_PATH/backend not found)")
[ -d "$CHAIN_INDEXER_PATH" ]          || missing+=("CHAIN_INDEXER_PATH ($CHAIN_INDEXER_PATH not found)")
if (( ${#missing[@]} )); then
  echo "$(red 'Missing sibling repos:')"
  printf '  - %s\n' "${missing[@]}"
  echo
  echo 'Either clone these as siblings of this repo, or export'
  echo 'BLOCK_EXPLORER_PATH / CHAIN_INDEXER_PATH to point at your checkouts.'
  exit 1
fi
export BLOCK_EXPLORER_PATH CHAIN_INDEXER_PATH

# Auto-include an optional local compose override. Passing -f above disables
# Docker Compose's usual auto-merge of docker-compose.override.yml, so a local
# override would otherwise only apply if hand-passed with a second -f. Picking
# it up here keeps `make full-stack-dev` a single command while letting a dev
# layer a CONFIG_FILE mount + extra env (operator token, Azure, …) on top.
# Gitignored (docker-compose.*.override.yml); copy the .example to start.
OVERRIDE_FILE="docker-compose.privacy.dev.override.yml"
if [[ -f "$OVERRIDE_FILE" ]]; then
  COMPOSE_ARGS+=(-f "$OVERRIDE_FILE")
  echo "$(bold '==>') $(green "Including local compose override: $OVERRIDE_FILE")"
fi

echo "$(bold '==>') $(yellow 'Stopping any existing privacy stack')"
docker compose "${COMPOSE_ARGS[@]}" down --remove-orphans 2>/dev/null || true

# Ensure every required secret exists in $ENV_FILE, generating only the ones
# that are MISSING and preserving everything already present — including secrets
# an operator added by hand (AZURE_AD_CLIENT_SECRET, AUDIT_CHECKPOINT_KEY, …).
# Idempotent, so `make full-stack-dev` is a single command no matter what's
# already in the file, and a partially-populated file can no longer silently
# miss a base secret. (The old all-or-nothing generate/reuse split did exactly
# that; its unquoted heredoc also tripped `set -u` on the SSO_* comment refs.)
umask 077
if [[ ! -f "$ENV_FILE" ]]; then
  cat > "$ENV_FILE" <<'HEADER'
# Managed by scripts/privacy-dev-up.sh — missing secrets are appended on each run.
# Gitignored via .env.* rule. Delete to rotate ALL secrets (then also run
# 'docker compose ... down -v' to drop postgres volumes). Operator-added keys
# (e.g. AZURE_AD_CLIENT_SECRET) are preserved across runs.
HEADER
fi

_generated=()
# ensure_secret KEY VALUE — append KEY=VALUE only when KEY is not already set.
ensure_secret() {
  if ! grep -qE "^$1=" "$ENV_FILE"; then
    printf '%s=%s\n' "$1" "$2" >>"$ENV_FILE"
    _generated+=("$1")
  fi
}

ensure_secret PRIVACY_POSTGRES_PASSWORD        "$(openssl rand -hex 32)"
# RD-1147: password for the restricted audit-DB runtime role (privacy_proxy_app).
# The container's init hook (scripts/init-audit-db.sh) provisions the role with
# this password; the backend's AUDIT_DATABASE_URL connects as it so the
# access_logs append-only seal is enforced in dev.
ensure_secret AUDIT_APP_PASSWORD               "$(openssl rand -hex 32)"
ensure_secret INDEXER_POSTGRES_PASSWORD        "$(openssl rand -hex 32)"
ensure_secret BLOCK_EXPLORER_POSTGRES_PASSWORD "$(openssl rand -hex 32)"
ensure_secret REDIS_PASSWORD                   "$(openssl rand -hex 32)"
ensure_secret JWT_SECRET                       "$(openssl rand -hex 32)"
ensure_secret JWT_REFRESH_SECRET               "$(openssl rand -hex 32)"
ensure_secret ADMIN_API_TOKEN                  "$(openssl rand -hex 32)"

# RD-993 + RD-1006: silent-SSO first-party client (block-explorer). The client
# id, secret, and its bcrypt hash are a linked unit, so (re)generate all three
# together and only when the allowlist entry is absent. htpasswd is the portable
# bcrypt CLI (Apache utils; preinstalled on macOS, `apt install apache2-utils`
# on Debian) — needed only for this step. The value is single-quoted because the
# bcrypt hash contains `$`, which `source` (below) would otherwise mangle.
if ! grep -qE '^OAUTH_FIRST_PARTY_CLIENTS=' "$ENV_FILE"; then
  if ! command -v htpasswd >/dev/null 2>&1; then
    echo "$(red 'ERROR') htpasswd not found — install apache2-utils (Linux) or use the bundled macOS Apache utils. Required to hash the SSO client secret for OAUTH_FIRST_PARTY_CLIENTS." >&2
    exit 1
  fi
  sso_client_id="explorer"
  sso_client_secret="$(openssl rand -hex 32)"
  sso_client_hash="$(htpasswd -bnBC 12 '' "$sso_client_secret" | tr -d ':\n')"
  {
    printf 'SSO_CLIENT_ID=%s\n' "$sso_client_id"
    printf 'SSO_CLIENT_SECRET=%s\n' "$sso_client_secret"
    printf "OAUTH_FIRST_PARTY_CLIENTS='%s:%s'\n" "$sso_client_id" "$sso_client_hash"
  } >>"$ENV_FILE"
  _generated+=(SSO_CLIENT_ID SSO_CLIENT_SECRET OAUTH_FIRST_PARTY_CLIENTS)
fi
umask 022

if (( ${#_generated[@]} )); then
  echo "$(bold '==>') $(green "Generated missing secrets in $ENV_FILE:") ${_generated[*]}"
else
  echo "$(bold '==>') $(green "All required secrets already present in $ENV_FILE")"
fi

# Export the secrets so docker compose picks them up.
set -a
# shellcheck disable=SC1090
source "$ENV_FILE"
set +a

# Make Docker Compose auto-load these secrets without going through this
# script. Compose only reads a file literally named `.env` for ${VAR}
# interpolation — it does NOT know about $ENV_FILE. Without a `.env`, any
# `docker compose up` outside this script re-runs interpolation with the
# vars unset and trips the fail-closed `${INDEXER_POSTGRES_PASSWORD:?...}`
# guards. The most common offender is Docker Desktop's start/play button,
# which re-runs `up` (not a bare `docker start`) every time — so without
# this, the UI button is broken for everyone, not just the first dev.
#
# Point `.env` at $ENV_FILE so the button (and a plain `docker compose up`)
# just work. Trade-off: `.env` is auto-loaded by EVERY compose file in this
# dir (base, prod, scale, e2e), so they'll now see these dev secrets too —
# acceptable on a dev box, and the reason the secrets live in a
# stack-specific file rather than `.env` in the first place.
#
# A symlink (or absent `.env`) is ours to manage and we repoint it freely
# — that also self-heals after a secret rotation. A *regular* `.env` is
# someone's hand-rolled config; never clobber it, just tell them how to opt in.
if [[ -L ".env" || ! -e ".env" ]]; then
  ln -sf "$ENV_FILE" .env
  echo "$(bold '==>') $(green "Linked .env -> $ENV_FILE") (Docker Desktop's start button will work)"
else
  echo "$(bold '==>') $(yellow 'A real .env already exists — leaving it untouched.')"
  echo "      Docker Desktop's start button can't resolve privacy secrets until .env"
  echo "      provides them. To opt in:  ln -sf $ENV_FILE .env"
fi

# Build identity (RD-1023). Resolve from git unless already set by the
# caller (e.g. the Makefile exports these), so the backend reports a real
# version/commit instead of dev/none/unknown. Forwarded to the compose
# `args:` blocks. Falls back to safe defaults when git is unavailable.
export VERSION="${VERSION:-$(git describe --tags --always --dirty 2>/dev/null || echo dev)}"
export GIT_COMMIT="${GIT_COMMIT:-$(git rev-parse --short HEAD 2>/dev/null || echo none)}"
export BUILD_TIME="${BUILD_TIME:-$(date -u +%Y-%m-%dT%H:%M:%SZ)}"

# block-explorer build identity. block-explorer stamps its own binary
# (backend/Dockerfile.api ARGs, surfaced at /version + UI footer); its version
# comes from block-explorer's OWN git tree — a different value than the proxy's.
# Resolved from $BLOCK_EXPLORER_PATH so the explorer-api build args carry the
# explorer's real tag/commit, not the proxy's.
BE_PATH="${BLOCK_EXPLORER_PATH:-../block-explorer}"
export BLOCK_EXPLORER_VERSION="${BLOCK_EXPLORER_VERSION:-$(git -C "$BE_PATH" describe --tags --always --dirty 2>/dev/null || echo dev)}"
export BLOCK_EXPLORER_GIT_COMMIT="${BLOCK_EXPLORER_GIT_COMMIT:-$(git -C "$BE_PATH" rev-parse --short HEAD 2>/dev/null || echo none)}"
export BLOCK_EXPLORER_BUILD_TIME="${BLOCK_EXPLORER_BUILD_TIME:-$(date -u +%Y-%m-%dT%H:%M:%SZ)}"

echo "$(bold '==>') $(green 'Starting privacy stack in dev mode')"
echo "      privacy-proxy:  $VERSION / $GIT_COMMIT"
echo "      block-explorer: $BLOCK_EXPLORER_VERSION / $BLOCK_EXPLORER_GIT_COMMIT"
docker compose "${COMPOSE_ARGS[@]}" up -d --build

echo "$(bold '==>') Waiting for proxy-backend to become healthy…"
healthy=0
for _ in $(seq 1 60); do
  status="$(docker inspect --format='{{.State.Health.Status}}' \
    "$(docker compose "${COMPOSE_ARGS[@]}" ps -q proxy-backend)" 2>/dev/null || echo starting)"
  if [[ "$status" == "healthy" ]]; then
    healthy=1
    break
  fi
  sleep 2
done
if [[ "$healthy" -eq 1 ]]; then
  echo "    $(green 'Backend healthy.')"
else
  echo "    $(red 'Backend did not reach healthy state in 120s.') Check:"
  echo "      docker compose ${COMPOSE_ARGS[*]} logs proxy-backend"
fi

cat <<EOF

$(bold '================================================================')
$(bold 'Privacy stack is up — DEV MODE (mock auth enabled).')

  Open Privacy Suite backend:   http://localhost:${HOST_PORT_PROXY:-8080}
  Open Privacy Suite frontend:  http://localhost:${HOST_PORT_UI:-5173}
  Block-explorer frontend: http://localhost:${HOST_PORT_EXPLORER:-3001}

$(yellow 'Mock login') — open the Open Privacy Suite frontend, click through to
the login page, use "Mock Login (Skip Wallet)" or the dev identity
picker. Signature verification is disabled; do NOT deploy this manifest
to anything customer-facing.

Stop the stack with:
  docker compose ${COMPOSE_ARGS[*]} down

Wipe data (postgres volumes, indexer state, etc.):
  docker compose ${COMPOSE_ARGS[*]} down -v
$(bold '================================================================')
EOF
