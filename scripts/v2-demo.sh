#!/usr/bin/env bash
# Native V2 local stack. Only this checkout's labelled project is selected.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
command -v docker >/dev/null || { echo 'Docker is required.' >&2; exit 1; }
command -v node >/dev/null || { echo 'Node24 is required; see the V2 test prerequisites.' >&2; exit 1; }
# Public images use an isolated auth-free config; never consult macOS Keychain.
DOCKER_SELECTION="$(node "$ROOT/scripts/v2-demo/docker-env.mjs")"
export DOCKER_CONFIG="$(printf '%s' "$DOCKER_SELECTION" | node -e 'let v="";process.stdin.on("data",x=>v+=x).on("end",()=>console.log(JSON.parse(v).directory))')"
export DOCKER_HOST="$(printf '%s' "$DOCKER_SELECTION" | node -e 'let v="";process.stdin.on("data",x=>v+=x).on("end",()=>console.log(JSON.parse(v).host))')"
unset DOCKER_CONTEXT DOCKER_TLS_VERIFY DOCKER_CERT_PATH DOCKER_AUTH_CONFIG
docker compose version >/dev/null
export OPS_V2_DEMO_PROJECT="${OPS_V2_DEMO_PROJECT:-ops-v2-demo-$(printf '%s' "$ROOT" | cksum | awk '{print $1}')}"
case "$OPS_V2_DEMO_PROJECT" in
  *[!a-z0-9_-]*|[!a-z0-9]*|'') echo 'Invalid OPS_V2_DEMO_PROJECT.' >&2; exit 2;;
esac
export OPS_V2_DEMO_ROOT="$ROOT"
export OPS_V2_DEMO_CONTROL_DIR="$ROOT/.tmp/v2-demo/$OPS_V2_DEMO_PROJECT"
mkdir -p "$OPS_V2_DEMO_CONTROL_DIR"
for file in ports postgres ops observer indexer explorer explorer-admin; do
  touch "$OPS_V2_DEMO_CONTROL_DIR/$file.env"
  chmod 600 "$OPS_V2_DEMO_CONTROL_DIR/$file.env"
done
COMPOSE=(docker compose --env-file "$OPS_V2_DEMO_CONTROL_DIR/ports.env" -p "$OPS_V2_DEMO_PROJECT" -f "$ROOT/deploy/v2-demo/compose.yml")
compose() { "${COMPOSE[@]}" "$@"; }
OWNED_COUNT="$(node "$ROOT/scripts/v2-demo/ownership.mjs")"
dependencies() {
  node "$ROOT/scripts/v2-demo/dependencies.mjs" "$OPS_V2_DEMO_CONTROL_DIR/dependencies.json"
  OPS_V2_DEMO_EXPLORER_SOURCE="$(node -e 'console.log(JSON.parse(require("fs").readFileSync(process.argv[1])).dependencies.explorer.directory)' "$OPS_V2_DEMO_CONTROL_DIR/dependencies.json")"
  OPS_V2_DEMO_INDEXER_SOURCE="$(node -e 'console.log(JSON.parse(require("fs").readFileSync(process.argv[1])).dependencies.indexer.directory)' "$OPS_V2_DEMO_CONTROL_DIR/dependencies.json")"
  export OPS_V2_DEMO_EXPLORER_SOURCE OPS_V2_DEMO_INDEXER_SOURCE
}
copy_runtime() {
  compose run --rm --no-deps --entrypoint cat bootstrap /demo/compose.env > "$OPS_V2_DEMO_CONTROL_DIR/ports.env"
  for file in postgres ops observer indexer explorer explorer-admin; do
    case "$file" in
      postgres|explorer-admin) source="/demo/private/$file.env";;
      indexer) source=/demo/indexer.env;;
      *) source="/demo/$file/env";;
    esac
    temporary="$OPS_V2_DEMO_CONTROL_DIR/$file.env.next"
    compose run --rm --no-deps --entrypoint cat bootstrap "$source" > "$temporary"
    chmod 600 "$temporary"
    mv "$temporary" "$OPS_V2_DEMO_CONTROL_DIR/$file.env"
  done
}
export_serving() { compose run --rm --no-deps --user 0 --entrypoint sh bootstrap /opt/v2-demo/export.sh; }
copy_public() {
  compose run --rm --no-deps --entrypoint cat bootstrap /demo/runtime.json > "$OPS_V2_DEMO_CONTROL_DIR/runtime.json"
  compose run --rm --no-deps --entrypoint cat bootstrap /wallet-output/wallet-state/metadata.json > "$OPS_V2_DEMO_CONTROL_DIR/wallet-metadata.json"
}
stop_serving() {
  # Keep Postgres available until serving requests and observer leases drain.
  compose stop -t 30 ops explorer-api explorer-web
  compose stop -t 30 observer indexer demo-wallet reth
}
up() {
  dependencies
  npm ci --prefix tools/v2-test-wallet --ignore-scripts
  node scripts/v2-test-prerequisites.mjs
  # Go builds are intentionally sequential, including sibling repositories.
  compose build bootstrap
  compose run --rm --no-deps bootstrap init --root /demo
  compose run --rm --no-deps --entrypoint cat bootstrap /demo/compose.env > "$OPS_V2_DEMO_CONTROL_DIR/ports.env"
  compose run --rm --no-deps --entrypoint cat bootstrap /demo/private/postgres.env > "$OPS_V2_DEMO_CONTROL_DIR/postgres.env"
  export_serving
  compose build ops
  compose build explorer-api
  compose build indexer
  start_prepared
}
start_prepared() {
  # Reload selected files and process-local CA pools together. State stays in
  # the owned volumes; a repeated up deliberately restarts serving processes.
  compose stop -t 30 ops explorer-api explorer-web
  compose run --rm --no-deps --user 0 --entrypoint sh bootstrap -ec 'mkdir -p /circuits; cp -R /host-circuits/. /circuits/; chown -R 1000:1000 /circuits; find /circuits -type f -exec chmod 644 {} \;'
  compose up -d --wait --wait-timeout 90 postgres
  compose up -d --force-recreate --wait --wait-timeout 90 demo-wallet
  compose up -d reth
  compose run --rm --no-deps --entrypoint node bootstrap scripts/v2-demo/wait-rpc.mjs
  compose run --rm --no-deps bootstrap configure --root /demo --prepare-databases
  compose run --rm --no-deps --entrypoint cat bootstrap /demo/indexer.env > "$OPS_V2_DEMO_CONTROL_DIR/indexer.env"
  compose up -d indexer
  compose run --rm --no-deps bootstrap configure --root /demo --wallet-output /wallet-output/wallet-state
  copy_runtime
  export_serving
  compose run --rm --no-deps explorer-admin
  if ! compose run --rm --no-deps bootstrap explorer-state --root /demo > "$OPS_V2_DEMO_CONTROL_DIR/explorer-state.log" 2>&1; then
    compose run --rm --no-deps explorer-admin 'exec sso-v2-admin --source /demo/explorer/source.json --sha256 "$(cat /demo/explorer/source.sha256)" --action initialize'
  fi
  compose run --rm --no-deps bootstrap explorer-state --root /demo
  compose up -d observer
  compose up -d --force-recreate ops explorer-api explorer-web
  compose run --rm --no-deps bootstrap wait --root /demo
  copy_public
  compose run --rm --no-deps --entrypoint cat bootstrap /demo/urls.txt
}
case "${1:-up}" in
  build-bootstrap) compose build bootstrap;;
  build-runtime) compose build ops; compose build explorer-api; compose build indexer;;
  build-indexer) compose build indexer;;
  build-ops) compose build ops;;
  resume) [ "$OWNED_COUNT" != 0 ]; start_prepared;;
  repair-tls)
    [ "$OWNED_COUNT" != 0 ] || { echo 'Run demo up first.' >&2; exit 1; }
    compose stop -t 30 ops explorer-api explorer-web demo-wallet
    compose run --rm --no-deps bootstrap repair-tls --root /demo
    export_serving
    start_prepared;;
  up) up;;
  check)
    up
    npm ci --prefix e2e/playwright --ignore-scripts
    export OPS_TEST_BROWSER_CHANNEL="${OPS_TEST_BROWSER_CHANNEL:-chromium}"
    if [ "$OPS_TEST_BROWSER_CHANNEL" = chromium ]; then ./e2e/playwright/node_modules/.bin/playwright install chromium; fi
    node "$ROOT/scripts/v2-demo/check.mjs" "$OPS_V2_DEMO_CONTROL_DIR";;
  barrier) compose run --rm --no-deps bootstrap check --root /demo --transaction "${2:?transaction required}" --receipt-block "${3:?block required}" --contract "${4:?contract required}";;
  status) if [ "$OWNED_COUNT" = 0 ]; then echo 'This checkout has no V2 demo resources.'; else compose ps -a; compose run --rm --no-deps bootstrap status --root /demo; fi;;
  down) if [ "$OWNED_COUNT" != 0 ]; then stop_serving; compose down --remove-orphans; fi;;
  reset) if [ "$OWNED_COUNT" != 0 ]; then stop_serving; compose down --volumes --remove-orphans; fi;;
  logs) compose logs -f;;
  revision)
    [ "$OWNED_COUNT" != 0 ] || { echo 'Run demo up first.' >&2; exit 1; }
    compose stop ops
    compose run --rm --no-deps bootstrap revision --root /demo --reader-grant "${2:-off}" --wallet-output /wallet-output/wallet-state
    copy_runtime
    export_serving
    compose up -d --force-recreate ops
    compose run --rm --no-deps bootstrap wait --root /demo;;
  *) echo 'Usage: v2-demo.sh up|check|status|down|reset|logs|repair-tls|revision [on|off]' >&2; exit 2;;
esac
