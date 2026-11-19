#!/usr/bin/env bash
# Native V2 local stack. Only this checkout's labelled project is selected.
set -Eeuo pipefail
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
compose() {
  case "$1" in
    run) shift; "${COMPOSE[@]}" run --pull never "$@";;
    up) shift; "${COMPOSE[@]}" up --pull never --no-build "$@";;
    *) "${COMPOSE[@]}" "$@";;
  esac
}
OWNED_COUNT="$(node "$ROOT/scripts/v2-demo/ownership.mjs")"
require_prepared() {
  [ "$OWNED_COUNT" != 0 ] || { echo 'This checkout has no prepared demo. Run make demo-v2 with space for the initial build.' >&2; exit 1; }
  node "$ROOT/scripts/v2-demo/prepared.mjs" "${1:-runtime}"
}
check_prepared() {
  export OPS_TEST_BROWSER_CHANNEL="${OPS_TEST_BROWSER_CHANNEL:-chrome}"
  require_prepared browser
  node "$ROOT/scripts/v2-demo/check.mjs" "$OPS_V2_DEMO_CONTROL_DIR" "${1:-walkthrough}"
}
identity_input() {
  IDENTITY_INPUT="$(node -e 'const fs=require("fs"),p=require("path");const f=p.resolve(process.argv[1]||"");const s=fs.lstatSync(f);if(!s.isFile()||s.size>1048576||/[\r\n,:]/.test(f))process.exit(2);console.log(f)' "${1:?Supply IDENTITY_FILE with the native identity.json}")"
}
stop_failed_apply() {
  trap - ERR INT TERM
  compose stop -t 30 ops explorer-api explorer-web >/dev/null 2>&1 || true
  echo 'Config apply did not complete; affected consumers were asked to stop. The selected source is retained. Correct it or resume to retry; operational data was not reset.' >&2
}
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
  # Public certificates let browser checks pin the owned localhost leaf before
  # accepting its normal Chrome interstitial; no private key is exported.
  compose run --rm --no-deps --entrypoint cat bootstrap /demo/ca.crt > "$OPS_V2_DEMO_CONTROL_DIR/ca.crt"
  compose run --rm --no-deps --entrypoint cat bootstrap /demo/tls.crt > "$OPS_V2_DEMO_CONTROL_DIR/tls.crt"
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
  # Initial setup may download images; prepared commands never do.
  compose pull postgres reth
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
  resume) require_prepared; start_prepared;;
  check-indexer-boundary) require_prepared; compose run --rm --no-deps bootstrap check-indexer-boundary --root /demo;;
  check-login)
    export OPS_TEST_BROWSER_CHANNEL="${OPS_TEST_BROWSER_CHANNEL:-chrome}"
    require_prepared browser
    NODE_EXTRA_CA_CERTS="$OPS_V2_DEMO_CONTROL_DIR/ca.crt" node "$ROOT/scripts/v2-demo/check-demo-login.mjs" "$OPS_V2_DEMO_CONTROL_DIR";;
  check-prepared) check_prepared;;
  check-ui)
    export OPS_TEST_BROWSER_CHANNEL="${OPS_TEST_BROWSER_CHANNEL:-chrome}"
    require_prepared browser
    UI_SOURCE="$OPS_V2_DEMO_CONTROL_DIR/ui-source-$(node -e 'console.log(Date.now())')"
    node "$ROOT/scripts/v2-demo/export-config.mjs" "$UI_SOURCE"
    OPS_DEMO_SOURCE_DIR="$UI_SOURCE/core" node "$ROOT/scripts/v2-demo/check.mjs" "$OPS_V2_DEMO_CONTROL_DIR" ui-preview;;
  info) node "$ROOT/scripts/v2-demo/info.mjs";;
  check-mapping)
    case "${2:-}" in admin|reader) check_prepared "reader-${2}";; *) echo 'Expected admin or reader.' >&2; exit 2;; esac;;
  walkthrough)
    export OPS_DEMO_INTERACTIVE=1 OPS_TEST_BROWSER_CHANNEL="${OPS_TEST_BROWSER_CHANNEL:-chrome}"
    [ -t 0 ] || { echo 'Run make demo-v2-walkthrough in an interactive terminal.' >&2; exit 2; }
    require_prepared browser
    start_prepared
    node "$ROOT/scripts/v2-demo/check.mjs" "$OPS_V2_DEMO_CONTROL_DIR" walkthrough;;
  export-config) require_prepared; node "$ROOT/scripts/v2-demo/export-config.mjs" "${2:?Supply CONFIG_DIR with a new directory}";;
  check-config|apply-config)
    require_prepared
    identity_input "${2:-}"
    compose run --rm --no-deps -v "$IDENTITY_INPUT:/input/identity.json:ro" bootstrap check-identity --root /demo --wallet-output /wallet-output/wallet-state --identity-file /input/identity.json
    if [ "$1" = apply-config ]; then
      compose stop -t 30 ops explorer-api explorer-web
      trap 'stop_failed_apply; exit 1' ERR
      trap 'stop_failed_apply; exit 130' INT
      trap 'stop_failed_apply; exit 143' TERM
      compose run --rm --no-deps -v "$IDENTITY_INPUT:/input/identity.json:ro" bootstrap apply-identity --root /demo --wallet-output /wallet-output/wallet-state --identity-file /input/identity.json
      copy_runtime
      export_serving
      compose up -d --force-recreate ops explorer-api explorer-web
      compose run --rm --no-deps bootstrap wait --root /demo
      trap - ERR INT TERM
      echo 'Mappings applied. Start a fresh login in OPS and Explorer; existing renewal families may require reauthentication.'
    fi;;
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
  *) echo 'Usage: v2-demo.sh up|resume|check|check-prepared|check-ui|walkthrough|export-config DIR|check-config FILE|apply-config FILE|check-mapping admin|reader|status|down|reset|logs|repair-tls|revision on|off' >&2; exit 2;;
esac
