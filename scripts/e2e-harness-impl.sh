#!/usr/bin/env bash
# Run every end-to-end lane without sharing Docker Compose resources with
# developer stacks or other harness runs.

set -Eeuo pipefail
IFS=$'\n\t'

readonly SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly REPO_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd)"
readonly PRIVACY_COMPOSE_OVERRIDE="${REPO_ROOT}/docker-compose.privacy.e2e.yml"
readonly DEFAULT_BLOCK_EXPLORER_REPO="https://github.com/gateway-fm/ops-explorer.git"
readonly DEFAULT_BLOCK_EXPLORER_REF="v0.9.0-rc.1"
readonly DEFAULT_BLOCK_EXPLORER_SHA="6910cf0a64229e283ca3f5ce1a4fb995581bd2d9"
readonly DEFAULT_CHAIN_INDEXER_REPO="https://github.com/gateway-fm/ops-indexer.git"
readonly DEFAULT_CHAIN_INDEXER_REF="v0.4.0-rc.1"
readonly DEFAULT_CHAIN_INDEXER_SHA="e4af8a606bac23ae9731e52b3e4aa119ee9bb915"

usage() {
  cat <<'USAGE'
Usage: scripts/e2e-harness.sh MODE [OPTIONS]

Modes:
  preflight [MODE] Fast, non-mutating host-capability check (handled by launcher)
  all              Run Go (default and mockauth), Playwright, and privacy E2E
  go               Run both Go E2E build-tag lanes
  go-default       Run the untagged Go E2E lane
  go-mockauth      Run the mockauth-tagged Go E2E lane
  playwright       Run browser E2E in an isolated Compose project
  privacy          Run the privacy-bypass E2E in an isolated Compose project
  chaos            Inject process faults into this run's Playwright stack
  soak             Repeat an existing suite for a fixed duration
  doctor           Check prerequisites and validate both Compose manifests
  down             Remove only the artifact-owned harness projects

Options:
  --run-id ID              Run identifier (default: UTC timestamp + pid + random)
  --project NAME           Compose project base (env: E2E_PROJECT)
  --artifact-dir DIR       Full run output directory (env: E2E_ARTIFACT_DIR)
  --suite MODE             Suite repeated by soak (default: all)
  --duration DURATION      Soak/chaos target duration (chaos always faults each service once)
  --interval DURATION      Delay between chaos cycles (default: 30s)
  --keep-stack             Do not tear down the Playwright stack on exit
  --dry-run                Print commands without executing them
  -h, --help               Show this help

Canonical environment variables:
  E2E_RUN_ID, E2E_PROJECT, E2E_PRIVACY_PROJECT, E2E_ARTIFACT_DIR,
  E2E_KEEP_STACK, E2E_SOAK_DURATION, E2E_SOAK_SUITE,
  E2E_PLAYWRIGHT_RESULTS_DIR, E2E_PLAYWRIGHT_REPORT_DIR,
  E2E_GO_MAX_PROCS, E2E_GO_TEST_PARALLELISM, E2E_PLAYWRIGHT_WORKERS, E2E_COMPOSE_PARALLEL_LIMIT,
  E2E_BLOCK_EXPLORER_PATH, E2E_CHAIN_INDEXER_PATH,
  E2E_BLOCK_EXPLORER_REF, E2E_CHAIN_INDEXER_REF,
  E2E_BLOCK_EXPLORER_REPOSITORY, E2E_CHAIN_INDEXER_REPOSITORY

Chaos tuning:
  E2E_CHAOS_DURATION (default 10m), E2E_CHAOS_INTERVAL (default 30s),
  E2E_CHAOS_HOLD (default 5s), E2E_CHAOS_SERVICES (space-separated),
  E2E_HEALTH_TIMEOUT (default 3m)

Examples:
  scripts/e2e-harness.sh preflight all
  scripts/e2e-harness.sh doctor
  scripts/e2e-harness.sh all
  scripts/e2e-harness.sh soak --suite go --duration 8h
  scripts/e2e-harness.sh chaos --duration 30m --interval 20s
  E2E_RUN_ID=my-run scripts/e2e-harness.sh down
USAGE
}

die() {
  printf 'e2e-harness: ERROR: %s\n' "$*" >&2
  exit 1
}

note() {
  printf 'e2e-harness: %s\n' "$*"
}

is_true() {
  case "${1:-}" in
    1|true|TRUE|yes|YES|on|ON) return 0 ;;
    *) return 1 ;;
  esac
}

duration_seconds() {
  local value="$1"
  local number unit multiplier=1
  [[ "$value" =~ ^([0-9]+)([smhd]?)$ ]] || return 1
  number=$(( 10#${BASH_REMATCH[1]} ))
  unit="${BASH_REMATCH[2]}"
  case "$unit" in
    s|"") multiplier=1 ;;
    m) multiplier=60 ;;
    h) multiplier=3600 ;;
    d) multiplier=86400 ;;
  esac
  printf "%s\n" "$(( number * multiplier ))"
}

validate_duration() {
  local label="$1"
  local value="$2"
  local seconds
  seconds="$(duration_seconds "$value")" || die "$label must be an integer followed by s, m, h, or d (got: $value)"
  (( seconds > 0 )) || die "$label must be greater than zero"
  printf '%s\n' "$seconds"
}

validate_run_id() {
  [[ "$1" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]{0,79}$ ]] ||
    die "run ID must start with an alphanumeric and contain only alphanumerics, dot, underscore, or hyphen"
}

validate_project() {
  local value="$1"
  [[ "$value" =~ ^[a-z0-9][a-z0-9_-]*$ ]] ||
    die "Compose project must be lowercase and contain only a-z, 0-9, underscore, or hyphen (got: $value)"
  (( ${#value} <= 63 )) || die "Compose project must be at most 63 characters (got ${#value})"
}

validate_harness_identity_file() {
  local file="$1"
  local label="$2"
  local actual_run_id="" actual_project="" actual_privacy_project="" key value
  [[ -f "$file" ]] || die "${label} is missing: ${file}"
  while IFS="=" read -r key value; do
    case "$key" in
      run_id) actual_run_id="$value" ;;
      project) actual_project="$value" ;;
      privacy_project) actual_privacy_project="$value" ;;
    esac
  done < "$file"
  if [[ "$actual_run_id" != "$RUN_ID" || "$actual_project" != "$PROJECT" || "$actual_privacy_project" != "$PRIVACY_PROJECT" ]]; then
    die "${label} does not match run=${RUN_ID}, project=${PROJECT}, privacy_project=${PRIVACY_PROJECT}: ${file}"
  fi
}
run_metadata_value() {
  local file="$1"
  local wanted="$2"
  local key value
  [[ -f "$file" ]] || return 1
  while IFS="=" read -r key value; do
    if [[ "$key" == "$wanted" ]]; then
      printf '%s\n' "$value"
      return 0
    fi
  done < "$file"
  return 1
}

project_owner_marker() {
  case "$1" in
    base) printf "%s\n" "${ARTIFACT_DIR}/.base-project-owner" ;;
    privacy) printf "%s\n" "${ARTIFACT_DIR}/.privacy-project-owner" ;;
    *) die "unknown project marker scope: $1" ;;
  esac
}

mark_project_owned() {
  (( DRY_RUN == 0 )) || return 0
  local scope="$1"
  local kind="$2"
  local marker
  marker="$(project_owner_marker "$scope")"
  if ! (
    set -o noclobber
    {
      printf "run_id=%s\n" "$RUN_ID"
      printf "project=%s\n" "$PROJECT"
      printf "privacy_project=%s\n" "$PRIVACY_PROJECT"
      printf "kind=%s\n" "$kind"
    } > "$marker"
  ) 2>/dev/null; then
    die "project ownership marker already exists: ${marker}"
  fi
}

clear_project_owned() {
  (( DRY_RUN == 0 )) || return 0
  local marker
  marker="$(project_owner_marker "$1")"
  rm -f -- "$marker"
}

load_active_project_markers() {
  local marker key value kind
  BASE_PROJECT_OWNED=0
  PRIVACY_PROJECT_OWNED=0

  marker="$(project_owner_marker base)"
  if [[ -f "$marker" ]]; then
    validate_harness_identity_file "$marker" "base-project ownership marker"
    kind=""
    while IFS="=" read -r key value; do
      [[ "$key" != "kind" ]] || kind="$value"
    done < "$marker"
    [[ "$kind" == "go" || "$kind" == "playwright" ]] || die "invalid base-project stack kind in ${marker}"
    BASE_PROJECT_OWNED=1
    BASE_STACK_KIND="$kind"
  fi

  marker="$(project_owner_marker privacy)"
  if [[ -f "$marker" ]]; then
    validate_harness_identity_file "$marker" "privacy-project ownership marker"
    kind=""
    while IFS="=" read -r key value; do
      [[ "$key" != "kind" ]] || kind="$value"
    done < "$marker"
    [[ "$kind" == "privacy" ]] || die "invalid privacy-project stack kind in ${marker}"
    PRIVACY_PROJECT_OWNED=1
  fi
}
acquire_project_lock() {
  local project="$1"
  local lock_dir="/tmp/privacy-proxy-e2e-project-locks"
  local lock_file="${lock_dir}/${project}.lock"
  local fd
  command -v flock >/dev/null 2>&1 || die "flock is required for shared-host E2E project locking"
  mkdir -p -- "$lock_dir"
  exec {fd}>"$lock_file"
  if ! flock --nonblock "$fd"; then
    exec {fd}>&-
    die "another harness process holds Compose project lock: ${project}"
  fi
  PROJECT_LOCK_FDS+=("$fd")
}

release_project_locks() {
  local index fd
  for (( index=${#PROJECT_LOCK_FDS[@]}-1; index >= 0; index-- )); do
    fd="${PROJECT_LOCK_FDS[$index]}"
    exec {fd}>&-
  done
  PROJECT_LOCK_FDS=()
}

acquire_mode_project_locks() {
  (( DRY_RUN == 0 )) || return 0
  case "$MODE" in
    all|soak)
      acquire_project_lock "$PROJECT"
      acquire_project_lock "$PRIVACY_PROJECT"
      ;;
    go|go-default|go-mockauth|playwright|chaos)
      acquire_project_lock "$PROJECT"
      ;;
    privacy)
      acquire_project_lock "$PRIVACY_PROJECT"
      ;;
    down)
      (( BASE_PROJECT_OWNED == 0 )) || acquire_project_lock "$PROJECT"
      (( PRIVACY_PROJECT_OWNED == 0 )) || acquire_project_lock "$PRIVACY_PROJECT"
      ;;
  esac
}

default_run_id() {
  printf '%s-%s-%05d\n' "$(date -u +%Y%m%dT%H%M%SZ)" "$$" "$(( RANDOM % 100000 ))"
}

project_slug() {
  local value="${1,,}"
  value="${value//./-}"
  value="${value//_/-}"
  value="${value//[^a-z0-9-]/-}"
  value="${value:0:38}"
  value="${value%-}"
  printf '%s\n' "$value"
}

MODE="${1:-all}"
if [[ "$MODE" != -* ]]; then
  shift || true
else
  MODE="all"
fi

RUN_ID="${E2E_RUN_ID:-}"
RUN_ID_EXPLICIT=0
[[ -n "${E2E_RUN_ID:-}" ]] && RUN_ID_EXPLICIT=1
PROJECT="${E2E_PROJECT:-}"
PRIVACY_PROJECT="${E2E_PRIVACY_PROJECT:-}"
ARTIFACT_DIR="${E2E_ARTIFACT_DIR:-}"
E2E_BLOCK_EXPLORER_PATH="${E2E_BLOCK_EXPLORER_PATH:-}"
E2E_CHAIN_INDEXER_PATH="${E2E_CHAIN_INDEXER_PATH:-}"
BLOCK_EXPLORER_PATH_SUPPLIED=0
CHAIN_INDEXER_PATH_SUPPLIED=0
[[ -n "$E2E_BLOCK_EXPLORER_PATH" ]] && BLOCK_EXPLORER_PATH_SUPPLIED=1
[[ -n "$E2E_CHAIN_INDEXER_PATH" ]] && CHAIN_INDEXER_PATH_SUPPLIED=1
BLOCK_EXPLORER_REF="${E2E_BLOCK_EXPLORER_REF:-$DEFAULT_BLOCK_EXPLORER_REF}"
CHAIN_INDEXER_REF="${E2E_CHAIN_INDEXER_REF:-$DEFAULT_CHAIN_INDEXER_REF}"
BLOCK_EXPLORER_REPOSITORY="${E2E_BLOCK_EXPLORER_REPOSITORY:-$DEFAULT_BLOCK_EXPLORER_REPO}"
CHAIN_INDEXER_REPOSITORY="${E2E_CHAIN_INDEXER_REPOSITORY:-$DEFAULT_CHAIN_INDEXER_REPO}"
[[ "$BLOCK_EXPLORER_REF" != *$'\n'* ]] || die "E2E_BLOCK_EXPLORER_REF must not contain a newline"
[[ "$CHAIN_INDEXER_REF" != *$'\n'* ]] || die "E2E_CHAIN_INDEXER_REF must not contain a newline"
[[ "$BLOCK_EXPLORER_REPOSITORY" != *$'\n'* ]] || die "E2E_BLOCK_EXPLORER_REPOSITORY must not contain a newline"
[[ "$CHAIN_INDEXER_REPOSITORY" != *$'\n'* ]] || die "E2E_CHAIN_INDEXER_REPOSITORY must not contain a newline"
KEEP_STACK=0
DRY_RUN=0
is_true "${E2E_KEEP_STACK:-}" && KEEP_STACK=1
is_true "${E2E_DRY_RUN:-}" && DRY_RUN=1
SOAK_SUITE="${E2E_SOAK_SUITE:-all}"
SOAK_DURATION="${E2E_SOAK_DURATION:-1h}"
CHAOS_DURATION="${E2E_CHAOS_DURATION:-10m}"
CHAOS_INTERVAL="${E2E_CHAOS_INTERVAL:-30s}"
GO_MAX_PROCS="${E2E_GO_MAX_PROCS:-2}"
GO_TEST_PARALLELISM="${E2E_GO_TEST_PARALLELISM:-1}"
PLAYWRIGHT_WORKERS="${E2E_PLAYWRIGHT_WORKERS:-1}"
COMPOSE_PARALLEL_LIMIT="${E2E_COMPOSE_PARALLEL_LIMIT:-1}"
for resource_limit in "$GO_MAX_PROCS" "$GO_TEST_PARALLELISM" "$PLAYWRIGHT_WORKERS" "$COMPOSE_PARALLEL_LIMIT"; do
  [[ "$resource_limit" =~ ^[1-9][0-9]*$ ]] || die "resource concurrency limits must be positive integers"
done
BASE_PROJECT_OWNED=0
PRIVACY_PROJECT_OWNED=0
BASE_STACK_KIND=""
PROJECT_LOCK_FDS=()

while (( $# > 0 )); do
  case "$1" in
    --run-id)
      (( $# >= 2 )) || die "--run-id requires a value"
      RUN_ID="$2"
      RUN_ID_EXPLICIT=1
      shift 2
      ;;
    --project)
      (( $# >= 2 )) || die "--project requires a value"
      PROJECT="$2"
      shift 2
      ;;
    --artifact-dir|--artifacts)
      (( $# >= 2 )) || die "$1 requires a value"
      ARTIFACT_DIR="$2"
      shift 2
      ;;
    --suite)
      (( $# >= 2 )) || die "--suite requires a value"
      SOAK_SUITE="$2"
      shift 2
      ;;
    --duration)
      (( $# >= 2 )) || die "--duration requires a value"
      if [[ "$MODE" == "chaos" ]]; then
        CHAOS_DURATION="$2"
      else
        SOAK_DURATION="$2"
      fi
      shift 2
      ;;
    --interval)
      (( $# >= 2 )) || die "--interval requires a value"
      CHAOS_INTERVAL="$2"
      shift 2
      ;;
    --keep-stack)
      KEEP_STACK=1
      shift
      ;;
    --dry-run)
      DRY_RUN=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *) die "unknown option: $1" ;;
  esac
done

case "$MODE" in
  all|go|go-default|go-mockauth|playwright|privacy|privacy-bypass|chaos|soak|doctor|down) ;;
  *) usage >&2; die "unknown mode: $MODE" ;;
esac

[[ "$MODE" != "privacy-bypass" ]] || MODE="privacy"

if [[ -z "$RUN_ID" ]]; then
  RUN_ID="$(default_run_id)"
fi
validate_run_id "$RUN_ID"

if [[ -z "$PROJECT" ]]; then
  PROJECT="privacy-proxy-e2e-$(project_slug "$RUN_ID")"
fi
validate_project "$PROJECT"

if [[ -z "$PRIVACY_PROJECT" ]]; then
  if (( ${#PROJECT} > 55 )); then
    PRIVACY_PROJECT="${PROJECT:0:55}-privacy"
  else
    PRIVACY_PROJECT="${PROJECT}-privacy"
  fi
fi
validate_project "$PRIVACY_PROJECT"
[[ "$PROJECT" != "$PRIVACY_PROJECT" ]] || die "E2E_PROJECT and E2E_PRIVACY_PROJECT must be different"

if [[ "$MODE" == "down" && "$RUN_ID_EXPLICIT" -eq 0 ]]; then
  die "down requires the original explicit E2E_RUN_ID (and E2E_ARTIFACT_DIR if customized); refusing to guess a cleanup target"
fi

if [[ -z "$ARTIFACT_DIR" ]]; then
  ARTIFACT_DIR="${REPO_ROOT}/.tmp/e2e-runs/${RUN_ID}"
elif [[ "$ARTIFACT_DIR" != /* ]]; then
  ARTIFACT_DIR="${REPO_ROOT}/${ARTIFACT_DIR}"
fi

if [[ "$MODE" == "down" ]]; then
  validate_harness_identity_file "${ARTIFACT_DIR}/.harness-owner" "harness ownership marker"
  validate_harness_identity_file "${ARTIFACT_DIR}/run.env" "harness run metadata"
  load_active_project_markers
  if [[ -z "$E2E_BLOCK_EXPLORER_PATH" ]]; then
    E2E_BLOCK_EXPLORER_PATH="$(run_metadata_value "${ARTIFACT_DIR}/run.env" block_explorer_source_path || true)"
  fi
  if [[ -z "$E2E_CHAIN_INDEXER_PATH" ]]; then
    E2E_CHAIN_INDEXER_PATH="$(run_metadata_value "${ARTIFACT_DIR}/run.env" chain_indexer_source_path || true)"
  fi
fi

[[ -n "$E2E_BLOCK_EXPLORER_PATH" ]] || E2E_BLOCK_EXPLORER_PATH="${ARTIFACT_DIR}/sources/ops-explorer"
[[ -n "$E2E_CHAIN_INDEXER_PATH" ]] || E2E_CHAIN_INDEXER_PATH="${ARTIFACT_DIR}/sources/ops-indexer"
[[ "$E2E_BLOCK_EXPLORER_PATH" != *$'\n'* ]] || die "E2E_BLOCK_EXPLORER_PATH must not contain a newline"
[[ "$E2E_CHAIN_INDEXER_PATH" != *$'\n'* ]] || die "E2E_CHAIN_INDEXER_PATH must not contain a newline"

readonly RUN_ID PROJECT PRIVACY_PROJECT ARTIFACT_DIR
readonly LOG_DIR="${ARTIFACT_DIR}/logs"
readonly PLAYWRIGHT_RESULTS_DIR="${E2E_PLAYWRIGHT_RESULTS_DIR:-${ARTIFACT_DIR}/playwright/test-results}"
readonly PLAYWRIGHT_REPORT_DIR="${E2E_PLAYWRIGHT_REPORT_DIR:-${ARTIFACT_DIR}/playwright/playwright-report}"
readonly SUMMARY_FILE="${ARTIFACT_DIR}/summary.tsv"
readonly COMMANDS_FILE="${ARTIFACT_DIR}/commands.log"
readonly GO_COMPOSE_OVERRIDE="${ARTIFACT_DIR}/generated/go-compose.override.yml"

mkdir -p -- "$LOG_DIR"
STARTED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
GIT_SHA=unknown
GIT_DIRTY=unknown

if [[ "$MODE" != "down" ]]; then
  mkdir -p -- "$PLAYWRIGHT_RESULTS_DIR" "$PLAYWRIGHT_REPORT_DIR" "${ARTIFACT_DIR}/generated"
  if ! (
    set -o noclobber
    {
      printf "run_id=%s\n" "$RUN_ID"
      printf "project=%s\n" "$PROJECT"
      printf "privacy_project=%s\n" "$PRIVACY_PROJECT"
    } > "${ARTIFACT_DIR}/.harness-owner"
  ) 2>/dev/null; then
    die "artifact directory is already owned by another or previous harness run: ${ARTIFACT_DIR}"
  fi
  if command -v git >/dev/null 2>&1; then
    GIT_SHA="$(git -C "$REPO_ROOT" rev-parse HEAD 2>/dev/null || printf unknown)"
    if GIT_CHANGES="$(git -C "$REPO_ROOT" status --porcelain --untracked-files=normal 2>/dev/null)"; then
      if [[ -n "$GIT_CHANGES" ]]; then
        GIT_DIRTY=true
      else
        GIT_DIRTY=false
      fi
    fi
  fi
  {
    printf "run_id=%s\n" "$RUN_ID"
    printf "mode=%s\n" "$MODE"
    printf "project=%s\n" "$PROJECT"
    printf "privacy_project=%s\n" "$PRIVACY_PROJECT"
    printf "git_sha=%s\n" "$GIT_SHA"
    printf "git_dirty=%s\n" "$GIT_DIRTY"
    printf "started_at=%s\n" "$STARTED_AT"
    printf "repo_root=%s\n" "$REPO_ROOT"
    printf "privacy_compose_override=%s\n" "$PRIVACY_COMPOSE_OVERRIDE"
    printf "block_explorer_requested_repository=%s\n" "$BLOCK_EXPLORER_REPOSITORY"
    printf "block_explorer_requested_ref=%s\n" "$BLOCK_EXPLORER_REF"
    printf "chain_indexer_requested_repository=%s\n" "$CHAIN_INDEXER_REPOSITORY"
    printf "chain_indexer_requested_ref=%s\n" "$CHAIN_INDEXER_REF"
  } > "${ARTIFACT_DIR}/run.env"
  printf "started_at\tlane\titeration\tstatus\texit_code\n" > "$SUMMARY_FILE"
  : > "$COMMANDS_FILE"
else
  [[ -e "$SUMMARY_FILE" ]] || printf "started_at\tlane\titeration\tstatus\texit_code\n" > "$SUMMARY_FILE"
  [[ -e "$COMMANDS_FILE" ]] || : > "$COMMANDS_FILE"
fi

export E2E_RUN_ID="$RUN_ID"
export E2E_PROJECT="$PROJECT"
export E2E_PRIVACY_PROJECT="$PRIVACY_PROJECT"
export E2E_PRIVACY_COMPOSE_OVERRIDE="$PRIVACY_COMPOSE_OVERRIDE"
export E2E_BLOCK_EXPLORER_PATH
export E2E_CHAIN_INDEXER_PATH
export E2E_BLOCK_EXPLORER_REF="$BLOCK_EXPLORER_REF"
export E2E_CHAIN_INDEXER_REF="$CHAIN_INDEXER_REF"
export E2E_BLOCK_EXPLORER_REPOSITORY="$BLOCK_EXPLORER_REPOSITORY"
export E2E_CHAIN_INDEXER_REPOSITORY="$CHAIN_INDEXER_REPOSITORY"
export E2E_BUILD_VERSION="${E2E_BUILD_VERSION:-e2e}"
export E2E_BUILD_GIT_COMMIT="${E2E_BUILD_GIT_COMMIT:-$GIT_SHA}"
export E2E_BUILD_TIME="${E2E_BUILD_TIME:-$STARTED_AT}"
export E2E_ARTIFACT_DIR="$ARTIFACT_DIR"
export E2E_PLAYWRIGHT_RESULTS_DIR="$PLAYWRIGHT_RESULTS_DIR"
export E2E_PLAYWRIGHT_REPORT_DIR="$PLAYWRIGHT_REPORT_DIR"
export E2E_PLAYWRIGHT_WORKERS="$PLAYWRIGHT_WORKERS"
export COMPOSE_PARALLEL_LIMIT

declare -a COMPOSE=()
COMPOSE_READY=0
PRIVACY_SOURCES_READY=0
BLOCK_EXPLORER_SHA=""
CHAIN_INDEXER_SHA=""
PLAYWRIGHT_STACK_ACTIVE=0
PRIVACY_STACK_ACTIVE=0
PAUSED_CONTAINER=""
ACTIVE_COMMAND_PID=""
CURRENT_ITERATION=0
if [[ "$MODE" == "down" ]]; then
  EXIT_RECORDED=1
else
  EXIT_RECORDED=0
fi

detect_compose() {
  (( COMPOSE_READY == 0 )) || return 0
  if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
    COMPOSE=(docker compose)
  else
    return 1
  fi
  COMPOSE_READY=1
}

compose_e2e() {
  detect_compose || die "Docker Compose v2 is required"
  "${COMPOSE[@]}" --project-name "$PROJECT" --file "${REPO_ROOT}/docker-compose.e2e.yml" "$@"
}

write_go_compose_override() {
  mkdir -p -- "$(dirname -- "$GO_COMPOSE_OVERRIDE")"
  printf "%s\n" \
    "services:" \
    "  postgres:" \
    "    ports:" \
    "      - 127.0.0.1::5432" \
    "  anvil:" \
    "    ports:" \
    "      - 127.0.0.1::8545" \
    > "$GO_COMPOSE_OVERRIDE"
}

compose_go() {
  detect_compose || die "Docker Compose v2 is required"
  [[ -f "$GO_COMPOSE_OVERRIDE" ]] || write_go_compose_override
  "${COMPOSE[@]}" --project-name "$PROJECT" \
    --file "${REPO_ROOT}/docker-compose.e2e.yml" \
    --file "$GO_COMPOSE_OVERRIDE" "$@"
}

compose_active_stack() {
  if [[ "$BASE_STACK_KIND" == "go" ]]; then
    compose_go "$@"
  else
    compose_e2e "$@"
  fi
}

compose_privacy() {
  detect_compose || die "Docker Compose v2 is required"
  env \
    JWT_SECRET=test-jwt-secret-do-not-use-in-production-1234567890 \
    JWT_REFRESH_SECRET=test-refresh-secret-do-not-use-in-production-0987654321 \
    ADMIN_API_TOKEN=test-admin-token \
    PRIVACY_POSTGRES_PASSWORD=test-privacy-pg-password \
    AUDIT_APP_PASSWORD=test-audit-app-password \
    INDEXER_POSTGRES_PASSWORD=test-indexer-pg-password \
    REDIS_PASSWORD=test-redis-password \
    BLOCK_EXPLORER_POSTGRES_PASSWORD=test-bff-pg-password \
    CORS_ALLOWED_ORIGINS=https://explorer.e2e.invalid,https://frontend.e2e.invalid \
    "${COMPOSE[@]}" --project-name "$PRIVACY_PROJECT" --file "${REPO_ROOT}/docker-compose.privacy.yml" \
    --file "$PRIVACY_COMPOSE_OVERRIDE" "$@"
}

quote_command() {
  local arg
  for arg in "$@"; do
    printf '%q ' "$arg"
  done
  printf '\n'
}

iteration_label() {
  if (( CURRENT_ITERATION > 0 )); then
    printf '%04d' "$CURRENT_ITERATION"
  else
    printf 'once'
  fi
}

run_logged() {
  local lane="$1"
  shift
  local iter label status started
  iter="$(iteration_label)"
  label="${lane}-${iter}"
  started="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

  {
    printf '[%s] ' "$started"
    quote_command "$@"
  } >> "$COMMANDS_FILE"

  if (( DRY_RUN == 1 )); then
    printf '[dry-run] '
    quote_command "$@"
    printf '%s\t%s\t%s\tdry-run\t0\n' "$started" "$lane" "$iter" >> "$SUMMARY_FILE"
    return 0
  fi

  note "running ${lane} (log: ${LOG_DIR}/${label}.log)"
  (
    trap - EXIT INT TERM
    set +e
    "$@" 2>&1 | tee "${LOG_DIR}/${label}.log"
    exit "${PIPESTATUS[0]}"
  ) &
  ACTIVE_COMMAND_PID=$!
  set +e
  wait "$ACTIVE_COMMAND_PID"
  status=$?
  set -e
  ACTIVE_COMMAND_PID=""

  if (( status == 0 )); then
    printf '%s\t%s\t%s\tpassed\t0\n' "$started" "$lane" "$iter" >> "$SUMMARY_FILE"
    note "${lane} passed"
  else
    printf '%s\t%s\t%s\tfailed\t%d\n' "$started" "$lane" "$iter" "$status" >> "$SUMMARY_FILE"
    note "${lane} failed with exit code ${status}"
  fi
  return "$status"
}

canonical_source_path() {
  local path="$1"
  if [[ "$path" != /* ]]; then
    path="${REPO_ROOT}/${path}"
  fi
  [[ -d "$path" ]] || die "source checkout does not exist: $path"
  (cd -- "$path" && pwd -P)
}

validate_source_checkout() {
  local label="$1"
  local path="$2"
  shift 2
  local required sha
  git -C "$path" rev-parse --is-inside-work-tree >/dev/null 2>&1 ||
    die "$label source is not a Git checkout: $path"
  for required in "$@"; do
    [[ -f "${path}/${required}" ]] ||
      die "$label source is missing ${required}: $path"
  done
  sha="$(git -C "$path" rev-parse --verify "HEAD~0" 2>/dev/null)" ||
    die "could not resolve $label source HEAD: $path"
  printf "%s\n" "$sha"
}

source_dirty_state() {
  local path="$1"
  local changes
  changes="$(git -C "$path" status --porcelain --untracked-files=normal 2>/dev/null)" ||
    die "could not inspect source checkout: $path"
  if [[ -n "$changes" ]]; then
    printf "true\n"
  else
    printf "false\n"
  fi
}

clone_pinned_source() {
  local label="$1"
  local repository="$2"
  local ref="$3"
  local destination="$4"
  local expected_sha="$5"
  shift 5

  [[ ! -e "$destination" ]] ||
    die "refusing to replace existing harness source path: $destination"
  mkdir -p -- "$(dirname -- "$destination")"
  run_logged "privacy-source-${label}" git clone --depth 1 --branch "$ref" --single-branch "$repository" "$destination" || return $?

  if (( DRY_RUN == 1 )); then
    RESOLVED_SOURCE_SHA=dry-run
    return 0
  fi

  RESOLVED_SOURCE_SHA="$(validate_source_checkout "$label" "$destination" "$@")"
  if [[ -n "$expected_sha" && "$RESOLVED_SOURCE_SHA" != "$expected_sha" ]]; then
    die "$label ref $ref resolved to $RESOLVED_SOURCE_SHA, expected pinned commit $expected_sha"
  fi
}

prepare_privacy_sources() {
  (( PRIVACY_SOURCES_READY == 0 )) || return 0
  command -v git >/dev/null 2>&1 || die "git is required to acquire privacy E2E sources"

  local expected_sha=""
  local explorer_dirty=unknown
  local indexer_dirty=unknown
  local explorer_source_mode=managed-clone
  local indexer_source_mode=managed-clone
  local explorer_effective_version="$BLOCK_EXPLORER_REF"

  if (( BLOCK_EXPLORER_PATH_SUPPLIED == 1 )); then
    explorer_source_mode=supplied
    E2E_BLOCK_EXPLORER_PATH="$(canonical_source_path "$E2E_BLOCK_EXPLORER_PATH")"
    BLOCK_EXPLORER_SHA="$(validate_source_checkout block-explorer "$E2E_BLOCK_EXPLORER_PATH" backend/Dockerfile.api frontend/Dockerfile)"
    if [[ "$BLOCK_EXPLORER_REF" == "$DEFAULT_BLOCK_EXPLORER_REF" && "$BLOCK_EXPLORER_SHA" != "$DEFAULT_BLOCK_EXPLORER_SHA" ]]; then
      die "block-explorer ref $BLOCK_EXPLORER_REF resolved to $BLOCK_EXPLORER_SHA, expected pinned commit $DEFAULT_BLOCK_EXPLORER_SHA; set E2E_BLOCK_EXPLORER_REF when using a different commit"
    fi
    explorer_dirty="$(source_dirty_state "$E2E_BLOCK_EXPLORER_PATH")"
  else
    if [[ "$BLOCK_EXPLORER_REF" == "$DEFAULT_BLOCK_EXPLORER_REF" ]]; then
      expected_sha="$DEFAULT_BLOCK_EXPLORER_SHA"
    fi
    clone_pinned_source block-explorer "$BLOCK_EXPLORER_REPOSITORY" "$BLOCK_EXPLORER_REF" "$E2E_BLOCK_EXPLORER_PATH" "$expected_sha" backend/Dockerfile.api frontend/Dockerfile || return $?
    BLOCK_EXPLORER_SHA="$RESOLVED_SOURCE_SHA"
    (( DRY_RUN == 1 )) || explorer_dirty="$(source_dirty_state "$E2E_BLOCK_EXPLORER_PATH")"
  fi

  expected_sha=""
  if (( CHAIN_INDEXER_PATH_SUPPLIED == 1 )); then
    indexer_source_mode=supplied
    E2E_CHAIN_INDEXER_PATH="$(canonical_source_path "$E2E_CHAIN_INDEXER_PATH")"
    CHAIN_INDEXER_SHA="$(validate_source_checkout chain-indexer "$E2E_CHAIN_INDEXER_PATH" Dockerfile)"
    if [[ "$CHAIN_INDEXER_REF" == "$DEFAULT_CHAIN_INDEXER_REF" && "$CHAIN_INDEXER_SHA" != "$DEFAULT_CHAIN_INDEXER_SHA" ]]; then
      die "chain-indexer ref $CHAIN_INDEXER_REF resolved to $CHAIN_INDEXER_SHA, expected pinned commit $DEFAULT_CHAIN_INDEXER_SHA; set E2E_CHAIN_INDEXER_REF when using a different commit"
    fi
    indexer_dirty="$(source_dirty_state "$E2E_CHAIN_INDEXER_PATH")"
  else
    if [[ "$CHAIN_INDEXER_REF" == "$DEFAULT_CHAIN_INDEXER_REF" ]]; then
      expected_sha="$DEFAULT_CHAIN_INDEXER_SHA"
    fi
    clone_pinned_source chain-indexer "$CHAIN_INDEXER_REPOSITORY" "$CHAIN_INDEXER_REF" "$E2E_CHAIN_INDEXER_PATH" "$expected_sha" Dockerfile || return $?
    CHAIN_INDEXER_SHA="$RESOLVED_SOURCE_SHA"
    (( DRY_RUN == 1 )) || indexer_dirty="$(source_dirty_state "$E2E_CHAIN_INDEXER_PATH")"
  fi

  if (( BLOCK_EXPLORER_PATH_SUPPLIED == 1 )); then
    explorer_effective_version="local-${BLOCK_EXPLORER_SHA:0:12}"
  fi

  export E2E_BLOCK_EXPLORER_PATH E2E_CHAIN_INDEXER_PATH
  export E2E_BLOCK_EXPLORER_VERSION="$explorer_effective_version"
  export E2E_BLOCK_EXPLORER_GIT_COMMIT="$BLOCK_EXPLORER_SHA"

  {
    printf "block_explorer_source_path=%s\n" "$E2E_BLOCK_EXPLORER_PATH"
    printf "block_explorer_source_mode=%s\n" "$explorer_source_mode"
    printf "block_explorer_effective_version=%s\n" "$explorer_effective_version"
    printf "block_explorer_resolved_sha=%s\n" "$BLOCK_EXPLORER_SHA"
    printf "block_explorer_dirty=%s\n" "$explorer_dirty"
    printf "chain_indexer_source_path=%s\n" "$E2E_CHAIN_INDEXER_PATH"
    printf "chain_indexer_source_mode=%s\n" "$indexer_source_mode"
    printf "chain_indexer_resolved_sha=%s\n" "$CHAIN_INDEXER_SHA"
    printf "chain_indexer_dirty=%s\n" "$indexer_dirty"
  } >> "${ARTIFACT_DIR}/run.env"

  PRIVACY_SOURCES_READY=1
}

query_project_resource_ids() {
  local project="$1"
  local resource_type="$2"
  shift 2
  local ids
  if ! ids="$(docker "$@")"; then
    printf "e2e-harness: Docker %s inventory query failed for Compose project '%s'\n" "$resource_type" "$project" >&2
    return 1
  fi
  [[ -z "$ids" ]] || printf '%s\n' "$ids"
}

resource_ids_for_project() {
  local project="$1"
  query_project_resource_ids "$project" containers container ls -aq --filter "label=com.docker.compose.project=${project}" || return $?
  query_project_resource_ids "$project" networks network ls -q --filter "label=com.docker.compose.project=${project}" || return $?
  query_project_resource_ids "$project" volumes volume ls -q --filter "label=com.docker.compose.project=${project}" || return $?
  query_project_resource_ids "$project" images image ls -q --filter "reference=${project}-*" || return $?
}

assert_project_unused() {
  local project="$1"
  (( DRY_RUN == 0 )) || return 0
  local resources
  if ! resources="$(resource_ids_for_project "$project")"; then
    die "could not verify Compose project '$project' is unused; refusing to acquire ownership"
  fi
  if [[ -n "$resources" ]]; then
    die "Compose project '$project' already owns resources or matching image refs; choose another E2E_RUN_ID/E2E_PROJECT or explicitly run down"
  fi
}

container_belongs_to_project() {
  local container="$1"
  local expected="$2"
  local actual
  actual="$(docker inspect --format '{{ index .Config.Labels "com.docker.compose.project" }}' "$container" 2>/dev/null || true)"
  [[ "$actual" == "$expected" ]]
}

safe_unpause() {
  [[ -n "$PAUSED_CONTAINER" ]] || return 0
  if container_belongs_to_project "$PAUSED_CONTAINER" "$PROJECT"; then
    docker unpause "$PAUSED_CONTAINER" >/dev/null 2>&1 || true
  fi
  PAUSED_CONTAINER=""
}

collect_e2e_state() {
  local phase="$1"
  (( DRY_RUN == 0 )) || return 0
  detect_compose || return 0
  compose_active_stack ps --all > "${LOG_DIR}/compose-${phase}-ps.log" 2>&1 || true
  compose_active_stack logs --no-color > "${LOG_DIR}/compose-${phase}.log" 2>&1 || true
}

collect_privacy_state() {
  local phase="$1"
  (( DRY_RUN == 0 )) || return 0
  detect_compose || return 0
  compose_privacy ps --all > "${LOG_DIR}/privacy-compose-${phase}-ps.log" 2>&1 || true
  compose_privacy logs --no-color > "${LOG_DIR}/privacy-compose-${phase}.log" 2>&1 || true
}

stop_playwright_stack() {
  (( PLAYWRIGHT_STACK_ACTIVE == 1 )) || return 0
  safe_unpause
  collect_e2e_state "before-down-$(date -u +%H%M%S)"
  if (( KEEP_STACK == 1 )) && [[ "$BASE_STACK_KIND" == "playwright" ]]; then
    note "keeping Compose project ${PROJECT}"
    return 0
  fi
  if (( DRY_RUN == 1 )); then
    run_logged compose-down compose_active_stack down --volumes --remove-orphans --rmi local
  else
    local cleanup_status=0
    note "removing only Compose project ${PROJECT}"
    compose_active_stack down --volumes --remove-orphans --rmi local >> "${LOG_DIR}/compose-down.log" 2>&1 || cleanup_status=$?
    if (( cleanup_status != 0 )); then
      note "cleanup failed for Compose project ${PROJECT} with exit code ${cleanup_status}; see ${LOG_DIR}/compose-down.log"
      return "$cleanup_status"
    fi
  fi
  clear_project_owned base || return $?
  BASE_PROJECT_OWNED=0
  PLAYWRIGHT_STACK_ACTIVE=0
  BASE_STACK_KIND=""
}

stop_privacy_stack() {
  (( PRIVACY_STACK_ACTIVE == 1 )) || return 0
  collect_privacy_state "before-down-$(date -u +%H%M%S)"
  if (( DRY_RUN == 1 )); then
    run_logged privacy-compose-down compose_privacy down --volumes --remove-orphans --rmi local
  else
    local cleanup_status=0
    note "removing only Compose project ${PRIVACY_PROJECT}"
    compose_privacy down --volumes --remove-orphans --rmi local >> "${LOG_DIR}/privacy-compose-down.log" 2>&1 || cleanup_status=$?
    if (( cleanup_status != 0 )); then
      note "cleanup failed for Compose project ${PRIVACY_PROJECT} with exit code ${cleanup_status}; see ${LOG_DIR}/privacy-compose-down.log"
      return "$cleanup_status"
    fi
  fi
  clear_project_owned privacy || return $?
  PRIVACY_PROJECT_OWNED=0
  PRIVACY_STACK_ACTIVE=0
}

on_exit() {
  local status="$1"
  local cleanup_status=0
  local current_cleanup_status=0
  local lock_cleanup_status=0
  trap - EXIT INT TERM
  set +e
  safe_unpause
  stop_playwright_stack || cleanup_status=$?
  stop_privacy_stack || current_cleanup_status=$?
  release_project_locks || lock_cleanup_status=$?
  if (( cleanup_status == 0 && current_cleanup_status != 0 )); then
    cleanup_status="$current_cleanup_status"
  fi
  if (( cleanup_status == 0 && lock_cleanup_status != 0 )); then
    cleanup_status="$lock_cleanup_status"
  fi
  if (( status == 0 && cleanup_status != 0 )); then
    status="$cleanup_status"
  fi
  if (( EXIT_RECORDED == 0 )); then
    {
      printf 'finished_at=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
      printf 'exit_code=%d\n' "$status"
    } >> "${ARTIFACT_DIR}/run.env"
    EXIT_RECORDED=1
  fi
  note "artifacts: ${ARTIFACT_DIR}"
  exit "$status"
}

terminate_process_tree() {
  local parent="$1"
  local signal="$2"
  local child
  while IFS= read -r child; do
    child="${child//[!0-9]/}"
    [[ -n "$child" ]] || continue
    terminate_process_tree "$child" "$signal"
  done < <(ps -o pid= --ppid "$parent" 2>/dev/null || true)
  kill -s "$signal" "$parent" 2>/dev/null || true
}

wait_for_active_command() {
  local attempts="$1"
  local state iteration
  for (( iteration=0; iteration < attempts; iteration++ )); do
    state="$(ps -o stat= -p "$ACTIVE_COMMAND_PID" 2>/dev/null || true)"
    state="${state//[[:space:]]/}"
    if [[ -z "$state" || "$state" == Z* ]]; then
      wait "$ACTIVE_COMMAND_PID" 2>/dev/null || true
      ACTIVE_COMMAND_PID=""
      return 0
    fi
    sleep 0.1
  done
  return 1
}

on_signal() {
  local signal="$1"
  note "received ${signal}; forwarding it to the active command and cleaning up this run only"
  if [[ -n "$ACTIVE_COMMAND_PID" ]]; then
    terminate_process_tree "$ACTIVE_COMMAND_PID" "$signal"
    if ! wait_for_active_command 20; then
      terminate_process_tree "$ACTIVE_COMMAND_PID" TERM
    fi
    if [[ -n "$ACTIVE_COMMAND_PID" ]] && ! wait_for_active_command 30; then
      note "active command did not stop after TERM; escalating to KILL"
      terminate_process_tree "$ACTIVE_COMMAND_PID" KILL
      wait "$ACTIVE_COMMAND_PID" 2>/dev/null || true
      ACTIVE_COMMAND_PID=""
    fi
  fi
  case "$signal" in
    INT) exit 130 ;;
    TERM) exit 143 ;;
  esac
}

trap 'on_exit $?' EXIT
trap 'on_signal INT' INT
trap 'on_signal TERM' TERM

doctor() {
  local failed=0
  local compose_available=0
  note "run ID: ${RUN_ID}"
  note "Playwright project: ${PROJECT}"
  note "privacy project: ${PRIVACY_PROJECT}"
  note "artifacts: ${ARTIFACT_DIR}"
  note "concurrency: Go max-procs=$GO_MAX_PROCS, Go test parallelism=$GO_TEST_PARALLELISM, Playwright workers=$PLAYWRIGHT_WORKERS, Compose parallelism=$COMPOSE_PARALLEL_LIMIT"

  if command -v go >/dev/null 2>&1; then
    note "go: $(go version)"
    if [[ "$(go env CGO_ENABLED 2>/dev/null)" != "1" ]]; then
      printf "unavailable: Go race detector requires CGO_ENABLED=1\n" >&2
      failed=1
    fi
    if ! command -v cc >/dev/null 2>&1 && ! command -v gcc >/dev/null 2>&1 && ! command -v clang >/dev/null 2>&1; then
      printf "missing: C compiler required by go test -race (cc, gcc, or clang)\n" >&2
      failed=1
    fi
  else
    printf "missing: go\n" >&2
    failed=1
  fi

  if command -v flock >/dev/null 2>&1; then
    note "flock: available"
  else
    printf "missing: flock (required for shared-host project locks)\n" >&2
    failed=1
  fi

  if command -v ps >/dev/null 2>&1 && ps -o pid= --ppid "$$" >/dev/null 2>&1; then
    note "ps: GNU --ppid process selection available"
  else
    printf "missing: ps with GNU --ppid support (required for process-tree signal forwarding)\n" >&2
    failed=1
  fi

  if command -v git >/dev/null 2>&1; then
    note "git: $(git --version)"
    note "privacy sources: ops-explorer ${BLOCK_EXPLORER_REF}, ops-indexer ${CHAIN_INDEXER_REF}"
  else
    printf "missing: git (required to acquire pinned privacy E2E sources)\n" >&2
    failed=1
  fi

  if command -v docker >/dev/null 2>&1; then
    note "docker client: $(docker --version)"
    if (( DRY_RUN == 0 )) && ! docker info >/dev/null 2>&1; then
      printf 'unavailable: Docker daemon\n' >&2
      failed=1
    fi
  else
    printf 'missing: docker\n' >&2
    failed=1
  fi

  if detect_compose; then
    compose_available=1
    note "compose: $("${COMPOSE[@]}" version 2>/dev/null | head -n 1)"
  else
    printf 'missing: Docker Compose v2\n' >&2
    failed=1
  fi

  local required
  for required in \
    "${REPO_ROOT}/go.mod" \
    "${REPO_ROOT}/docker-compose.e2e.yml" \
    "${REPO_ROOT}/docker-compose.privacy.yml" \
    "$PRIVACY_COMPOSE_OVERRIDE" \
    "${REPO_ROOT}/e2e/playwright/package.json"; do
    if [[ ! -f "$required" ]]; then
      printf 'missing: %s\n' "$required" >&2
      failed=1
    fi
  done

  if (( compose_available == 1 && DRY_RUN == 0 )); then
    if ! compose_e2e config --quiet > "${LOG_DIR}/doctor-e2e-compose.log" 2>&1; then
      printf 'invalid: docker-compose.e2e.yml (see doctor-e2e-compose.log)\n' >&2
      failed=1
    fi
    if ! compose_go config --quiet > "${LOG_DIR}/doctor-go-compose.log" 2>&1; then
      printf "invalid: generated Go E2E Compose override (see doctor-go-compose.log)\n" >&2
      failed=1
    fi
    if ! compose_privacy config --quiet > "${LOG_DIR}/doctor-privacy-compose.log" 2>&1; then
      printf 'invalid: merged privacy E2E Compose configuration (see doctor-privacy-compose.log)\n' >&2
      failed=1
    fi
  fi

  (( failed == 0 )) || return 1
  note "doctor checks passed"
}

start_playwright_stack() {
  if (( PLAYWRIGHT_STACK_ACTIVE == 1 )); then
    if [[ "$BASE_STACK_KIND" == "playwright" ]]; then
      return 0
    fi
    note "cannot start Playwright while a ${BASE_STACK_KIND:-unknown} base stack remains active"
    return 1
  fi
  assert_project_unused "$PROJECT"
  mark_project_owned base playwright
  BASE_PROJECT_OWNED=1
  BASE_STACK_KIND="playwright"
  PLAYWRIGHT_STACK_ACTIVE=1
  run_logged compose-build-playwright compose_e2e build playwright || return $?
  run_logged compose-up compose_e2e up --detach --build postgres anvil proxy-backend proxy-frontend || return $?
}

compose_go_port() {
  local service="$1"
  local container_port="$2"
  local endpoint host_port
  endpoint="$(compose_go port "$service" "$container_port" 2>/dev/null | tail -n 1)"
  [[ "$endpoint" =~ ^127\.0\.0\.1:([0-9]+)$ ]] ||
    die "could not discover a loopback port for ${service}:${container_port} (got: ${endpoint:-none})"
  host_port="${BASH_REMATCH[1]}"
  printf "127.0.0.1:%s\n" "$host_port"
}

start_go_infra() {
  local postgres_container anvil_container postgres_endpoint anvil_endpoint
  (( PLAYWRIGHT_STACK_ACTIVE == 0 )) || die "cannot start Go infrastructure while another base stack is active"
  assert_project_unused "$PROJECT"
  write_go_compose_override
  mark_project_owned base go
  BASE_PROJECT_OWNED=1
  BASE_STACK_KIND="go"
  PLAYWRIGHT_STACK_ACTIVE=1
  run_logged go-infra-up compose_go up --detach postgres anvil || return $?

  if (( DRY_RUN == 1 )); then
    postgres_endpoint="127.0.0.1:<dynamic-postgres-port>"
    anvil_endpoint="127.0.0.1:<dynamic-anvil-port>"
  else
    postgres_container="$(compose_go ps --quiet postgres)"
    anvil_container="$(compose_go ps --quiet anvil)"
    [[ -n "$postgres_container" && -n "$anvil_container" ]] || die "Go E2E infrastructure did not create both owned containers"
    container_belongs_to_project "$postgres_container" "$PROJECT" || die "Postgres container is not owned by $PROJECT"
    container_belongs_to_project "$anvil_container" "$PROJECT" || die "Anvil container is not owned by $PROJECT"
    wait_container_ready "$postgres_container" || die "run-owned Postgres did not become healthy"
    wait_container_ready "$anvil_container" || die "run-owned Anvil did not become healthy"
    postgres_endpoint="$(compose_go_port postgres 5432)"
    anvil_endpoint="$(compose_go_port anvil 8545)"
  fi

  GO_DEFAULT_DATABASE_URL="postgres://postgres:postgres@${postgres_endpoint}/e2e_default?sslmode=disable"
  GO_MOCKAUTH_DATABASE_URL="postgres://postgres:postgres@${postgres_endpoint}/e2e_mockauth?sslmode=disable"
  GO_NODE_URL="http://${anvil_endpoint}"
}

# CREATE2 intentionally keeps its fresh testcontainers Anvil; scrub ambient
# reuse/cleanup overrides so that exception remains isolated and Ryuk-owned.
run_go_default_tests() {
  run_logged go-default env -u ANVIL_URL TESTCONTAINERS_RYUK_DISABLED=false TESTCONTAINERS_REUSE_ENABLE=false \
    GOMAXPROCS="$GO_MAX_PROCS" \
    E2E_RUN_ID="$RUN_ID" \
    E2E_DATABASE_URL="$GO_DEFAULT_DATABASE_URL" \
    E2E_NODE_URL="$GO_NODE_URL" \
    go test -race -parallel "$GO_TEST_PARALLELISM" ./e2e/... -count=1 -v -p 1 -timeout "${E2E_GO_TIMEOUT:-30m}"
}

run_go_mockauth_tests() {
  run_logged go-mockauth env -u ANVIL_URL TESTCONTAINERS_RYUK_DISABLED=false TESTCONTAINERS_REUSE_ENABLE=false \
    GOMAXPROCS="$GO_MAX_PROCS" \
    E2E_RUN_ID="$RUN_ID" \
    E2E_DATABASE_URL="$GO_MOCKAUTH_DATABASE_URL" \
    E2E_NODE_URL="$GO_NODE_URL" \
    go test -race -parallel "$GO_TEST_PARALLELISM" -tags mockauth ./e2e/... -count=1 -v -p 1 -timeout "${E2E_GO_TIMEOUT:-30m}"
}

run_go_default() {
  local status=0 cleanup_status=0
  start_go_infra || status=$?
  if (( status == 0 )); then
    run_go_default_tests || status=$?
  fi
  stop_playwright_stack || cleanup_status=$?
  if (( status == 0 && cleanup_status != 0 )); then
    status="$cleanup_status"
  fi
  return "$status"
}

run_go_mockauth() {
  local status=0 cleanup_status=0
  start_go_infra || status=$?
  if (( status == 0 )); then
    run_go_mockauth_tests || status=$?
  fi
  stop_playwright_stack || cleanup_status=$?
  if (( status == 0 && cleanup_status != 0 )); then
    status="$cleanup_status"
  fi
  return "$status"
}

run_go() {
  local status=0 lane_status=0 cleanup_status=0
  start_go_infra || status=$?
  if (( status == 0 )); then
    run_go_default_tests || status=$?
    run_go_mockauth_tests || lane_status=$?
    if (( status == 0 && lane_status != 0 )); then
      status="$lane_status"
    fi
  fi
  stop_playwright_stack || cleanup_status=$?
  if (( status == 0 && cleanup_status != 0 )); then
    status="$cleanup_status"
  fi
  return "$status"
}

run_playwright() {
  local status=0 cleanup_status=0
  start_playwright_stack || status=$?
  if (( status == 0 )); then
    run_logged playwright compose_e2e run --rm playwright npm test || status=$?
  fi
  stop_playwright_stack || cleanup_status=$?
  if (( status == 0 && cleanup_status != 0 )); then
    status="$cleanup_status"
  fi
  return "$status"
}

run_privacy() {
  local status=0 cleanup_status=0
  local service

  prepare_privacy_sources || status=$?
  if (( status == 0 )); then
    assert_project_unused "$PRIVACY_PROJECT"
    mark_project_owned privacy privacy
    PRIVACY_PROJECT_OWNED=1
    PRIVACY_STACK_ACTIVE=1
  fi

  if (( status == 0 )); then
    for service in proxy-backend proxy-frontend chain-indexer block-explorer-api block-explorer-frontend; do
      run_logged "privacy-build-${service}" compose_privacy build "$service" || { status=$?; break; }
    done
  fi

  if (( status == 0 )); then
    run_logged privacy env -u HOST_PORT_PROXY -u HOST_PORT_UI -u HOST_PORT_EXPLORER \
      GOMAXPROCS="$GO_MAX_PROCS" \
      E2E_PRIVACY_PROJECT="$PRIVACY_PROJECT" \
      E2E_PRIVACY_COMPOSE_OVERRIDE="$PRIVACY_COMPOSE_OVERRIDE" \
      E2E_ARTIFACT_DIR="${ARTIFACT_DIR}/privacy" \
      go test -tags privacy_bypass -p 1 -parallel "$GO_TEST_PARALLELISM" -count=1 -timeout "${E2E_PRIVACY_TIMEOUT:-15m}" -v \
      -run "^(TestPrivacyModeBypassClosure|TestPrivacyProjectCollisionFailsClosed)$" ./e2e/... || status=$?
  fi

  stop_privacy_stack || cleanup_status=$?
  if (( status == 0 && cleanup_status != 0 )); then
    status="$cleanup_status"
  fi
  return "$status"
}

run_all() {
  local status=0 lane_status=0
  run_go || status=$?
  run_playwright || lane_status=$?
  if (( status == 0 && lane_status != 0 )); then
    status="$lane_status"
  fi
  lane_status=0
  run_privacy || lane_status=$?
  if (( status == 0 && lane_status != 0 )); then
    status="$lane_status"
  fi
  return "$status"
}

wait_container_ready() {
  local container="$1"
  local timeout_seconds deadline state
  timeout_seconds="$(validate_duration E2E_HEALTH_TIMEOUT "${E2E_HEALTH_TIMEOUT:-3m}")"
  deadline=$(( $(date +%s) + timeout_seconds ))

  while (( $(date +%s) < deadline )); do
    state="$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "$container" 2>/dev/null || true)"
    case "$state" in
      healthy|running) return 0 ;;
      unhealthy|dead) return 1 ;;
    esac
    sleep 2
  done
  return 1
}

chaos_container_for_service() {
  local service="$1"
  local container
  container="$(compose_e2e ps --quiet "$service" 2>/dev/null || true)"
  [[ -n "$container" ]] || die "chaos target service '$service' has no container in project '$PROJECT'"
  [[ "$container" != *$'\n'* ]] || die "chaos target service '$service' resolved to multiple containers"
  container_belongs_to_project "$container" "$PROJECT" ||
    die "refusing chaos action: container '$container' is not owned by project '$PROJECT'"
  printf '%s\n' "$container"
}

inject_chaos() {
  local service="$1"
  local action="$2"
  local container hold_seconds
  if (( DRY_RUN == 1 )); then
    container="<project:${PROJECT};service:${service}>"
  else
    container="$(chaos_container_for_service "$service")"
  fi
  hold_seconds="$(validate_duration E2E_CHAOS_HOLD "${E2E_CHAOS_HOLD:-5s}")"
  note "chaos: ${action} ${service} (${container:0:12}), verified project=${PROJECT}"

  case "$action" in
    kill)
      run_logged "chaos-${service}-kill" docker kill --signal KILL "$container"
      run_logged "chaos-${service}-recover" compose_e2e up --detach --no-deps "$service"
      ;;
    pause)
      PAUSED_CONTAINER="$container"
      run_logged "chaos-${service}-pause" docker pause "$container"
      if (( DRY_RUN == 0 )); then
        sleep "$hold_seconds"
      fi
      run_logged "chaos-${service}-unpause" docker unpause "$container"
      PAUSED_CONTAINER=""
      ;;
    restart)
      run_logged "chaos-${service}-restart" docker restart "$container"
      ;;
    *) die "unsupported chaos action: $action" ;;
  esac

  if (( DRY_RUN == 0 )); then
    container="$(chaos_container_for_service "$service")"
    wait_container_ready "$container" || die "chaos target '$service' did not recover before E2E_HEALTH_TIMEOUT"
  fi
}

run_chaos() {
  local duration_seconds interval_seconds deadline cycle service action
  local -a services actions
  duration_seconds="$(validate_duration E2E_CHAOS_DURATION "$CHAOS_DURATION")"
  interval_seconds="$(validate_duration E2E_CHAOS_INTERVAL "$CHAOS_INTERVAL")"
  IFS=" " read -r -a services <<< "${E2E_CHAOS_SERVICES:-proxy-backend proxy-frontend anvil postgres}"
  actions=(kill pause restart)
  (( ${#services[@]} > 0 )) || die "E2E_CHAOS_SERVICES must name at least one service"

  start_playwright_stack
  run_logged chaos-baseline compose_e2e run --rm playwright npm test

  deadline=$(( $(date +%s) + duration_seconds ))
  cycle=0
  while (( cycle < ${#services[@]} || $(date +%s) < deadline )); do
    cycle=$(( cycle + 1 ))
    CURRENT_ITERATION="$cycle"
    service="${services[$(( (cycle - 1) % ${#services[@]} ))]}"
    action="${actions[$(( (cycle - 1) % ${#actions[@]} ))]}"
    inject_chaos "$service" "$action"
    run_logged chaos-playwright compose_e2e run --rm playwright npm test
    collect_e2e_state "chaos-$(printf '%04d' "$cycle")"

    if (( DRY_RUN == 1 && cycle >= ${#services[@]} )); then
      break
    fi
    if (( cycle >= ${#services[@]} && $(date +%s) >= deadline )); then
      break
    fi
    if (( DRY_RUN == 0 && $(date +%s) < deadline )); then
      sleep "$interval_seconds"
    fi
  done
  CURRENT_ITERATION=0
  stop_playwright_stack
}

run_suite() {
  local suite="$1"
  case "$suite" in
    all) run_all ;;
    go) run_go ;;
    go-default) run_go_default ;;
    go-mockauth) run_go_mockauth ;;
    playwright) run_playwright ;;
    privacy|privacy-bypass) run_privacy ;;
    *) die "unsupported suite '$suite'; use all, go, go-default, go-mockauth, playwright, or privacy" ;;
  esac
}

run_soak() {
  local duration_seconds deadline iteration
  duration_seconds="$(validate_duration E2E_SOAK_DURATION "$SOAK_DURATION")"
  deadline=$(( $(date +%s) + duration_seconds ))
  iteration=0
  note "soak: suite=${SOAK_SUITE}, duration=${SOAK_DURATION}"

  while (( iteration == 0 || $(date +%s) < deadline )); do
    iteration=$(( iteration + 1 ))
    CURRENT_ITERATION="$iteration"
    note "soak iteration ${iteration}"
    run_suite "$SOAK_SUITE"
    if (( DRY_RUN == 1 )); then
      break
    fi
  done
  CURRENT_ITERATION=0
}

down_projects() {
  local status=0 privacy_status=0
  if (( BASE_PROJECT_OWNED == 0 && PRIVACY_PROJECT_OWNED == 0 )); then
    note "no active project ownership markers remain for run ${RUN_ID}"
    return 0
  fi
  detect_compose || die "Docker Compose v2 is required for down"
  PLAYWRIGHT_STACK_ACTIVE="$BASE_PROJECT_OWNED"
  PRIVACY_STACK_ACTIVE="$PRIVACY_PROJECT_OWNED"
  KEEP_STACK=0
  stop_playwright_stack || status=$?
  stop_privacy_stack || privacy_status=$?
  if (( status == 0 && privacy_status != 0 )); then
    status="$privacy_status"
  fi
  return "$status"
}

acquire_mode_project_locks

cd -- "$REPO_ROOT"
case "$MODE" in
  all) run_all ;;
  go) run_go ;;
  go-default) run_go_default ;;
  go-mockauth) run_go_mockauth ;;
  playwright) run_playwright ;;
  privacy) run_privacy ;;
  chaos) run_chaos ;;
  soak) run_soak ;;
  doctor) doctor ;;
  down) down_projects ;;
esac
