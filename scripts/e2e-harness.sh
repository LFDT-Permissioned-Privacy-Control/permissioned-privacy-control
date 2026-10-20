#!/usr/bin/env bash
# Keep this launcher parseable by the Bash 3.2 shipped with macOS. The harness
# implementation intentionally uses newer Bash and Linux process primitives.

set -u

SCRIPT_DIR=$(CDPATH= cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
IMPLEMENTATION="${SCRIPT_DIR}/e2e-harness-impl.sh"
SELECTED_BASH=""
PREFLIGHT_FAILED=0

launcher_error() {
  printf 'e2e-harness: ERROR: %s\n' "$*" >&2
}

resolve_executable() {
  case "$1" in
    */*)
      [ -x "$1" ] || return 1
      printf '%s\n' "$1"
      ;;
    *) command -v "$1" 2>/dev/null ;;
  esac
}

is_supported_bash() {
  "$1" -c '
    major=${BASH_VERSINFO[0]}
    minor=${BASH_VERSINFO[1]}
    if [ "$major" -gt 4 ] || { [ "$major" -eq 4 ] && [ "$minor" -ge 1 ]; }; then
      exit 0
    fi
    exit 1
  ' >/dev/null 2>&1
}

select_modern_bash() {
  candidate=""

  if [ -n "${E2E_BASH-}" ]; then
    candidate=$(resolve_executable "$E2E_BASH") || {
      launcher_error "E2E_BASH is not executable: $E2E_BASH"
      return 1
    }
    if ! is_supported_bash "$candidate"; then
      launcher_error "E2E_BASH must be Bash 4.1 or newer: $candidate"
      return 1
    fi
    SELECTED_BASH=$candidate
    return 0
  fi

  path_bash=$(command -v bash 2>/dev/null || true)
  path_bash5=$(command -v bash5 2>/dev/null || true)
  path_bash4=$(command -v bash4 2>/dev/null || true)
  for candidate in \
    "$path_bash" \
    "$path_bash5" \
    "$path_bash4" \
    /opt/homebrew/bin/bash \
    /usr/local/bin/bash \
    /opt/local/bin/bash \
    /run/current-system/sw/bin/bash \
    /bin/bash \
    /usr/bin/bash; do
    [ -n "$candidate" ] || continue
    [ -x "$candidate" ] || continue
    if is_supported_bash "$candidate"; then
      SELECTED_BASH=$candidate
      return 0
    fi
  done

  launcher_error "Bash 4.1 or newer is required; stock macOS Bash 3.2 is not supported"
  printf '%s\n' \
    "e2e-harness: install a modern Bash (for example, 'brew install bash')" \
    "e2e-harness: or set E2E_BASH to its executable path" >&2
  return 1
}

preflight_missing() {
  launcher_error "$1"
  PREFLIGHT_FAILED=1
}

check_portability_primitives() {
  if ! command -v flock >/dev/null 2>&1; then
    preflight_missing "flock is required for shared-host project locking"
  fi

  if ! command -v ps >/dev/null 2>&1; then
    preflight_missing "ps with GNU --ppid support is required for process-tree cleanup"
  elif ! ps -o pid= --ppid "$$" >/dev/null 2>&1; then
    preflight_missing "ps must support GNU --ppid process selection (BSD ps is not supported)"
  fi
}

check_docker_tools() {
  if ! command -v docker >/dev/null 2>&1; then
    preflight_missing "docker is required"
    return
  fi
  if ! docker compose version >/dev/null 2>&1; then
    preflight_missing "Docker Compose v2 is required"
  fi
  if ! docker info >/dev/null 2>&1; then
    preflight_missing "the Docker daemon is unavailable"
  fi
}

check_go_tools() {
  if ! command -v go >/dev/null 2>&1; then
    preflight_missing "go is required for this E2E lane"
    return
  fi
  if [ "$(go env CGO_ENABLED 2>/dev/null)" != "1" ]; then
    preflight_missing "CGO_ENABLED=1 is required by the Go race detector"
  fi
  if ! command -v cc >/dev/null 2>&1 && \
     ! command -v gcc >/dev/null 2>&1 && \
     ! command -v clang >/dev/null 2>&1; then
    preflight_missing "a C compiler (cc, gcc, or clang) is required by go test -race"
  fi
}

run_preflight() {
  lane=${1:-all}
  case "$lane" in
    all|go|go-default|go-mockauth|playwright|privacy|privacy-bypass|chaos|soak|doctor|down) ;;
    *)
      launcher_error "unsupported preflight mode '$lane'"
      printf '%s\n' 'Usage: scripts/e2e-harness.sh preflight [MODE]' >&2
      return 2
      ;;
  esac

  PREFLIGHT_FAILED=0
  check_portability_primitives
  check_docker_tools

  case "$lane" in
    all|go|go-default|go-mockauth|privacy|privacy-bypass|soak|doctor)
      check_go_tools
      ;;
  esac
  case "$lane" in
    all|privacy|privacy-bypass|soak|doctor)
      command -v git >/dev/null 2>&1 || preflight_missing "git is required to acquire pinned privacy sources"
      ;;
  esac

  if [ "$PREFLIGHT_FAILED" -ne 0 ]; then
    return 1
  fi
  printf 'e2e-harness: host preflight passed for %s\n' "$lane"
}

if [ ! -r "$IMPLEMENTATION" ]; then
  launcher_error "implementation is missing: $IMPLEMENTATION"
  exit 1
fi

if ! select_modern_bash; then
  exit 1
fi

if [ "${1-}" = "preflight" ]; then
  if [ "$#" -gt 2 ]; then
    launcher_error "preflight accepts at most one mode"
    printf '%s\n' 'Usage: scripts/e2e-harness.sh preflight [MODE]' >&2
    exit 2
  fi
  run_preflight "${2:-all}"
  exit $?
fi

case "${1-}" in
  -h|--help) ;;
  doctor) ;;
  *)
    check_portability_primitives
    if [ "$PREFLIGHT_FAILED" -ne 0 ]; then
      printf '%s\n' \
        "e2e-harness: run 'scripts/e2e-harness.sh preflight ${1:-all}' for the complete host check" >&2
      exit 1
    fi
    ;;
esac

exec "$SELECTED_BASH" "$IMPLEMENTATION" "$@"
