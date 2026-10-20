#!/usr/bin/env bash

set -Eeuo pipefail

readonly SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly TEST_ROOT="$(mktemp -d)"
readonly FAKE_BIN="${TEST_ROOT}/bin"
readonly ARTIFACT_DIR="${TEST_ROOT}/artifacts"
readonly DOCKER_CALL_LOG="${TEST_ROOT}/docker-calls.log"
readonly HARNESS_LOG="${TEST_ROOT}/harness.log"
readonly RUN_ID="inventory-fail-closed"
readonly PROJECT="privacy-proxy-e2e-inventory-fail-closed"
export DOCKER_CALL_LOG

cleanup() {
  rm -rf -- "$TEST_ROOT"
}
trap cleanup EXIT

mkdir -p -- "$FAKE_BIN"
{
  printf '%s\n' '#!/usr/bin/env bash'
  printf '%s\n' 'set -u'
  printf '%s\n' 'printf '\''%s\n'\'' "$*" >> "$DOCKER_CALL_LOG"'
  printf '%s\n' 'case "${1:-} ${2:-}" in'
  printf '%s\n' '  "container ls") exit 0 ;;'
  printf '%s\n' '  "network ls") printf '\''simulated Docker API failure\n'\'' >&2; exit 42 ;;'
  printf '%s\n' '  *) printf '\''unexpected fake Docker call: %s\n'\'' "$*" >&2; exit 99 ;;'
  printf '%s\n' 'esac'
} > "${FAKE_BIN}/docker"
chmod +x "${FAKE_BIN}/docker"

if PATH="${FAKE_BIN}:${PATH}" E2E_RUN_ID="$RUN_ID" E2E_PROJECT="$PROJECT" E2E_ARTIFACT_DIR="$ARTIFACT_DIR" \
  "${SCRIPT_DIR}/e2e-harness.sh" playwright > "$HARNESS_LOG" 2>&1; then
  printf 'expected the harness to reject a failed Docker inventory query\n' >&2
  exit 1
fi

grep -F "Docker networks inventory query failed" "$HARNESS_LOG" >/dev/null || {
  printf 'missing network inventory failure diagnostic\n' >&2
  exit 1
}
grep -F "refusing to acquire ownership" "$HARNESS_LOG" >/dev/null || {
  printf 'missing fail-closed ownership diagnostic\n' >&2
  exit 1
}
[[ ! -e "${ARTIFACT_DIR}/.base-project-owner" ]] || {
  printf 'the harness marked the project owned after inventory failed\n' >&2
  exit 1
}
grep -F "container ls" "$DOCKER_CALL_LOG" >/dev/null || {
  printf 'container inventory query was not attempted\n' >&2
  exit 1
}
grep -F "network ls" "$DOCKER_CALL_LOG" >/dev/null || {
  printf 'network inventory query was not attempted\n' >&2
  exit 1
}
if grep -E '(^| )(compose|build|down)( |$)' "$DOCKER_CALL_LOG" >/dev/null; then
  printf 'the harness reached a build or cleanup mutation after inventory failed\n' >&2
  exit 1
fi

printf 'Docker inventory failure is fail-closed\n'
