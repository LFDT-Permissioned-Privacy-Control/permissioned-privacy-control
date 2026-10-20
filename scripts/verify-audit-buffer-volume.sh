#!/usr/bin/env bash
# RD-1112: verify the async audit buffer (AUDIT_BUFFER_DIR) is usable by the
# non-root runtime user in a freshly-mounted Docker named volume — the exact
# production deploy scenario.
#
# Why this exists as its own check: the fix lives in Dockerfile.backend, which
# pre-creates /var/lib/pp/auditbuf owned by appuser (uid 1000) so a fresh named
# volume inherits that ownership. A broken/removed chown, or a `USER appuser`
# reordered before it, silently breaks the buffer in prod — but a plain `docker
# build` still succeeds and Go tests still pass, so only running the image with a
# real named volume catches the regression.
#
# Exits non-zero (with a clear message) if the buffer dir is not writable.
set -euo pipefail

cd "$(dirname "$0")/.."

IMAGE="${IMAGE:-privacy-proxy-buffer-verify:local}"
BUF_DIR=/var/lib/pp/auditbuf
VOL="pp-auditbuf-verify-$$"

echo "==> building runtime-base (holds the buffer-dir ownership)"
docker build -f Dockerfile.backend --target runtime-base -t "$IMAGE" . >/dev/null

cleanup() { docker volume rm -f "$VOL" >/dev/null 2>&1 || true; }
trap cleanup EXIT
docker volume create "$VOL" >/dev/null

echo "==> asserting a fresh named volume is writable by the non-root runtime user"
# The image sets USER appuser (uid 1000). If the volume did not inherit that
# ownership, the touch fails with EACCES and this run exits non-zero.
out="$(docker run --rm -v "$VOL:$BUF_DIR" "$IMAGE" \
  sh -c "id -u && touch $BUF_DIR/.probe && echo WRITABLE")"
echo "$out"

echo "$out" | grep -qx "1000"     || { echo "FAIL: image is not running as uid 1000"; exit 1; }
echo "$out" | grep -qx "WRITABLE" || { echo "FAIL: audit buffer dir not writable by the non-root runtime user"; exit 1; }

echo "PASS: async audit buffer volume is writable by the non-root runtime user (uid 1000)"
