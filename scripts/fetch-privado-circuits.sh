#!/usr/bin/env bash
# Fetch the iden3 auth-v2 ZK circuit artifacts from Privado's canonical
# bundle, verifying SHA-256 against the pins passed in by the Makefile.
# Idempotent: no-op when the destination files already match.
#
# Usage:
#   fetch-privado-circuits.sh <dest_dir> <bundle_url> \
#       <wasm_sha256> <zkey_sha256> <vkey_sha256>
#
# Pins live in the top-level Makefile so they live next to the code that
# depends on them, not hidden in this script. Bumping a pin = bumping the
# Makefile constant + re-running this target.
set -euo pipefail

DEST_DIR="${1:?dest dir required}"
BUNDLE_URL="${2:?bundle URL required}"
WASM_SHA="${3:?wasm sha256 required}"
ZKEY_SHA="${4:?zkey sha256 required}"
VKEY_SHA="${5:?vkey sha256 required}"

AUTHV2_DIR="$DEST_DIR/authV2"
WASM="$AUTHV2_DIR/circuit.wasm"
ZKEY="$AUTHV2_DIR/circuit_final.zkey"
VKEY="$AUTHV2_DIR/verification_key.json"

sha256_of() {
  if command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | awk '{print $1}'
  else
    sha256sum "$1" | awk '{print $1}'
  fi
}

check_one() {
  local file="$1" want="$2"
  [[ -f "$file" ]] || return 1
  [[ "$(sha256_of "$file")" == "$want" ]]
}

if check_one "$WASM" "$WASM_SHA" \
   && check_one "$ZKEY" "$ZKEY_SHA" \
   && check_one "$VKEY" "$VKEY_SHA"; then
  echo "auth-v2 artifacts present in $AUTHV2_DIR (SHA-256 match) — nothing to do."
  exit 0
fi

echo "Fetching auth-v2 circuit artifacts from $BUNDLE_URL ..."
mkdir -p "$AUTHV2_DIR"
TMP_ZIP="$(mktemp -t privado-circuits.XXXXXX.zip)"
trap 'rm -f "$TMP_ZIP"' EXIT

# --fail makes curl exit non-zero on HTTP errors; -L follows redirects.
curl -fL --progress-bar "$BUNDLE_URL" -o "$TMP_ZIP"

echo "Extracting authV2/* ..."
unzip -o -q "$TMP_ZIP" "authV2/*" -d "$DEST_DIR"

# Per-file verify; bail loudly on any drift so the user knows to bump the
# Makefile pins (a checksum mismatch usually means Privado published a new
# bundle and the project hasn't picked it up yet).
for file_sha in "$WASM:$WASM_SHA" "$ZKEY:$ZKEY_SHA" "$VKEY:$VKEY_SHA"; do
  f="${file_sha%%:*}"
  want="${file_sha##*:}"
  got="$(sha256_of "$f")"
  if [[ "$got" != "$want" ]]; then
    echo "SHA-256 MISMATCH for $f" >&2
    echo "  want: $want" >&2
    echo "  got:  $got" >&2
    echo "  hint: bump the *_SHA256 pin in the top-level Makefile to the new value if you've verified the upstream change." >&2
    exit 1
  fi
done

echo "auth-v2 artifacts ready in $AUTHV2_DIR (SHA-256 verified)."
