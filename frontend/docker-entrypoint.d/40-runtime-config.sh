#!/bin/sh
# Regenerate /config.js from VITE_* environment variables on container start.
# The nginx:alpine base image runs every executable in /docker-entrypoint.d/
# before launching nginx, so this composes with 20-envsubst-on-templates.sh.
#
# This makes environment-specific values (e.g. VITE_BLOCK_EXPLORER_URL) a
# DEPLOY-time setting instead of a build-time bake — one image, many envs.
#
# SECURITY:
#   * Only VITE_*-prefixed vars are emitted. Never put secrets in VITE_* vars;
#     this file is served to every browser.
#   * Values are sanitized so an env value can't break out of the JS string
#     literal or the <script> context (XSS hardening).
set -eu

CONFIG_FILE="/usr/share/nginx/html/config.js"

printf 'window.__runtimeConfig = {\n' > "$CONFIG_FILE"

env | grep '^VITE_' | sort | while IFS='=' read -r key value; do
  # 1) backslash first (\ -> \\)  2) double quotes (" -> \")
  # 3) strip CR/LF (would terminate the JS string)  4) neutralise </script>
  sanitized=$(printf '%s' "$value" \
    | sed 's/\\/\\\\/g' \
    | sed 's/"/\\"/g' \
    | tr -d '\n\r' \
    | sed 's#</script>#<\\/script>#gi')
  printf '  "%s": "%s",\n' "$key" "$sanitized" >> "$CONFIG_FILE"
done

printf '};\n' >> "$CONFIG_FILE"

echo "runtime config: wrote $(grep -c '": "' "$CONFIG_FILE") VITE_* var(s) to ${CONFIG_FILE}"
