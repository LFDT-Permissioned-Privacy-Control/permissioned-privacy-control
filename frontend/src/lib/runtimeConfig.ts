// Runtime configuration — reads from window.__runtimeConfig, injected at
// container startup by docker-entrypoint.d/40-runtime-config.sh, with a
// fallback to import.meta.env for the Vite dev server.
//
// In production the nginx image regenerates /config.js from VITE_* env vars on
// every container start, so environment-specific URLs (e.g. the block-explorer
// origin) are a deploy-time setting — NOT baked into the JS bundle at build.
//
// SECURITY: only VITE_*-prefixed env vars are exposed to the browser. Never put
// secrets in a VITE_* variable — everything here is world-readable.

interface RuntimeConfig {
  [key: string]: string | undefined;
}

declare global {
  interface Window {
    __runtimeConfig?: RuntimeConfig;
  }
}

/**
 * Resolve a VITE_* configuration value.
 * Priority: window.__runtimeConfig (runtime) > import.meta.env (build/dev) > fallback.
 * Safe when /config.js failed to load (optional chaining → fallback).
 */
export function getConfig(key: string, fallback = ''): string {
  const runtimeValue = window.__runtimeConfig?.[key];
  if (runtimeValue !== undefined && runtimeValue !== '') {
    return runtimeValue;
  }

  const buildValue = import.meta.env[key as keyof ImportMetaEnv];
  if (buildValue !== undefined && buildValue !== '') {
    return String(buildValue);
  }

  return fallback;
}
