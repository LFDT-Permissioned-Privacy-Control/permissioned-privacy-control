import { getConfig } from '@/lib/runtimeConfig';

/**
 * Resolve the block-explorer base URL the RBAC "View as" button navigates to.
 *
 * Read at call time from runtime config (window.__runtimeConfig, regenerated
 * per-deploy by the nginx container) so it is a deploy-time setting, not baked
 * into the bundle. In the Vite dev server we fall back to the local explorer;
 * in a production build there is deliberately NO localhost fallback — an
 * unconfigured deployment must disable the affordance rather than silently send
 * an admin to localhost (the build-time bake that did so broke devnet).
 *
 * Returns '' (→ caller disables the button) unless the value is a valid
 * absolute http(s) URL. The scheme check is defence-in-depth: the value is
 * operator-controlled, but we still refuse to navigate to javascript:/data:/etc.
 */
export function resolveExplorerUrl(): string {
  const configured = getConfig(
    'VITE_BLOCK_EXPLORER_URL',
    import.meta.env.DEV ? 'http://localhost:3001' : '',
  );
  if (!configured) return '';
  try {
    const parsed = new URL(configured);
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') return '';
    return configured.replace(/\/+$/, '');
  } catch {
    return '';
  }
}
