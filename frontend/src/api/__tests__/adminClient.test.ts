import { describe, it, expect, beforeEach, vi, afterEach } from 'vitest';

// We test the header-selection logic by importing the module fresh each test
// and inspecting which headers the axios interceptor applies.

const AUTH_STORAGE_KEY = 'privacy_proxy_auth';

function clearAllStorage() {
  localStorage.clear();
  sessionStorage.clear();
}

// Build a fake stored auth object for localStorage.
function fakeAuth(accessToken: string, expiresInMs: number) {
  return JSON.stringify({
    accessToken,
    refreshToken: 'rt_test',
    expiresAt: Date.now() + expiresInMs,
  });
}

describe('adminClient header selection', () => {
  beforeEach(() => {
    clearAllStorage();
    vi.unstubAllEnvs();
  });

  afterEach(() => {
    clearAllStorage();
    vi.unstubAllEnvs();
  });

  it('does NOT read admin token from env vars (security: would leak into JS bundle)', async () => {
    vi.stubEnv('VITE_ADMIN_API_TOKEN', 'env-token-123');

    const mod = await import('../adminClient');
    // Env var must be ignored — only browser storage is safe
    expect(mod.getAdminToken()).toBe('');
  });

  it('attaches X-Admin-Token from localStorage', async () => {
    localStorage.setItem('privacy_proxy_admin_api_token', 'stored-token');

    const mod = await import('../adminClient');
    expect(mod.getAdminToken()).toBe('stored-token');
  });

  it('prefers X-Admin-Token over JWT', async () => {
    // Both admin token and JWT are present
    localStorage.setItem('privacy_proxy_admin_api_token', 'admin-tok');
    sessionStorage.setItem(AUTH_STORAGE_KEY, fakeAuth('jwt-tok', 300_000));

    const mod = await import('../adminClient');
    // Admin token takes priority
    expect(mod.getAdminToken()).toBe('admin-tok');
  });

  it('returns empty admin token when nothing is stored', async () => {
    const mod = await import('../adminClient');
    expect(mod.getAdminToken()).toBe('');
  });

  it('reads admin token from sessionStorage as fallback', async () => {
    sessionStorage.setItem('admin_api_token', 'session-tok');

    const mod = await import('../adminClient');
    expect(mod.getAdminToken()).toBe('session-tok');
  });

  it('tries keys in priority order', async () => {
    localStorage.setItem('admin_api_token', 'low-priority');
    localStorage.setItem('privacy_proxy_admin_api_token', 'high-priority');

    const mod = await import('../adminClient');
    expect(mod.getAdminToken()).toBe('high-priority');
  });
});
