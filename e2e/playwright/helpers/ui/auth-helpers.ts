import { Page, expect } from '@playwright/test';
import { selectors } from './selectors';

const ADMIN_URL = process.env.ADMIN_URL || process.env.PROXY_URL || 'http://localhost:8080';
const ADMIN_TOKEN = process.env.ADMIN_API_TOKEN || 'e2e-test-admin-token';

interface AuthTokens {
  accessToken: string;
  refreshToken: string;
  expiresIn: number;
}

/**
 * Perform mock login via the UI mock login button.
 * Requires VITE_ALLOW_MOCK_LOGIN=true in the frontend environment.
 *
 * @param page - Playwright page object
 */
export async function mockLoginViaUI(page: Page): Promise<void> {
  // Navigate to login page
  await page.goto('/login');

  // Wait for the login page to be visible
  await expect(page.locator(selectors.login.page)).toBeVisible({ timeout: 10000 });

  // Wait for dev tools to appear (indicates mock login is available)
  const devTools = page.locator(selectors.login.devTools);
  await expect(devTools).toBeVisible({ timeout: 10000 });

  // Click the mock login button
  const mockLoginBtn = page.locator(selectors.login.mockLoginBtn);
  await expect(mockLoginBtn).toBeVisible();
  await mockLoginBtn.click();

  // Wait for success state or redirect
  // The login will redirect to /link-wallet on success
  await expect(page).toHaveURL(/\/(link-wallet|admin)/, { timeout: 15000 });
}

/**
 * Perform mock login via direct API calls and inject tokens into localStorage.
 * This is faster than UI-based login and useful for setting up authenticated state.
 *
 * By default, grants admin claim so the user can access admin routes.
 * Pass { admin: false } to create a non-admin user.
 *
 * @param page - Playwright page object
 * @param userDID - Optional DID for the mock user (defaults to a generated DID)
 * @param options - Options for login behavior
 */
// Tracks the DID set up by the most recent mockLoginViaAPI call. Used by
// RBACTestFixture.createOrg so newly-created orgs automatically include the
// test user as a tier-2 admin (is_org_admin = true). Without this, JWT
// admins are scoped to their original `e2e-admin-org` only and the
// admin-org middleware rejects calls to /api/v1/admin/orgs/<new-org>/...
let _currentMockAdminDID: string | null = null;

// RD-1107: the mock admin's access token, captured alongside the DID. The
// RBACTestFixture routes per-org mutations through this JWT (the mock admin is
// is_org_admin in every fixture-created org) because the super-admin token can
// no longer perform per-org tenant management.
let _currentMockAdminToken: string | null = null;

export function getCurrentMockAdminDID(): string | null {
  return _currentMockAdminDID;
}

export function getCurrentMockAdminToken(): string | null {
  return _currentMockAdminToken;
}

export async function mockLoginViaAPI(
  page: Page,
  userDID?: string,
  options: { admin?: boolean } = {},
): Promise<string> {
  const { admin = true } = options;
  const did = userDID || `did:privado:dev_${Date.now()}`;

  // Get tokens via API (also creates the user in the DB)
  const tokens = await getAuthTokens(did);

  // Grant admin claim if needed
  if (admin) {
    await ensureAdminClaim(did);
    _currentMockAdminDID = did;
    _currentMockAdminToken = tokens.accessToken;
  } else {
    _currentMockAdminDID = null;
    _currentMockAdminToken = null;
  }

  // Synchronously clear any "auth_cleared" sentinel left by a beforeEach
  // that invoked clearAuth(). This is best-effort and is allowed to fail
  // when no document is loaded yet — the init script below will handle
  // those cases on the next navigation.
  try {
    await page.evaluate(() => sessionStorage.removeItem('privacy_proxy_auth_cleared'));
  } catch {
    /* no document context yet, init script will pick it up */
  }

  // Set up sessionStorage with auth tokens before navigating. The init
  // script honors the "cleared" flag so that a later clearAuth() prevents
  // re-injection on subsequent page loads/reloads.
  await page.addInitScript((authData) => {
    if (sessionStorage.getItem('privacy_proxy_auth_cleared')) return;
    const storageKey = 'privacy_proxy_auth';
    const auth = {
      accessToken: authData.accessToken,
      refreshToken: authData.refreshToken,
      expiresAt: Date.now() + authData.expiresIn * 1000,
    };
    sessionStorage.setItem(storageKey, JSON.stringify(auth));
  }, tokens);

  return did;
}

/**
 * Get auth tokens via the backend API using mock authentication.
 * This directly calls the auth endpoints to get JWT tokens.
 *
 * @param userDID - The DID to authenticate as
 * @returns Auth tokens
 */
export async function getAuthTokens(userDID: string): Promise<AuthTokens> {
  // Step 1: Create auth request to get session ID
  const authRequestResponse = await fetch(`${ADMIN_URL}/auth/request`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
  });

  if (!authRequestResponse.ok) {
    const body = await authRequestResponse.text();
    throw new Error(`Failed to create auth request: ${authRequestResponse.status} - ${body}`);
  }

  const { session_id } = await authRequestResponse.json();

  // Step 2: Verify with mock JWZ token (dev mode only)
  const verifyResponse = await fetch(`${ADMIN_URL}/auth/verify`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      session_id,
      jwz_token: `mock.${userDID}`,
    }),
  });

  if (!verifyResponse.ok) {
    const body = await verifyResponse.text();
    throw new Error(`Failed to verify auth: ${verifyResponse.status} - ${body}`);
  }

  const data = await verifyResponse.json();
  return {
    accessToken: data.access_token,
    refreshToken: data.refresh_token,
    expiresIn: data.expires_in,
  };
}

/**
 * Check if the user is currently authenticated by examining sessionStorage.
 *
 * @param page - Playwright page object
 * @returns True if authenticated
 */
export async function isAuthenticated(page: Page): Promise<boolean> {
  return page.evaluate(() => {
    const stored = sessionStorage.getItem('privacy_proxy_auth');
    if (!stored) return false;

    try {
      const auth = JSON.parse(stored);
      return auth.expiresAt > Date.now();
    } catch {
      return false;
    }
  });
}

/**
 * Clear authentication state (logout).
 *
 * @param page - Playwright page object
 */
export async function clearAuth(page: Page): Promise<void> {
  await page.evaluate(() => {
    sessionStorage.removeItem('privacy_proxy_auth');
    // Set flag so that addInitScript won't re-inject tokens on reload
    sessionStorage.setItem('privacy_proxy_auth_cleared', '1');
  });
}

/**
 * Navigate to admin section after ensuring authentication.
 * If not authenticated, performs mock login first.
 *
 * @param page - Playwright page object
 * @param path - Admin path to navigate to (e.g., '/admin/dashboard')
 */
export async function navigateToAdminAuthenticated(
  page: Page,
  path: string = '/admin/dashboard'
): Promise<void> {
  // First, inject auth tokens via API (with admin claim)
  await mockLoginViaAPI(page);

  // Now navigate to the admin page
  await page.goto(path);

  // Wait for admin app to be visible
  await expect(page.locator(selectors.admin.app)).toBeVisible({ timeout: 10000 });
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

const adminHeaders = {
  'Content-Type': 'application/json',
  'X-Admin-Token': ADMIN_TOKEN,
};

// Cache: we reuse a single "e2e admin" group across all test users to avoid
// creating hundreds of orgs/groups. Created lazily on first call.
let adminGroupCache: { orgId: string; groupId: string } | null = null;

/**
 * Ensure a shared "e2e admin" org+group exists with the admin claim.
 * Returns { orgId, groupId }.
 */
async function getOrCreateAdminGroup(): Promise<{ orgId: string; groupId: string }> {
  if (adminGroupCache) return adminGroupCache;

  // Try to find existing org by slug
  const orgsRes = await fetch(`${ADMIN_URL}/api/v1/admin/orgs?limit=1000`, {
    headers: adminHeaders,
  });
  if (!orgsRes.ok) throw new Error(`Failed to list orgs: ${orgsRes.status}`);
  const orgs = ((await orgsRes.json()) as { data: { id: string; slug: string }[] }).data ?? [];
  const existing = orgs.find((o) => o.slug === 'e2e-admin-org');

  if (existing) {
    // Find the admin group within this org
    const groupsRes = await fetch(`${ADMIN_URL}/api/v1/admin/orgs/${existing.id}/groups`, {
      headers: adminHeaders,
    });
    if (!groupsRes.ok) throw new Error(`Failed to list groups: ${groupsRes.status}`);
    const groups = ((await groupsRes.json()) as { data: { group: { id: string; slug: string } }[] }).data ?? [];
    const adminGroup = groups.find((g) => g.group.slug === 'e2e-admin-group');
    if (adminGroup) {
      adminGroupCache = { orgId: existing.id, groupId: adminGroup.group.id };
      return adminGroupCache;
    }
  }

  // Create org
  const orgRes = await fetch(`${ADMIN_URL}/api/v1/admin/orgs`, {
    method: 'POST',
    headers: adminHeaders,
    body: JSON.stringify({ slug: 'e2e-admin-org', name: 'E2E Admin Org' }),
  });
  if (!orgRes.ok && orgRes.status !== 409) {
    throw new Error(`Failed to create admin org: ${orgRes.status} - ${await orgRes.text()}`);
  }
  // Re-fetch to get the ID (handles both create and 409 conflict)
  const orgsRes2 = await fetch(`${ADMIN_URL}/api/v1/admin/orgs?limit=1000`, {
    headers: adminHeaders,
  });
  const orgs2 = ((await orgsRes2.json()) as { data: { id: string; slug: string }[] }).data ?? [];
  const org = orgs2.find((o) => o.slug === 'e2e-admin-org');
  if (!org) throw new Error('Failed to find e2e-admin-org after creation');

  // Create group. is_org_admin=true matches the 3-tier admin model (RD-849):
  // /api/v1/admin/* gates on is_org_admin, not on group_access claims alone.
  const groupRes = await fetch(`${ADMIN_URL}/api/v1/admin/orgs/${org.id}/groups`, {
    method: 'POST',
    headers: adminHeaders,
    body: JSON.stringify({ slug: 'e2e-admin-group', name: 'E2E Admin Group', is_org_admin: true }),
  });
  if (!groupRes.ok && groupRes.status !== 409) {
    throw new Error(`Failed to create admin group: ${groupRes.status} - ${await groupRes.text()}`);
  }

  // Get group ID
  const groupsRes2 = await fetch(`${ADMIN_URL}/api/v1/admin/orgs/${org.id}/groups`, {
    headers: adminHeaders,
  });
  const groups2 = ((await groupsRes2.json()) as { data: { group: { id: string; slug: string } }[] }).data ?? [];
  const group = groups2.find((g) => g.group.slug === 'e2e-admin-group');
  if (!group) throw new Error('Failed to find e2e-admin-group after creation');

  // Set admin claim on the group
  await fetch(`${ADMIN_URL}/api/v1/admin/orgs/${org.id}/groups/${group.group.id}/access`, {
    method: 'PUT',
    headers: adminHeaders,
    body: JSON.stringify({
      allowed_methods: ['*'],
      claims: ['admin'],
    }),
  });

  adminGroupCache = { orgId: org.id, groupId: group.group.id };
  return adminGroupCache;
}

/**
 * Grant the admin claim to a user by adding them to the shared e2e admin group.
 * Idempotent — safe to call multiple times for the same user.
 */
async function ensureAdminClaim(userDID: string): Promise<void> {
  const { groupId } = await getOrCreateAdminGroup();

  // Find the user by external ID
  const usersRes = await fetch(`${ADMIN_URL}/api/v1/admin/users?limit=1000`, {
    headers: adminHeaders,
  });
  if (!usersRes.ok) throw new Error(`Failed to list users: ${usersRes.status}`);
  const users = ((await usersRes.json()) as { data: { id: string; external_id: string }[] }).data ?? [];
  const user = users.find((u) => u.external_id === userDID);
  if (!user) throw new Error(`User not found for DID: ${userDID}`);

  // Add membership (ignore 409 conflict = already a member)
  const memberRes = await fetch(`${ADMIN_URL}/api/v1/admin/users/${user.id}/memberships`, {
    method: 'POST',
    headers: adminHeaders,
    body: JSON.stringify({ group_id: groupId }),
  });
  if (!memberRes.ok && memberRes.status !== 409) {
    const body = await memberRes.text();
    // Treat duplicate key constraint as success (membership already exists via dev provisioner)
    if (!body.includes('duplicate key') && !body.includes('23505')) {
      throw new Error(`Failed to add admin membership: ${memberRes.status} - ${body}`);
    }
  }
}
