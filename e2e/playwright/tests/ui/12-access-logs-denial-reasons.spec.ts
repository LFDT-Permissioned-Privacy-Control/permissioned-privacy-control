import { test, expect } from '@playwright/test';
import { mockLoginViaAPI } from '../../helpers/ui/auth-helpers';

const PROXY_URL = process.env.PROXY_URL || 'http://localhost:8080';
const ADMIN_TOKEN = process.env.ADMIN_API_TOKEN || 'e2e-test-admin-token';

// ---------------------------------------------------------------------------
// RD-1137B — Denial reasons in the Access Logs view (v0.12.0 acceptance §3B).
//
// Acceptance "Expect": Dashboard → Access Logs → Outcome = "Denied" → denied
// rows show a HUMANIZED denial reason (e.g. "Sender not linked"); success rows
// show none; the Status column shows the TRUE HTTP status (not the collapsed
// 404 the client receives, and not a hardcoded 403).
//
// The proxy accepts JSON-RPC anonymously at POST / (OptionalJWTAuthMiddleware).
// We mint two deterministic access-log rows straight through the proxy:
//   - a DENIAL: anonymous eth_getBalance → not on the anonymous allowlist →
//     recorded with a curated reason (method_not_allowed / auth_required) and
//     the real 4xx status, even though the client body is a collapsed 404
//     (RD-1099 enumeration-oracle defense; RD-1137 logs the real status).
//   - a SUCCESS: anonymous eth_blockNumber → 200, no denial reason.
//
// Anonymous rows carry a NULL org, so only the super-admin token can see them
// (RD-1135). We inject that token into the admin client (same technique as the
// currency-selector spec) so the Access Logs view is fleet-wide.
//
// Reason humanization (AccessLogs.formatReason): snake_case → "Sentence case"
// (e.g. method_not_allowed → "Method not allowed"). We assert the humanized
// SHAPE (leading capital + a lowercased following word, i.e. a space) and,
// critically, that the raw snake_case code is NOT shown.
// ---------------------------------------------------------------------------

const DENIED_METHOD = 'eth_getBalance';
const SUCCESS_METHOD = 'eth_blockNumber';

// Humanized reason: starts with an uppercase letter, then lowercase, and
// contains a space where an underscore used to be — never a bare snake_case
// token like "method_not_allowed".
const HUMANIZED_REASON = /^[A-Z][a-z]+ [a-z].*/;

async function rpc(method: string, params: unknown[] = []): Promise<void> {
  // Anonymous (no auth header) so the row is org-free and the RBAC decision
  // is deterministic against the anonymous allowlist.
  await fetch(`${PROXY_URL}/`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }),
  });
}

test.describe('Access Logs denial reasons (RD-1137B)', () => {
  test.beforeEach(async ({ page }) => {
    await mockLoginViaAPI(page);
    // Make the admin client send X-Admin-Token (super-admin) so the org-scoped
    // logs view (RD-1135) returns the anonymous NULL-org rows we generate.
    await page.addInitScript((token) => {
      window.localStorage.setItem('privacy_proxy_admin_api_token', token);
    }, ADMIN_TOKEN);
  });

  async function setOutcome(page: import('@playwright/test').Page, optionName: RegExp) {
    const form = page.locator('form[aria-label="Access log filters"]');
    // The Outcome control is the Radix Select showing the "Outcome" placeholder.
    await form.getByRole('combobox').click();
    await page.getByRole('option', { name: optionName }).click();
  }

  async function filterByMethod(page: import('@playwright/test').Page, method: string) {
    const form = page.locator('form[aria-label="Access log filters"]');
    const methodInput = form.getByPlaceholder(/Method/);
    await methodInput.fill(method);
    await form.getByRole('button', { name: /Apply filters/ }).click();
  }

  test('denied rows show a humanized reason and the true 4xx status', async ({ page }) => {
    await rpc(DENIED_METHOD, ['0x0000000000000000000000000000000000000000', 'latest']);

    await page.goto('/admin/logs');
    await expect(page.getByRole('heading', { name: 'Access Logs' })).toBeVisible({ timeout: 10000 });

    await setOutcome(page, /Denied \(4xx\)/);
    await filterByMethod(page, DENIED_METHOD);

    // At least one denied row for our method.
    const row = page.locator('tbody tr').filter({ hasText: DENIED_METHOD }).first();
    await expect(row).toBeVisible({ timeout: 10000 });

    // Status column (4th cell, index 3) shows the TRUE status: a 4xx code
    // (403 method_not_allowed / 401 auth_required) — NOT the 404 body the
    // client got, and not a 2xx.
    const statusCell = row.getByRole('cell').nth(3);
    await expect(statusCell).toHaveText(/^4\d{2}$/);

    // Reason column (5th cell, index 4) shows a HUMANIZED reason, not the raw
    // snake_case code and not the empty "-" placeholder.
    const reasonCell = row.getByRole('cell').nth(4);
    await expect(reasonCell).toHaveText(HUMANIZED_REASON);
    await expect(reasonCell).not.toHaveText('-');
    await expect(reasonCell).not.toHaveText(/_/);
  });

  test('success rows carry no denial reason', async ({ page }) => {
    await rpc(SUCCESS_METHOD);

    await page.goto('/admin/logs');
    await expect(page.getByRole('heading', { name: 'Access Logs' })).toBeVisible({ timeout: 10000 });

    await setOutcome(page, /Success \(2xx\)/);
    await filterByMethod(page, SUCCESS_METHOD);

    const row = page.locator('tbody tr').filter({ hasText: SUCCESS_METHOD }).first();
    await expect(row).toBeVisible({ timeout: 10000 });

    // Status is 2xx and the reason cell is the empty "-" placeholder.
    await expect(row.getByRole('cell').nth(3)).toHaveText(/^2\d{2}$/);
    await expect(row.getByRole('cell').nth(4)).toHaveText('-');
  });
});
