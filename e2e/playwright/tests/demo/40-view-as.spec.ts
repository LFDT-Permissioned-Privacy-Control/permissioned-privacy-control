import { test, expect } from '@playwright/test';
import { setExplorerAuthCookie } from '../../helpers/demo/api';
import { readDemoManifest } from '../../helpers/demo/state';

const FRONTEND_URL = process.env.FRONTEND_URL || 'http://localhost:5173';

test('the real View as button opens explorer with only the target user visibility', async ({ page, context }) => {
  const m = await readDemoManifest();
  await setExplorerAuthCookie(context, m.personas.admin.token);
  await page.addInitScript(({ token }) => {
    sessionStorage.setItem('privacy_proxy_auth', JSON.stringify({
      accessToken: token,
      refreshToken: 'demo-e2e-refresh-not-used',
      expiresAt: Date.now() + 30 * 60 * 1000,
    }));
  }, { token: m.personas.admin.token });

  await page.goto(`${FRONTEND_URL}/admin/rbac/users?org=${m.orgs.a.id}`);
  const row = page.locator('tbody tr').filter({
    has: page.locator(`[title="${m.personas.outsider.did}"]`),
  });
  await expect(row).toHaveCount(1);
  const button = row.getByTitle('View as in Explorer');
  await expect(button).toBeEnabled();
  await button.click();

  await expect(page.getByTestId('impersonation-banner')).toBeVisible({ timeout: 20_000 });
  await expect(page).toHaveURL(/^http:\/\/block-explorer-frontend\/$/);
  await expect(page.getByText(/View-as mode/i)).toBeVisible();

  const search = page.getByRole('textbox', { name: /Search Gateway Explorer/i });
  await search.fill(m.contracts.counter.address);
  await search.press('Enter');
  await expect(page).toHaveURL(new RegExp(`/address/${m.contracts.counter.address}$`, 'i'));
  await expect(page.getByTestId('impersonation-banner')).toBeVisible();
  await expect(page.getByRole('heading', { name: /Address Restricted/i })).toBeVisible();
  const body = await page.locator('body').innerText();
  expect(body.toLowerCase()).not.toContain(m.transactions.writerIncrement.hash.toLowerCase());

  await page.getByRole('button', { name: /Stop viewing as/i }).click();
  await expect(page.getByTestId('impersonation-banner')).not.toBeVisible();
  await page.goto(`/address/${m.contracts.counter.address}`);
  await expect(page.getByRole('heading', { name: /Address Restricted/i })).not.toBeVisible();
  // Absence of the restriction heading is not enough: a blank page, 404, or a
  // failed admin-session restore would also satisfy it. Assert the admin
  // positively sees the counter contract's address page again.
  await expect(page.getByTestId('tab-transactions')).toBeVisible();
});
