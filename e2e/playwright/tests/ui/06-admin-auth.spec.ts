import { test, expect } from '@playwright/test';
import {
  mockLoginViaAPI,
  clearAuth,
} from '../../helpers/ui/auth-helpers';
import { selectors } from '../../helpers/ui/selectors';

test.describe('Admin Dashboard Auth', () => {
  test('admin user can access admin dashboard', async ({ page }) => {
    // mockLoginViaAPI grants admin claim by default
    await mockLoginViaAPI(page);
    await page.goto('/admin/dashboard');

    // Should see the admin app (not access denied)
    await expect(page.locator(selectors.admin.app)).toBeVisible({ timeout: 15000 });
  });

  test('non-admin user sees access denied', async ({ page }) => {
    const nonAdminDID = `did:test:ui_nonadmin_${Date.now()}`;
    await mockLoginViaAPI(page, nonAdminDID, { admin: false });
    await page.goto('/admin/dashboard');

    // Should see the "Access Denied" message
    await expect(page.getByText('Access Denied')).toBeVisible({ timeout: 15000 });
    await expect(
      page.getByText("You don't have admin privileges")
    ).toBeVisible();

    // Should NOT see the admin app
    await expect(page.locator(selectors.admin.app)).not.toBeVisible();
  });

  test('unauthenticated user is redirected to login', async ({ page }) => {
    await page.goto('/login');
    await clearAuth(page);

    await page.goto('/admin/dashboard');

    // RequireAuth should redirect to /login
    await expect(page).toHaveURL(/\/login/, { timeout: 15000 });
  });

  test('clearing auth and reloading redirects to login', async ({ page }) => {
    // First, log in as admin and verify dashboard loads
    await mockLoginViaAPI(page);
    await page.goto('/admin/dashboard');
    await expect(page.locator(selectors.admin.app)).toBeVisible({ timeout: 15000 });

    // Clear auth and reload
    await clearAuth(page);
    await page.reload();

    // Should be redirected to login
    await expect(page).toHaveURL(/\/login/, { timeout: 15000 });
  });
});
