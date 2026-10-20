import { test, expect } from '@playwright/test';
import { selectors } from '../../helpers/ui/selectors';
import { mockLoginViaAPI } from '../../helpers/ui/auth-helpers';
import { RBACTestFixture } from '../../helpers/rbac-fixtures';

// RD-917 §1 + RD-916: tenant lifecycle (POST/DELETE /admin/orgs) is
// reserved for super-admin (X-Admin-Token), which never has a UI session.
// The "Add Organization" and per-row "Delete organization" buttons were
// removed from OrganizationList.tsx. Tests that previously exercised
// those flows are replaced with negative assertions; tests that need a
// pre-existing org now seed via RBACTestFixture (which calls the admin
// API with X-Admin-Token).

test.describe('Organization CRUD', () => {
  test.beforeEach(async ({ page }) => {
    await mockLoginViaAPI(page);
  });

  test('organizations list displays correctly', async ({ page }) => {
    await page.goto('/admin/rbac/organizations');
    await expect(page.locator(selectors.rbac.manager)).toBeVisible({ timeout: 10000 });

    const orgsTab = page.locator(selectors.rbac.tabOrganizations);
    await expect(orgsTab).toHaveAttribute('data-state', 'active');

    await expect(page.getByRole('heading', { name: 'Organizations', exact: true })).toBeVisible();
    await expect(page.getByText('Top-level tenants that contain groups and contracts')).toBeVisible();
  });

  test('does not expose an "Add Organization" button (RD-917 §1: super-admin only)', async ({ page }) => {
    await page.goto('/admin/rbac/organizations');
    await expect(page.locator(selectors.rbac.manager)).toBeVisible({ timeout: 10000 });

    // Tier-1 super-admin (X-Admin-Token) never has a UI session, so the
    // create-org flow is intentionally absent from the dashboard.
    await expect(page.getByRole('button', { name: /add organization/i })).toHaveCount(0);
  });

  test('does not expose per-row "Delete organization" buttons (RD-917 §1: super-admin only)', async ({ page, request }) => {
    // Seed an org via the admin API so we can assert against rendered rows.
    const fixture = new RBACTestFixture(request);
    const org = await fixture.createOrg('no-delete-btn');

    await page.goto('/admin/rbac/organizations');
    await expect(page.locator(selectors.rbac.manager)).toBeVisible({ timeout: 10000 });

    const orgRow = page.getByRole('row').filter({ hasText: org.name });
    await expect(orgRow).toBeVisible({ timeout: 10000 });

    // No per-row delete button — tenant deletion is super-admin only.
    await expect(orgRow.getByTitle(/delete organization/i)).toHaveCount(0);
  });

  test('can edit an existing organization', async ({ page, request }) => {
    // Create the org via the fixture API. This both seeds the test org and
    // auto-grants the mock-admin user is_org_admin in it (see
    // RBACTestFixture.createOrg) — JWT admins need is_org_admin in the
    // target org to PUT /api/v1/admin/orgs/:id.
    const fixture = new RBACTestFixture(request);
    const org = await fixture.createOrg('edit-org');
    const orgName = org.name;

    await page.goto('/admin/rbac/organizations');
    await expect(page.locator(selectors.rbac.manager)).toBeVisible({ timeout: 10000 });

    const orgRow = page.getByRole('row').filter({ hasText: orgName });
    await expect(orgRow).toBeVisible({ timeout: 10000 });

    const editBtn = orgRow.getByTitle(/edit organization/i);
    await editBtn.click();

    const dialog = page.locator(selectors.common.dialog);
    await expect(dialog).toBeVisible();
    await expect(dialog.getByText('Edit Organization')).toBeVisible();

    const newName = `${orgName} Updated`;
    const nameInput = dialog.getByLabel(/name/i);
    await nameInput.clear();
    await nameInput.fill(newName);

    await dialog.getByRole('button', { name: /update organization/i }).click();

    await expect(dialog).not.toBeVisible({ timeout: 10000 });
    await expect(page.getByText(newName)).toBeVisible({ timeout: 10000 });
  });

  test('organization list shows created date column', async ({ page }) => {
    await page.goto('/admin/rbac/organizations');
    await expect(page.locator(selectors.rbac.manager)).toBeVisible({ timeout: 10000 });

    await expect(page.getByRole('columnheader', { name: /created/i })).toBeVisible();
  });

  test('organization list shows slug badge', async ({ page, request }) => {
    const fixture = new RBACTestFixture(request);
    const org = await fixture.createOrg('slug-badge');

    await page.goto('/admin/rbac/organizations');
    await expect(page.locator(selectors.rbac.manager)).toBeVisible({ timeout: 10000 });

    // The slug now appears in two places on the row: concatenated into the
    // displayed name (`Test Org <slug>`) and as a standalone monospace badge.
    // Use { exact: true } to target only the standalone badge so we don't trip
    // Playwright's strict-mode duplicate-element guard.
    await expect(page.getByText(org.slug, { exact: true })).toBeVisible({ timeout: 10000 });
  });

  test('clicking organization row selects it', async ({ page, request }) => {
    const fixture = new RBACTestFixture(request);
    const org = await fixture.createOrg('row-select');

    await page.goto('/admin/rbac/organizations');
    await expect(page.locator(selectors.rbac.manager)).toBeVisible({ timeout: 10000 });

    const orgRow = page.getByRole('row').filter({ hasText: org.name });
    await expect(orgRow).toBeVisible({ timeout: 10000 });

    await orgRow.click();

    await page.locator(selectors.rbac.tabGroups).click();

    const orgSelector = page.locator(selectors.rbac.orgSelector);
    await expect(orgSelector).toContainText(org.name);
  });
});
