import { test, expect } from '@playwright/test';
import { mockLoginViaAPI } from '../../../helpers/ui/auth-helpers';
import { RBACTestFixture } from '../../../helpers/rbac-fixtures';

// ---------------------------------------------------------------------------
// RD-1165 — Currency Selector UI (per-org, post-RD-1158).
//
// Since RD-1158 the base currency is a PER-ORG compliance setting, not a global
// super-admin switch. CurrencySelector renders an *editable* dropdown only when
// an org is in scope (CurrencyContext.canEdit === !!orgId, wired from
// ComplianceManager's selectedOrg); with no org it renders a read-only span
// (both carry data-testid="currency-selector"). ComplianceManager reads the
// selected org from the `?org=<id>` query param.
//
// So any test that actually opens the dropdown and switches currency must put
// an org in scope first — mirroring the sibling compliance specs
// (11-compliance-unsaved-changes, 13-compliance-monitor-mode): mock-login,
// create an org where that user is a tier-2 org admin via RBACTestFixture, then
// navigate to /admin/compliance/config?org=<id>. The switch then rides the
// per-org, org-admin-gated config endpoint (PUT /orgs/:id/compliance/config
// with { currency }) — NOT the old global super-admin base-currency endpoint.
//
// The read-only tests (default USD display, cross-tab visibility) only need the
// span, so they run without an org in scope.
// ---------------------------------------------------------------------------

test.describe('Currency Selector UI', () => {
  let fixture: RBACTestFixture;

  test.afterEach(async () => {
    if (fixture) {
      await fixture.cleanup();
    }
  });

  test('displays default USD currency in the selector', async ({ page }) => {
    // No org in scope → read-only span; it still shows the global default.
    await mockLoginViaAPI(page);
    await page.goto('/admin/compliance/config');

    // Wait for the compliance page to load
    await expect(page.getByRole('heading', { name: 'Compliance', exact: true })).toBeVisible({ timeout: 10000 });

    // Currency selector should show USD
    const selector = page.getByTestId('currency-selector');
    await expect(selector).toBeVisible({ timeout: 5000 });
    await expect(selector).toContainText('$ USD');
  });

  test('changes currency to EUR via the dropdown', async ({ page, request }) => {
    // Editable dropdown requires an org in scope: create one where the mock
    // admin is a tier-2 org admin, then select it via the ?org= query param.
    const currentDid = `did:privado:test_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;
    await mockLoginViaAPI(page, currentDid);
    fixture = new RBACTestFixture(request);
    const org = await fixture.createOrgWithAdmin('cc-currency-eur', currentDid);

    await page.goto(`/admin/compliance/config?org=${org.id}`);
    await expect(page.getByRole('heading', { name: 'Compliance', exact: true })).toBeVisible({ timeout: 10000 });

    // A brand-new org has no compliance config yet → currency defaults to USD.
    const selector = page.getByTestId('currency-selector');
    await expect(selector).toBeVisible({ timeout: 5000 });
    await expect(selector).toContainText('$ USD');

    // Open the currency dropdown (rendered because an org is in scope).
    await selector.click();

    // Wait for dropdown options to appear and click EUR
    const eurOption = page.getByRole('option', { name: /EUR/ });
    await expect(eurOption).toBeVisible({ timeout: 5000 });
    await eurOption.click();

    // Verify the selector now shows EUR (per-org currency was persisted).
    await expect(selector).toContainText('EUR', { timeout: 5000 });
  });

  test('currency change persists across page reload', async ({ page, request }) => {
    const currentDid = `did:privado:test_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;
    await mockLoginViaAPI(page, currentDid);
    fixture = new RBACTestFixture(request);
    const org = await fixture.createOrgWithAdmin('cc-currency-reload', currentDid);

    await page.goto(`/admin/compliance/config?org=${org.id}`);
    await expect(page.getByRole('heading', { name: 'Compliance', exact: true })).toBeVisible({ timeout: 10000 });

    const selector = page.getByTestId('currency-selector');
    await expect(selector).toBeVisible({ timeout: 5000 });

    // Change to EUR
    await selector.click();
    const eurOption = page.getByRole('option', { name: /EUR/ });
    await expect(eurOption).toBeVisible({ timeout: 5000 });
    await eurOption.click();
    await expect(selector).toContainText('EUR', { timeout: 5000 });

    // Reload the page (keep the org in scope via the same ?org= param).
    await page.goto(`/admin/compliance/config?org=${org.id}`);
    await expect(page.getByRole('heading', { name: 'Compliance', exact: true })).toBeVisible({ timeout: 10000 });

    // Verify EUR is still selected — the per-org config was persisted server-side.
    const selectorAfterReload = page.getByTestId('currency-selector');
    await expect(selectorAfterReload).toBeVisible({ timeout: 5000 });
    await expect(selectorAfterReload).toContainText('EUR', { timeout: 5000 });

    // Cleanup: change back to USD (the org itself is torn down in afterEach,
    // but restore the setting so the assertion genuinely round-trips both ways).
    await selectorAfterReload.click();
    const usdOption = page.getByRole('option', { name: /USD/ });
    await expect(usdOption).toBeVisible({ timeout: 5000 });
    await usdOption.click();
    await expect(selectorAfterReload).toContainText('$ USD', { timeout: 5000 });
  });

  test('currency selector is visible across compliance tabs', async ({ page }) => {
    // Visibility only — the read-only span is present with or without an org,
    // so no org scope is required here.
    await mockLoginViaAPI(page);

    // Start on config tab
    await page.goto('/admin/compliance/config');
    await expect(page.getByRole('heading', { name: 'Compliance', exact: true })).toBeVisible({ timeout: 10000 });
    await expect(page.getByTestId('currency-selector')).toBeVisible({ timeout: 5000 });

    // Navigate to sanctions tab (global tab)
    await page.getByRole('tab', { name: /Sanctions/ }).click();
    await expect(page.getByTestId('currency-selector')).toBeVisible({ timeout: 5000 });

    // Navigate to token prices tab
    await page.getByRole('tab', { name: /Token Prices/ }).click();
    await expect(page.getByTestId('currency-selector')).toBeVisible({ timeout: 5000 });
  });
});
