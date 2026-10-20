import { test, expect } from '@playwright/test';
import { mockLoginViaAPI, getCurrentMockAdminToken } from '../../helpers/ui/auth-helpers';
import { RBACTestFixture } from '../../helpers/rbac-fixtures';

const ADMIN_URL = process.env.ADMIN_URL || process.env.PROXY_URL || 'http://localhost:8080';

// ---------------------------------------------------------------------------
// RD-1070 — Compliance config unsaved-changes guard (v0.12.0 acceptance §3E).
//
// Acceptance "Expect": Compliance → toggle Enabled → an "Unsaved changes" badge
// appears and Save becomes enabled (Save is gated on dirty state); reloading
// while dirty triggers a confirm-discard (beforeunload) prompt.
//
// Copy mirrors ComplianceConfig.tsx + its vitest suite:
//   - Enabled toggle button reads "…— Click to disable" / "…— Click to enable".
//   - Dirty state surfaces both a "Unsaved changes" warning Badge and a
//     "You have unsaved changes" hint next to Save.
//   - Save button label: "Save Configuration"; disabled when clean, enabled
//     when dirty.
//   - A `beforeunload` handler is registered while dirty (and torn down when
//     clean). Playwright can't drive the native OS dialog, so we assert the
//     handler is installed by dispatching a cancelable `beforeunload` event and
//     checking it was default-prevented (the confirm-discard signal), and that
//     it is NOT installed when the form is clean.
//
// dirty-state note: ComplianceConfig treats a missing config (a brand-new org,
// 404) as permanently dirty so the first save can create it. To exercise the
// clean⇄dirty transition we seed an initial saved config via the org-admin JWT
// (per RD-1107 per-org compliance config is org-admin scoped, not super-admin)
// so the page loads in a known-clean state.
// ---------------------------------------------------------------------------

async function seedCleanConfig(orgId: string): Promise<void> {
  const token = getCurrentMockAdminToken();
  if (!token) throw new Error('expected a mock-admin JWT from mockLoginViaAPI');
  const res = await fetch(`${ADMIN_URL}/api/v1/admin/orgs/${orgId}/compliance/config`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
    body: JSON.stringify({
      enabled: true,
      threshold_fiat: 1000,
      unknown_price_policy: 'forbidden',
      enforcement_mode: 'enforce',
    }),
  });
  if (!res.ok) {
    throw new Error(`failed to seed compliance config: ${res.status} - ${await res.text()}`);
  }
}

async function beforeUnloadIsGuarded(page: import('@playwright/test').Page): Promise<boolean> {
  // Dispatch a cancelable beforeunload; the component's handler calls
  // preventDefault()/sets returnValue when (and only when) the form is dirty.
  return page.evaluate(() => {
    const evt = new Event('beforeunload', { cancelable: true });
    window.dispatchEvent(evt);
    return evt.defaultPrevented;
  });
}

test.describe('Compliance config unsaved-changes guard (RD-1070)', () => {
  let fixture: RBACTestFixture;

  test.afterEach(async () => {
    if (fixture) {
      await fixture.cleanup();
    }
  });

  test('toggling Enabled shows the badge, enables Save, and arms the reload guard', async ({ page, request }) => {
    const currentDid = `did:privado:test_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;
    await mockLoginViaAPI(page, currentDid);

    fixture = new RBACTestFixture(request);
    const org = await fixture.createOrgWithAdmin('cc-dirty', currentDid);
    await seedCleanConfig(org.id);

    // ComplianceManager reads the selected org from the ?org= query param.
    await page.goto(`/admin/compliance/config?org=${org.id}`);
    await expect(page.getByText('Compliance Configuration')).toBeVisible({ timeout: 10000 });

    // Clean state: no dirty cues, Save disabled, reload guard NOT armed.
    const saveBtn = page.getByRole('button', { name: /Save Configuration/ });
    await expect(saveBtn).toBeDisabled();
    // exact:true so the "Unsaved changes" Badge is not conflated with the
    // "You have unsaved changes" hint (substring match would hit both).
    await expect(page.getByText('Unsaved changes', { exact: true })).toHaveCount(0);
    await expect(page.getByText('You have unsaved changes')).toHaveCount(0);
    expect(await beforeUnloadIsGuarded(page)).toBe(false);

    // Toggle Enabled via the enforcement button ("… — Click to enable/disable").
    await page.getByRole('button', { name: /Click to (enable|disable)/ }).click();

    // Dirty state: badge + hint appear, Save enabled, reload guard armed.
    await expect(page.getByText('Unsaved changes', { exact: true })).toBeVisible();
    await expect(page.getByText('You have unsaved changes')).toBeVisible();
    await expect(saveBtn).toBeEnabled();
    expect(await beforeUnloadIsGuarded(page)).toBe(true);
  });

  test('reload guard clears once the form is no longer dirty', async ({ page, request }) => {
    const currentDid = `did:privado:test_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;
    await mockLoginViaAPI(page, currentDid);

    fixture = new RBACTestFixture(request);
    const org = await fixture.createOrgWithAdmin('cc-clean', currentDid);
    await seedCleanConfig(org.id);

    await page.goto(`/admin/compliance/config?org=${org.id}`);
    await expect(page.getByText('Compliance Configuration')).toBeVisible({ timeout: 10000 });

    // Make it dirty → guard armed.
    await page.getByRole('button', { name: /Click to (enable|disable)/ }).click();
    await expect(page.getByText('Unsaved changes', { exact: true })).toBeVisible();
    expect(await beforeUnloadIsGuarded(page)).toBe(true);

    // Toggle back → clean again → guard disarmed, cues gone, Save disabled.
    await page.getByRole('button', { name: /Click to (enable|disable)/ }).click();
    await expect(page.getByText('Unsaved changes', { exact: true })).toHaveCount(0);
    await expect(page.getByRole('button', { name: /Save Configuration/ })).toBeDisabled();
    expect(await beforeUnloadIsGuarded(page)).toBe(false);
  });
});
