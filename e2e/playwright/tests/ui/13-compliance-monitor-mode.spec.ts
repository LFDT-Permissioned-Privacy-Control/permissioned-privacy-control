import { test, expect } from '@playwright/test';
import { mockLoginViaAPI } from '../../helpers/ui/auth-helpers';
import { RBACTestFixture } from '../../helpers/rbac-fixtures';

// ---------------------------------------------------------------------------
// RD-1044 — Compliance enforcement "Monitor" mode (v0.12.0 acceptance §3C).
//
// Acceptance "Expect": Compliance → set Enforcement mode = Monitor (amber
// warning notes sanctions still block) → Save → an above-threshold transfer
// proceeds and shows in Compliance → Logs with decision `allowed` + a
// would-block marker; a sanctioned recipient is still blocked.
//
// SCOPE OF THIS UI SPEC (see the honest split below):
//   * Testable at the UI layer (asserted here): the Compliance Config screen
//     lets you choose Monitor, save it, surfaces the amber "Sanctions still
//     block" warning, and the mode persists across reload. This is the UI half
//     RD-1159 Phase 3 targets.
//   * The transfer-proceeds / sanctioned-still-blocked BACKEND behavior is
//     already locked by Go tests (TestCheckerCheck_MonitorMode,
//     TestUpdateComplianceConfig_EnforcementMode) and needs a funded
//     deployed-token + travel-rule setup that is out of a UI spec's reach — not
//     re-driven through the browser here.
//   * The "would-block marker in Compliance → Logs" is documented behavior but
//     is NOT rendered by ComplianceLogList today (the `would_block` field
//     exists on the ComplianceLog type but no badge/text surfaces it). That
//     assertion is captured as a test.fixme below so it is discoverable and
//     encodes the acceptance contract without failing CI on an unimplemented
//     UI element. Flip it to a live test once the marker ships (RD-1044 UI).
//
// Copy mirrors ComplianceConfig.tsx: enforcement-mode Select options
// "Enforce — block violations" / "Monitor — allow & record"; amber note
// "Monitor mode: threshold & travel-rule violations are recorded but NOT
// blocked. Sanctions still block."; Save button "Save Configuration"; success
// banner "Configuration saved successfully".
//
// Switching the enforcement mode marks the form dirty and enables Save. NOTE:
// this spec originally surfaced an RD-1044 bug — ComplianceConfig.isDirty did
// NOT track enforcement_mode, so a mode-only change (the exact operator action
// here) left Save disabled and the switch was unsaveable. Fixed in the same
// change: enforcement_mode is now part of isDirty.
// ---------------------------------------------------------------------------

const MONITOR_WARNING =
  /Monitor mode: threshold .* recorded but NOT blocked\. Sanctions still block\./;

test.describe('Compliance monitor mode (RD-1044)', () => {
  let fixture: RBACTestFixture;

  test.afterEach(async () => {
    if (fixture) {
      await fixture.cleanup();
    }
  });

  test('Enforcement mode = Monitor saves, warns that sanctions still block, and persists', async ({ page, request }) => {
    const currentDid = `did:privado:test_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;
    await mockLoginViaAPI(page, currentDid);

    fixture = new RBACTestFixture(request);
    const org = await fixture.createOrgWithAdmin('cc-monitor', currentDid);

    await page.goto(`/admin/compliance/config?org=${org.id}`);
    await expect(page.getByText('Compliance Configuration')).toBeVisible({ timeout: 10000 });

    // Default mode is Enforce → no monitor warning yet.
    await expect(page.getByText(MONITOR_WARNING)).toHaveCount(0);

    // Open the "Enforcement mode" Select and pick Monitor. It is the last
    // combobox in the form (after "Transfers with unknown price").
    const comboboxes = page.getByRole('combobox');
    await comboboxes.last().click();
    // Only one option mentions "Monitor" (the other is "Enforce — block
    // violations"), so match loosely to avoid depending on the em-dash glyph.
    await page.getByRole('option', { name: /Monitor/ }).click();

    // The amber warning appears, explicitly noting sanctions still block.
    await expect(page.getByText(MONITOR_WARNING)).toBeVisible();

    // Save is now enabled (the mode switch marked the form dirty) — persist it.
    await page.getByRole('button', { name: /Save Configuration/ }).click();
    await expect(page.getByText('Configuration saved successfully')).toBeVisible({ timeout: 10000 });

    // Persistence: reload and confirm Monitor stuck (warning still present).
    await page.reload();
    await expect(page.getByText('Compliance Configuration')).toBeVisible({ timeout: 10000 });
    await expect(page.getByText(MONITOR_WARNING)).toBeVisible({ timeout: 10000 });
  });

  // The acceptance also expects a monitored (would-have-blocked) transfer to
  // appear in Compliance → Logs with decision `allowed` + a would-block marker.
  // ComplianceLogList does not render the `would_block` flag yet, so this is a
  // fixme (discoverable via --list, non-failing) until the marker UI ships.
  test.fixme('monitored violation shows in Compliance → Logs as allowed + a would-block marker', async ({ page, request }) => {
    const currentDid = `did:privado:test_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;
    await mockLoginViaAPI(page, currentDid);

    fixture = new RBACTestFixture(request);
    const org = await fixture.createOrgWithAdmin('cc-monitor-log', currentDid);

    // Preconditions once the marker exists: monitor mode on, a token with a
    // known price, and an above-threshold transfer driven through the proxy so
    // a would_block=true row is recorded.
    await page.goto(`/admin/compliance/logs?org=${org.id}`);
    await expect(page.getByText('Compliance Logs')).toBeVisible({ timeout: 10000 });

    const row = page.locator('tbody tr').first();
    await expect(row).toBeVisible();
    // decision `allowed` (monitor let it proceed)...
    await expect(row.getByText('allowed')).toBeVisible();
    // ...plus a would-block marker distinguishing it from a plain allow.
    await expect(row.getByText(/would.?block/i)).toBeVisible();
  });
});
