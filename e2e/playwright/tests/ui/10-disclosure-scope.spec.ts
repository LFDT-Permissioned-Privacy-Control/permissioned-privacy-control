import { test, expect, Locator } from '@playwright/test';
import { mockLoginViaAPI } from '../../helpers/ui/auth-helpers';

// ---------------------------------------------------------------------------
// RD-1072 — Disclosure "Requested Data Scope" full-vs-narrow mutual exclusivity
// (v0.12.0 acceptance §3E).
//
// Acceptance "Expect": Disclosure → Create Request → ticking Full Disclosure
// then a narrow scope (and the reverse) are mutually exclusive; the two narrow
// scopes (Activity Logs + Transaction History) can combine.
//
// The scope controls are <button type="button"> toggles (no aria-pressed);
// selection is shown by the `bg-primary-50` class — the same signal the vitest
// scope test uses (CreateDisclosureRequestForm.scope.test.tsx). We assert on
// that class through the full browser stack.
//
// Flow: /admin/disclosure → "Create Request" → "Create Disclosure Request"
// dialog holds the form; the scope buttons are always present (no need to pick
// a target user first).
// ---------------------------------------------------------------------------

const SELECTED = /bg-primary-50/;

test.describe('Disclosure request scope mutual exclusivity (RD-1072)', () => {
  test.beforeEach(async ({ page }) => {
    await mockLoginViaAPI(page);
  });

  async function openCreateForm(page: import('@playwright/test').Page): Promise<{
    dialog: Locator;
    full: Locator;
    activity: Locator;
    txHistory: Locator;
  }> {
    await page.goto('/admin/disclosure');
    await page.getByRole('button', { name: /^Create Request$/ }).click();

    const dialog = page.getByRole('dialog').filter({ hasText: 'Create Disclosure Request' });
    await expect(dialog).toBeVisible({ timeout: 10000 });

    return {
      dialog,
      full: dialog.getByRole('button', { name: /Full Disclosure/ }),
      activity: dialog.getByRole('button', { name: /Activity Logs/ }),
      txHistory: dialog.getByRole('button', { name: /Transaction History/ }),
    };
  }

  test('selecting Full Disclosure clears both narrow scopes', async ({ page }) => {
    const { full, activity, txHistory } = await openCreateForm(page);

    await activity.click();
    await txHistory.click();
    await expect(activity).toHaveClass(SELECTED);
    await expect(txHistory).toHaveClass(SELECTED);

    await full.click();
    await expect(full).toHaveClass(SELECTED);
    await expect(activity).not.toHaveClass(SELECTED);
    await expect(txHistory).not.toHaveClass(SELECTED);
  });

  test('selecting a narrow scope clears Full Disclosure', async ({ page }) => {
    const { full, activity } = await openCreateForm(page);

    await full.click();
    await expect(full).toHaveClass(SELECTED);

    await activity.click();
    await expect(activity).toHaveClass(SELECTED);
    await expect(full).not.toHaveClass(SELECTED);
  });

  test('the two narrow scopes combine', async ({ page }) => {
    const { full, activity, txHistory } = await openCreateForm(page);

    await activity.click();
    await txHistory.click();

    await expect(activity).toHaveClass(SELECTED);
    await expect(txHistory).toHaveClass(SELECTED);
    // Full stays unselected while the narrow pair is active.
    await expect(full).not.toHaveClass(SELECTED);
  });
});
