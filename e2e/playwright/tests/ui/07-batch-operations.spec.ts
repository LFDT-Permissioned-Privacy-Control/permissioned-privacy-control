import { test, expect } from '@playwright/test';
import { selectors } from '../../helpers/ui/selectors';
import { mockLoginViaAPI } from '../../helpers/ui/auth-helpers';
import { RBACTestFixture } from '../../helpers/rbac-fixtures';

// Selector convention note (RD-965, see e2e/playwright/CONVENTIONS.md):
//
// The .nth(N) calls in this file address rows / group cards in a
// batch-operation context where the test deliberately doesn't care
// which row gets clicked — only that K rows are picked. Examples:
//
//   - `for (i=0..N) rows.nth(i)` — iterate over visible rows to assert
//     each renders the same control. Identity isn't checked.
//   - `rows.nth(0).click(); rows.nth(1).click();` — pick any two rows
//     for a batch-action test. The batch UI doesn't change shape
//     based on which two were picked.
//
// All other selectors in this file go through `getByRole` or the
// shared selectors map. The ABI-param case that does depend on
// semantic identity (where positional .nth() WAS brittle) is the one
// in ui/08-event-rules.spec.ts; that one was migrated to
// `getByTestId('abi-param-{name}')` against a data-testid added to
// the EventParamConstraint component.

// ---------------------------------------------------------------------------
// Group A: Contract Multi-Select
// ---------------------------------------------------------------------------

test.describe('Contract multi-select', () => {
  let fixture: RBACTestFixture;

  test.beforeEach(async ({ page }) => {
    await mockLoginViaAPI(page);
  });

  test.afterEach(async () => {
    if (fixture) {
      await fixture.cleanup();
    }
  });

  test('A1: checkboxes visible, toggle toolbar on select/deselect', async ({ page, request }) => {
    fixture = new RBACTestFixture(request);
    const org = await fixture.createOrg('batch-a1');
    await fixture.createContract(org.id, { name: 'Contract A1-1' });
    await fixture.createContract(org.id, { name: 'Contract A1-2' });
    await fixture.createContract(org.id, { name: 'Contract A1-3' });

    await page.goto('/admin/rbac/contracts');
    await expect(page.locator(selectors.rbac.manager)).toBeVisible({ timeout: 10000 });

    // Select the test org
    await page.locator(selectors.rbac.orgSelector).click();
    await page.getByText(org.name).click();

    // Wait for contracts to load
    const rows = page.locator('table tbody tr');
    await expect(rows).toHaveCount(3, { timeout: 10000 });

    // Checkboxes should be visible on each row
    for (let i = 0; i < 3; i++) {
      await expect(rows.nth(i).locator('[role="checkbox"]')).toBeVisible();
    }

    // Click first checkbox - toolbar should appear
    await rows.nth(0).locator('[role="checkbox"]').click();
    await expect(page.locator(selectors.batch.toolbar)).toBeVisible({ timeout: 5000 });

    // Uncheck - toolbar should disappear
    await rows.nth(0).locator('[role="checkbox"]').click();
    await expect(page.locator(selectors.batch.toolbar)).not.toBeVisible();
  });

  test('A2: select all toggles all checkboxes', async ({ page, request }) => {
    fixture = new RBACTestFixture(request);
    const org = await fixture.createOrg('batch-a2');
    await fixture.createContract(org.id, { name: 'Contract A2-1' });
    await fixture.createContract(org.id, { name: 'Contract A2-2' });
    await fixture.createContract(org.id, { name: 'Contract A2-3' });

    await page.goto('/admin/rbac/contracts');
    await expect(page.locator(selectors.rbac.manager)).toBeVisible({ timeout: 10000 });

    await page.locator(selectors.rbac.orgSelector).click();
    await page.getByText(org.name).click();

    const rows = page.locator('table tbody tr');
    await expect(rows).toHaveCount(3, { timeout: 10000 });

    // Click select-all checkbox in the header
    const selectAllCheckbox = page.locator('table thead [role="checkbox"]');
    await selectAllCheckbox.click();

    // All row checkboxes should be checked
    for (let i = 0; i < 3; i++) {
      await expect(rows.nth(i).locator('[role="checkbox"]')).toHaveAttribute('data-state', 'checked');
    }

    // Toolbar should say "3 selected"
    await expect(page.locator(selectors.batch.toolbar)).toContainText('3 selected');

    // Click select-all again to deselect all
    await selectAllCheckbox.click();

    // All should be unchecked
    for (let i = 0; i < 3; i++) {
      await expect(rows.nth(i).locator('[role="checkbox"]')).toHaveAttribute('data-state', 'unchecked');
    }
  });

  test('A3: partial selection shows indeterminate state on header checkbox', async ({ page, request }) => {
    fixture = new RBACTestFixture(request);
    const org = await fixture.createOrg('batch-a3');
    await fixture.createContract(org.id, { name: 'Contract A3-1' });
    await fixture.createContract(org.id, { name: 'Contract A3-2' });
    await fixture.createContract(org.id, { name: 'Contract A3-3' });

    await page.goto('/admin/rbac/contracts');
    await expect(page.locator(selectors.rbac.manager)).toBeVisible({ timeout: 10000 });

    await page.locator(selectors.rbac.orgSelector).click();
    await page.getByText(org.name).click();

    const rows = page.locator('table tbody tr');
    await expect(rows).toHaveCount(3, { timeout: 10000 });

    const headerCheckbox = page.locator('table thead [role="checkbox"]');

    // Click one contract checkbox - header should become indeterminate
    await rows.nth(0).locator('[role="checkbox"]').click();
    await expect(headerCheckbox).toHaveAttribute('data-state', 'indeterminate');

    // Select all remaining via header click
    await headerCheckbox.click();

    // Header should now be checked (all selected)
    await expect(headerCheckbox).toHaveAttribute('data-state', 'checked');
  });

  test('A4: clear button deselects all', async ({ page, request }) => {
    fixture = new RBACTestFixture(request);
    const org = await fixture.createOrg('batch-a4');
    await fixture.createContract(org.id, { name: 'Contract A4-1' });
    await fixture.createContract(org.id, { name: 'Contract A4-2' });
    await fixture.createContract(org.id, { name: 'Contract A4-3' });

    await page.goto('/admin/rbac/contracts');
    await expect(page.locator(selectors.rbac.manager)).toBeVisible({ timeout: 10000 });

    await page.locator(selectors.rbac.orgSelector).click();
    await page.getByText(org.name).click();

    const rows = page.locator('table tbody tr');
    await expect(rows).toHaveCount(3, { timeout: 10000 });

    // Select 2 contracts
    await rows.nth(0).locator('[role="checkbox"]').click();
    await rows.nth(1).locator('[role="checkbox"]').click();

    await expect(page.locator(selectors.batch.toolbar)).toBeVisible({ timeout: 5000 });

    // Click Clear button
    await page.locator(selectors.batch.clearBtn).click();

    // All deselected, toolbar gone
    await expect(page.locator(selectors.batch.toolbar)).not.toBeVisible();
    for (let i = 0; i < 3; i++) {
      await expect(rows.nth(i).locator('[role="checkbox"]')).toHaveAttribute('data-state', 'unchecked');
    }
  });
});

// ---------------------------------------------------------------------------
// Group B: Move to Group Dialog
// ---------------------------------------------------------------------------

test.describe('Move to Group dialog', () => {
  let fixture: RBACTestFixture;

  test.beforeEach(async ({ page }) => {
    await mockLoginViaAPI(page);
  });

  test.afterEach(async () => {
    if (fixture) {
      await fixture.cleanup();
    }
  });

  // OBSOLETE: the legacy Move-to-Group dialog text/structure has changed
  // (the placeholder "e.g. DeFi Contracts" and the "Existing group" label
  // no longer exist in the current MoveToGroupDialog). These tests assert
  // against UI that's been redesigned; needs a rewrite by frontend.
  test.skip('B1: move contracts to existing group', async ({ page, request }) => {
    fixture = new RBACTestFixture(request);
    const org = await fixture.createOrg('batch-b1');

    // Create target group with deploy access
    const targetGroup = await fixture.createGroup(org.id, 'target-grp', { name: 'Target Group' });
    await fixture.rbac.setGroupAccess(org.id, targetGroup.id, {
      allowed_methods: ['*'],
      claims: ['deploy'],
    });

    // Create 2 auto groups with contracts granted to them
    const autoGroup1 = await fixture.createAutoGroup(org.id, 'auto-grp-1');
    const autoGroup2 = await fixture.createAutoGroup(org.id, 'auto-grp-2');
    const contract1 = await fixture.createContractWithGrant(org.id, autoGroup1.id, { name: 'Contract B1-1' });
    const contract2 = await fixture.createContractWithGrant(org.id, autoGroup2.id, { name: 'Contract B1-2' });

    await page.goto('/admin/rbac/contracts');
    await expect(page.locator(selectors.rbac.manager)).toBeVisible({ timeout: 10000 });

    await page.locator(selectors.rbac.orgSelector).click();
    await page.getByText(org.name).click();

    const rows = page.locator('table tbody tr');
    await expect(rows).toHaveCount(2, { timeout: 10000 });

    // Select both contracts
    await rows.nth(0).locator('[role="checkbox"]').click();
    await rows.nth(1).locator('[role="checkbox"]').click();

    // Click "Move to Group" button
    await page.locator(selectors.batch.moveBtn).click();

    // Dialog should open
    const dialog = page.locator(selectors.common.dialog);
    await expect(dialog).toBeVisible({ timeout: 5000 });

    // Select "Existing group" radio and pick target group
    await dialog.getByText('Existing group').click();
    await dialog.locator(selectors.batch.moveGroupSelect).click();
    await page.getByRole('option', { name: targetGroup.name }).click();

    // "Delete empty auto-created groups" checkbox should be checked by default
    const deleteEmptyCheckbox = dialog.locator(selectors.batch.moveDeleteEmptyCheckbox);
    await expect(deleteEmptyCheckbox).toBeVisible();

    // Confirm the move
    await dialog.locator(selectors.batch.moveConfirmBtn).click();

    // Dialog should close
    await expect(dialog).not.toBeVisible({ timeout: 10000 });

    // Verify via API: contracts should have grants to the target group
    const grants1 = await fixture.rbac.listContractGrants(org.id, contract1.address!);
    const grants2 = await fixture.rbac.listContractGrants(org.id, contract2.address!);
    expect(grants1.some(g => g.group_id === targetGroup.id)).toBe(true);
    expect(grants2.some(g => g.group_id === targetGroup.id)).toBe(true);
  });

  // OBSOLETE: the legacy Move-to-Group dialog text/structure has changed
  // (the placeholder "e.g. DeFi Contracts" and the "Existing group" label
  // no longer exist in the current MoveToGroupDialog). These tests assert
  // against UI that's been redesigned; needs a rewrite by frontend.
  test.skip('B2: move contracts to new group with auto-slug', async ({ page, request }) => {
    fixture = new RBACTestFixture(request);
    const org = await fixture.createOrg('batch-b2');
    const contract1 = await fixture.createContract(org.id, { name: 'Contract B2-1' });
    const contract2 = await fixture.createContract(org.id, { name: 'Contract B2-2' });

    await page.goto('/admin/rbac/contracts');
    await expect(page.locator(selectors.rbac.manager)).toBeVisible({ timeout: 10000 });

    await page.locator(selectors.rbac.orgSelector).click();
    await page.getByText(org.name).click();

    const rows = page.locator('table tbody tr');
    await expect(rows).toHaveCount(2, { timeout: 10000 });

    // Select both
    await rows.nth(0).locator('[role="checkbox"]').click();
    await rows.nth(1).locator('[role="checkbox"]').click();

    // Open move dialog
    await page.locator(selectors.batch.moveBtn).click();
    const dialog = page.locator(selectors.common.dialog);
    await expect(dialog).toBeVisible({ timeout: 5000 });

    // Select "Create new group" radio
    await dialog.getByText('Create new group').click();

    // Type group name
    const nameInput = dialog.getByPlaceholder('e.g. DeFi Contracts');
    await nameInput.fill('Production Contracts');

    // Slug should auto-fill
    const slugInput = dialog.getByPlaceholder('e.g. defi-contracts');
    await expect(slugInput).toHaveValue('production-contracts');

    // Confirm
    await dialog.locator(selectors.batch.moveConfirmBtn).click();

    // Dialog should close
    await expect(dialog).not.toBeVisible({ timeout: 10000 });

    // Verify via API: a new group named "Production Contracts" should exist
    const groups = await fixture.rbac.listGroups(org.id);
    const newGroup = groups.find(g => g.name === 'Production Contracts');
    expect(newGroup).toBeTruthy();
    expect(newGroup!.slug).toBe('production-contracts');

    // Both contracts should have grants to the new group
    const grants1 = await fixture.rbac.listContractGrants(org.id, contract1.address!);
    const grants2 = await fixture.rbac.listContractGrants(org.id, contract2.address!);
    expect(grants1.some(g => g.group_id === newGroup!.id)).toBe(true);
    expect(grants2.some(g => g.group_id === newGroup!.id)).toBe(true);
  });

  // OBSOLETE: the legacy Move-to-Group dialog text/structure has changed
  // (the placeholder "e.g. DeFi Contracts" and the "Existing group" label
  // no longer exist in the current MoveToGroupDialog). These tests assert
  // against UI that's been redesigned; needs a rewrite by frontend.
  test.skip('B3: duplicate slug shows error, dialog stays open', async ({ page, request }) => {
    fixture = new RBACTestFixture(request);
    const org = await fixture.createOrg('batch-b3');

    // Create a group that will cause a slug collision
    await fixture.createGroup(org.id, 'existing-group', { name: 'Existing Group' });
    const contract1 = await fixture.createContract(org.id, { name: 'Contract B3-1' });

    await page.goto('/admin/rbac/contracts');
    await expect(page.locator(selectors.rbac.manager)).toBeVisible({ timeout: 10000 });

    await page.locator(selectors.rbac.orgSelector).click();
    await page.getByText(org.name).click();

    const rows = page.locator('table tbody tr');
    await expect(rows).toHaveCount(1, { timeout: 10000 });

    // Select the contract
    await rows.nth(0).locator('[role="checkbox"]').click();

    // Open move dialog
    await page.locator(selectors.batch.moveBtn).click();
    const dialog = page.locator(selectors.common.dialog);
    await expect(dialog).toBeVisible({ timeout: 5000 });

    // Select "Create new group" and type a name that generates the duplicate slug
    await dialog.getByText('Create new group').click();
    const nameInput = dialog.getByPlaceholder('e.g. DeFi Contracts');
    // The existing group slug is "{testId}-prefixed", but we need to match exactly.
    // Use the slug input to manually type the duplicate slug.
    await nameInput.fill('Existing Group');
    const slugInput = dialog.getByPlaceholder('e.g. defi-contracts');
    await slugInput.clear();
    await slugInput.fill(fixture.slug('existing-group'));

    // Confirm - should fail
    await dialog.locator(selectors.batch.moveConfirmBtn).click();

    // Error should be visible in the dialog
    await expect(dialog.getByText(/already exists|duplicate|conflict|failed|status code 400/i)).toBeVisible({ timeout: 5000 });

    // Dialog should still be open
    await expect(dialog).toBeVisible();
  });
});

// ---------------------------------------------------------------------------
// Group C: Group Filtering
// ---------------------------------------------------------------------------

test.describe('Group filtering', () => {
  let fixture: RBACTestFixture;

  test.beforeEach(async ({ page }) => {
    await mockLoginViaAPI(page);
  });

  test.afterEach(async () => {
    if (fixture) {
      await fixture.cleanup();
    }
  });

  // OBSOLETE: the All / Auto-created / Manual filter buttons (testids
  // group-filter-all, group-filter-auto, group-filter-manual) no longer
  // exist in GroupList — that filter UI was removed. Tests need a rewrite
  // for whatever replaced it (or removal if the feature was dropped).
  test.skip('C1: filter buttons toggle between All, Auto-created, and Manual', async ({ page, request }) => {
    fixture = new RBACTestFixture(request);
    const org = await fixture.createOrg('batch-c1');

    await fixture.createAutoGroup(org.id, 'auto-1', { name: 'Auto Group One' });
    await fixture.createAutoGroup(org.id, 'auto-2', { name: 'Auto Group Two' });
    await fixture.createGroup(org.id, 'manual-1', { name: 'Manual Group One' });

    await page.goto('/admin/rbac/groups');
    await expect(page.locator(selectors.rbac.manager)).toBeVisible({ timeout: 10000 });

    await page.locator(selectors.rbac.orgSelector).click();
    await page.getByText(org.name).click();

    // Wait for groups to load - expect 3 group cards
    const groupCards = page.locator('[data-testid="group-card"]');
    await expect(groupCards).toHaveCount(3, { timeout: 10000 });

    // "All" filter should be active by default
    const allBtn = page.locator(selectors.batch.filterAll);

    // Click "Auto-created" filter
    await page.locator(selectors.batch.filterAuto).click();
    await expect(groupCards).toHaveCount(2, { timeout: 5000 });

    // Both visible groups should have Auto badge
    for (let i = 0; i < 2; i++) {
      await expect(groupCards.nth(i).locator(selectors.batch.autoBadge)).toBeVisible();
    }

    // Click "Manual" filter
    await page.locator(selectors.batch.filterManual).click();
    await expect(groupCards).toHaveCount(1, { timeout: 5000 });

    // Manual group should NOT have Auto badge
    await expect(groupCards.nth(0).getByText('Manual Group One')).toBeVisible();

    // Click "All" to restore
    await allBtn.click();
    await expect(groupCards).toHaveCount(3, { timeout: 5000 });
  });

  // OBSOLETE: the All / Auto-created / Manual filter buttons (testids
  // group-filter-all, group-filter-auto, group-filter-manual) no longer
  // exist in GroupList — that filter UI was removed. Tests need a rewrite
  // for whatever replaced it (or removal if the feature was dropped).
  test.skip('C2: auto badge appears only on auto-created groups', async ({ page, request }) => {
    fixture = new RBACTestFixture(request);
    const org = await fixture.createOrg('batch-c2');

    await fixture.createAutoGroup(org.id, 'auto-badge', { name: 'Auto Badge Group' });
    await fixture.createGroup(org.id, 'manual-badge', { name: 'Manual Badge Group' });

    await page.goto('/admin/rbac/groups');
    await expect(page.locator(selectors.rbac.manager)).toBeVisible({ timeout: 10000 });

    await page.locator(selectors.rbac.orgSelector).click();
    await page.getByText(org.name).click();

    const groupCards = page.locator('[data-testid="group-card"]');
    await expect(groupCards).toHaveCount(3, { timeout: 10000 }); // 2 user + 1 auto-admin

    // Auto group should have Auto badge
    const autoCard = groupCards.filter({ hasText: 'Auto Badge Group' });
    await expect(autoCard.locator(selectors.batch.autoBadge)).toBeVisible();

    // Manual group should NOT have Auto badge
    const manualCard = groupCards.filter({ hasText: 'Manual Badge Group' });
    await expect(manualCard.locator(selectors.batch.autoBadge)).toHaveCount(0);
  });
});

// ---------------------------------------------------------------------------
// Group D: Group Batch Delete
// ---------------------------------------------------------------------------

test.describe('Group batch delete', () => {
  let fixture: RBACTestFixture;

  test.beforeEach(async ({ page }) => {
    await mockLoginViaAPI(page);
  });

  test.afterEach(async () => {
    if (fixture) {
      await fixture.cleanup();
    }
  });

  test('D1: select groups, toolbar shows count, clear deselects', async ({ page, request }) => {
    fixture = new RBACTestFixture(request);
    const org = await fixture.createOrg('batch-d1');
    await fixture.createGroup(org.id, 'grp-d1-1', { name: 'Group D1 Alpha' });
    await fixture.createGroup(org.id, 'grp-d1-2', { name: 'Group D1 Beta' });
    await fixture.createGroup(org.id, 'grp-d1-3', { name: 'Group D1 Gamma' });

    await page.goto('/admin/rbac/groups');
    await expect(page.locator(selectors.rbac.manager)).toBeVisible({ timeout: 10000 });

    await page.locator(selectors.rbac.orgSelector).click();
    await page.getByText(org.name).click();

    const groupCards = page.locator('[data-testid="group-card"]');
    await expect(groupCards).toHaveCount(4, { timeout: 10000 }); // 3 user + 1 auto-admin

    // Check 2 groups
    const card1 = groupCards.filter({ hasText: 'Group D1 Alpha' });
    const card2 = groupCards.filter({ hasText: 'Group D1 Beta' });

    await card1.locator('[role="checkbox"]').first().click();
    await card2.locator('[role="checkbox"]').first().click();

    // Toolbar should show "2 selected" and "Delete Selected"
    await expect(page.locator(selectors.batch.toolbar)).toContainText('2 selected');
    await expect(page.locator(selectors.batch.deleteBtn)).toBeVisible();

    // Uncheck one
    await card1.locator('[role="checkbox"]').first().click();
    await expect(page.locator(selectors.batch.toolbar)).toContainText('1 selected');

    // Clear all
    await page.locator(selectors.batch.clearBtn).click();
    await expect(page.locator(selectors.batch.toolbar)).not.toBeVisible();
  });

  test('D2: delete preview dialog shows group info, cancel preserves groups', async ({ page, request }) => {
    fixture = new RBACTestFixture(request);
    const org = await fixture.createOrg('batch-d2');

    const group1 = await fixture.createGroup(org.id, 'grp-d2-1', { name: 'Group D2 Alpha' });
    const group2 = await fixture.createGroup(org.id, 'grp-d2-2', { name: 'Group D2 Beta' });

    // Add a contract grant and a member to each group
    const contract1 = await fixture.createContractWithGrant(org.id, group1.id, { name: 'C-D2-1' });
    const contract2 = await fixture.createContractWithGrant(org.id, group2.id, { name: 'C-D2-2' });
    await fixture.createUserWithMembership(request, group1.id);
    await fixture.createUserWithMembership(request, group2.id);

    await page.goto('/admin/rbac/groups');
    await expect(page.locator(selectors.rbac.manager)).toBeVisible({ timeout: 10000 });

    await page.locator(selectors.rbac.orgSelector).click();
    await page.getByText(org.name).click();

    const groupCards = page.locator('[data-testid="group-card"]');
    await expect(groupCards).toHaveCount(3, { timeout: 10000 }); // 2 user + 1 auto-admin

    // Select both groups
    await groupCards.filter({ hasText: 'Group D2 Alpha' }).locator('[role="checkbox"]').first().click();
    await groupCards.filter({ hasText: 'Group D2 Beta' }).locator('[role="checkbox"]').first().click();

    // Click "Delete Selected"
    await page.locator(selectors.batch.deleteBtn).click();

    // Preview dialog should open
    const dialog = page.locator(selectors.common.dialog);
    await expect(dialog).toBeVisible({ timeout: 5000 });

    // Should show group names and counts
    await expect(dialog.getByText('Group D2 Alpha')).toBeVisible();
    await expect(dialog.getByText('Group D2 Beta')).toBeVisible();

    // Cancel
    await dialog.getByRole('button', { name: /cancel/i }).click();
    await expect(dialog).not.toBeVisible();

    // Groups should still be visible (2 user + 1 auto-admin)
    await expect(groupCards).toHaveCount(3);
  });

  test('D3: confirm delete removes groups', async ({ page, request }) => {
    fixture = new RBACTestFixture(request);
    const org = await fixture.createOrg('batch-d3');

    const group1 = await fixture.createGroup(org.id, 'grp-d3-1', { name: 'Group D3 Alpha' });
    const group2 = await fixture.createGroup(org.id, 'grp-d3-2', { name: 'Group D3 Beta' });

    await page.goto('/admin/rbac/groups');
    await expect(page.locator(selectors.rbac.manager)).toBeVisible({ timeout: 10000 });

    await page.locator(selectors.rbac.orgSelector).click();
    await page.getByText(org.name).click();

    const groupCards = page.locator('[data-testid="group-card"]');
    await expect(groupCards).toHaveCount(3, { timeout: 10000 }); // 2 user + 1 auto-admin

    // Select both
    await groupCards.filter({ hasText: 'Group D3 Alpha' }).locator('[role="checkbox"]').first().click();
    await groupCards.filter({ hasText: 'Group D3 Beta' }).locator('[role="checkbox"]').first().click();

    // Delete Selected
    await page.locator(selectors.batch.deleteBtn).click();

    const dialog = page.locator(selectors.common.dialog);
    await expect(dialog).toBeVisible({ timeout: 5000 });

    // Confirm deletion
    await dialog.locator(selectors.batch.batchDeleteConfirmBtn).click();

    // Dialog should close
    await expect(dialog).not.toBeVisible({ timeout: 10000 });

    // User groups should disappear from the UI; the auto-admin group
    // (added by createOrg for JWT auth) remains.
    await expect(groupCards).toHaveCount(1, { timeout: 10000 });

    // Verify via API
    const remainingGroups = await fixture.rbac.listGroups(org.id);
    const deletedIds = [group1.id, group2.id];
    for (const id of deletedIds) {
      expect(remainingGroups.find(g => g.id === id)).toBeUndefined();
    }
  });

  // OBSOLETE: BatchDeleteConfirmDialog no longer renders a "created manually
  // / configured intentionally" caution when the selection includes a non-
  // auto-created group. The dialog now just shows the per-group preview
  // (name + contract/member counts) and a generic "remove access" line.
  // Skipping until the warning UI is reintroduced or the test is rewritten.
  test.skip('D4: deleting non-auto groups shows warning in preview', async ({ page, request }) => {
    fixture = new RBACTestFixture(request);
    const org = await fixture.createOrg('batch-d4');

    await fixture.createAutoGroup(org.id, 'auto-d4', { name: 'Auto Group D4' });
    await fixture.createGroup(org.id, 'manual-d4', { name: 'Manual Group D4' });

    await page.goto('/admin/rbac/groups');
    await expect(page.locator(selectors.rbac.manager)).toBeVisible({ timeout: 10000 });

    await page.locator(selectors.rbac.orgSelector).click();
    await page.getByText(org.name).click();

    const groupCards = page.locator('[data-testid="group-card"]');
    await expect(groupCards).toHaveCount(3, { timeout: 10000 }); // 2 user + 1 auto-admin

    // Select both
    await groupCards.filter({ hasText: 'Auto Group D4' }).locator('[role="checkbox"]').first().click();
    await groupCards.filter({ hasText: 'Manual Group D4' }).locator('[role="checkbox"]').first().click();

    // Delete Selected
    await page.locator(selectors.batch.deleteBtn).click();

    const dialog = page.locator(selectors.common.dialog);
    await expect(dialog).toBeVisible({ timeout: 5000 });

    // Should show warning about manually-created / non-auto groups
    await expect(dialog.getByText(/created manually|configured intentionally/i)).toBeVisible();
  });
});

// ---------------------------------------------------------------------------
// Group E: Edge Cases
// ---------------------------------------------------------------------------

test.describe('Batch operations edge cases', () => {
  let fixture: RBACTestFixture;

  test.beforeEach(async ({ page }) => {
    await mockLoginViaAPI(page);
  });

  test.afterEach(async () => {
    if (fixture) {
      await fixture.cleanup();
    }
  });

  // OBSOLETE: the All / Auto-created / Manual filter buttons (testids
  // group-filter-all, group-filter-auto, group-filter-manual) no longer
  // exist in GroupList — that filter UI was removed. Tests need a rewrite
  // for whatever replaced it (or removal if the feature was dropped).
  test.skip('E1: switching group filter clears selection', async ({ page, request }) => {
    fixture = new RBACTestFixture(request);
    const org = await fixture.createOrg('batch-e1');

    await fixture.createAutoGroup(org.id, 'auto-e1', { name: 'Auto E1' });
    await fixture.createGroup(org.id, 'manual-e1', { name: 'Manual E1' });

    await page.goto('/admin/rbac/groups');
    await expect(page.locator(selectors.rbac.manager)).toBeVisible({ timeout: 10000 });

    await page.locator(selectors.rbac.orgSelector).click();
    await page.getByText(org.name).click();

    const groupCards = page.locator('[data-testid="group-card"]');
    await expect(groupCards).toHaveCount(3, { timeout: 10000 }); // 2 user + 1 auto-admin

    // Select both groups
    await groupCards.filter({ hasText: 'Auto E1' }).locator('[role="checkbox"]').first().click();
    await groupCards.filter({ hasText: 'Manual E1' }).locator('[role="checkbox"]').first().click();

    await expect(page.locator(selectors.batch.toolbar)).toBeVisible();

    // Switch filter to "Auto-created"
    await page.locator(selectors.batch.filterAuto).click();

    // Selection should be cleared, toolbar gone
    await expect(page.locator(selectors.batch.toolbar)).not.toBeVisible({ timeout: 5000 });
  });

  test('E2: switching org clears contract selection', async ({ page, request }) => {
    fixture = new RBACTestFixture(request);
    const org1 = await fixture.createOrg('batch-e2a');
    const org2 = await fixture.createOrg('batch-e2b');

    await fixture.createContract(org1.id, { name: 'Contract E2-1' });
    await fixture.createContract(org1.id, { name: 'Contract E2-2' });
    await fixture.createContract(org2.id, { name: 'Contract E2-3' });

    await page.goto('/admin/rbac/contracts');
    await expect(page.locator(selectors.rbac.manager)).toBeVisible({ timeout: 10000 });

    // Select first org
    await page.locator(selectors.rbac.orgSelector).click();
    await page.getByText(org1.name).click();

    const rows = page.locator('table tbody tr');
    await expect(rows).toHaveCount(2, { timeout: 10000 });

    // Select both contracts
    await rows.nth(0).locator('[role="checkbox"]').click();
    await rows.nth(1).locator('[role="checkbox"]').click();

    await expect(page.locator(selectors.batch.toolbar)).toBeVisible();

    // Switch org
    await page.locator(selectors.rbac.orgSelector).click();
    await page.getByText(org2.name).click();

    // Selection should be cleared
    await expect(page.locator(selectors.batch.toolbar)).not.toBeVisible({ timeout: 5000 });
  });

  test('E3: empty contracts tab shows empty state, no checkboxes', async ({ page, request }) => {
    fixture = new RBACTestFixture(request);
    const org = await fixture.createOrg('batch-e3');

    await page.goto('/admin/rbac/contracts');
    await expect(page.locator(selectors.rbac.manager)).toBeVisible({ timeout: 10000 });

    await page.locator(selectors.rbac.orgSelector).click();
    await page.getByText(org.name).click();

    // Should see empty state
    await expect(page.getByText(/no contracts/i)).toBeVisible({ timeout: 10000 });

    // No checkboxes should be present
    const checkboxes = page.locator('table tbody [role="checkbox"]');
    await expect(checkboxes).toHaveCount(0);
  });
});
