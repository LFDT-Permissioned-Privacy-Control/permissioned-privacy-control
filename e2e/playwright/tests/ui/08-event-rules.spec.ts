import { test, expect } from '@playwright/test';
import { selectors } from '../../helpers/ui/selectors';
import { mockLoginViaAPI } from '../../helpers/ui/auth-helpers';
import { RBACTestFixture } from '../../helpers/rbac-fixtures';
import { getJWTToken } from '../../helpers/auth';

// Minimal ERC20 ABI with Transfer and Approval events + a transfer function.
// The backend parses this to extract event signatures for the event picker.
const ERC20_ABI = JSON.stringify([
  {
    anonymous: false,
    inputs: [
      { indexed: true, name: 'from', type: 'address' },
      { indexed: true, name: 'to', type: 'address' },
      { indexed: false, name: 'value', type: 'uint256' },
    ],
    name: 'Transfer',
    type: 'event',
  },
  {
    anonymous: false,
    inputs: [
      { indexed: true, name: 'owner', type: 'address' },
      { indexed: true, name: 'spender', type: 'address' },
      { indexed: false, name: 'value', type: 'uint256' },
    ],
    name: 'Approval',
    type: 'event',
  },
  {
    inputs: [
      { name: 'to', type: 'address' },
      { name: 'amount', type: 'uint256' },
    ],
    name: 'transfer',
    outputs: [{ name: '', type: 'bool' }],
    type: 'function',
    stateMutability: 'nonpayable',
  },
  {
    inputs: [{ name: 'account', type: 'address' }],
    name: 'balanceOf',
    outputs: [{ name: '', type: 'uint256' }],
    type: 'function',
    stateMutability: 'view',
  },
]);

// ---------------------------------------------------------------------------
// Helper: open the Contract Permissions dialog for the first contract in the
// table, then click "Add Group" to open the grant form, select the first
// available group, and advance the wizard to step 2 (events). The grant form
// became a two-step wizard in PR #217 (split-contract-grant-form); step 1 is
// group + functions, step 2 is events.
// Returns the grant form dialog locator (on step 2).
// ---------------------------------------------------------------------------
async function openGrantForm(
  page: import('@playwright/test').Page,
  opts?: { groupId?: string },
) {
  // Click the shield icon on the first contract row to open the permissions dialog
  const rows = page.locator('table tbody tr');
  await expect(rows).toHaveCount(1, { timeout: 10000 });
  const shieldBtn = rows.first().getByTitle('Manage permissions');
  await shieldBtn.click();

  // Wait for the "Contract Permissions" dialog
  const permDialog = page.locator(selectors.common.dialog);
  await expect(permDialog).toBeVisible({ timeout: 5000 });
  await expect(permDialog.getByText('Contract Permissions')).toBeVisible();

  // Click "Add Group" to open the grant form
  await permDialog.getByRole('button', { name: /add group/i }).click();

  // A nested dialog appears — use the "Add Group Access" title to scope
  const grantDialog = page.locator(selectors.common.dialog).filter({ hasText: 'Add Group Access' });
  await expect(grantDialog).toBeVisible({ timeout: 5000 });

  // Step 1: select a group, then click "Next" to advance to the events step.
  // Callers that assert API state (e.g. "grant exists for groupId X") must pass
  // `opts.groupId`, otherwise the helper picks the first available group — which
  // can be the auto-created E2E_HIDDEN_ADMIN group from createOrgWithAdmin.
  // The form's "Next" button only enables once a group is selected
  // (functionMode defaults to 'all', so functions need no setup).
  const groupSelect = grantDialog.locator('select').first();
  if (opts?.groupId) {
    await groupSelect.selectOption(opts.groupId);
  } else {
    await groupSelect.selectOption({ index: 1 });
  }
  await grantDialog.getByRole('button', { name: 'Next' }).click();

  // The events section is now visible (step 2).
  return grantDialog;
}

// ---------------------------------------------------------------------------
// Helper: open the edit-events form for the first grant on the first contract.
// The grant card now exposes two pencils — "Edit function access" (functions
// only) and "Edit event visibility" (events only). Use the events pencil so
// the form opens with editMode === 'events' and the events section is shown
// without needing a wizard step.
// ---------------------------------------------------------------------------
async function openEditGrantForm(page: import('@playwright/test').Page) {
  const rows = page.locator('table tbody tr');
  await expect(rows).toHaveCount(1, { timeout: 10000 });
  const shieldBtn = rows.first().getByTitle('Manage permissions');
  await shieldBtn.click();

  const permDialog = page.locator(selectors.common.dialog);
  await expect(permDialog).toBeVisible({ timeout: 5000 });
  await expect(permDialog.getByText('Contract Permissions')).toBeVisible();

  // Click the pencil button in the events row (NOT the functions row) so the
  // form opens directly in editMode='events'. The pencils used to expose a
  // `title=` attribute, but commit 65fbc6c wrapped them in a Radix Tooltip,
  // which moves the label text to a Portal element and drops the title
  // attribute — so `getByTitle` no longer resolves. Target structurally
  // instead: each grant card has two parallel rows (Functions / Events) with
  // the same flex layout; filter by the row's visible "Events:" label and
  // pick the (single) button inside it.
  const eventRow = permDialog
    .locator('div.flex.items-start.justify-between')
    .filter({ hasText: 'Events:' })
    .first();
  await eventRow.locator('button').first().click();

  // The edit-events dialog has the "Edit Event Rules" title.
  const editDialog = page.locator(selectors.common.dialog).filter({ hasText: 'Edit Event Rules' });
  await expect(editDialog).toBeVisible({ timeout: 5000 });
  return editDialog;
}

// ---------------------------------------------------------------------------
// Group A: Default state and mode switching
// ---------------------------------------------------------------------------

test.describe('Event rules — default state and mode switching', () => {
  let fixture: RBACTestFixture;

  test.beforeEach(async ({ page }) => {
    await mockLoginViaAPI(page);
  });

  test.afterEach(async () => {
    if (fixture) {
      await fixture.cleanup();
    }
  });

  test('A1: grant form defaults to "No events visible"', async ({ page, request }) => {
    fixture = new RBACTestFixture(request);
    const currentDid = `did:privado:test_${Date.now()}_${Math.random().toString(36).substring(7)}`;
    await mockLoginViaAPI(page, currentDid);
    const org = await fixture.createOrgWithAdmin('ev-a1', currentDid);
    const group = await fixture.createGroup(org.id, 'grp-a1', { name: 'Group A1' });
    await fixture.createContractWithABI(org.id, {
      name: 'Token A1',
      abi: ERC20_ABI,
    });

    await page.goto('/admin/rbac/contracts');
    await expect(page.locator(selectors.rbac.manager)).toBeVisible({ timeout: 10000 });

    await page.locator(selectors.rbac.orgSelector).click();
    await page.getByText(org.name).click();

    const grantDialog = await openGrantForm(page);

    // "No events visible" radio should be checked by default
    const noneEventsRadio = grantDialog.locator('input[name="eventMode"][value="none"]');
    await expect(noneEventsRadio).toBeChecked();

    // The event picker should NOT be visible in "all" mode
    await expect(grantDialog.getByText('Visible events:')).not.toBeVisible();
    await expect(grantDialog.getByText('Contract events')).not.toBeVisible();
  });

  test('A2: switching to "Specific events only" shows event picker', async ({ page, request }) => {
    fixture = new RBACTestFixture(request);
    const currentDid = `did:privado:test_${Date.now()}_${Math.random().toString(36).substring(7)}`;
    await mockLoginViaAPI(page, currentDid);
    const org = await fixture.createOrgWithAdmin('ev-a2', currentDid);
    const group = await fixture.createGroup(org.id, 'grp-a2', { name: 'Group A2' });
    await fixture.createContractWithABI(org.id, {
      name: 'Token A2',
      abi: ERC20_ABI,
    });

    await page.goto('/admin/rbac/contracts');
    await expect(page.locator(selectors.rbac.manager)).toBeVisible({ timeout: 10000 });

    await page.locator(selectors.rbac.orgSelector).click();
    await page.getByText(org.name).click();

    const grantDialog = await openGrantForm(page);

    // Click "Specific events only" radio
    await grantDialog.getByText('Specific events only').click();

    const specificRadio = grantDialog.locator('input[name="eventMode"][value="specific"]');
    await expect(specificRadio).toBeChecked();

    // Event picker should now be visible with 2 events from the ERC20 ABI
    await expect(grantDialog.getByText('Contract events (2):')).toBeVisible({ timeout: 5000 });

    // Both events should appear in the picker
    await expect(grantDialog.getByRole('button', { name: /Transfer/ })).toBeVisible();
    await expect(grantDialog.getByRole('button', { name: /Approval/ })).toBeVisible();
  });

  test('A3: switching back to "All events visible" hides event picker', async ({ page, request }) => {
    fixture = new RBACTestFixture(request);
    const currentDid = `did:privado:test_${Date.now()}_${Math.random().toString(36).substring(7)}`;
    await mockLoginViaAPI(page, currentDid);
    const org = await fixture.createOrgWithAdmin('ev-a3', currentDid);
    const group = await fixture.createGroup(org.id, 'grp-a3', { name: 'Group A3' });
    await fixture.createContractWithABI(org.id, {
      name: 'Token A3',
      abi: ERC20_ABI,
    });

    await page.goto('/admin/rbac/contracts');
    await expect(page.locator(selectors.rbac.manager)).toBeVisible({ timeout: 10000 });

    await page.locator(selectors.rbac.orgSelector).click();
    await page.getByText(org.name).click();

    const grantDialog = await openGrantForm(page);

    // Switch to specific
    await grantDialog.getByText('Specific events only').click();
    await expect(grantDialog.getByText('Contract events (2):')).toBeVisible({ timeout: 5000 });

    // Switch back to all
    await grantDialog.getByText('All events visible').click();

    const allRadio = grantDialog.locator('input[name="eventMode"][value="all"]');
    await expect(allRadio).toBeChecked();

    // Event picker should be hidden again
    await expect(grantDialog.getByText('Contract events (2):')).not.toBeVisible();
  });
});

// ---------------------------------------------------------------------------
// Group B: Selecting events and adding param constraints
// ---------------------------------------------------------------------------

test.describe('Event rules — selecting events and constraints', () => {
  let fixture: RBACTestFixture;

  test.beforeEach(async ({ page }) => {
    await mockLoginViaAPI(page);
  });

  test.afterEach(async () => {
    if (fixture) {
      await fixture.cleanup();
    }
  });

  test('B1: selecting events from the picker adds them to the visible list', async ({ page, request }) => {
    fixture = new RBACTestFixture(request);
    const currentDid = `did:privado:test_${Date.now()}_${Math.random().toString(36).substring(7)}`;
    await mockLoginViaAPI(page, currentDid);
    const org = await fixture.createOrgWithAdmin('ev-b1', currentDid);
    await fixture.createGroup(org.id, 'grp-b1', { name: 'Group B1' });
    await fixture.createContractWithABI(org.id, {
      name: 'Token B1',
      abi: ERC20_ABI,
    });

    await page.goto('/admin/rbac/contracts');
    await expect(page.locator(selectors.rbac.manager)).toBeVisible({ timeout: 10000 });

    await page.locator(selectors.rbac.orgSelector).click();
    await page.getByText(org.name).click();

    const grantDialog = await openGrantForm(page);

    // Switch to specific events
    await grantDialog.getByText('Specific events only').click();
    await expect(grantDialog.getByText('Contract events (2):')).toBeVisible({ timeout: 5000 });

    // Click Transfer event in the picker
    await grantDialog.getByRole('button', { name: /Transfer/ }).click();

    // "Visible events:" section should appear with Transfer listed
    await expect(grantDialog.getByText('Visible events:')).toBeVisible();
    // The selected event should show in a pill/card containing the event name
    const visibleSection = grantDialog.locator('.space-y-3').filter({ hasText: 'Visible events:' });
    await expect(visibleSection.getByText('Transfer', { exact: true }).first()).toBeVisible();

    // The Transfer button in the picker should now be disabled (already selected)
    const transferPickerBtn = grantDialog.locator('button').filter({ hasText: 'Transfer' }).last();
    await expect(transferPickerBtn).toBeDisabled();
  });

  test('B2: removing a selected event re-enables it in the picker', async ({ page, request }) => {
    fixture = new RBACTestFixture(request);
    const currentDid = `did:privado:test_${Date.now()}_${Math.random().toString(36).substring(7)}`;
    await mockLoginViaAPI(page, currentDid);
    const org = await fixture.createOrgWithAdmin('ev-b2', currentDid);
    await fixture.createGroup(org.id, 'grp-b2', { name: 'Group B2' });
    await fixture.createContractWithABI(org.id, {
      name: 'Token B2',
      abi: ERC20_ABI,
    });

    await page.goto('/admin/rbac/contracts');
    await expect(page.locator(selectors.rbac.manager)).toBeVisible({ timeout: 10000 });

    await page.locator(selectors.rbac.orgSelector).click();
    await page.getByText(org.name).click();

    const grantDialog = await openGrantForm(page);

    // Switch to specific events
    await grantDialog.getByText('Specific events only').click();
    await expect(grantDialog.getByText('Contract events (2):')).toBeVisible({ timeout: 5000 });

    // Add Transfer
    await grantDialog.getByRole('button', { name: /Transfer/ }).click();
    await expect(grantDialog.getByText('Visible events:')).toBeVisible();

    // Remove Transfer by clicking the X button on the selected event pill
    const selectedEvent = grantDialog.locator('.border.border-primary-50').filter({ hasText: 'Transfer' }).first();
    await selectedEvent.locator('button').click();

    // "Visible events:" header should disappear (no events selected)
    await expect(grantDialog.getByText('Visible events:')).not.toBeVisible();
  });

  test('B3: address param constraint checkbox appears for events with address inputs', async ({ page, request }) => {
    fixture = new RBACTestFixture(request);
    const currentDid = `did:privado:test_${Date.now()}_${Math.random().toString(36).substring(7)}`;
    await mockLoginViaAPI(page, currentDid);
    const org = await fixture.createOrgWithAdmin('ev-b3', currentDid);
    await fixture.createGroup(org.id, 'grp-b3', { name: 'Group B3' });
    await fixture.createContractWithABI(org.id, {
      name: 'Token B3',
      abi: ERC20_ABI,
    });

    await page.goto('/admin/rbac/contracts');
    await expect(page.locator(selectors.rbac.manager)).toBeVisible({ timeout: 10000 });

    await page.locator(selectors.rbac.orgSelector).click();
    await page.getByText(org.name).click();

    const grantDialog = await openGrantForm(page);

    // Switch to specific events and add Transfer
    await grantDialog.getByText('Specific events only').click();
    await expect(grantDialog.getByText('Contract events (2):')).toBeVisible({ timeout: 5000 });
    await grantDialog.getByRole('button', { name: /Transfer/ }).click();

    // Transfer has address params (from, to, value) — each renders as a constraint
    // row with the param name and a <select> offering "Caller's address (self)".
    const selectedEvent = grantDialog.locator('.border.border-primary-50.bg-neutral-50').filter({ hasText: 'Transfer' }).first();

    // Param name codes should be visible
    await expect(selectedEvent.locator('code', { hasText: /^from$/ })).toBeVisible();
    await expect(selectedEvent.locator('code', { hasText: /^to$/ })).toBeVisible();

    // The address-typed constraint <select>s expose the "self" option
    const selects = selectedEvent.locator('select');
    await expect(selects.first()).toBeVisible();
    await expect(selectedEvent.getByRole('option', { name: /Caller's address \(self\)/ }).first()).toBeAttached();
  });

  test('B4: checking a param constraint checkbox adds a param_rule', async ({ page, request }) => {
    fixture = new RBACTestFixture(request);
    const currentDid = `did:privado:test_${Date.now()}_${Math.random().toString(36).substring(7)}`;
    await mockLoginViaAPI(page, currentDid);
    const org = await fixture.createOrgWithAdmin('ev-b4', currentDid);
    const group = await fixture.createGroup(org.id, 'grp-b4', { name: 'Group B4' });
    await fixture.rbac.setGroupAccess(org.id, group.id, {
      allowed_methods: ['*'],
      claims: ['deploy'],
    });
    const contract = await fixture.createContractWithABI(org.id, {
      name: 'Token B4',
      abi: ERC20_ABI,
    });
    const address = contract.address || contract.contract_address || '';

    await page.goto('/admin/rbac/contracts');
    await expect(page.locator(selectors.rbac.manager)).toBeVisible({ timeout: 10000 });

    await page.locator(selectors.rbac.orgSelector).click();
    await page.getByText(org.name).click();

    const grantDialog = await openGrantForm(page, { groupId: group.id });

    // Switch to specific events and add Transfer
    await grantDialog.getByText('Specific events only').click();
    await expect(grantDialog.getByText('Contract events (2):')).toBeVisible({ timeout: 5000 });
    await grantDialog.getByRole('button', { name: /Transfer/ }).click();

    // The param-constraint UI is a <select> per address-typed param. The
    // backend's GET events endpoint returns default_param_rules that pin both
    // `from` (index 0) and `to` (index 1) to 'self', and the form auto-populates
    // those defaults on event-add. Confirm the from select reflects 'self', then
    // explicitly drop 'to' to 'any' so the saved rule only constrains 'from'.
    const selectedEvent = grantDialog.locator('.border.border-primary-50.bg-neutral-50').filter({ hasText: 'Transfer' }).first();
    // Address ABI params by name via data-testid (RD-965). Previously this
    // used paramSelects.nth(0/1) keyed off render order — coupling tests
    // to the form's <select> ordering rather than the ABI parameter
    // identity. The data-testid is set in ContractGrantForm's
    // EventParamConstraint component.
    const fromSelect = selectedEvent.getByTestId('abi-param-from');
    const toSelect = selectedEvent.getByTestId('abi-param-to');
    await expect(fromSelect).toHaveValue('self');
    await expect(toSelect).toHaveValue('self');
    await toSelect.selectOption('any');
    await expect(toSelect).toHaveValue('any');

    // The 'from=self' rule chip should remain visible
    await expect(selectedEvent.getByText('from=self')).toBeVisible();

    // Save the grant
    await grantDialog.getByRole('button', { name: /create grant/i }).click();

    // Dialog should close
    await expect(grantDialog).not.toBeVisible({ timeout: 10000 });

    // Verify via API that the grant has the event rule with exactly one
    // param_rule (the 'from'='self' constraint we kept).
    const grants = await fixture.rbac.listContractGrants(org.id, address);
    const savedGrant = grants.find(g => g.group_id === group.id);
    expect(savedGrant).toBeTruthy();
    expect(savedGrant!.event_rules).toBeTruthy();
    expect(savedGrant!.event_rules!.length).toBe(1);
    expect(savedGrant!.event_rules![0].name).toBe('Transfer');
    expect(savedGrant!.event_rules![0].param_rules).toBeTruthy();
    expect(savedGrant!.event_rules![0].param_rules!.length).toBe(1);
    expect(savedGrant!.event_rules![0].param_rules![0]).toEqual({ index: 0, must_be: 'self' });
  });
});

// ---------------------------------------------------------------------------
// Group C: Saving and displaying grants with event rules
// ---------------------------------------------------------------------------

test.describe('Event rules — save and display', () => {
  let fixture: RBACTestFixture;

  test.beforeEach(async ({ page }) => {
    await mockLoginViaAPI(page);
  });

  test.afterEach(async () => {
    if (fixture) {
      await fixture.cleanup();
    }
  });

  test('C1: save grant with specific events, verify display as pills', async ({ page, request }) => {
    fixture = new RBACTestFixture(request);
    const currentDid = `did:privado:test_${Date.now()}_${Math.random().toString(36).substring(7)}`;
    await mockLoginViaAPI(page, currentDid);
    const org = await fixture.createOrgWithAdmin('ev-c1', currentDid);
    const group = await fixture.createGroup(org.id, 'grp-c1', { name: 'Group C1' });
    await fixture.rbac.setGroupAccess(org.id, group.id, {
      allowed_methods: ['*'],
      claims: ['deploy'],
    });
    const contract = await fixture.createContractWithABI(org.id, {
      name: 'Token C1',
      abi: ERC20_ABI,
    });
    const address = contract.address || contract.contract_address || '';

    await page.goto('/admin/rbac/contracts');
    await expect(page.locator(selectors.rbac.manager)).toBeVisible({ timeout: 10000 });

    await page.locator(selectors.rbac.orgSelector).click();
    await page.getByText(org.name).click();

    const grantDialog = await openGrantForm(page);

    // Switch to specific events, add both Transfer and Approval (group selected by helper)
    await grantDialog.getByText('Specific events only').click();
    await expect(grantDialog.getByText('Contract events (2):')).toBeVisible({ timeout: 5000 });
    await grantDialog.getByRole('button', { name: /Transfer/ }).click();
    await grantDialog.getByRole('button', { name: /Approval/ }).click();

    // Save
    await grantDialog.getByRole('button', { name: /create grant/i }).click();
    await expect(grantDialog).not.toBeVisible({ timeout: 10000 });

    // The permissions dialog should now show the grant card with event pills
    const permDialog = page.locator(selectors.common.dialog);
    await expect(permDialog).toBeVisible();

    // Should show "Events:" label with event name pills (violet-colored)
    await expect(permDialog.getByText('Events:')).toBeVisible();
    // Event pills use violet-100 background and contain event names
    const eventPills = permDialog.locator('.bg-violet-100');
    await expect(eventPills).toHaveCount(2);
    await expect(permDialog.locator('.bg-violet-100').filter({ hasText: 'Transfer' })).toBeVisible();
    await expect(permDialog.locator('.bg-violet-100').filter({ hasText: 'Approval' })).toBeVisible();
  });

  test('C2: grant with "All events" shows "All events visible" in display', async ({ page, request }) => {
    fixture = new RBACTestFixture(request);
    const currentDid = `did:privado:test_${Date.now()}_${Math.random().toString(36).substring(7)}`;
    await mockLoginViaAPI(page, currentDid);
    const org = await fixture.createOrgWithAdmin('ev-c2', currentDid);
    const group = await fixture.createGroup(org.id, 'grp-c2', { name: 'Group C2' });
    await fixture.rbac.setGroupAccess(org.id, group.id, {
      allowed_methods: ['*'],
      claims: ['deploy'],
    });
    const contract = await fixture.createContractWithABI(org.id, {
      name: 'Token C2',
      abi: ERC20_ABI,
    });
    const address = contract.address || contract.contract_address || '';

    await page.goto('/admin/rbac/contracts');
    await expect(page.locator(selectors.rbac.manager)).toBeVisible({ timeout: 10000 });

    await page.locator(selectors.rbac.orgSelector).click();
    await page.getByText(org.name).click();

    const grantDialog = await openGrantForm(page, { groupId: group.id });

    // Explicitly choose "All events visible" — the form default is now "No events visible"
    // (since RD-875 wildcard-event_rules support: undefined => 'none').
    await grantDialog.locator('input[name="eventMode"][value="all"]').click();

    await grantDialog.getByRole('button', { name: /create grant/i }).click();
    await expect(grantDialog).not.toBeVisible({ timeout: 10000 });

    // Should show "All events visible" in the grant card
    const permDialog = page.locator(selectors.common.dialog);
    await expect(permDialog).toBeVisible();
    await expect(permDialog.getByText('All events visible').first()).toBeVisible();

    // Verify via API: event_rules should be the wildcard '*' string (RD-875)
    const grants = await fixture.rbac.listContractGrants(org.id, address);
    const savedGrant = grants.find(g => g.group_id === group.id);
    expect(savedGrant).toBeTruthy();
    expect(savedGrant!.event_rules).toBe('*');
  });

  test('C3: validation error when specific mode selected but no events added', async ({ page, request }) => {
    fixture = new RBACTestFixture(request);
    const currentDid = `did:privado:test_${Date.now()}_${Math.random().toString(36).substring(7)}`;
    await mockLoginViaAPI(page, currentDid);
    const org = await fixture.createOrgWithAdmin('ev-c3', currentDid);
    const group = await fixture.createGroup(org.id, 'grp-c3', { name: 'Group C3' });
    await fixture.rbac.setGroupAccess(org.id, group.id, {
      allowed_methods: ['*'],
      claims: ['deploy'],
    });
    await fixture.createContractWithABI(org.id, {
      name: 'Token C3',
      abi: ERC20_ABI,
    });

    await page.goto('/admin/rbac/contracts');
    await expect(page.locator(selectors.rbac.manager)).toBeVisible({ timeout: 10000 });

    await page.locator(selectors.rbac.orgSelector).click();
    await page.getByText(org.name).click();

    const grantDialog = await openGrantForm(page);

    // Switch to specific events but do NOT add any events (group selected by helper)
    await grantDialog.getByText('Specific events only').click();

    // Try to save
    // Submit button should be disabled natively
    await expect(grantDialog.getByRole('button', { name: /create grant/i })).toBeDisabled();

    // Should show validation error
    await expect(grantDialog.getByText(/select at least one event/i)).toBeVisible({ timeout: 5000 });

    // Dialog should still be open
    await expect(grantDialog).toBeVisible();
  });
});

// ---------------------------------------------------------------------------
// Group D: Editing existing grants
// ---------------------------------------------------------------------------

test.describe('Event rules — editing existing grants', () => {
  let fixture: RBACTestFixture;

  test.beforeEach(async ({ page }) => {
    await mockLoginViaAPI(page);
  });

  test.afterEach(async () => {
    if (fixture) {
      await fixture.cleanup();
    }
  });

  test('D1: edit form pre-populates existing event rules', async ({ page, request }) => {
    fixture = new RBACTestFixture(request);
    const currentDid = `did:privado:test_${Date.now()}_${Math.random().toString(36).substring(7)}`;
    await mockLoginViaAPI(page, currentDid);
    const org = await fixture.createOrgWithAdmin('ev-d1', currentDid);
    const group = await fixture.createGroup(org.id, 'grp-d1', { name: 'Group D1' });
    await fixture.rbac.setGroupAccess(org.id, group.id, {
      allowed_methods: ['*'],
      claims: ['deploy'],
    });
    const contract = await fixture.createContractWithABI(org.id, {
      name: 'Token D1',
      abi: ERC20_ABI,
    });
    const address = contract.address || contract.contract_address || '';

    // Fetch events from API to get real topic0 values
    const events = await fixture.rbac.listContractEvents(org.id, address);
    const transferEvent = events.find(e => e.name === 'Transfer');
    expect(transferEvent).toBeTruthy();

    // Create grant with a specific event rule via API
    await fixture.rbac.createContractGrant(org.id, address, {
      group_id: group.id,
      event_rules: [{
        topic0: transferEvent!.topic0,
        name: 'Transfer',
      }],
    });

    await page.goto('/admin/rbac/contracts');
    await expect(page.locator(selectors.rbac.manager)).toBeVisible({ timeout: 10000 });

    await page.locator(selectors.rbac.orgSelector).click();
    await page.getByText(org.name).click();

    // Open the edit form for the existing grant
    const editDialog = await openEditGrantForm(page);

    // "Specific events only" radio should be pre-selected
    const specificRadio = editDialog.locator('input[name="eventMode"][value="specific"]');
    await expect(specificRadio).toBeChecked();

    // Transfer should appear in the "Visible events:" section
    await expect(editDialog.getByText('Visible events:')).toBeVisible();
    const visibleSection = editDialog.locator('.space-y-3').filter({ hasText: 'Visible events:' });
    await expect(visibleSection.getByText('Transfer', { exact: true }).first()).toBeVisible();
  });

  test('D2: edit grant to add more events', async ({ page, request }) => {
    fixture = new RBACTestFixture(request);
    const currentDid = `did:privado:test_${Date.now()}_${Math.random().toString(36).substring(7)}`;
    await mockLoginViaAPI(page, currentDid);
    const org = await fixture.createOrgWithAdmin('ev-d2', currentDid);
    const group = await fixture.createGroup(org.id, 'grp-d2', { name: 'Group D2' });
    await fixture.rbac.setGroupAccess(org.id, group.id, {
      allowed_methods: ['*'],
      claims: ['deploy'],
    });
    const contract = await fixture.createContractWithABI(org.id, {
      name: 'Token D2',
      abi: ERC20_ABI,
    });
    const address = contract.address || contract.contract_address || '';

    // Fetch events from API to get real topic0 values
    const events = await fixture.rbac.listContractEvents(org.id, address);
    const transferEvent = events.find(e => e.name === 'Transfer');
    expect(transferEvent).toBeTruthy();

    // Create grant with only Transfer
    await fixture.rbac.createContractGrant(org.id, address, {
      group_id: group.id,
      event_rules: [{
        topic0: transferEvent!.topic0,
        name: 'Transfer',
      }],
    });

    await page.goto('/admin/rbac/contracts');
    await expect(page.locator(selectors.rbac.manager)).toBeVisible({ timeout: 10000 });

    await page.locator(selectors.rbac.orgSelector).click();
    await page.getByText(org.name).click();

    const editDialog = await openEditGrantForm(page);

    // Transfer should already be selected. Add Approval.
    await expect(editDialog.getByText('Contract events (2):')).toBeVisible({ timeout: 5000 });
    await editDialog.getByRole('button', { name: /Approval/ }).click();

    // Both should now be in the visible list
    const visibleSection = editDialog.locator('.space-y-3').filter({ hasText: 'Visible events:' });
    await expect(visibleSection.getByText('Transfer', { exact: true }).first()).toBeVisible();
    await expect(visibleSection.getByText('Approval', { exact: true }).first()).toBeVisible();

    // Save
    await editDialog.getByRole('button', { name: /save changes/i }).click();
    await expect(editDialog).not.toBeVisible({ timeout: 10000 });

    // Verify via API
    const grants = await fixture.rbac.listContractGrants(org.id, address);
    const savedGrant = grants.find(g => g.group_id === group.id);
    expect(savedGrant).toBeTruthy();
    expect(savedGrant!.event_rules).toBeTruthy();
    expect(savedGrant!.event_rules!.length).toBe(2);
    const ruleNames = savedGrant!.event_rules!.map(r => r.name).sort();
    expect(ruleNames).toEqual(['Approval', 'Transfer']);
  });

  test('D3: edit grant to switch from specific events back to all events', async ({ page, request }) => {
    fixture = new RBACTestFixture(request);
    const currentDid = `did:privado:test_${Date.now()}_${Math.random().toString(36).substring(7)}`;
    await mockLoginViaAPI(page, currentDid);
    const org = await fixture.createOrgWithAdmin('ev-d3', currentDid);
    const group = await fixture.createGroup(org.id, 'grp-d3', { name: 'Group D3' });
    await fixture.rbac.setGroupAccess(org.id, group.id, {
      allowed_methods: ['*'],
      claims: ['deploy'],
    });
    const contract = await fixture.createContractWithABI(org.id, {
      name: 'Token D3',
      abi: ERC20_ABI,
    });
    const address = contract.address || contract.contract_address || '';

    // Fetch events from API
    const events = await fixture.rbac.listContractEvents(org.id, address);
    const transferEvent = events.find(e => e.name === 'Transfer');

    // Create grant with specific event
    await fixture.rbac.createContractGrant(org.id, address, {
      group_id: group.id,
      event_rules: [{
        topic0: transferEvent!.topic0,
        name: 'Transfer',
      }],
    });

    await page.goto('/admin/rbac/contracts');
    await expect(page.locator(selectors.rbac.manager)).toBeVisible({ timeout: 10000 });

    await page.locator(selectors.rbac.orgSelector).click();
    await page.getByText(org.name).click();

    const editDialog = await openEditGrantForm(page);

    // Should be in "specific" mode with Transfer selected
    const specificRadio = editDialog.locator('input[name="eventMode"][value="specific"]');
    await expect(specificRadio).toBeChecked();

    // Switch back to "All events visible"
    await editDialog.getByText('All events visible').click();

    const allRadio = editDialog.locator('input[name="eventMode"][value="all"]');
    await expect(allRadio).toBeChecked();

    // Save
    await editDialog.getByRole('button', { name: /save changes/i }).click();
    await expect(editDialog).not.toBeVisible({ timeout: 10000 });

    // Verify via API: event_rules should be the wildcard '*' (RD-875 — was null pre-wildcard)
    const grants = await fixture.rbac.listContractGrants(org.id, address);
    const savedGrant = grants.find(g => g.group_id === group.id);
    expect(savedGrant).toBeTruthy();
    expect(savedGrant!.event_rules).toBe('*');

    // Verify in the UI: permissions dialog should show "All events visible"
    const permDialog = page.locator(selectors.common.dialog);
    await expect(permDialog).toBeVisible();
    await expect(permDialog.getByText('All events visible').first()).toBeVisible();
  });
});

// ---------------------------------------------------------------------------
// Group E: Contract without ABI — no event picker
// ---------------------------------------------------------------------------

test.describe('Event rules — contract without ABI', () => {
  let fixture: RBACTestFixture;

  test.beforeEach(async ({ page }) => {
    await mockLoginViaAPI(page);
  });

  test.afterEach(async () => {
    if (fixture) {
      await fixture.cleanup();
    }
  });

  test('E1: no ABI shows warning when switching to specific events', async ({ page, request }) => {
    fixture = new RBACTestFixture(request);
    const currentDid = `did:privado:test_${Date.now()}_${Math.random().toString(36).substring(7)}`;
    await mockLoginViaAPI(page, currentDid);
    const org = await fixture.createOrgWithAdmin('ev-e1', currentDid);
    await fixture.createGroup(org.id, 'grp-e1', { name: 'Group E1' });
    // Create contract WITHOUT ABI
    await fixture.createContract(org.id, { name: 'No ABI Contract' });

    await page.goto('/admin/rbac/contracts');
    await expect(page.locator(selectors.rbac.manager)).toBeVisible({ timeout: 10000 });

    await page.locator(selectors.rbac.orgSelector).click();
    await page.getByText(org.name).click();

    const grantDialog = await openGrantForm(page);

    // Switch to specific events
    await grantDialog.getByText('Specific events only').click();

    // Should show "No ABI uploaded" warning instead of event picker
    await expect(grantDialog.getByText(/no abi uploaded/i)).toBeVisible({ timeout: 5000 });
  });
});

// ---------------------------------------------------------------------------
// Group F: Persistence and Validation (P13, P14, P16)
// ---------------------------------------------------------------------------

test.describe('Event rules — persistence and validation', () => {
  let fixture: RBACTestFixture;

  test.beforeEach(async ({ page }) => {
    await mockLoginViaAPI(page);
  });

  test.afterEach(async () => {
    if (fixture) {
      await fixture.cleanup();
    }
  });

  test('P13: save rules, navigate away, return — rules still displayed', async ({ page, request }) => {
    fixture = new RBACTestFixture(request);
    const currentDid = `did:privado:test_${Date.now()}_${Math.random().toString(36).substring(7)}`;
    await mockLoginViaAPI(page, currentDid);
    const org = await fixture.createOrgWithAdmin('ev-p13', currentDid);
    const group = await fixture.createGroup(org.id, 'grp-p13', { name: 'Group P13' });
    await fixture.rbac.setGroupAccess(org.id, group.id, {
      allowed_methods: ['*'],
      claims: ['deploy'],
    });
    const contract = await fixture.createContractWithABI(org.id, {
      name: 'Token P13',
      abi: ERC20_ABI,
    });
    const address = contract.address || contract.contract_address || '';

    // Fetch events from API to get real topic0 values
    const events = await fixture.rbac.listContractEvents(org.id, address);
    const transferEvent = events.find(e => e.name === 'Transfer');
    expect(transferEvent).toBeTruthy();

    // Create grant with Transfer event rule via API
    await fixture.rbac.createContractGrant(org.id, address, {
      group_id: group.id,
      event_rules: [{
        topic0: transferEvent!.topic0,
        name: 'Transfer',
      }],
    });

    // Navigate to contracts page
    await page.goto('/admin/rbac/contracts');
    await expect(page.locator(selectors.rbac.manager)).toBeVisible({ timeout: 10000 });

    await page.locator(selectors.rbac.orgSelector).click();
    await page.getByText(org.name).click();

    // Open permissions dialog — grant card should show Transfer event pill
    const rows = page.locator('table tbody tr');
    await expect(rows).toHaveCount(1, { timeout: 10000 });
    const shieldBtn = rows.first().getByTitle('Manage permissions');
    await shieldBtn.click();

    const permDialog = page.locator(selectors.common.dialog);
    await expect(permDialog).toBeVisible({ timeout: 5000 });
    await expect(permDialog.getByText('Events:')).toBeVisible();
    await expect(permDialog.locator('.bg-violet-100').filter({ hasText: 'Transfer' })).toBeVisible();

    // Close the dialog
    await permDialog.getByRole('button', { name: /close/i }).first().click();

    // Navigate away to a different page
    await page.goto('/admin');
    await page.waitForTimeout(500);

    // Navigate back to contracts
    await page.goto('/admin/rbac/contracts');
    await expect(page.locator(selectors.rbac.manager)).toBeVisible({ timeout: 10000 });

    await page.locator(selectors.rbac.orgSelector).click();
    await page.getByText(org.name).click();

    // Re-open permissions dialog — Transfer rule should still be there
    const rows2 = page.locator('table tbody tr');
    await expect(rows2).toHaveCount(1, { timeout: 10000 });
    const shieldBtn2 = rows2.first().getByTitle('Manage permissions');
    await shieldBtn2.click();

    const permDialog2 = page.locator(selectors.common.dialog);
    await expect(permDialog2).toBeVisible({ timeout: 5000 });
    await expect(permDialog2.getByText('Events:')).toBeVisible();
    await expect(permDialog2.locator('.bg-violet-100').filter({ hasText: 'Transfer' })).toBeVisible();
  });

  test('P14: enter invalid topic0 manually — validation error', async ({ page, request }) => {
    fixture = new RBACTestFixture(request);
    const currentDid = `did:privado:test_${Date.now()}_${Math.random().toString(36).substring(7)}`;
    await mockLoginViaAPI(page, currentDid);
    const org = await fixture.createOrgWithAdmin('ev-p14', currentDid);
    const group = await fixture.createGroup(org.id, 'grp-p14', { name: 'Group P14' });
    await fixture.rbac.setGroupAccess(org.id, group.id, {
      allowed_methods: ['*'],
      claims: ['deploy'],
    });
    const contract = await fixture.createContractWithABI(org.id, {
      name: 'Token P14',
      abi: ERC20_ABI,
    });
    const address = contract.address || contract.contract_address || '';

    // Try creating a grant with invalid topic0 directly via API — should fail.
    // RD-1107: contract grants are per-org tenant management, so this must go
    // through the org admin's JWT — the super-admin X-Admin-Token would be
    // 403'd before the topic0 validation runs. currentDid is is_org_admin here.
    const adminUrl = process.env.ADMIN_URL || process.env.PROXY_URL || 'http://localhost:8080';
    const orgAdminToken = await getJWTToken(request, currentDid);
    const response = await request.post(
      `${adminUrl}/api/v1/admin/orgs/${org.id}/contracts/${address}/grants`,
      {
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${orgAdminToken}`,
        },
        data: {
          group_id: group.id,
          event_rules: [{
            topic0: '0xZZZZ',
            name: 'Bad',
          }],
        },
      }
    );

    // API should reject invalid topic0 with 400
    expect(response.status()).toBe(400);
    const body = await response.text();
    expect(body.toLowerCase()).toContain('invalid topic0');
  });

  test('P16: delete 1 of 2 rules, save — only 1 remains', async ({ page, request }) => {
    fixture = new RBACTestFixture(request);
    const currentDid = `did:privado:test_${Date.now()}_${Math.random().toString(36).substring(7)}`;
    await mockLoginViaAPI(page, currentDid);
    const org = await fixture.createOrgWithAdmin('ev-p16', currentDid);
    const group = await fixture.createGroup(org.id, 'grp-p16', { name: 'Group P16' });
    await fixture.rbac.setGroupAccess(org.id, group.id, {
      allowed_methods: ['*'],
      claims: ['deploy'],
    });
    const contract = await fixture.createContractWithABI(org.id, {
      name: 'Token P16',
      abi: ERC20_ABI,
    });
    const address = contract.address || contract.contract_address || '';

    // Fetch events from API to get real topic0 values
    const events = await fixture.rbac.listContractEvents(org.id, address);
    const transferEvent = events.find(e => e.name === 'Transfer');
    const approvalEvent = events.find(e => e.name === 'Approval');
    expect(transferEvent).toBeTruthy();
    expect(approvalEvent).toBeTruthy();

    // Create grant with both Transfer and Approval event rules
    await fixture.rbac.createContractGrant(org.id, address, {
      group_id: group.id,
      event_rules: [
        { topic0: transferEvent!.topic0, name: 'Transfer' },
        { topic0: approvalEvent!.topic0, name: 'Approval' },
      ],
    });

    await page.goto('/admin/rbac/contracts');
    await expect(page.locator(selectors.rbac.manager)).toBeVisible({ timeout: 10000 });

    await page.locator(selectors.rbac.orgSelector).click();
    await page.getByText(org.name).click();

    // Open the edit form for the existing grant
    const editDialog = await openEditGrantForm(page);

    // Both Transfer and Approval should appear in the "Visible events:" section
    const visibleSection = editDialog.locator('.space-y-3').filter({ hasText: 'Visible events:' });
    await expect(visibleSection.getByText('Transfer', { exact: true }).first()).toBeVisible();
    await expect(visibleSection.getByText('Approval', { exact: true }).first()).toBeVisible();

    // Remove Transfer by clicking the X button on its pill. The outer event
    // pill is uniquely classed `.bg-neutral-50` — the inner event chip span
    // shares `.border.border-primary-50` so we must qualify by bg.
    const transferPill = editDialog.locator('.border.border-primary-50.bg-neutral-50').filter({ hasText: 'Transfer' }).first();
    await transferPill.getByRole('button').first().click();

    // Only Approval should remain
    await expect(visibleSection.getByText('Approval', { exact: true }).first()).toBeVisible();
    // Transfer should no longer be in the visible section as a pill
    const remainingPills = editDialog.locator('.space-y-3').filter({ hasText: 'Visible events:' }).locator('.border.border-primary-50.bg-neutral-50');
    // There should be exactly 1 pill remaining (Approval)
    await expect(remainingPills).toHaveCount(1);

    // Save
    await editDialog.getByRole('button', { name: /save changes/i }).click();
    await expect(editDialog).not.toBeVisible({ timeout: 10000 });

    // Verify via API: only 1 event rule remains
    const grants = await fixture.rbac.listContractGrants(org.id, address);
    const savedGrant = grants.find(g => g.group_id === group.id);
    expect(savedGrant).toBeTruthy();
    expect(savedGrant!.event_rules).toBeTruthy();
    expect(savedGrant!.event_rules!.length).toBe(1);
    expect(savedGrant!.event_rules![0].name).toBe('Approval');
  });
});
