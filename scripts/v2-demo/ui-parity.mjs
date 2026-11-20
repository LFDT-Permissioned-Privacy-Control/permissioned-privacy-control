// Assertions against the actual native browser and its own authorized API.
// No mock response, injected identity, policy mutation or address resolver.
import assert from 'node:assert/strict';
import { mkdir, readFile } from 'node:fs/promises';
import path from 'node:path';
import { demoAccount } from '../../tools/v2-demo-wallet/accounts.mjs';
import { checkViewerCountRendering, checkTransferTypeRendering } from './explorer-data-parity.mjs';

export async function checkAdminEntry({ users, runtime, outputDirectory, passed }) {
  const results = [];
  const screenshots = path.join(outputDirectory, 'admin-entry');
  await mkdir(screenshots, { recursive: true, mode: 0o700 });
  const from = new Date(Date.now() - 60000).toISOString().replace(/\.\d{3}Z$/, 'Z');
  const to = new Date().toISOString().replace(/\.\d{3}Z$/, 'Z');
  const logs = `/api/v2/orgs/${runtime.organizationId}/access-logs?` + new URLSearchParams({ from, to, limit: '1' });
  const endpoints = ['/api/v2/self/selection', `/api/v2/orgs/${runtime.organizationId}/compliance/config`, logs,
    '/api/v1/disclosure/cases?' + new URLSearchParams({ role: 'data-org-admin', organizationId: runtime.organizationId, limit: '1' }), `/api/v2/orgs/${runtime.organizationId}/diagnostics`];
  for (const name of ['admin', 'deployer', 'reader', 'outsider']) {
    const user = users.get(name), admin = name === 'admin';
    const selfResponse = await user.context.request.get(runtime.opsOrigin + '/api/v2/self', { headers: { Authorization: 'Bearer ' + user.access.accessToken } });
    assert.equal(selfResponse.status(), 200);
    const self = await selfResponse.json();
    assert.equal(self.actorId, user.access.actorId);
    assert.equal(self.organizations.some(org => org.isOrgAdmin === true || org.isOrgReadonlyAdmin === true), admin, name + ': live organization role');
    await user.page.goto(runtime.opsOrigin + '/admin/account');
    await user.page.getByTestId('account-identity').waitFor();
    assert.ok((await user.page.getByTestId('account-identity').textContent()).includes(self.actorId), name + ': own account actor matches verified Self');
    for (const org of self.organizations) {
      assert.ok(Array.isArray(org.groups) && org.groups.length === org.groupCount && org.groupsTruncated === false, name + ': complete own-group projection for this small demo');
      for (const group of org.groups) assert.equal(await user.page.getByTestId('account-own-groups').getByText(group.name, { exact: true }).isVisible(), true, name + ': verified own group badge');
    }
    if (name !== 'outsider') assert.ok(self.organizations.some(org => org.groups.length > 0), name + ': proof mapped into a real group');
    assert.equal(await user.page.getByTestId('admin-nav').count(), admin ? 1 : 0, name + ': own account admin navigation');
    await user.page.getByTestId('account-dropdown-trigger').click();
    assert.equal(await user.page.getByTestId('back-to-app-link').count(), admin ? 1 : 0, name + ': dashboard menu');
    await user.page.keyboard.press('Escape');
    await user.page.goto(runtime.opsOrigin + '/admin/rbac/organizations');
    if (admin) await user.page.getByRole('button', { name: 'Open saved draft', exact: true }).waitFor();
    else {
      for (const target of ['/admin/identity/profiles', '/admin/identity/claim-mappings', '/admin/disclosure/rules', '/admin/compliance/policy', '/admin/settings', '/admin/configuration']) {
        await user.page.goto(runtime.opsOrigin + target);
        await user.page.getByRole('heading', { name: 'Access Denied', exact: true }).waitFor();
        assert.equal(await user.page.getByTestId('admin-nav').count(), 0);
        assert.equal(await user.page.getByTestId('admin-secondary-row').count(), 0);
      }
      await user.page.getByRole('heading', { name: 'Access Denied', exact: true }).waitFor();
      assert.equal(await user.page.getByTestId('admin-nav').count(), 0);
      assert.equal(await user.page.getByTestId('rbac-manager').count(), 0);
      await user.page.screenshot({ path: path.join(screenshots, name + '-denied.png'), fullPage: true, animations: 'disabled' });
      await user.page.getByRole('button', { name: 'Go to your account', exact: true }).click();
      await user.page.getByTestId('account-identity').waitFor();
    }
    const statuses = [];
    for (const endpoint of endpoints) {
      const response = await user.context.request.get(runtime.opsOrigin + endpoint, { headers: { Authorization: 'Bearer ' + user.access.accessToken } });
      const deniedStatus = endpoint.startsWith('/api/v1/disclosure/cases?') ? 404 : 403; // Case administration hides unauthorized scope existence.
      assert.equal(response.status(), admin ? 200 : deniedStatus, name + ': protected API ' + endpoint.split('?')[0]);
      statuses.push(response.status());
    }
    await user.page.screenshot({ path: path.join(screenshots, name + '.png'), fullPage: true, animations: 'disabled' });
    results.push({ persona: name, organizationAdmin: admin, ownAccountAvailable: true, consoleDenied: !admin, protectedAPIStatuses: statuses });
    if (admin) {
      const endpoint = `/api/v2/orgs/${runtime.organizationId}/diagnostics`;
      const sample = user.page.waitForResponse(response => new URL(response.url()).pathname === endpoint && response.request().method() === 'GET');
      await user.page.goto(runtime.opsOrigin + '/admin/diagnostics?org=' + runtime.organizationId);
      const response = await sample; assert.equal(response.status(), 200);
      const health = await response.json(); assert.equal(health.organizationId, runtime.organizationId);
      assert.equal(response.headers()['cache-control'], 'no-store');
      await user.page.getByRole('heading', { name: 'OPS build', exact: true }).waitFor();
      await user.page.getByText(health.build.commit, { exact: true }).waitFor();
      const node = user.page.getByText('Blockchain node (sampled)', { exact: true }).locator('xpath=ancestor::div[contains(concat(" ",normalize-space(@class)," ")," group ")][1]');
      await node.getByText({ connected: 'Connected', unavailable: 'Unavailable', unknown: 'Unknown' }[health.node.state], { exact: true }).waitFor();
      const next = await user.page.waitForResponse(response => new URL(response.url()).pathname === endpoint && response.request().method() === 'GET', { timeout: 12000 });
      assert.equal(next.status(), 200, 'Visible diagnostics refreshes within the V1 five-second interval');
      await user.page.screenshot({ path: path.join(screenshots, 'admin-diagnostics.png'), fullPage: true, animations: 'disabled' });
    }
    await user.page.goto(runtime.explorerOrigin);
    await user.page.locator('[data-field=app-actor]').waitFor();
  }
  passed('verified admin console gate; Reader, execution-admin Deployer and unmapped accounts retain own account/Explorer but are denied protected API access');
  return results;
}

async function checkAdminNavigation({ user, runtime, sourceDirectory, outputDirectory, passed }) {
  const page = user.page, output = path.join(outputDirectory, 'admin-navigation');
  await mkdir(output, { recursive: true, mode: 0o700 });
  await page.goto(runtime.opsOrigin + '/admin/rbac/organizations');
  await page.getByLabel('Policy source folder', { exact: true }).setInputFiles(sourceDirectory);
  await page.getByTestId('workspace-source').waitFor();
  assert.deepEqual(await page.getByTestId('rbac-tabs').getByRole('tab').allTextContents(), ['Organizations', 'Groups', 'Contracts', 'Execution Policy']);
  assert.deepEqual(await page.getByTestId('admin-nav').getByRole('tab').allTextContents(), ['RBAC', 'Identity', 'Compliance', 'Disclosure']);
  await page.screenshot({ path: path.join(output, 'rbac-desktop.png'), fullPage: true, animations: 'disabled' });
  await page.getByRole('tab', { name: 'Identity', exact: true }).click();
  assert.deepEqual(await page.getByTestId('identity-tabs').getByRole('tab').allTextContents(), ['Profiles', 'Claim mappings']);
  assert.equal(await page.getByRole('tab', { name: 'Azure Tenants', exact: true }).count(), 0);
  await page.getByRole('tab', { name: 'Claim mappings', exact: true }).click();
  await page.screenshot({ path: path.join(output, 'identity-desktop.png'), fullPage: true, animations: 'disabled' });
  await page.getByRole('button', { name: 'Edit local proposal', exact: true }).click();
  await page.getByRole('tab', { name: 'RBAC', exact: true }).click();
  await page.getByRole('button', { name: 'New organization', exact: true }).click();
  await page.getByLabel('Name', { exact: true }).fill('Unfinished navigation test');
  await page.goBack(); // Leave an open editor by browser history, without canceling it.
  await page.getByTestId('identity-tabs').waitFor();
  for (const [section, child] of [['Compliance', 'Policy draft'], ['Disclosure', 'Rules draft']]) {
    await page.getByRole('tab', { name: section, exact: true }).click();
    await page.getByRole('tab', { name: child, exact: true }).click();
    await page.getByTestId('workspace-source').waitFor();
    assert.equal(await page.getByRole('tab', { name: child, exact: true }).getAttribute('aria-selected'), 'true');
    await page.screenshot({ path: path.join(output, section.toLowerCase() + '-draft.png'), fullPage: true, animations: 'disabled' });
  }
  await page.getByRole('link', { name: 'Settings', exact: true }).click();
  assert.equal(await page.getByRole('link', { name: 'Settings', exact: true }).getAttribute('aria-current'), 'page');
  await page.screenshot({ path: path.join(output, 'settings.png'), fullPage: true, animations: 'disabled' });
  await page.getByRole('button', { name: 'Review & export', exact: true }).click();
  assert.equal(await page.getByRole('button', { name: 'Export configuration draft', exact: true }).isDisabled(), true);
  await page.getByRole('tab', { name: 'RBAC', exact: true }).click();
  assert.equal(await page.getByLabel('Name', { exact: true }).inputValue(), 'Unfinished navigation test');
  await page.getByRole('dialog').getByRole('button', { name: 'Cancel', exact: true }).click();
  for (const width of [1280, 390]) {
    await page.setViewportSize({ width, height: 844 });
    await page.screenshot({ path: path.join(output, 'rbac-' + width + '.png'), fullPage: true, animations: 'disabled' });
    const layout = await page.evaluate(() => ({ width: innerWidth, content: document.documentElement.scrollWidth }));
    assert.ok(layout.content <= layout.width, 'Navigation must wrap without horizontal page overflow at ' + width);
    for (const name of ['RBAC', 'Identity', 'Compliance', 'Disclosure', 'Organizations', 'Groups', 'Contracts', 'Execution Policy']) assert.equal(await page.getByRole('tab', { name, exact: true }).isVisible(), true);
  }
  await page.setViewportSize({ width: 1280, height: 900 });
  await page.getByRole('button', { name: 'Review & export', exact: true }).click();
  assert.equal(await page.getByRole('button', { name: 'Export configuration draft', exact: true }).isEnabled(), true);
  await page.screenshot({ path: path.join(output, 'review-export.png'), fullPage: true, animations: 'disabled' });
  await page.getByRole('button', { name: 'Close source', exact: true }).click();
  await page.goto(runtime.explorerOrigin);
  await page.locator('[data-field=app-actor]').waitFor();
  passed('regrouped navigation preserves the imported source and unfinished fields across business sections; desktop/mobile navigation wraps');
  return { rbacTabs: 4, identityTabs: 2, widths: [1280, 390], unfinishedFormRecovered: true, sourceActivated: false, screenshots: output };
}


// Exercise only an explicitly imported copy of the owned public source. Every
// unfinished edit is canceled, and the final UI export must retain every input
// byte. No fixture identity, mocked response or live configuration write is used.
async function checkSourceAuthoringParity({ user, runtime, sourceDirectory, outputDirectory, passed }) {
  const page = user.page, output = path.join(outputDirectory, 'source-authoring');
  await mkdir(output, { recursive: true, mode: 0o700 });
  const readSource = async name => {
    assert.match(name, /^[a-z0-9][a-z0-9_-]*\.json$/, 'Read only flat public source documents');
    return JSON.parse(await readFile(path.join(sourceDirectory, name), 'utf8'));
  };
  const draft = await readSource('draft.json');
  assert.ok(draft.organizations.some(org => org.id === runtime.organizationId));
  const reference = kind => {
    const ref = draft.documents.find(ref => ref.organizationId === runtime.organizationId && ref.kind === kind);
    assert.ok(ref, 'Owned source declares ' + kind);
    return ref.path;
  };
  const groups = (await readSource(reference('groups'))).spec.groups;
  const registry = (await readSource(reference('contract-registry'))).spec.contracts;
  const identity = await readSource(draft.identityCatalog.path);
  const group = groups.find(group => !group.isOrgAdmin && group.claims.includes('admin')) ?? groups.find(group => !group.isOrgAdmin && group.allowedMethods.length);
  const contract = registry.find(contract => contract.address.toLowerCase() === runtime.targetContract.toLowerCase());
  const profile = identity.profiles[0];
  const mapping = identity.mappings.find(mapping => mapping.organizationId === runtime.organizationId && mapping.groupIds.length && groups.some(group => !mapping.groupIds.includes(group.id)));
  assert.ok(group && contract && profile && mapping, 'The real demo public source provides each authoring surface');
  const mutationRequests = [], palettes = [];
  const observe = request => {
    const url = new URL(request.url());
    if (url.origin === runtime.opsOrigin && ['POST', 'PUT', 'PATCH', 'DELETE'].includes(request.method()) && /^\/api\/(?:v1|v2)\//.test(url.pathname) && /(?:orgs|configuration|policy|bundle|selection|compliance|disclosure)/.test(url.pathname)) mutationRequests.push({ method: request.method(), path: url.pathname });
  };
  const escape = value => value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const groupChoice = (dialog, selected) => dialog.getByRole('checkbox', { name: new RegExp('^' + escape(selected.name) + '\\s') });
  async function capture(name, width) {
    await page.screenshot({ path: path.join(output, name + '-' + width + '.png'), fullPage: true, animations: 'disabled' });
    const layout = await page.evaluate(() => ({ width: innerWidth, content: document.documentElement.scrollWidth }));
    assert.ok(layout.content <= layout.width, name + ': no horizontal page overflow at ' + width);
  }
  async function editMode(editing) {
    // Radix keeps the closing dialog mounted during its exit transition and
    // temporarily hides the underlying controls from the accessibility tree.
    await page.getByRole('dialog').waitFor({ state: 'hidden' });
    const button = page.getByRole('button', { name: editing ? 'Edit local proposal' : 'Inspect proposal', exact: true });
    if (await button.count()) await button.click();
    await page.getByRole('button', { name: editing ? 'Inspect proposal' : 'Edit local proposal', exact: true }).waitFor({ state: 'visible' });
  }
  const closeDialog = async () => {
    const dialog = page.getByRole('dialog').last(), closing = await dialog.elementHandle();
    assert.ok(closing);
    await dialog.getByRole('button', { name: 'Close', exact: true }).first().click();
    await closing.waitForElementState('hidden'); // Keep the inner dialog identity after its parent becomes visible.
    await closing.dispose();
  };
  async function palette(label, locator) {
    // Shared V1 Tailwind tokens: primary #8950FA, primary-50 #F5F3FF,
    // primary-200 #C4A8FD. Poll through transitions before comparing colours.
    const primary = 'rgb(137, 80, 250)', pale = 'rgb(245, 243, 255)', border = 'rgb(196, 168, 253)';
    const selected = !label.includes('unselected');
    const expected = !selected ? {} : label.startsWith('group-access-preset') ? { border: primary, background: pale }
      : label.startsWith('group-metadata-role') || label.startsWith('mapping-') ? { border, background: pale }
        : label.startsWith('read-grant-') || label.startsWith('group-readonly-') ? { border: primary } : {};
    await locator.evaluate(async (element, expected) => {
      const deadline = performance.now() + 2500;
      while (performance.now() < deadline) {
        const style = getComputedStyle(element);
        if ((!expected.border || style.borderColor === expected.border) && (!expected.background || style.backgroundColor === expected.background)) return;
        await new Promise(resolve => requestAnimationFrame(resolve));
      }
    }, expected);
    const style = await locator.evaluate(element => { const style = getComputedStyle(element); return { background: style.backgroundColor, border: style.borderColor, color: style.color }; });
    if (expected.border) assert.equal(style.border, expected.border, label + ': V1 selected border');
    if (expected.background) assert.equal(style.background, expected.background, label + ': V1 selected background');
    const marker = locator.locator('[data-state="checked"]').first();
    if (await marker.count()) {
      await marker.evaluate(async (element, primary) => {
        const deadline = performance.now() + 2500;
        while (getComputedStyle(element).backgroundColor !== primary && performance.now() < deadline) await new Promise(resolve => requestAnimationFrame(resolve));
      }, primary);
      style.checkedBackground = await marker.evaluate(element => getComputedStyle(element).backgroundColor);
      assert.equal(style.checkedBackground, primary, label + ': selected marker retains the exact V1 accent color');
    }
    palettes.push({ label, ...style });
    return style;
  }
  page.on('request', observe);
  try {
    await page.goto(runtime.opsOrigin + '/admin/rbac/groups?org=' + runtime.organizationId);
    await page.getByLabel('Policy source folder', { exact: true }).setInputFiles(sourceDirectory);
    await page.getByTestId('workspace-source').waitFor();
    for (const width of [1280, 390]) {
      await page.setViewportSize({ width, height: 844 });
      await page.getByRole('tab', { name: 'RBAC', exact: true }).click();
      await page.getByRole('tab', { name: 'Groups', exact: true }).click();
      await editMode(false);
      let card = page.getByTestId('group-card').filter({ has: page.getByText(group.name, { exact: true }) });
      await card.getByTitle('View declared permissions', { exact: true }).click();
      let dialog = page.getByRole('dialog').last();
      const declaredClaim = group.claims.includes('admin') ? dialog.getByRole('checkbox', { name: 'Execution administrator', exact: true }) : dialog.getByRole('checkbox', { name: group.allowedMethods.find(method => ['eth_call', 'eth_getBalance', 'eth_chainId'].includes(method)), exact: true });
      assert.equal(await declaredClaim.isChecked(), true);
      assert.equal(await declaredClaim.isDisabled(), true);
      await palette('group-readonly-' + width, declaredClaim.locator('..'));
      await capture('group-readonly-permissions', width);
      await closeDialog();
      await editMode(true);
      card = page.getByTestId('group-card').filter({ has: page.getByText(group.name, { exact: true }) });
      await card.getByTitle('Edit group draft', { exact: true }).click();
      dialog = page.getByRole('dialog').last();
      assert.equal(await dialog.getByLabel('Additional method names', { exact: true }).count(), 0, 'Metadata pencil does not open the access editor');
      await dialog.getByLabel('Description', { exact: true }).fill('Unfinished local parity metadata');
      const readonly = dialog.getByRole('radio', { name: 'Read-only organization admin', exact: true });
      await readonly.locator('..').click();
      assert.equal(await readonly.isChecked(), true);
      const selectedRole = await palette('group-metadata-role-' + width, readonly.locator('..'));
      const memberRole = await palette('group-metadata-unselected-' + width, dialog.getByRole('radio', { name: 'Member', exact: true }).locator('..'));
      assert.notDeepEqual(selectedRole, memberRole, 'Selected and unselected metadata roles are visually distinct');
      await capture('group-metadata-pencil', width);
      await dialog.getByRole('button', { name: 'Cancel', exact: true }).click();
      await card.getByTitle('Edit access settings', { exact: true }).click();
      dialog = page.getByRole('dialog').last();
      assert.equal(await dialog.getByLabel('Name', { exact: true }).count(), 0, 'Access gear does not open the metadata editor');
      const preset = dialog.getByRole('button', { name: 'Network reader', exact: true });
      await preset.click();
      assert.equal(await preset.getAttribute('aria-pressed'), 'true');
      const selectedPreset = await palette('group-access-preset-' + width, preset);
      const otherPreset = await palette('group-access-unselected-preset-' + width, dialog.getByRole('button', { name: 'Trace developer', exact: true }));
      assert.notDeepEqual(selectedPreset, otherPreset, 'Selected preset retains its V1 highlight');
      await capture('group-access-selected-preset', width);
      const accountState = dialog.getByRole('checkbox', { name: 'eth_getBalance', exact: true });
      await accountState.locator('..').click();
      assert.equal(await accountState.isChecked(), true);
      assert.equal(await preset.getAttribute('aria-pressed'), 'false', 'A custom method edit removes a misleading preset match');
      await palette('group-access-method-' + width, accountState.locator('..'));
      await capture('group-access-custom-method', width);
      await dialog.getByRole('button', { name: 'Cancel', exact: true }).click();

      await editMode(false);
      await page.getByRole('tab', { name: 'Contracts', exact: true }).click();
      const row = page.getByRole('button', { name: contract.name, exact: true }).locator('xpath=ancestor::tr[1]');
      for (const name of ['Address', 'Name', 'ABI', 'Read groups', 'Execution rules']) assert.equal(await page.getByRole('columnheader', { name, exact: true }).isVisible(), true);
      await capture('contracts-table', width);
      await row.getByRole('button', { name: /^ABI ·/ }).click();
      dialog = page.getByRole('dialog').last();
      await dialog.getByRole('heading', { name: /^Contract functions/ }).waitFor();
      await dialog.getByRole('heading', { name: /^Contract events/ }).waitFor();
      const viewFunction = contract.abi.find(entry => entry.type === 'function' && entry.stateMutability === 'view' && entry.inputs.length === 0);
      assert.ok(viewFunction, 'Owned ABI provides a view function for inspection');
      assert.equal(await dialog.getByText(viewFunction.name + '()', { exact: true }).isVisible(), true);
      assert.equal(await dialog.getByText('view', { exact: true }).first().isVisible(), true);
      assert.equal(await dialog.getByText('Advanced public ABI JSON', { exact: true }).locator('..').evaluate(element => element.open), false, 'Raw ABI is an advanced disclosure');
      await capture('contracts-readonly-abi', width);
      await closeDialog();
      await row.getByRole('button', { name: 'Read grants', exact: true }).click();
      dialog = page.getByRole('dialog').last();
      await dialog.getByRole('heading', { name: 'Groups with read access', exact: true }).waitFor();
      assert.equal(await dialog.getByLabel('Visible to unlock', { exact: true }).isChecked(), contract.allowVisibleToUnlock === true);
      await capture('contracts-read-grant-cards', width);
      const grant = contract.readGrants.find(grant => grant.eventRules.mode === 'allowlist') ?? contract.readGrants[0];
      assert.ok(grant, 'Owned public registry has an existing read grant');
      const grantGroup = groups.find(group => group.id === grant.groupId);
      await dialog.getByRole('button', { name: grantGroup.name, exact: true }).click();
      const grantDialog = page.getByRole('dialog').last();
      const mode = { all: 'All events visible', none: 'No events visible', allowlist: 'Specific events only' }[grant.eventRules.mode];
      const selectedMode = grantDialog.getByRole('radio', { name: mode, exact: true });
      assert.equal(await selectedMode.isChecked(), true); assert.equal(await selectedMode.isDisabled(), true);
      await palette('read-grant-readonly-mode-' + width, selectedMode.locator('..'));
      await capture('contracts-readonly-selected-events', width);
      await closeDialog(); await closeDialog();
      await editMode(true);
      await row.getByRole('button', { name: /^ABI ·/ }).click();
      dialog = page.getByRole('dialog').last();
      assert.equal(await dialog.getByRole('button', { name: 'Replace ABI file', exact: true }).isVisible(), true);
      assert.equal(await dialog.getByText('Paste or inspect ABI JSON', { exact: true }).locator('..').evaluate(element => element.open), false);
      await capture('contracts-upload-first-edit', width);
      await dialog.getByRole('button', { name: 'Cancel', exact: true }).click();

      await editMode(false);
      await page.getByRole('tab', { name: 'Identity', exact: true }).click();
      await page.getByRole('tab', { name: 'Profiles', exact: true }).click();
      await page.getByRole('button', { name: profile.name ?? profile.id, exact: true }).click();
      dialog = page.getByRole('dialog').last();
      assert.equal(await dialog.getByText(String(profile.kind), { exact: true }).isVisible(), true);
      assert.equal(await dialog.getByText('Raw JSON (advanced)', { exact: true }).locator('..').evaluate(element => element.open), false);
      if (profile.allowedCredentialIssuers?.length) assert.equal(await dialog.getByText('Allowed credential issuers', { exact: true }).locator('..').getByText(profile.allowedCredentialIssuers[0], { exact: true }).isVisible(), true);
      await capture('identity-readable-profile', width);
      await closeDialog();
      await page.getByRole('tab', { name: 'Claim mappings', exact: true }).click();
      await editMode(true);
      const mappingRow = page.getByRole('heading', { name: mapping.id, exact: true }).locator('xpath=ancestor::article[1]');
      await mappingRow.getByRole('button', { name: 'Edit mapping', exact: true }).click();
      dialog = page.getByRole('dialog').last();
      const selectedGroup = groups.find(group => mapping.groupIds.includes(group.id)), unselectedGroup = groups.find(group => !mapping.groupIds.includes(group.id));
      const selected = groupChoice(dialog, selectedGroup), unselected = groupChoice(dialog, unselectedGroup);
      assert.equal(await selected.isChecked(), true); assert.equal(await unselected.isChecked(), false);
      await palette('mapping-selected-group-' + width, selected.locator('..'));
      await unselected.locator('..').click();
      assert.equal(await unselected.isChecked(), true);
      await palette('mapping-additional-group-' + width, unselected.locator('..'));
      await capture('identity-mapping-selected-groups', width);
      await dialog.getByRole('button', { name: 'Cancel', exact: true }).click();
      await mappingRow.getByRole('button', { name: 'Remove mapping', exact: true }).click();
      dialog = page.getByRole('dialog').last();
      assert.ok((await dialog.textContent()).includes('After approval and deployment'));
      await capture('identity-mapping-removal-confirmation', width);
      await dialog.getByRole('button', { name: 'Cancel', exact: true }).click();
    }
    await page.setViewportSize({ width: 1280, height: 900 });
    await page.getByRole('button', { name: 'Review & export', exact: true }).click();
    const download = page.waitForEvent('download');
    await page.getByRole('button', { name: 'Export configuration draft', exact: true }).click();
    const exported = JSON.parse(await readFile(await (await download).path(), 'utf8'));
    assert.equal(exported.apiVersion, 'ops.ui-source-package/v1'); assert.equal(exported.roots.length, 1);
    const expectedPaths = new Set(['draft.json', ...draft.documents.map(ref => ref.path), ...['identityCatalog', 'runtimeCatalog', 'disclosureCatalog', 'complianceCatalog', 'authCatalog'].flatMap(key => draft[key] ? [draft[key].path] : [])]);
    assert.equal(exported.roots[0].files.length, expectedPaths.size);
    for (const file of exported.roots[0].files) {
      assert.ok(expectedPaths.delete(file.path), 'Only a referenced public source file is exported');
      assert.equal(file.dataBase64, (await readFile(path.join(sourceDirectory, file.path))).toString('base64'), 'Canceled edits preserve original source bytes: ' + file.path);
    }
    assert.equal(expectedPaths.size, 0);
    assert.deepEqual(mutationRequests, [], 'Authoring screenshots never write live policy/configuration APIs');
    await page.getByRole('button', { name: 'Close source', exact: true }).click();
    await page.getByTestId('workspace-source').waitFor({ state: 'hidden' });
    await page.goto(runtime.explorerOrigin); await page.locator('[data-field=app-actor]').waitFor();
    passed('V1 group metadata/access/selected palettes, structured Contracts ABI/read grants and readable Identity/mapping forms at desktop/mobile; canceled drafts export byte-identically without live writes');
    return { widths: [1280, 390], screenshots: output, palettes, canceledSourceBytesUnchanged: true, liveConfigurationWrites: mutationRequests, sourceActivated: false };
  } finally {
    page.off('request', observe);
    await page.setViewportSize({ width: 1280, height: 900 });
  }
}

async function copyVisibleAddress(page, row, expected) {
  // Exercise the real CopyButton without overwriting the operator's OS
  // clipboard. Only this temporary page's Clipboard API is substituted.
  await page.evaluate(() => {
    const descriptor = Object.getOwnPropertyDescriptor(navigator, 'clipboard'), writes = [];
    globalThis.__opsParityClipboard = { descriptor, writes };
    Object.defineProperty(navigator, 'clipboard', { configurable: true, value: { writeText: async value => { writes.push(value); } } });
  });
  try {
    await row.getByTitle('Copy to clipboard', { exact: true }).click();
    assert.deepEqual(await page.evaluate(() => globalThis.__opsParityClipboard.writes), [expected]);
  } finally {
    await page.evaluate(() => { const saved = globalThis.__opsParityClipboard; if (saved.descriptor) Object.defineProperty(navigator, 'clipboard', saved.descriptor); else delete navigator.clipboard; delete globalThis.__opsParityClipboard; });
  }
}

async function transactionView(user, runtime, hash, expected, screenshots, name) {
  const enrichment = [], rpcLookups = [];
  const observe = request => { const u = new URL(request.url()); if (u.origin !== runtime.explorerOrigin) return; if (/^\/api\/v2\/explorer\/(?:tokens\/0x[0-9a-f]{40}|addresses\/0x[0-9a-f]{40}\/contract)$/.test(u.pathname)) enrichment.push(u.pathname); if (/^\/(?:api\/)?(?:v2\/)?rpc(?:\/|$)/.test(u.pathname)) rpcLookups.push(u.pathname); };
  user.page.on('request', observe);
  const response = user.page.waitForResponse(r => r.request().method() === 'GET' && new URL(r.url()).pathname === '/api/v2/explorer/transactions/' + hash);
  const transfers = Array.isArray(expected) ? user.page.waitForResponse(r => r.request().method() === 'GET' && new URL(r.url()).pathname === '/api/v2/explorer/transactions/' + hash + '/transfers') : undefined;
  await user.page.goto(runtime.explorerOrigin + '/tx/' + hash);
  const wire = await response;
  assert.equal(wire.status(), expected === 'forbidden' ? 403 : 200);
  const value = await wire.json();
  if (expected === 'forbidden' || expected === 'unavailable') {
    if (expected === 'unavailable') {
      assert.equal(value, null);
      await user.page.getByRole('heading', { name: 'Transaction unavailable', exact: true }).waitFor();
    } else await user.page.getByRole('alert').waitFor();
    assert.equal(await user.page.getByTestId('tx-status').count(), 0);
    assert.equal(await user.page.locator('[data-label="Transaction Hash"]').count(), 0);
  } else {
    assert.equal(value.hash, hash);
    await user.page.getByTestId('tx-status').waitFor();
    for (const [field, reason, label, linked] of expected) {
      const address = value[field.toLowerCase()];
      assert.equal(value.addressMetadata?.[address], reason, name + ': native reason for ' + field);
      const row = user.page.locator('[data-testid="info-row"][data-label="' + field + '"]');
      await row.locator('[data-testid="address-label"][data-reason="' + reason + '"]').getByText(label, { exact: true }).waitFor();
      assert.equal(await row.locator('a').count(), linked ? 1 : 0, name + ': address navigation');
      if (!linked) {
        assert.equal(await row.getByText('Demo Ledger', { exact: true }).count(), 0);
        assert.ok(enrichment.every(endpoint => !endpoint.includes(address)), 'Counterparty badge must not trigger address/token name lookup');
        await copyVisibleAddress(user.page, row, address);
      }
    }
    assert.equal(await user.page.getByText('Disclosed', { exact: true }).count(), 0, 'Ordinary transaction never gains a case badge');
    const transferResponse = await transfers; assert.equal(transferResponse.status(), 200);
    const transferPage = await transferResponse.json();
    const section = user.page.locator('[data-testid="info-row"][data-label="ERC-20 Tokens Transferred"]');
    if (!transferPage.items.length && transferPage.page.hasMore === false) await section.waitFor({ state: 'hidden' });
    else {
      await section.waitFor();
      assert.equal(await section.getByRole('columnheader').count(), 0, 'Transaction details use compact rows, not feed headers');
    }
    assert.deepEqual(rpcLookups, [], 'Transaction relationship labels never resolve metadata with ordinary RPC');
  }
  await user.page.evaluate(() => window.scrollTo(0, 0));
  await user.page.screenshot({ path: path.join(screenshots, name + '.png'), fullPage: true, animations: 'disabled' });
  user.page.off('request', observe);
  return value;
}

async function ordinarySnapshot({ user, bff, rpc, runtime, hash, blockNumber }) {
  const logs = await rpc(user, 'eth_getLogs', [{ address: runtime.targetContract, fromBlock: blockNumber, toBlock: blockNumber }]);
  const receipt = await rpc(user, 'eth_getTransactionReceipt', [hash]);
  const transaction = await rpc(user, 'eth_getTransactionByHash', [hash]);
  const explorer = await bff(user, '/transactions/' + hash);
  return { logs, receipt, transaction, explorer };
}

async function caseIsolation({ users, runtime, hash, nodeRPC, rpc, bff, screenshots }) {
  const admin = users.get('admin'), reader = users.get('reader'), deployer = users.get('deployer');
  const tx = await nodeRPC(admin, 'eth_getTransactionByHash', [hash]);
  const block = await nodeRPC(admin, 'eth_getBlockByNumber', [tx.blockNumber, false]);
  const time = Number(BigInt(block.timestamp));
  const before = new Map();
  for (const [name, user] of [['admin', admin], ['reader', reader]]) before.set(name, await ordinarySnapshot({ user, bff, rpc, runtime, hash, blockNumber: tx.blockNumber }));
  assert.equal(before.get('reader').transaction, null);
  assert.equal(before.get('reader').explorer.value, null);
  assert.equal(before.get('admin').explorer.value.addressMetadata[tx.from.toLowerCase()], 'participant_override');
  await admin.page.goto(runtime.explorerOrigin + '/disclosures');
  await admin.page.getByText('Open a disclosure case', { exact: true }).click();
  await admin.page.getByLabel('Approved rule ID', { exact: true }).fill('demo-auditor');
  await admin.page.getByLabel('Client actor IDs', { exact: true }).fill(deployer.access.actorId);
  const reference = 'PARITY-' + Date.now();
  await admin.page.getByLabel('Case reference', { exact: true }).fill(reference);
  await admin.page.getByLabel('Purpose', { exact: true }).fill('Verify case access does not change ordinary RPC or Explorer authority');
  await admin.page.getByLabel('Legal basis', { exact: true }).fill('Controlled local regression fixture');
  const localDate = seconds => { const d = new Date(seconds * 1000); return new Date(d.getTime() - d.getTimezoneOffset() * 60000).toISOString().slice(0, 16); };
  await admin.page.getByLabel('From (local time)', { exact: true }).fill(localDate(time - 120));
  await admin.page.getByLabel('Through (local time)', { exact: true }).fill(localDate(time + 120));
  for (const label of ['Addresses', 'Activity', 'Activity summary', 'Sanctions', 'Compliance']) await admin.page.getByLabel(label, { exact: true }).uncheck();
  await admin.page.getByLabel('Events', { exact: true }).check();
  await admin.page.getByLabel('Transactions', { exact: true }).check();
  await admin.page.getByLabel('Detail level').selectOption('full');
  const created = admin.page.waitForResponse(r => r.request().method() === 'POST' && new URL(r.url()).pathname.endsWith('/disclosure/cases'));
  await admin.page.getByRole('button', { name: 'Open case', exact: true }).click();
  assert.ok([200, 201].includes((await created).status()));
  await admin.page.getByRole('heading', { name: reference, exact: true }).waitFor();
  const caseId = new URL(admin.page.url()).pathname.split('/').at(-1);
  let revoked = false;
  try {
    const read = admin.page.waitForResponse(r => r.request().method() === 'POST' && new URL(r.url()).pathname.endsWith('/disclosure/cases/' + caseId + '/read'));
    await admin.page.getByRole('group', { name: 'Case data', exact: true }).getByRole('button', { name: 'Transactions', exact: true }).click();
    let response = await read;
    const cursors = new Set();
    for (let page = 0; ; page++) {
      assert.equal(response.status(), 200);
      const envelope = await response.json();
      assert.equal(envelope.caseId, caseId); assert.equal(envelope.level, 'full');
      if (envelope.result.items.some(item => item.transactionHash === hash)) break;
      const cursor = envelope.result.nextCursor;
      assert.ok(cursor && !cursors.has(cursor) && page < 15, 'Actual case read must reach the same private sample used by ordinary snapshots'); cursors.add(cursor);
      const next = admin.page.waitForResponse(r => r.request().method() === 'POST' && new URL(r.url()).pathname.endsWith('/disclosure/cases/' + caseId + '/read'));
      await admin.page.getByRole('button', { name: envelope.result.items.length ? 'Next page' : 'Continue', exact: true }).click(); response = await next;
    }
    await admin.page.getByTestId('disclosure-transaction-row').first().waitFor();
    let events = admin.page.waitForResponse(r => r.request().method() === 'POST' && new URL(r.url()).pathname.endsWith('/disclosure/cases/' + caseId + '/read'));
    await admin.page.getByRole('group', { name: 'Case data', exact: true }).getByRole('button', { name: 'Events', exact: true }).click();
    const eventCursors = new Set(); let event;
    for (let page = 0; ; page++) {
      const response = await events; assert.equal(response.status(), 200);
      const envelope = await response.json();
      assert.equal(envelope.caseId, caseId); assert.equal(envelope.resource, 'events'); assert.equal(envelope.level, 'full');
      event = envelope.result.items.find(item => item.transactionHash === hash);
      if (event) break;
      const cursor = envelope.result.nextCursor;
      assert.ok(cursor && !eventCursors.has(cursor) && page < 15, 'Actual case Events must reach the sample log'); eventCursors.add(cursor);
      events = admin.page.waitForResponse(r => r.request().method() === 'POST' && new URL(r.url()).pathname.endsWith('/disclosure/cases/' + caseId + '/read'));
      await admin.page.getByRole('button', { name: envelope.result.items.length ? 'Next page' : 'Continue', exact: true }).click();
    }
    assert.equal(event.payload, 'disclosed');
    const readerBefore = JSON.stringify(before.get('reader')).toLowerCase();
    const canary = event.topics.find(topic => /^0x[0-9a-f]{64}$/.test(topic) && topic !== '0x' + '0'.repeat(64) && !readerBefore.includes(topic.toLowerCase()));
    assert.ok(canary, 'The full case must expose an actual event field absent from the other principal’s ordinary baseline');
    await admin.page.screenshot({ path: path.join(screenshots, 'active-case.png'), fullPage: true, animations: 'disabled' });
    for (const [name, user] of [['admin', admin], ['reader', reader]]) {
      const current = await ordinarySnapshot({ user, bff, rpc, runtime, hash, blockNumber: tx.blockNumber });
      assert.deepEqual(current, before.get(name), 'Active persisted case must not change ordinary ' + name + ' outputs');
      if (name === 'reader') assert.ok(!JSON.stringify(current).toLowerCase().includes(canary.toLowerCase()));
    }
    await admin.page.getByText('Revoke this case', { exact: true }).click();
    await admin.page.getByLabel('Revocation reason', { exact: true }).fill('Completed native UI parity regression');
    const revokedResponse = admin.page.waitForResponse(r => r.request().method() === 'POST' && new URL(r.url()).pathname.endsWith('/disclosure/cases/' + caseId + '/revoke'));
    await admin.page.getByRole('button', { name: 'Revoke case', exact: true }).click();
    assert.equal((await revokedResponse).status(), 200); revoked = true;
    await admin.page.locator('[data-testid="info-row"][data-label="Status"]').getByText('revoked', { exact: true }).waitFor();
    assert.equal(await admin.page.getByTestId('disclosure-transaction-row').count(), 0);
    for (const [name, user] of [['admin', admin], ['reader', reader]]) assert.deepEqual(await ordinarySnapshot({ user, bff, rpc, runtime, hash, blockNumber: tx.blockNumber }), before.get(name), 'Revoked case must not change ordinary ' + name + ' outputs');
    return { caseId, persistedCreateReadRevoke: true, transactionsAndEventsRead: true, otherPrincipalEventCanaryRemainedPrivate: true, ordinaryRPCAndExplorerUnchanged: true };
  } finally {
    if (!revoked) {
      // The case was created by this isolated regression. Retire only it if a
      // later assertion failed; never broaden configuration to clean up.
      await admin.page.evaluate(async ({ caseId, activation }) => { await fetch('/api/disclosure/cases/' + caseId + '/revoke', { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-OPS-App-Session': activation }, body: JSON.stringify({ reason: 'Regression cleanup' }) }); }, { caseId, activation: admin.status.session_id }).catch(() => {});
    }
  }
}

export async function checkNativeUIParity({ users, runtime, privateHash, sharedHash, outputDirectory, sourceDirectory, nodeRPC, rpc, bff, passed }) {
  assert.ok(sourceDirectory, 'Export the owned demo public source for navigation checks');
  assert.notEqual(privateHash, sharedHash, 'Private and explicitly shared scenarios require different transactions');
  assert.equal(new Set(['admin', 'deployer', 'reader', 'outsider'].map(name => users.get(name).access.actorId)).size, 4, 'Proof personas must remain different principals');
  const screenshots = path.join(outputDirectory, 'ui-parity'); await mkdir(screenshots, { recursive: true, mode: 0o700 });
  const adminEntry = await checkAdminEntry({ users, runtime, outputDirectory, passed });
  const navigation = await checkAdminNavigation({ user: users.get('admin'), runtime, sourceDirectory, outputDirectory, passed });
  const authoring = await checkSourceAuthoringParity({ user: users.get('admin'), runtime, sourceDirectory, outputDirectory, passed });
  const viewerCounts = await checkViewerCountRendering({ users, runtime, privateHash, screenshots, passed });
  const transferTypes = await checkTransferTypeRendering({ users, runtime, screenshots, passed });
  const cases = [];
  await transactionView(users.get('deployer'), runtime, privateHash, [['From', 'own_address', 'Mine', true], ['To', 'rbac_group_member', 'My Org', true]], screenshots, 'owner'); cases.push('owner-Mine');
  await transactionView(users.get('admin'), runtime, sharedHash, [['From', 'participant_override', 'Counterparty', false], ['To', 'rbac_group_member', 'My Org', true]], screenshots, 'same-org-counterparty'); cases.push('same-org-Counterparty');
  await transactionView(users.get('reader'), runtime, privateHash, 'unavailable', screenshots, 'reader-private-denied'); cases.push('same-org-nonowner-private-denied');
  await transactionView(users.get('reader'), runtime, sharedHash, [['From', 'visible_to_grant', 'Shared', true], ['To', 'rbac_group_member', 'My Org', true]], screenshots, 'explicit-share'); cases.push('genuine-visibleTo-Shared');
  await transactionView(users.get('outsider'), runtime, sharedHash, 'forbidden', screenshots, 'unmapped-outsider'); cases.push('unmapped-outsider-denied');
  // A directly addressable counterparty does not become Mine through a case.
  assert.notEqual(demoAccount('admin').address.toLowerCase(), demoAccount('deployer').address.toLowerCase());
  passed('native V2 API-to-page Mine/My Org/Counterparty/Shared and denied persona matrix');
  const isolation = await caseIsolation({ users, runtime, hash: privateHash, nodeRPC, rpc, bff, screenshots });
  passed('persisted case create/read/revoke leaves ordinary RPC and Explorer unchanged for the recipient and another principal');
  return { cases, screenshots, isolation, adminEntry, navigation, authoring, viewerCounts, transferTypes, clipboard: 'Real rendered CopyButton with a page-local Clipboard API substitute; OS clipboard untouched', limits: ['The unmapped outsider has no organization; a second-organization browser fixture is not claimed.', 'The Admin case recipient already has ordinary emitter authority. The full-case canary check establishes isolation from another principal (Reader), not an otherwise deprived case recipient.', 'Server reorg acquisition/delivery regressions are separate; this browser run does not mutate chain canonicality.'] };
}
