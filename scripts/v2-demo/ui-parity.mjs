// Assertions against the actual native browser and its own authorized API.
// No mock response, injected identity, policy mutation or address resolver.
import assert from 'node:assert/strict';
import { mkdir } from 'node:fs/promises';
import { spawnSync } from 'node:child_process';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
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
  const endpoints = ['/api/v2/configuration/sources', `/api/v2/orgs/${runtime.organizationId}/compliance/config`, logs,
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
    if (admin) await user.page.getByTestId('rbac-title').waitFor();
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

async function openConfiguration(user, runtime, id = 'current') {
  await user.page.goto(runtime.opsOrigin + '/admin/configuration');
  await user.page.getByTestId('configuration-source-' + id).click();
  const roots = user.page.getByLabel('Source root', { exact: true });
  if (await roots.count()) await roots.selectOption('core');
  await user.page.getByTestId('workspace-source').waitFor();
}

async function configurationSnapshot(user, runtime) {
  const headers = { Authorization: 'Bearer ' + user.access.accessToken };
  const response = await user.context.request.get(runtime.opsOrigin + '/api/v2/configuration/sources/current', { headers });
  assert.equal(response.status(), 200, 'The owned demo publishes current source separately from its runtime artifacts');
  const project = await response.json();
  assert.equal(project.apiVersion, 'ops.ui-source-package/v1');
  const core = project.roots.find(root => root.id === 'core'); assert.ok(core);
  const files = new Map(core.files.map(file => [file.path, Buffer.from(file.dataBase64, 'base64')]));
  const read = name => { assert.ok(files.has(name), 'Referenced public source ' + name); return JSON.parse(files.get(name).toString('utf8')); };
  const draft = read('draft.json');
  return { project, files, read, draft };
}

async function checkAdminNavigation({ user, runtime, outputDirectory, passed }) {
  const page = user.page, output = path.join(outputDirectory, 'admin-navigation');
  await mkdir(output, { recursive: true, mode: 0o700 });
  await openConfiguration(user, runtime);
  assert.deepEqual(await page.getByTestId('rbac-tabs').getByRole('tab').allTextContents(), ['Organizations', 'Groups', 'Contracts', 'Execution Policy', 'Source files']);
  assert.deepEqual(await page.getByTestId('admin-nav').getByRole('tab').allTextContents(), ['RBAC', 'Identity', 'Compliance', 'Disclosure']);
  await page.getByRole('tab', { name: 'Organizations', exact: true }).click();
  await page.getByRole('cell', { name: 'Demo Bank', exact: true }).waitFor();
  await page.screenshot({ path: path.join(output, 'rbac-desktop.png'), fullPage: true, animations: 'disabled' });
  await page.getByRole('tab', { name: 'Identity', exact: true }).click();
  assert.deepEqual(await page.getByTestId('identity-tabs').getByRole('tab').allTextContents(), ['Profiles', 'Claim mappings']);
  assert.equal(await page.getByRole('tab', { name: 'Azure Tenants', exact: true }).count(), 0);
  await page.getByRole('tab', { name: 'Claim mappings', exact: true }).click();
  await page.screenshot({ path: path.join(output, 'identity-desktop.png'), fullPage: true, animations: 'disabled' });
  for (const [section, child] of [['Compliance', 'Policy'], ['Disclosure', 'Rules']]) {
    await page.getByRole('tab', { name: section, exact: true }).click();
    await page.getByRole('tab', { name: child, exact: true }).click();
    await page.getByTestId('workspace-source').waitFor({ state: 'attached' });
    await page.screenshot({ path: path.join(output, section.toLowerCase() + '-source.png'), fullPage: true, animations: 'disabled' });
  }
  await page.getByRole('link', { name: 'Settings', exact: true }).click();
  assert.equal(await page.getByRole('link', { name: 'Settings', exact: true }).getAttribute('aria-current'), 'page');
  await page.screenshot({ path: path.join(output, 'settings.png'), fullPage: true, animations: 'disabled' });
  await page.getByRole('tab', { name: 'RBAC', exact: true }).click();
  await page.getByRole('tab', { name: 'Organizations', exact: true }).click();
  await page.getByRole('cell', { name: 'Demo Bank', exact: true }).waitFor();
  for (const width of [1280, 390]) {
    await page.setViewportSize({ width, height: 844 });
    await page.screenshot({ path: path.join(output, 'rbac-' + width + '.png'), fullPage: true, animations: 'disabled' });
    const layout = await page.evaluate(() => ({ width: innerWidth, content: document.documentElement.scrollWidth }));
    assert.ok(layout.content <= layout.width, 'Navigation must fit without horizontal page overflow at ' + width);
    for (const name of ['RBAC', 'Identity', 'Compliance', 'Disclosure', 'Organizations', 'Groups', 'Contracts', 'Execution Policy', 'Source files']) assert.equal(await page.getByRole('tab', { name, exact: true }).isVisible(), true);
  }
  await page.setViewportSize({ width: 1280, height: 900 });
  await page.goto(runtime.explorerOrigin); await page.locator('[data-field=app-actor]').waitFor();
  passed('read-only configuration selection survives navigation across business sections; desktop/mobile retain the native layout');
  return { screenshots: output, selectedSource: 'current', widths: [1280, 390] };
}

async function checkReadOnlySourceParity({ user, runtime, outputDirectory, passed }) {
  const page = user.page, output = path.join(outputDirectory, 'configuration-viewer');
  await mkdir(output, { recursive: true, mode: 0o700 });
  const { read, draft } = await configurationSnapshot(user, runtime);
  assert.ok(draft.organizations.some(org => org.id === runtime.organizationId));
  const reference = kind => {
    const ref = draft.documents.find(ref => ref.organizationId === runtime.organizationId && ref.kind === kind);
    assert.ok(ref, 'Owned source declares ' + kind); return ref.path;
  };
  const groups = read(reference('groups')).spec.groups, registry = read(reference('contract-registry')).spec.contracts;
  const identity = read(draft.identityCatalog.path);
  const group = groups.find(group => !group.isOrgAdmin && group.claims.includes('admin')) ?? groups.find(group => !group.isOrgAdmin && group.allowedMethods.length);
  const contract = registry.find(contract => contract.address.toLowerCase() === runtime.targetContract.toLowerCase());
  const profile = identity.profiles[0];
  const mapping = identity.mappings.find(mapping => mapping.organizationId === runtime.organizationId && mapping.groupIds.length);
  assert.ok(group && contract && profile && mapping, 'Actual source covers group, contract, identity and mapping views');
  const execution = read(reference('execution-rules')).spec.policy;
  const binding = execution.bindings.find(binding => binding.group === group.id);
  const ruleIndex = binding?.allow.findIndex(rule => rule.storageAddress?.toLowerCase() === contract.address.toLowerCase() && rule.selector === '*');
  assert.ok(binding && ruleIndex >= 0, 'Actual source binds this group to the registered contract');
  const rule = binding.allow[ruleIndex];
  const mutationRequests = [], palettes = [], executionInspections = [];
  const observe = request => {
    const url = new URL(request.url());
    if (url.origin === runtime.opsOrigin && ['POST', 'PUT', 'PATCH', 'DELETE'].includes(request.method()) && /^\/api\/(?:v1|v2)\//.test(url.pathname) && /(?:orgs|configuration|policy|bundle|selection|compliance|disclosure)/.test(url.pathname)) mutationRequests.push({ method: request.method(), path: url.pathname });
  };
  const closeDialog = async () => {
    const dialog = page.getByRole('dialog').last(), closing = await dialog.elementHandle(); assert.ok(closing);
    await dialog.getByRole('button', { name: /^Close(?: .+)?$/ }).first().click();
    await closing.waitForElementState('hidden'); await closing.dispose();
  };
  async function capture(name, width) {
    await page.screenshot({ path: path.join(output, name + '-' + width + '.png'), fullPage: true, animations: 'disabled' });
    const layout = await page.evaluate(() => ({ width: innerWidth, content: document.documentElement.scrollWidth }));
    assert.ok(layout.content <= layout.width, name + ': no horizontal page overflow at ' + width);
    assert.equal(await page.getByRole('button', { name: /^(?:Edit local proposal|Review & export|Open saved draft|New organization|Add group|Register contract|Edit mapping|Remove mapping)$/ }).count(), 0, 'Viewer has no authoring controls');
    assert.equal(await page.locator('input[type=file]').count(), 0, 'No browser source or ABI upload');
  }
  async function palette(label, locator) {
    const expected = label.startsWith('read-grant-') ? 'rgb(196, 168, 253)' : 'rgb(137, 80, 250)';
    await locator.evaluate(async (element, expected) => {
      const deadline = performance.now() + 2500;
      while (getComputedStyle(element).borderColor !== expected && performance.now() < deadline) await new Promise(resolve => requestAnimationFrame(resolve));
    }, expected);
    const style = await locator.evaluate(element => { const style = getComputedStyle(element); return { background: style.backgroundColor, border: style.borderColor, color: style.color }; });
    assert.equal(style.border, expected, label + ': retained V1 selected permission border'); palettes.push({ label, ...style });
  }
  page.on('request', observe);
  try {
    await openConfiguration(user, runtime);
    for (const width of [1280, 390]) {
      await page.setViewportSize({ width, height: 844 });
      await page.getByRole('tab', { name: 'RBAC', exact: true }).click();
      await page.getByRole('tab', { name: 'Groups', exact: true }).click();
      const scope = page.getByTestId('org-selector');
      if (await scope.count() && !(await scope.textContent()).includes('Demo Bank')) { await scope.click(); await page.getByRole('option', { name: /Demo Bank/ }).click(); }
      const card = page.getByTestId('group-card').filter({ has: page.getByText(group.name, { exact: true }) });
      await card.getByTitle('View declared permissions', { exact: true }).click();
      let dialog = page.getByRole('dialog').last();
      const declaredClaim = group.claims.includes('admin') ? dialog.getByRole('checkbox', { name: 'Execution administrator', exact: true }) : dialog.getByRole('checkbox', { name: group.allowedMethods.find(method => ['eth_call', 'eth_getBalance', 'eth_chainId'].includes(method)), exact: true });
      assert.equal(await declaredClaim.isChecked(), true); assert.equal(await declaredClaim.isDisabled(), true);
      await palette('group-readonly-' + width, declaredClaim.locator('..'));
      await capture('group-declared-permissions', width); await closeDialog();
      await page.getByRole('tab', { name: 'Contracts', exact: true }).click();
      const row = page.getByRole('button', { name: contract.name, exact: true }).locator('xpath=ancestor::tr[1]');
      for (const name of ['Address', 'Name', 'ABI', 'Read groups', 'Execution rules']) assert.equal(await page.getByRole('columnheader', { name, exact: true }).isVisible(), true);
      await capture('contracts-table', width);
      await row.getByRole('button', { name: /^ABI ·/ }).click();
      dialog = page.getByRole('dialog').last();
      await dialog.getByRole('heading', { name: /^Contract functions/ }).waitFor();
      await dialog.getByRole('heading', { name: /^Contract events/ }).waitFor();
      const viewFunction = contract.abi.find(entry => entry.type === 'function' && entry.stateMutability === 'view' && entry.inputs.length === 0); assert.ok(viewFunction);
      assert.equal(await dialog.getByText(viewFunction.name + '()', { exact: true }).isVisible(), true);
      assert.equal(await dialog.getByText('Advanced public ABI JSON', { exact: true }).locator('..').evaluate(element => element.open), false);
      await capture('contracts-structured-abi', width); await closeDialog();
      await row.getByRole('button', { name: 'Read grants', exact: true }).click();
      dialog = page.getByRole('dialog').last();
      await dialog.getByRole('heading', { name: 'Groups with read access', exact: true }).waitFor();
      assert.equal(await dialog.getByLabel('Visible to unlock', { exact: true }).isChecked(), contract.allowVisibleToUnlock === true);
      const grant = contract.readGrants.find(grant => grant.eventRules.mode === 'allowlist') ?? contract.readGrants[0]; assert.ok(grant);
      await dialog.getByRole('button', { name: groups.find(group => group.id === grant.groupId).name, exact: true }).click();
      const grantDialog = page.getByRole('dialog').last();
      const mode = { all: 'All events visible', none: 'No events visible', allowlist: 'Specific events only' }[grant.eventRules.mode];
      const selectedMode = grantDialog.getByRole('group', { name: 'Event visibility', exact: true }).getByText(mode, { exact: true }).locator('..');
      assert.ok((await selectedMode.textContent()).includes('Selected'));
      await palette('read-grant-readonly-mode-' + width, selectedMode);
      await capture('contracts-selected-event-rules', width); await closeDialog(); await closeDialog();
      await page.getByRole('tab', { name: 'Execution Policy', exact: true }).click();
      await page.getByRole('heading', { name: 'Execution permissions', exact: true }).waitFor();
      const bindingSection = page.getByRole('heading', { name: group.name, exact: true }).locator('xpath=ancestor::section[1]');
      await bindingSection.getByRole('link', { name: 'View group permissions', exact: true }).waitFor();
      assert.ok((await bindingSection.textContent()).includes(contract.name), 'Binding resolves its target to the registered contract name');
      await bindingSection.getByRole('button', { name: 'Inspect binding', exact: true }).click();
      dialog = page.getByRole('dialog').last();
      await dialog.getByRole('heading', { name: 'Native execution inspection', exact: true }).waitFor();
      await dialog.getByRole('heading', { name: group.name, exact: true }).waitFor();
      const target = dialog.getByText('Target', { exact: true }).first().locator('..');
      assert.ok((await target.textContent()).includes(contract.name));
      assert.ok((await target.textContent()).includes(contract.address));
      assert.equal((await dialog.getByText('Function / input', { exact: true }).first().locator('..').textContent()).trim(), 'Function / inputAny input');
      assert.ok((await dialog.getByText('Selector', { exact: true }).first().locator('..').textContent()).includes(rule.selector));
      assert.equal(await dialog.getByText('Advanced native binding JSON', { exact: true }).locator('..').evaluate(element => element.open), false, 'Binding JSON remains an optional advanced view');
      await capture('execution-binding-contract-linkage', width); await closeDialog();
      await bindingSection.getByRole('button', { name: 'Inspect rule', exact: true }).nth(ruleIndex).click();
      dialog = page.getByRole('dialog').last();
      await dialog.getByRole('heading', { name: 'Native execution inspection', exact: true }).waitFor();
      assert.ok((await dialog.getByText('Target', { exact: true }).locator('..').textContent()).includes(contract.name));
      assert.ok((await dialog.getByText('Executing code', { exact: true }).locator('..').textContent()).includes(contract.address));
      assert.equal((await dialog.getByText('Function / input', { exact: true }).locator('..').textContent()).trim(), 'Function / inputAny input');
      assert.equal(await dialog.getByText('Advanced native rule JSON', { exact: true }).locator('..').evaluate(element => element.open), false, 'Rule details do not require raw JSON');
      await capture('execution-rule-details', width); await closeDialog();
      executionInspections.push({ width, groupId: binding.group, contract: contract.address, selector: rule.selector, displayedInput: 'Any input' });
      await page.getByRole('tab', { name: 'Identity', exact: true }).click();
      await page.getByRole('tab', { name: 'Profiles', exact: true }).click();
      await page.getByRole('button', { name: profile.name ?? profile.id, exact: true }).click();
      dialog = page.getByRole('dialog').last();
      assert.equal(await dialog.getByText(String(profile.kind), { exact: true }).isVisible(), true);
      if (profile.allowedCredentialIssuers?.length) assert.equal(await dialog.getByText('Allowed credential issuers', { exact: true }).locator('..').getByText(profile.allowedCredentialIssuers[0], { exact: true }).isVisible(), true);
      await capture('identity-readable-profile', width); await closeDialog();
      await page.getByRole('tab', { name: 'Claim mappings', exact: true }).click();
      const mappingRow = page.getByRole('heading', { name: mapping.id, exact: true }).locator('xpath=ancestor::article[1]');
      await mappingRow.waitFor();
      for (const id of mapping.groupIds) assert.ok((await mappingRow.textContent()).includes(groups.find(group => group.id === id).name), 'Mapping shows the configured group name');
      await capture('identity-group-linkage', width);
    }
    assert.deepEqual(mutationRequests, [], 'Inspection never writes configuration/operational policy APIs');
    passed('read-only V1 permission palettes, structured ABI/read grants, execution binding/rule inspection and identity/group linkage at desktop/mobile without config writes');
    return { widths: [1280, 390], screenshots: output, palettes, executionInspections, liveConfigurationWrites: mutationRequests, sourceActivated: false };
  } finally { page.off('request', observe); await page.setViewportSize({ width: 1280, height: 900 }); }
}

function viewerFixture(action) {
  const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
  const result = spawnSync(path.join(root, 'scripts/v2-demo.sh'), ['viewer-fixture', action], { env: process.env, encoding: 'utf8', timeout: 30_000, maxBuffer: 1 << 20 });
  assert.equal(result.status, 0, 'External viewer fixture ' + action + ': ' + result.stderr);
}

async function checkExactPreviewExecution({ user, runtime, output }) {
  const require = createRequire(new URL('../../tools/v2-test-wallet/package.json', import.meta.url));
  const { Interface } = require('ethers');
  const response = await user.context.request.get(runtime.opsOrigin + '/api/v2/configuration/sources/ui-parity-preview', { headers: { Authorization: 'Bearer ' + user.access.accessToken } });
  assert.equal(response.status(), 200);
  const project = await response.json(), core = project.roots.find(root => root.id === 'core'); assert.ok(core);
  const documents = new Map(core.files.map(file => [file.path, JSON.parse(Buffer.from(file.dataBase64, 'base64').toString('utf8'))]));
  const draft = documents.get('draft.json');
  const source = kind => documents.get(draft.documents.find(ref => ref.organizationId === runtime.organizationId && ref.kind === kind).path).spec;
  const groups = source('groups').groups, contracts = source('contract-registry').contracts;
  const binding = source('execution-rules').policy.bindings.find(binding => binding.allow.some(rule => rule.storageAddress?.toLowerCase() === runtime.targetContract.toLowerCase() && !['*', '0x'].includes(rule.selector)));
  assert.ok(binding, 'The external preview includes an exact function rule');
  const ruleIndex = binding.allow.findIndex(rule => rule.storageAddress?.toLowerCase() === runtime.targetContract.toLowerCase() && !['*', '0x'].includes(rule.selector)), rule = binding.allow[ruleIndex];
  const group = groups.find(group => group.id === binding.group), contract = contracts.find(contract => contract.address.toLowerCase() === (rule.codeAddress || rule.storageAddress).toLowerCase());
  assert.ok(group && contract); assert.match(rule.abiDigest, /^[0-9a-f]{64}$/);
  const func = new Interface(contract.abi).getFunction(rule.selector); assert.ok(func);
  const signature = func.format('sighash'), evidence = [];
  const page = user.page;
  for (const width of [1280, 390]) {
    await page.setViewportSize({ width, height: 844 });
    await page.getByRole('tab', { name: 'RBAC', exact: true }).click();
    await page.getByRole('tab', { name: 'Execution Policy', exact: true }).click();
    const scope = page.getByTestId('org-selector');
    if (!(await scope.textContent()).includes('Demo Bank preview')) { await scope.click(); await page.getByRole('option', { name: /Demo Bank preview/ }).click(); }
    const section = page.getByRole('heading', { name: group.name, exact: true }).locator('xpath=ancestor::section[1]');
    assert.ok((await section.textContent()).includes(contract.name));
    await section.getByText(signature, { exact: true }).waitFor();
    const close = async () => { const dialog = page.getByRole('dialog').last(), element = await dialog.elementHandle(); await dialog.getByRole('button', { name: /^Close(?: .+)?$/ }).first().click(); await element.waitForElementState('hidden'); await element.dispose(); };
    const assertDetails = async (dialog, index) => {
      const field = name => dialog.getByText(name, { exact: true }).nth(index).locator('..');
      assert.ok((await field('Target').textContent()).includes(contract.name));
      assert.ok((await field('Target').textContent()).includes(rule.storageAddress));
      assert.ok((await field('Executing code').textContent()).includes(rule.codeAddress || rule.storageAddress));
      assert.ok((await field('Function / input').textContent()).includes(signature));
      assert.ok((await field('Selector').textContent()).includes(rule.selector));
      assert.ok((await field('Pinned ABI digest').textContent()).includes(rule.abiDigest));
    };
    await section.getByRole('button', { name: 'Inspect binding', exact: true }).click();
    let dialog = page.getByRole('dialog').last();
    await dialog.getByRole('heading', { name: group.name, exact: true }).waitFor();
    await assertDetails(dialog, ruleIndex);
    await page.screenshot({ path: path.join(output, 'exact-execution-binding-' + width + '.png'), fullPage: true, animations: 'disabled' });
    await close();
    await section.getByRole('button', { name: 'Inspect rule', exact: true }).nth(ruleIndex).click();
    dialog = page.getByRole('dialog').last(); await assertDetails(dialog, 0);
    await page.screenshot({ path: path.join(output, 'exact-execution-rule-' + width + '.png'), fullPage: true, animations: 'disabled' });
    const layout = await page.evaluate(() => ({ width: innerWidth, content: document.documentElement.scrollWidth }));
    assert.ok(layout.content <= layout.width, 'Exact function rule inspection fits at ' + width);
    await close(); evidence.push({ width, groupId: binding.group, contract: contract.address, function: signature, selector: rule.selector, abiDigest: rule.abiDigest });
  }
  await page.setViewportSize({ width: 1280, height: 900 });
  return evidence;
}

async function checkFolderRefresh({ user, runtime, outputDirectory, passed }) {
  const page = user.page, output = path.join(outputDirectory, 'configuration-viewer');
  const sourceBefore = await configurationSnapshot(user, runtime);
  const selfBefore = await user.context.request.get(runtime.opsOrigin + '/api/v2/self', { headers: { Authorization: 'Bearer ' + user.access.accessToken } });
  assert.equal(selfBefore.status(), 200); const rolesBefore = (await selfBefore.json()).organizations;
  viewerFixture('remove');
  try {
    await openConfiguration(user, runtime);
    viewerFixture('add');
    const preview = page.getByTestId('configuration-source-ui-parity-preview');
    await preview.waitFor({ timeout: 12000 }); await preview.click();
    const roots = page.getByLabel('Source root', { exact: true }); if (await roots.count()) await roots.selectOption('core');
    const exactExecution = await checkExactPreviewExecution({ user, runtime, output });
    await page.getByRole('tab', { name: 'Organizations', exact: true }).click();
    await page.getByRole('cell', { name: 'Demo Bank preview', exact: true }).waitFor();
    await page.getByRole('cell', { name: 'Demo Bank preview', exact: true }).click();
    const group = page.getByTestId('group-card').filter({ has: page.getByText('Deployer preview', { exact: true }) });
    await group.getByTitle('View declared permissions', { exact: true }).click();
    viewerFixture('update');
    await page.getByRole('heading', { name: 'Deployer preview — declared permissions', exact: true }).waitFor({ state: 'hidden', timeout: 12000 });
    // A stable-ID inspector either updates to the new record or closes. It may
    // not keep the old copied object while fresh data is displayed behind it.
    // The native dialog has both its standard X and footer Close controls.
    // Escape closes the current inspection without an ambiguous text selector.
    await page.keyboard.press('Escape');
    await page.getByRole('dialog').last().waitFor({ state: 'hidden' });
    await page.getByTestId('group-card').getByText('Deployer refreshed', { exact: true }).waitFor({ timeout: 12000 });
    await page.screenshot({ path: path.join(output, 'external-update.png'), fullPage: true, animations: 'disabled' });
    viewerFixture('remove');
    await preview.waitFor({ state: 'hidden', timeout: 12000 });
    await page.getByTestId('workspace-source').waitFor({ state: 'hidden', timeout: 12000 });
    assert.equal(await page.getByText('Deployer refreshed', { exact: true }).count(), 0);
    assert.equal(await page.getByRole('dialog').count(), 0);
    viewerFixture('add');
    await preview.waitFor({ timeout: 12000 });
    assert.equal(await page.getByTestId('workspace-source').count(), 0, 'A reappearing folder does not silently change selection');
    const selfAfter = await user.context.request.get(runtime.opsOrigin + '/api/v2/self', { headers: { Authorization: 'Bearer ' + user.access.accessToken } });
    assert.equal(selfAfter.status(), 200); assert.deepEqual((await selfAfter.json()).organizations, rolesBefore, 'Preview data cannot change actual memberships');
    const sourceAfter = await configurationSnapshot(user, runtime);
    assert.deepEqual(sourceAfter.project, sourceBefore.project, 'The current source stays byte-identical');
    passed('external add/update/remove refreshes real tabs and nested views, clears deleted selection, and leaves actual access/current source unchanged');
    return { externalPublisher: 'viewer-fixture', exactExecution, baseSourceUnchanged: true, rolesUnchanged: true, screenshots: output };
  } finally { viewerFixture('remove'); }
}

export async function checkConfigurationViewer({ user, runtime, outputDirectory, passed }) {
  const navigation = await checkAdminNavigation({ user, runtime, outputDirectory, passed });
  const inspection = await checkReadOnlySourceParity({ user, runtime, outputDirectory, passed });
  const refresh = await checkFolderRefresh({ user, runtime, outputDirectory, passed });
  return { navigation, inspection, refresh };
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

export async function checkNativeUIParity({ users, runtime, privateHash, sharedHash, outputDirectory, nodeRPC, rpc, bff, passed }) {
  assert.notEqual(privateHash, sharedHash, 'Private and explicitly shared scenarios require different transactions');
  assert.equal(new Set(['admin', 'deployer', 'reader', 'outsider'].map(name => users.get(name).access.actorId)).size, 4, 'Proof personas must remain different principals');
  const screenshots = path.join(outputDirectory, 'ui-parity'); await mkdir(screenshots, { recursive: true, mode: 0o700 });
  const adminEntry = await checkAdminEntry({ users, runtime, outputDirectory, passed });
  const configurationViewer = await checkConfigurationViewer({ user: users.get('admin'), runtime, outputDirectory, passed });
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
  return { cases, screenshots, isolation, adminEntry, configurationViewer, viewerCounts, transferTypes, clipboard: 'Real rendered CopyButton with a page-local Clipboard API substitute; OS clipboard untouched', limits: ['The unmapped outsider has no organization; a second-organization browser fixture is not claimed.', 'The Admin case recipient already has ordinary emitter authority. The full-case canary check establishes isolation from another principal (Reader), not an otherwise deprived case recipient.', 'Server reorg acquisition/delivery regressions are separate; this browser run does not mutate chain canonicality.'] };
}
