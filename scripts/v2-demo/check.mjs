#!/usr/bin/env node
// Actual public UI/provider + production API walkthrough. No test-control
// routes, manufactured tokens, SQL-seeded identities or fake application node.
import assert from 'node:assert/strict';
import { readFile, writeFile, rename, rm, mkdir } from 'node:fs/promises';
import { createRequire } from 'node:module';
import { spawnSync } from 'node:child_process';
import { createInterface } from 'node:readline/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { demoAccount } from '../../tools/v2-demo-wallet/accounts.mjs';
import { signChallenge } from '../../tools/v2-demo-wallet/sign-message.mjs';
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const directory = path.resolve(process.argv[2] ?? '');
assert.ok(directory.startsWith(path.join(root, '.tmp/v2-demo') + path.sep));
const mode = process.argv[3] ?? 'walkthrough';
assert.ok(['walkthrough', 'reader-admin', 'reader-reader', 'disclosure', 'ui-preview', 'ui-transaction'].includes(mode), 'Unknown demo check mode');
const interactive = process.env.OPS_DEMO_INTERACTIVE === '1';
assert.ok(!interactive || process.stdin.isTTY, 'Run the visible walkthrough in an interactive terminal');
const resultsFile = path.join(directory, mode === 'walkthrough' ? 'check-results.json' : mode === 'ui-preview' ? 'ui-preview-results.json' : mode === 'ui-transaction' ? 'transaction-ui-results.json' : 'mapping-results.json');
await rm(resultsFile, { force: true });
const runtime = JSON.parse(await readFile(path.join(directory, 'runtime.json'), 'utf8'));
assert.equal(runtime.testOnly, true); assert.equal(runtime.chainId, '31337');
for (const key of ['opsOrigin', 'explorerOrigin', 'walletOrigin']) {
  const u = new URL(runtime[key]); assert.equal(u.protocol, 'https:'); assert.equal(u.hostname, 'localhost'); assert.equal(u.origin, runtime[key]);
}
assert.match(runtime.targetContract, /^0x[0-9a-f]{40}$/);
const metadata = JSON.parse(await readFile(path.join(directory, 'wallet-metadata.json'), 'utf8'));
const contract = JSON.parse(await readFile(path.join(root, 'scripts/v2-demo/contract.json'), 'utf8'));
const require = createRequire(path.join(root, 'e2e/playwright/package.json'));
const { chromium } = require('@playwright/test');
const walletRequire = createRequire(path.join(root, 'tools/v2-test-wallet/package.json'));
const { Interface, keccak256, zeroPadValue } = walletRequire('ethers');
const abi = new Interface(contract.abi);
let stage = 'browser-start', count = 0;
const passed = label => { count++; console.log('PASS ' + label); };
const browser = await chromium.launch({ channel: process.env.OPS_TEST_BROWSER_CHANNEL ?? 'chrome', headless: !interactive, slowMo: interactive ? 150 : 0, args: ['--no-proxy-server'] });
const contexts = [], users = new Map(), failedReads = [];
let readerRevoked = false;
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
async function boundedWait(work, seconds, label) {
  const until = Date.now() + seconds * 1000;
  do { const value = await work(); if (value) return value; await sleep(500); } while (Date.now() < until);
  throw Error('Timed out: ' + label);
}
async function json(response, status = 200) {
  assert.equal(response.status(), status, 'HTTP status at ' + stage);
  assert.ok((await response.body()).length <= 8 << 20);
  return response.json();
}
async function login(persona, options = {}) {
  stage = 'login-' + persona;
  const context = await browser.newContext({ ignoreHTTPSErrors: true }); // This isolated demo's generated certificate only.
  contexts.push(context);
  const page = await context.newPage();
  page.on('response', response => { const url = new URL(response.url()); if (url.origin === runtime.explorerOrigin && url.pathname.startsWith('/api/') && response.status() >= 400 && failedReads.length < 200) failedReads.push({ persona, path: url.pathname, status: response.status() }); });
  if (options.clock) await page.clock.install({ time: new Date() });
  stage = persona + '-open-explorer';
  await page.goto(runtime.explorerOrigin);
  stage = persona + '-start-SSO';
  await page.getByRole('button', { name: 'Sign in', exact: true }).click();
  stage = persona + '-select-native-profile';
  await page.locator('[data-profile-id="demo-privado"]').waitFor({ state: 'attached' });
  if (await page.getByTestId('manual-wallet-login').count()) await page.getByText('Use a wallet manually', { exact: true }).click();
  await page.locator('[data-profile-id="demo-privado"]').click();
  const request = page.locator('[data-field=requestUri]'); await request.waitFor({ state: 'attached' });
  const requestUri = await request.textContent();
  assert.ok(requestUri.startsWith(runtime.opsOrigin + '/api/v2/auth/privado/requests/'));
  if (options.capture) await uiScreenshot(page, 'ops-proof-request');
  stage = persona + '-submit-public-proof-job';
  const job = await json(await context.request.post(runtime.walletOrigin + '/prove', { headers: { Origin: runtime.walletOrigin, 'Content-Type': 'application/json' }, data: { persona, requestUri } }), 202);
  await boundedWait(async () => {
    const status = await json(await context.request.get(runtime.walletOrigin + '/jobs/' + job.id));
    assert.notEqual(status.status, 'failed', 'real proof job failed');
    return status.status === 'submitted';
  }, 120, 'real role proof');
  stage = persona + '-display-verified-holder';
  const holder = page.locator('[data-field=holderDid]'); await holder.waitFor({ timeout: 20_000 });
  assert.equal(await holder.textContent(), metadata.personas.find(x => x.id === persona).holderDid);
  assert.equal(await page.locator('[data-field=actorId]').count(), 0);
  if (options.capture) await uiScreenshot(page, 'ops-holder-confirmation');
  const delivered = page.waitForResponse(r => r.url() === runtime.opsOrigin + '/api/v2/auth/privado/complete' && r.request().method() === 'POST');
  stage = persona + '-confirm-native-identity';
  await page.getByRole('button', { name: 'Use this identity', exact: true }).click();
  const access = await json(await delivered);
  assert.equal(access.sourceProfile, metadata.personas.find(x => x.id === persona).profileId); assert.equal(access.provider, 'privado');
  assert.match(access.accessToken, /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/);
  stage = persona + '-explicit-app-handoff';
  await page.getByRole('button', { name: 'Continue to application', exact: true }).waitFor();
  if (options.capture) await uiScreenshot(page, 'ops-application-confirmation');
  await page.getByRole('button', { name: 'Continue to application', exact: true }).click();
  await page.waitForURL(url => url.origin === runtime.explorerOrigin && url.pathname === '/');
  await page.locator('[data-field=app-actor]').waitFor();
  stage = persona + '-verify-app-session';
  const status = await page.evaluate(async () => (await fetch('/api/auth/status', { cache: 'no-store' })).json());
  assert.equal(status.did, access.actorId); assert.ok(status.session_id);
  const cookies = await context.cookies(runtime.explorerOrigin);
  assert.ok(cookies.some(c => c.name.startsWith('__Host-explorer-') && c.secure && c.httpOnly));
  const user = { context, page, access, status };
  users.set(persona, user);
  passed(persona + ': real Privado proof, explicit holder confirmation and production Explorer SSO');
  return user;
}
async function rpc(user, method, params, allowDenied = false) {
  const response = await user.context.request.post(runtime.opsOrigin + '/rpc/' + runtime.organizationId, {
    headers: { Authorization: 'Bearer ' + user.access.accessToken, Origin: runtime.opsOrigin },
    data: { jsonrpc: '2.0', id: 1, method, params }, timeout: 30_000,
  });
  if (allowDenied && response.status() === 403) return { denied: true };
  const result = await json(response);
  if (allowDenied && result.error?.code === -32001) return { denied: true };
  assert.equal(result.error, undefined, 'RPC ' + method + ' failed at ' + stage);
  return result.result;
}
async function nodeRPC(user, method, params) {
  const r = await user.context.request.post(runtime.rpcUrl, { data: { jsonrpc: '2.0', id: 1, method, params } });
  const result = await json(r); assert.equal(result.error, undefined); return result.result;
}
async function link(persona) {
  stage = 'wallet-link-' + persona;
  const user = users.get(persona), address = demoAccount(persona).address.toLowerCase();
  const headers = { Authorization: 'Bearer ' + user.access.accessToken, Origin: runtime.opsOrigin };
  const own = await json(await user.context.request.get(runtime.opsOrigin + '/api/v2/eth/addresses', { headers }));
  assert.ok(Array.isArray(own));
  if (!own.some(x => x.address === address)) {
    const challenge = await json(await user.context.request.post(runtime.opsOrigin + '/api/v2/eth/link/challenge', { headers, data: { address } }));
    const signature = await signChallenge(persona, challenge.message, runtime.opsOrigin);
    const linked = await json(await user.context.request.post(runtime.opsOrigin + '/api/v2/eth/link/verify', { headers, data: { address, nonce: challenge.nonce, signature: signature.signature } }));
    assert.equal(linked.address, address);
  }
  const verified = await json(await user.context.request.get(runtime.opsOrigin + '/api/v2/eth/addresses', { headers }));
  assert.ok(verified.some(x => x.address === address));
  passed(persona + ': wallet ownership linked by a signed native challenge (or retained verified link)');
}
async function bff(user, target) {
  return user.page.evaluate(async ({ target, activation }) => {
    const r = await fetch('/api/v2/explorer' + target, { headers: { 'X-OPS-App-Session': activation }, cache: 'no-store' });
    return { status: r.status, value: await r.json() };
  }, { target, activation: user.status.session_id });
}
function demoCommand(args, label) {
  const result = spawnSync(path.join(root, 'scripts/v2-demo.sh'), args, { env: process.env, encoding: 'utf8', timeout: 120_000, maxBuffer: 1 << 20 });
  assert.equal(result.status, 0, label);
}
async function checkDisclosure(admin, deployer, reader, hash) {
  stage = 'disclosure-open-form';
  await admin.page.goto(runtime.explorerOrigin + '/disclosures');
  await admin.page.getByText('Open a disclosure case', { exact: true }).click();
  await admin.page.getByLabel('Approved rule ID', { exact: true }).fill('demo-auditor');
  await admin.page.getByLabel('Client actor IDs', { exact: true }).fill(deployer.access.actorId);
  const reference = 'DEMO-' + Date.now();
  await admin.page.getByLabel('Case reference', { exact: true }).fill(reference);
  await admin.page.getByLabel('Purpose', { exact: true }).fill('Inspect the demo contract transaction');
  await admin.page.getByLabel('Legal basis', { exact: true }).fill('Isolated local demo; not a legal compliance assertion');
  const localDate = seconds => { const d = new Date(seconds * 1000); return new Date(d.getTime() - d.getTimezoneOffset() * 60000).toISOString().slice(0, 16); };
  const now = Math.floor(Date.now() / 1000);
  // A retained dev chain can have a timestamp ahead of the host clock. Select
  // the actual sample's data interval instead of silently excluding it.
  const transaction = await nodeRPC(admin, 'eth_getTransactionByHash', [hash]);
  const block = await nodeRPC(admin, 'eth_getBlockByNumber', [transaction.blockNumber, false]);
  const sampleTime = Number(BigInt(block.timestamp));
  await admin.page.getByLabel('From (local time)', { exact: true }).fill(localDate(Math.min(now, sampleTime) - 3600));
  await admin.page.getByLabel('Through (local time)', { exact: true }).fill(localDate(Math.max(now, sampleTime) + 120));
  for (const label of ['Addresses', 'Activity', 'Activity summary', 'Sanctions', 'Compliance']) await admin.page.getByLabel(label, { exact: true }).uncheck();
  await admin.page.getByLabel('Events', { exact: true }).check();
  await admin.page.getByLabel('Detail level').selectOption('full');
  stage = 'disclosure-create-case';
  await admin.page.getByRole('button', { name: 'Open case', exact: true }).click();
  await admin.page.getByRole('heading', { name: reference, exact: true }).waitFor();
  const caseUrl = admin.page.url();
  stage = 'disclosure-read-transactions';
  const readResponse = admin.page.waitForResponse(r => r.request().method() === 'POST' && new URL(r.url()).pathname.endsWith('/disclosure/cases/' + new URL(caseUrl).pathname.split('/').at(-1) + '/read'));
  await admin.page.getByRole('button', { name: 'Transactions', exact: true }).click();
  let read = await readResponse;
  const seen = new Set(), cursors = new Set();
  for (let page = 1; ; page++) {
    const protectedData = await read.json();
    console.log('Disclosure transaction page ' + page + ': HTTP ' + read.status() + ', rows=' + (protectedData.result?.items?.length ?? 'unavailable'));
    if (read.status() !== 200) await writeFile(path.join(directory, 'failed-disclosure-read.json'), JSON.stringify({ status: read.status(), error: typeof protectedData.error === 'string' ? protectedData.error.slice(0, 160) : 'unavailable' }, null, 2) + '\n', { mode: 0o600 });
    assert.equal(read.status(), 200);
    for (const row of protectedData.result.items) {
      assert.equal(seen.has(row.transactionHash), false, 'Disclosure repeated a transaction between pages');
      seen.add(row.transactionHash);
    }
    if (seen.has(hash)) break;
    const cursor = protectedData.result.nextCursor;
    assert.ok(cursor && !cursors.has(cursor) && page < 32, 'Disclosure continuation ended or repeated before the sample transaction');
    cursors.add(cursor);
    const nextRead = admin.page.waitForResponse(r => r.request().method() === 'POST' && new URL(r.url()).pathname.endsWith('/disclosure/cases/' + new URL(caseUrl).pathname.split('/').at(-1) + '/read'));
    await admin.page.getByRole('button', { name: 'Next page', exact: true }).click();
    read = await nextRead;
  }
  await admin.page.locator('a[href$="/transactions/' + hash + '"]').first().waitFor({ timeout: 30_000 });
  assert.equal(await admin.page.getByRole('alert').count(), 0);
  stage = 'disclosure-read-events';
  const caseId = new URL(caseUrl).pathname.split('/').at(-1);
  const eventsResponse = admin.page.waitForResponse(r => r.request().method() === 'POST' && new URL(r.url()).pathname.endsWith('/disclosure/cases/' + caseId + '/read'));
  await admin.page.getByRole('button', { name: 'Events', exact: true }).click();
  let eventsRead = await eventsResponse, foundEvent = false;
  const eventIds = new Set(), eventCursors = new Set();
  for (let page = 0; page < 32; page++) {
    assert.equal(eventsRead.status(), 200, 'Case Events read must succeed');
    const value = await eventsRead.json();
    assert.equal(value.result.v, 1); assert.equal(value.result.population, 'EVENTS_FROM_DISCLOSED_TRANSACTIONS');
    for (const event of value.result.items) {
      assert.ok(!eventIds.has(event.eventId), 'Case Events pagination repeated a log'); eventIds.add(event.eventId);
      assert.equal(event.payload, 'disclosed'); assert.ok(Array.isArray(event.topics)); assert.match(event.data, /^0x(?:[0-9a-f]{2})*$/);
      if (event.transactionHash === hash) { assert.equal(event.emitter, runtime.targetContract); foundEvent = true; }
    }
    if (foundEvent || !value.result.nextCursor) break;
    assert.ok(!eventCursors.has(value.result.nextCursor)); eventCursors.add(value.result.nextCursor);
    const next = admin.page.waitForResponse(r => r.request().method() === 'POST' && new URL(r.url()).pathname.endsWith('/disclosure/cases/' + caseId + '/read'));
    await admin.page.getByRole('button', { name: value.result.items.length ? 'Next page' : 'Continue', exact: true }).click(); eventsRead = await next;
  }
  assert.ok(foundEvent, 'Case Events must include the actual sample contract log');
  await admin.page.getByText('Raw payload', { exact: true }).first().click();
  await admin.page.getByRole('button', { name: 'Download this page', exact: true }).waitFor();
  assert.equal(await admin.page.getByRole('alert').count(), 0);
  stage = 'disclosure-reader-denied';
  const deniedCase = reader.page.waitForResponse(r => r.request().method() === 'GET' && new URL(r.url()).pathname.endsWith('/disclosure/cases/' + caseId));
  await reader.page.goto(caseUrl);
  assert.equal((await deniedCase).status(), 404, 'Another recipient case must be unavailable, with a valid reader session');
  await reader.page.getByRole('alert').waitFor();
  assert.equal(await reader.page.locator('a[href$="/transactions/' + hash + '"]').count(), 0);
  assert.equal((await bff(reader, '/transactions/' + hash)).status, 200);
  passed('admin opens a standing-rule disclosure and reads its transaction and contract event without customer approval; reader cannot use the case');
  return caseUrl;
}
async function uiScreenshot(page, name) {
  const screenshots = path.join(directory, 'ui-preview');
  await mkdir(screenshots, { recursive: true, mode: 0o700 });
  await page.evaluate(() => window.scrollTo(0, 0));
  await page.screenshot({ path: path.join(screenshots, name + '.png'), fullPage: true, animations: 'disabled' });
}
async function checkEntryScreens() {
  stage = 'ui-preview-anonymous-explorer';
  const context = await browser.newContext({ ignoreHTTPSErrors: true });
  contexts.push(context);
  const page = await context.newPage();
  await page.setViewportSize({ width: 1440, height: 1040 });
  const privateReads = [];
  context.on('request', request => {
    const u = new URL(request.url());
    if (u.origin === runtime.explorerOrigin && /^\/api\/(?:v2\/explorer(?:\/|$)|eth\/|disclosure\/|grant\/|viewable-addresses)/.test(u.pathname)) privateReads.push(u.pathname);
  });
  await page.goto(runtime.explorerOrigin);
  await page.locator('[data-testid=explorer-auth-entry][data-auth-state=anonymous]').waitFor();
  assert.equal(await page.getByRole('alert').count(), 0);
  assert.equal(await page.getByText('Genesis hash', { exact: true }).count(), 0);
  assert.equal(await page.getByRole('heading', { name: 'Latest Transactions', exact: true }).count(), 0);
  assert.ok((await page.getByTestId('entry-sign-in').getAttribute('class')).includes('btn-primary'));
  await uiScreenshot(page, 'explorer-signed-out');
  // Start mobile capture at its real viewport. Resizing a previously painted
  // desktop page can produce a stitched full-page screenshot in headless Chrome.
  const mobilePage = await context.newPage();
  await mobilePage.setViewportSize({ width: 390, height: 844 });
  await mobilePage.goto(runtime.explorerOrigin);
  await mobilePage.locator('[data-testid=explorer-auth-entry][data-auth-state=anonymous]').waitFor();
  assert.equal(await mobilePage.locator('header').count(), 1);
  assert.equal(await mobilePage.getByTestId('explorer-auth-entry').count(), 1);
  assert.equal(await mobilePage.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true);
  await uiScreenshot(mobilePage, 'explorer-signed-out-mobile');
  stage = 'ui-preview-public-network';
  await page.goto(runtime.explorerOrigin + '/chain-info');
  await page.getByRole('heading', { name: 'Network setup', exact: true }).waitFor();
  await page.getByText('31337 (0x7a69)', { exact: true }).waitFor();
  assert.deepEqual(privateReads, [], 'Anonymous entry/public setup must not dispatch protected reads');
  await uiScreenshot(page, 'explorer-network-setup');
  passed('fresh Explorer entry uses the V1 prompt; public network setup dispatches no protected reads');
  stage = 'ui-preview-anonymous-ops';
  const opsContext = await browser.newContext({ ignoreHTTPSErrors: true });
  contexts.push(opsContext);
  const opsPage = await opsContext.newPage();
  await opsPage.setViewportSize({ width: 1440, height: 1040 });
  await opsPage.goto(runtime.opsOrigin + '/login');
  await opsPage.getByTestId('demo-persona-admin').waitFor();
  assert.equal(await opsPage.getByRole('alert').count(), 0, 'A fresh signed-out visit is not a failed login');
  assert.equal(await opsPage.getByRole('heading', { name: /^Sign in$/i }).count(), 1);
  await uiScreenshot(opsPage, 'ops-signed-out');
  await opsPage.reload();
  await opsPage.getByTestId('demo-persona-admin').waitFor();
  assert.equal(await opsPage.getByRole('alert').count(), 0, 'A repeated ordinary visit must remain a normal sign-in state');
  const opsMobilePage = await opsContext.newPage();
  await opsMobilePage.setViewportSize({ width: 390, height: 844 });
  await opsMobilePage.goto(runtime.opsOrigin + '/login');
  await opsMobilePage.getByTestId('demo-persona-admin').waitFor();
  assert.equal(await opsMobilePage.getByTestId('login-header').count(), 1);
  assert.equal(await opsMobilePage.getByTestId('auth-card').count(), 1);
  assert.equal(await opsMobilePage.getByRole('alert').count(), 0);
  assert.equal(await opsMobilePage.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true);
  await uiScreenshot(opsMobilePage, 'ops-signed-out-mobile');
  passed('fresh and repeated OPS login visits use the V1 login presentation without a false error');
}
async function checkUIPreview(user) {
  const previous = JSON.parse(await readFile(path.join(directory, 'check-state.json'), 'utf8'));
  assert.match(previous.lastTransaction ?? '', /^0x[0-9a-f]{64}$/);
  const screenshots = path.join(directory, 'ui-preview');
  await mkdir(screenshots, { recursive: true, mode: 0o700 });
  const { page, context } = user;
  await page.setViewportSize({ width: 1440, height: 1040 });
  async function screenshot(name) {
    await uiScreenshot(page, name);
  }
  stage = 'ui-preview-home';
  await page.goto(runtime.explorerOrigin);
  await page.getByRole('heading', { name: 'Latest Transactions', exact: true }).waitFor();
  await page.getByTestId('header-brand').waitFor();
  await page.getByTestId('block-row').first().waitFor();
  await screenshot('explorer-home');
  stage = 'ui-preview-transaction';
  await page.goto(runtime.explorerOrigin + '/tx/' + previous.lastTransaction);
  await page.locator('[data-testid=info-row][data-label="Transaction Hash"]').getByText(previous.lastTransaction, { exact: true }).waitFor();
  await page.getByTestId('tx-status').filter({ hasText: 'Success' }).waitFor();
  await screenshot('explorer-transaction');
  await page.getByTestId('tab-logs').click();
  await page.getByText(abi.getEvent('Changed').topicHash, { exact: true }).first().waitFor();
  await screenshot('explorer-transaction-logs');
  stage = 'ui-preview-address';
  await page.goto(runtime.explorerOrigin + '/address/' + runtime.targetContract);
  await page.getByTestId('tab-transactions').waitFor();
  await page.getByTestId('tab-logs').click();
  await page.getByText(abi.getEvent('Changed').topicHash, { exact: true }).first().waitFor();
  await screenshot('explorer-address');
  passed('original Explorer home, transaction and address presentations render real indexed data');
  stage = 'ui-preview-admin';
  await page.goto(runtime.opsOrigin + '/admin');
  // A full document reload may require another real Privado proof. Complete
  // that ordinary renewal; never inject a bearer or a manufactured browser state.
  await page.locator('[data-testid=rbac-title], [data-field=requestUri], a[href="/admin/rbac/organizations"]').first().waitFor({ state: 'attached' });
  if (await page.locator('[data-field=requestUri]').count()) {
    const requestUri = await page.locator('[data-field=requestUri]').textContent();
    assert.ok(requestUri.startsWith(runtime.opsOrigin + '/api/v2/auth/privado/requests/'));
    await screenshot('ops-renewal-proof-request');
    const job = await json(await context.request.post(runtime.walletOrigin + '/prove', { headers: { Origin: runtime.walletOrigin, 'Content-Type': 'application/json' }, data: { persona: 'admin', requestUri } }), 202);
    await boundedWait(async () => {
      const status = await json(await context.request.get(runtime.walletOrigin + '/jobs/' + job.id));
      assert.notEqual(status.status, 'failed'); return status.status === 'submitted';
    }, 120, 'Admin real renewal proof');
    await page.locator('[data-field=holderDid]').waitFor();
    await screenshot('ops-renewal-holder-confirmation');
    await page.getByRole('button', { name: 'Use this identity', exact: true }).click();
  }
  await page.locator('[data-testid=rbac-title], a[href="/admin/rbac/organizations"]').first().waitFor();
  if (!await page.getByTestId('rbac-title').count()) await page.getByRole('link', { name: 'Open configuration workspace', exact: true }).click();
  await page.getByTestId('rbac-title').waitFor();
  stage = 'ui-preview-import-source';
  const source = path.resolve(process.env.OPS_DEMO_SOURCE_DIR ?? path.join(root, '.tmp/v2-demo/ui-recovery-source/core'));
  assert.ok(source.startsWith(path.join(root, '.tmp/v2-demo') + path.sep));
  await page.getByLabel('Policy source folder', { exact: true }).setInputFiles(source);
  await page.getByTestId('workspace-source').waitFor();
  await page.getByRole('cell', { name: 'Demo Bank', exact: true }).waitFor();
  await screenshot('admin-organizations');
  await page.getByRole('cell', { name: 'Demo Bank', exact: true }).click();
  await page.getByTestId('tab-groups').click();
  assert.equal(await page.getByTestId('tab-groups').getAttribute('aria-selected'), 'true');
  for (const group of ['Admin', 'Deployer', 'Reader']) await page.getByTestId('group-card').getByText(group, { exact: true }).waitFor();
  await screenshot('admin-groups');
  assert.equal(await page.getByRole('alert').count(), 0);
  passed('original Admin shell displays imported Demo Bank organizations and groups without SQL policy CRUD');
  stage = 'ui-preview-selected-core';
  const selectionResponse = page.waitForResponse(response => new URL(response.url()).pathname === '/api/v2/self/selection');
  await page.getByRole('button', { name: 'Check this OPS instance', exact: true }).click();
  const selection = await json(await selectionResponse);
  assert.match(selection.manifestDigest, /^sha256:[0-9a-f]{64}$/);
  assert.equal(selection.chainId, runtime.chainId);
  await page.getByText('Selected revision:', { exact: false }).waitFor();
  await screenshot('admin-selected-core');
  passed('Admin checks the actual selected Core artifact separately from local source');
  stage = 'ui-preview-admin-access-logs';
  const logsResponse = page.waitForResponse(response => new URL(response.url()).pathname.endsWith('/access-logs'));
  await page.getByRole('tab', { name: 'Access Logs', exact: true }).click();
  const logs = await logsResponse;
  const logPage = await json(logs);
  assert.match(logs.headers()['x-ops-request-reference'] ?? '', /^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/);
  assert.ok(Array.isArray(logPage.items) && logPage.items.length <= 50);
  assert.equal(logPage.source.coverage, 'committed-sealed-prefix');
  await page.getByText('Sealed records only', { exact: false }).waitFor();
  const recordedActor = logPage.items.find(item => item.actorId)?.actorId;
  assert.ok(recordedActor, 'The owned demo must contain an attributed request');
  const actorCode = page.locator('table code[title]').filter({ hasText: recordedActor }).first();
  const actorLayout = await actorCode.evaluate(element => ({ title: element.title, whiteSpace: getComputedStyle(element).whiteSpace, width: element.getBoundingClientRect().width, rowHeight: element.closest('tr').getBoundingClientRect().height }));
  assert.equal(actorLayout.title, recordedActor, 'Full actor ID remains available');
  assert.equal(actorLayout.whiteSpace, 'nowrap');
  assert.ok(actorLayout.width >= 100 && actorLayout.rowHeight <= 128, 'Identifier wrapping must not create oversized access-log rows');
  await screenshot('admin-access-logs');
  passed('Admin reads organization Access Logs without a disclosure case, with a durable request reference');
  stage = 'ui-preview-admin-finance';
  const casesResponse = page.waitForResponse(response => new URL(response.url()).pathname === '/api/v1/disclosure/cases' && response.request().method() === 'GET');
  await page.getByRole('tab', { name: 'Disclosure', exact: true }).click();
  const existingCases = await json(await casesResponse);
  const expiredOpen = existingCases.items.find(item => item.status === 'open' && item.expiresAt * 1000 <= Date.now() && item.caseReference.startsWith('UI-FINANCE-'));
  if (expiredOpen) await page.getByRole('row').filter({ has: page.getByRole('cell', { name: expiredOpen.caseReference, exact: true }) }).first().getByText('Expired', { exact: true }).waitFor();
  await page.getByRole('button', { name: 'Create case', exact: true }).click();
  const form = page.getByRole('dialog');
  for (const [label, value] of [
    ['Standing rule ID', 'demo-auditor'],
    ['Case reference', 'UI-FINANCE-' + Date.now()],
    ['Purpose', 'Check native admission evidence'],
    ['Legal basis', 'Isolated functional demo'],
    ['Target OPS actor IDs', user.access.actorId],
  ]) await form.getByLabel(label, { exact: true }).fill(value);
  await form.getByRole('checkbox', { name: 'Compliance report', exact: true }).check();
  const caseCreated = page.waitForResponse(response => new URL(response.url()).pathname === '/api/v1/disclosure/cases' && response.request().method() === 'POST');
  await form.getByRole('button', { name: 'Create case', exact: true }).click();
  const created = await caseCreated;
  assert.ok(created.status() >= 200 && created.status() < 300, 'Native case creation must accept the default expiry under the demo rule');
  await page.getByLabel('Data resource', { exact: true }).selectOption('compliance_report');
  const evidenceResponse = page.waitForResponse(response => new URL(response.url()).pathname.endsWith('/read') && response.request().method() === 'POST');
  await page.getByRole('button', { name: 'Read permitted data', exact: true }).click();
  const evidence = await json(await evidenceResponse);
  assert.equal(evidence.view, 'list');
  assert.equal(evidence.resource, 'compliance_report');
  assert.match(evidence.result.matchingRetainedCount, /^(0|[1-9][0-9]*)$/);
  await rm(path.join(directory, 'ui-finance-error.json'), { force: true });
  await writeFile(path.join(directory, 'ui-finance-response.json'), JSON.stringify(evidence, null, 2) + '\n', { mode: 0o600 });
  try {
    await page.getByRole('button', { name: 'Download this page', exact: true }).waitFor({ timeout: 5000 });
  } catch (error) {
    await writeFile(path.join(directory, 'ui-finance-error.json'), JSON.stringify({ alerts: await page.getByRole('alert').allTextContents() }, null, 2) + '\n', { mode: 0o600 });
    throw error;
  }
  const auditResponse = page.waitForResponse(response => new URL(response.url()).pathname === `/api/v1/disclosure/cases/${evidence.caseId}/audit` && response.request().method() === 'GET');
  await page.getByRole('button', { name: 'Audit trail', exact: true }).click();
  const audit = await json(await auditResponse);
  assert.ok(Array.isArray(audit.items));
  const exposure = audit.items.find(item => item.action === 'exposure_prepared' && item.resource === evidence.resource && item.view === evidence.view);
  assert.ok(exposure, 'The current case audit must identify the actual compliance_report/list exposure');
  for (const field of ['queryDigest', 'sourceSetDigest', 'renderDigest', 'outputDigest', 'outputBytes']) assert.equal(Object.hasOwn(exposure, field), false, 'Private exposure receipt field must not enter the audit projection: ' + field);
  const auditRow = page.getByRole('row').filter({ hasText: 'exposure_prepared' }).filter({ hasText: 'Compliance report' }).first();
  await auditRow.getByRole('cell', { name: 'Compliance report', exact: true }).waitFor();
  await auditRow.getByRole('cell', { name: 'List', exact: true }).waitFor();
  await screenshot('admin-finance-evidence');
  passed('Admin creates a case, reads scoped admission evidence and checks its recorded resource/view in the case audit');
  await page.getByRole('dialog', { name: 'Disclosure case details', exact: true }).getByRole('button', { name: 'Close', exact: true }).click();
  stage = 'ui-preview-account';
  await page.getByTestId('account-dropdown-trigger').click();
  await page.getByRole('menuitem', { name: 'Account', exact: true }).click();
  await page.getByTestId('account-page').waitFor();
  for (const card of ['identity', 'session', 'organizations', 'wallets']) await page.getByTestId('account-' + card).waitFor();
  await page.locator('[data-field=actorId]').waitFor();
  assert.equal(await page.locator('[data-field=actorId]').textContent(), user.access.actorId);
  await page.getByTestId('linked-address').filter({ hasText: demoAccount('admin').address.toLowerCase() }).waitFor();
  assert.equal(await page.getByRole('button', { name: /Forget remembered app|Cancel wallet operation/ }).count(), 0);
  await screenshot('admin-account');
  passed('actual V1 account cards display the verified identity and own linked wallet without irrelevant controls');
  stage = 'ui-preview-client-account-expiry';
  const expiry = Date.parse(await page.locator('time[data-field=sessionExpiresAt]').getAttribute('datetime'));
  assert.ok(Number.isFinite(expiry));
  await page.clock.fastForward(Math.max(1, expiry - await page.evaluate(() => Date.now()) + 1000));
  await page.getByTestId('login-page').waitFor();
  assert.equal(await page.getByTestId('account-page').count(), 0);
  assert.equal(await page.locator('[data-field=actorId]').count(), 0);
  await screenshot('ops-session-ended');
  stage = 'ui-preview-client-explorer-expiry';
  const expiredPage = await context.newPage();
  await expiredPage.clock.install({ time: new Date() });
  await expiredPage.setViewportSize({ width: 1440, height: 1040 });
  await expiredPage.goto(runtime.explorerOrigin);
  await expiredPage.locator('[data-field=app-actor]').waitFor();
  const status = await expiredPage.evaluate(async () => (await fetch('/api/auth/status', { cache: 'no-store' })).json());
  assert.equal(status.authenticated, true);
  let readsAfterExpiry = 0;
  expiredPage.on('request', request => { if (new URL(request.url()).pathname.startsWith('/api/v2/explorer/')) readsAfterExpiry++; });
  await expiredPage.clock.fastForward(Math.max(1, status.expires_at * 1000 - await expiredPage.evaluate(() => Date.now()) + 1000));
  await expiredPage.locator('[data-testid=explorer-auth-entry][data-auth-state=expired]').waitFor();
  assert.equal(await expiredPage.locator('[data-field=app-actor]').count(), 0);
  assert.equal(readsAfterExpiry, 0, 'Client expiry must stop protected read dispatch');
  await uiScreenshot(expiredPage, 'explorer-session-expired');
  passed('advancing browser clocks past original signed expiry clears private OPS/Explorer displays');
  await writeFile(resultsFile, JSON.stringify({ passed: true, cases: count, scope: 'Stage 2 UI preview, not complete product parity', screenshots, transaction: previous.lastTransaction, importedSource: source }, null, 2) + '\n', { mode: 0o600 });
}
try {
  await (async () => {
  if (mode === 'ui-preview') { await checkEntryScreens(); await checkUIPreview(await login('admin', { clock: true, capture: true })); return; }
  if (mode === 'ui-transaction') {
    const user = await login('deployer');
    const saved = JSON.parse(await readFile(path.join(directory, 'check-state.json'), 'utf8'));
    const responses = [];
    user.page.on('response', response => { const url = new URL(response.url()); if (url.origin === runtime.explorerOrigin && url.pathname.startsWith('/api/')) responses.push({ path: url.pathname, status: response.status() }); });
    stage = 'transaction-ui-read';
    const transfers = user.page.waitForResponse(r => r.url().includes(saved.lastTransaction + '/transfers'), { timeout: 30_000 });
    await user.page.goto(runtime.explorerOrigin + '/transactions/' + saved.lastTransaction);
    await user.page.locator('[data-testid=info-row][data-label="Transaction Hash"]').getByText(saved.lastTransaction, { exact: true }).waitFor();
    await transfers; await sleep(250);
    const alerts = await user.page.getByRole('alert').allTextContents();
    await writeFile(resultsFile, JSON.stringify({ passed: alerts.length === 0, alerts, responses }, null, 2) + '\n', { mode: 0o600 });
    await user.page.screenshot({ path: path.join(directory, 'transaction-ui.png'), fullPage: true });
    assert.equal(alerts.length, 0); passed('actual transaction page and transfers complete without a read error'); return;
  }
  if (mode === 'disclosure') {
    for (const persona of ['admin', 'deployer', 'reader']) await login(persona);
    const previous = JSON.parse(await readFile(path.join(directory, 'check-state.json'), 'utf8'));
    const caseUrl = await checkDisclosure(users.get('admin'), users.get('deployer'), users.get('reader'), previous.lastTransaction);
    await writeFile(resultsFile, JSON.stringify({ passed: true, cases: count, disclosureUrl: caseUrl }, null, 2) + '\n', { mode: 0o600 });
    return;
  }
  if (mode !== 'walkthrough') {
    const reader = await login('reader');
    stage = 'mapping-current-admin-flag';
    const self = await json(await reader.context.request.get(runtime.opsOrigin + '/api/v2/self', { headers: { Authorization: 'Bearer ' + reader.access.accessToken } }));
    const isAdmin = mode === 'reader-admin';
    assert.equal(self.organizations.find(org => org.id === runtime.organizationId)?.isOrgAdmin, isAdmin);
    const previous = JSON.parse(await readFile(path.join(directory, 'check-state.json'), 'utf8'));
    assert.match(previous.lastTransaction ?? '', /^0x[0-9a-f]{64}$/);
    stage = 'mapping-retains-address-privacy';
    const logs = await rpc(reader, 'eth_getLogs', [{ address: runtime.targetContract, fromBlock: '0x' + previous.lastBlock.toString(16), toBlock: '0x' + previous.lastBlock.toString(16) }]);
    assert.equal(logs.length, 1);
    assert.equal(logs[0].topics[1].toLowerCase(), '0x' + '0'.repeat(64));
    const view = await bff(reader, '/transactions/' + previous.lastTransaction);
    assert.equal(view.status, 200);
    if (isAdmin) assert.equal(view.value.hash, previous.lastTransaction);
    else assert.equal(view.value, null);
    passed('unchanged Reader credential maps to ' + (isAdmin ? 'organization Admin' : 'Reader') + '; address privacy remains enforced');
    const signer = demoAccount('reader');
    const nonce = Number(BigInt(await nodeRPC(reader, 'eth_getTransactionCount', [signer.address, 'pending'])));
    const signed = await signer.signTransaction({ type: 2, chainId: 31337, nonce, gasLimit: 200_000, maxFeePerGas: 2_000_000_000, maxPriorityFeePerGas: 1_000_000_000, to: runtime.targetContract, data: abi.encodeFunctionData('set', [demoAccount('admin').address.toLowerCase(), 171]) });
    if (isAdmin) {
      stage = 'mapping-admin-signed-call';
      const hash = keccak256(signed);
      assert.equal(await rpc(reader, 'eth_sendRawTransaction', [signed]), hash);
      const receipt = await boundedWait(() => nodeRPC(reader, 'eth_getTransactionReceipt', [hash]), 60, 'mapped Admin signed call');
      assert.equal(receipt.status, '0x1');
      passed('mapped Admin can submit an allowed signed contract call through OPS');
    } else {
      stage = 'mapping-reader-write-denied';
      assert.equal((await rpc(reader, 'eth_sendRawTransaction', [signed], true)).denied, true);
      assert.equal(Number(BigInt(await nodeRPC(reader, 'eth_getTransactionCount', [signer.address, 'pending']))), nonce);
      passed('restored Reader cannot submit the signed call; chain nonce unchanged');
    }
    await writeFile(resultsFile, JSON.stringify({ passed: true, cases: count, expectedGroup: isAdmin ? 'Admin' : 'Reader', transaction: previous.lastTransaction }, null, 2) + '\n', { mode: 0o600 });
    console.log('Transaction: ' + runtime.explorerOrigin + '/transactions/' + previous.lastTransaction);
    return;
  }
  for (const persona of ['admin', 'deployer', 'reader', 'outsider']) await login(persona);
  await link('admin'); await link('deployer'); await link('reader');
  const deployer = users.get('deployer'), admin = users.get('admin'), reader = users.get('reader');
  const signer = demoAccount('deployer'), subject = demoAccount('admin').address.toLowerCase();
  stage = 'node-owned-signing-disabled';
  const unsigned = await json(await deployer.context.request.post(runtime.opsOrigin + '/rpc/' + runtime.organizationId, {
    headers: { Authorization: 'Bearer ' + deployer.access.accessToken, Origin: runtime.opsOrigin },
    data: { jsonrpc: '2.0', id: 1, method: 'eth_sendTransaction', params: [{ from: signer.address, to: subject, value: '0x0' }] },
  }));
  assert.equal(unsigned.error?.code, -32601); assert.equal(unsigned.result, undefined);
  passed('signed-transaction capability does not enable node-owned unsigned transaction signing');
  stage = 'actual-contract-deployment';
  const stateFile = path.join(directory, 'check-state.json');
  let previous = {};
  try { previous = JSON.parse(await readFile(stateFile, 'utf8')); } catch (e) { if (e.code !== 'ENOENT') throw e; }
  const save = async value => { const temp = stateFile + '.next'; await writeFile(temp, JSON.stringify(value, null, 2) + '\n', { mode: 0o600 }); await rename(temp, stateFile); };
  const code = await nodeRPC(deployer, 'eth_getCode', [runtime.targetContract, 'latest']);
  if (code === '0x') {
    assert.equal(BigInt(await nodeRPC(deployer, 'eth_getTransactionCount', [signer.address, 'latest'])), 0n, 'Fresh configured deployment address requires nonce zero');
    const signed = await signer.signTransaction({ type: 2, chainId: 31337, nonce: 0, gasLimit: 1_000_000, maxFeePerGas: 2_000_000_000, maxPriorityFeePerGas: 1_000_000_000, data: contract.bytecode });
    previous.deploymentHash = keccak256(signed); await save(previous);
    assert.equal(await rpc(deployer, 'eth_sendRawTransaction', [signed]), previous.deploymentHash);
  }
  assert.match(previous.deploymentHash ?? '', /^0x[0-9a-f]{64}$/);
  const deployment = await boundedWait(() => nodeRPC(deployer, 'eth_getTransactionReceipt', [previous.deploymentHash]), 60, 'real deployment receipt');
  assert.equal(deployment.status, '0x1'); assert.equal(deployment.contractAddress.toLowerCase(), runtime.targetContract);
  const deployedTransaction = await nodeRPC(deployer, 'eth_getTransactionByHash', [previous.deploymentHash]);
  assert.equal(deployedTransaction.from.toLowerCase(), signer.address.toLowerCase());
  assert.equal(deployedTransaction.to, null); assert.equal(deployedTransaction.input, contract.bytecode);
  assert.notEqual(await nodeRPC(deployer, 'eth_getCode', [runtime.targetContract, 'latest']), '0x');
  passed('application contract deployed through native OPS: real receipt and nonempty Reth runtime');
  stage = 'real-contract-call';
  const nonce = Number(BigInt(await nodeRPC(deployer, 'eth_getTransactionCount', [signer.address, 'pending'])));
  const call = await signer.signTransaction({ type: 2, chainId: 31337, nonce, gasLimit: 200_000, maxFeePerGas: 2_000_000_000, maxPriorityFeePerGas: 1_000_000_000, to: runtime.targetContract, data: abi.encodeFunctionData('set', [subject, 171]) });
  const hash = keccak256(call); assert.equal(await rpc(deployer, 'eth_sendRawTransaction', [call]), hash);
  const receipt = await boundedWait(() => nodeRPC(deployer, 'eth_getTransactionReceipt', [hash]), 60, 'real call receipt');
  assert.equal(receipt.status, '0x1'); assert.ok(receipt.logs.length === 1);
  previous.lastTransaction = hash; previous.lastBlock = Number(BigInt(receipt.blockNumber)); await save(previous);
  stage = 'actual-source-barriers';
  demoCommand(['barrier', hash, String(previous.lastBlock), runtime.targetContract], 'Actual observer/indexer barrier failed');
  passed('real indexer and creation observer caught up to the OPS transaction');
  stage = 'current-rights-privacy-comparison';
  const filter = { address: runtime.targetContract, fromBlock: receipt.blockNumber, toBlock: receipt.blockNumber };
  const full = await rpc(admin, 'eth_getLogs', [filter]); assert.equal(full.length, 1);
  assert.equal(full[0].topics[1].toLowerCase(), zeroPadValue(subject, 32));
  const masked = await rpc(reader, 'eth_getLogs', [filter]); assert.equal(masked.length, 1);
  assert.equal(masked[0].topics[1], '0x' + '0'.repeat(64)); assert.equal(masked[0].data, full[0].data);
  const value = await rpc(reader, 'eth_call', [{ to: runtime.targetContract, data: abi.encodeFunctionData('value') }, 'latest']);
  assert.equal(abi.decodeFunctionResult('value', value)[0], 171n);
  assert.equal(await rpc(reader, 'eth_getTransactionByHash', [hash]), null);
  assert.equal((await rpc(deployer, 'eth_getTransactionByHash', [hash])).hash, hash);
  const denied = await rpc(users.get('outsider'), 'eth_getLogs', [filter], true); assert.equal(denied.denied, true);
  passed('admin full event subject, reader masked subject + hidden transaction, deployer own transaction, outsider denied');
  stage = 'reader-write-denied';
  const readerSigner = demoAccount('reader');
  const readerNonce = await nodeRPC(reader, 'eth_getTransactionCount', [readerSigner.address, 'pending']);
  const forbiddenCall = await readerSigner.signTransaction({ type: 2, chainId: 31337, nonce: Number(BigInt(readerNonce)), gasLimit: 200_000, maxFeePerGas: 2_000_000_000, maxPriorityFeePerGas: 1_000_000_000, to: runtime.targetContract, data: abi.encodeFunctionData('set', [subject, 999]) });
  assert.equal((await rpc(reader, 'eth_sendRawTransaction', [forbiddenCall], true)).denied, true);
  assert.equal(await nodeRPC(reader, 'eth_getTransactionCount', [readerSigner.address, 'pending']), readerNonce);
  passed('reader signed write denied before broadcast; its chain nonce is unchanged');
  stage = 'actual-explorer-reads';
  const d = await bff(deployer, '/transactions/' + hash); assert.equal(d.status, 200); assert.equal(d.value.hash, hash);
  const r = await bff(reader, '/transactions/' + hash); assert.equal(r.status, 200); assert.equal(r.value, null);
  const o = await bff(users.get('outsider'), '/transactions/' + hash); assert.equal(o.status, 403);
  await deployer.page.goto(runtime.explorerOrigin + '/transactions/' + hash);
  await deployer.page.locator('[data-testid=info-row][data-label="Transaction Hash"]').getByText(hash, { exact: true }).waitFor();
  assert.equal(await deployer.page.getByRole('alert').count(), 0);
  await reader.page.goto(runtime.explorerOrigin + '/transactions/' + hash);
  await reader.page.getByRole('heading', { name: 'Transaction unavailable', exact: true }).waitFor();
  assert.equal(await reader.page.getByText(hash, { exact: true }).count(), 0);
  passed('actual production Explorer BFF and built UI retain the same restricted views');
  stage = 'explicit-transaction-sharing';
  const shareNonce = Number(BigInt(await nodeRPC(deployer, 'eth_getTransactionCount', [signer.address, 'pending'])));
  const sharedSigned = await signer.signTransaction({ type: 2, chainId: 31337, nonce: shareNonce, gasLimit: 200_000, maxFeePerGas: 2_000_000_000, maxPriorityFeePerGas: 1_000_000_000, to: runtime.targetContract, data: abi.encodeFunctionData('set', [subject, 171]) });
  const sharedHash = keccak256(sharedSigned);
  assert.equal(await rpc(deployer, 'eth_sendRawTransaction', [sharedSigned, { visibleTo: [reader.access.actorId] }]), sharedHash);
  const sharedReceipt = await boundedWait(() => nodeRPC(deployer, 'eth_getTransactionReceipt', [sharedHash]), 60, 'shared call receipt');
  assert.equal(sharedReceipt.status, '0x1');
  demoCommand(['barrier', sharedHash, String(Number(BigInt(sharedReceipt.blockNumber))), runtime.targetContract], 'Shared transaction source barrier failed');
  assert.equal((await rpc(reader, 'eth_getTransactionByHash', [sharedHash])).hash, sharedHash);
  const sharedLogs = await rpc(reader, 'eth_getLogs', [{ address: runtime.targetContract, fromBlock: sharedReceipt.blockNumber, toBlock: sharedReceipt.blockNumber }]);
  assert.equal(sharedLogs.length, 1); assert.equal(sharedLogs[0].topics[1].toLowerCase(), zeroPadValue(subject, 32));
  const sharedView = await bff(reader, '/transactions/' + sharedHash);
  assert.equal(sharedView.status, 200); assert.equal(sharedView.value.hash, sharedHash);
  assert.equal(await rpc(reader, 'eth_getTransactionByHash', [hash]), null);
  assert.equal((await bff(users.get('outsider'), '/transactions/' + sharedHash)).status, 403);
  passed('explicit visibleTo sharing reveals only the new transaction to Reader; old private transaction and outsider remain restricted');
  const caseUrl = await checkDisclosure(admin, deployer, reader, hash);
  stage = 'immutable-config-revision-restart';
  readerRevoked = true;
  demoCommand(['revision', 'off'], 'Reader revoke/restart failed');
  assert.deepEqual(await rpc(reader, 'eth_getLogs', [filter]), []);
  assert.equal((await rpc(admin, 'eth_getLogs', [filter])).length, 1);
  demoCommand(['revision', 'on'], 'Reader restore/restart failed');
  readerRevoked = false;
  assert.equal((await rpc(reader, 'eth_getLogs', [filter]))[0].topics[1], '0x' + '0'.repeat(64));
  passed('new immutable config + drained OPS restart revokes and restores the reader event grant without replacing identities or SQL policy settings');
  await reader.page.goto(runtime.explorerOrigin + '/transactions/' + sharedHash);
  await reader.page.locator('[data-testid=info-row][data-label="Transaction Hash"]').getByText(sharedHash, { exact: true }).waitFor();
  await writeFile(resultsFile, JSON.stringify({ passed: true, cases: count, transaction: hash, receiptBlock: previous.lastBlock, contract: runtime.targetContract, transactionUrl: runtime.explorerOrigin + '/transactions/' + hash, sharedTransaction: sharedHash, sharedTransactionUrl: runtime.explorerOrigin + '/transactions/' + sharedHash, contractUrl: runtime.explorerOrigin + '/addresses/' + runtime.targetContract + '/contract', disclosureUrl: caseUrl, deployerActorId: deployer.access.actorId, applicationNode: 'real-reth', identityState: 'public-controlled-Privado-fixture', receiptEnvelope: 'V1 retained sender/recipient visibility for event-entitled readers' }, null, 2) + '\n', { mode: 0o600 });
  console.log(`PASS ${count} native V2 real-chain walkthrough cases`);
  console.log('Transaction: ' + runtime.explorerOrigin + '/transactions/' + hash);
  console.log('Shared with Reader: ' + runtime.explorerOrigin + '/transactions/' + sharedHash);
  console.log('Contract: ' + runtime.targetContract);
  console.log('Disclosure case: ' + caseUrl);
  console.log('Original private transaction: Deployer sees its transaction; Admin sees the event subject; Reader sees a masked subject and unavailable transaction; Outsider is denied.');
  console.log('Shared transaction: Reader sees this transaction and its opted-in event payload; its group and write rights are unchanged.');
  })();
  if (interactive) {
    for (const [persona, user] of users) await user.page.evaluate(persona => { document.title = 'OPS demo · ' + persona; }, persona);
    const terminal = createInterface({ input: process.stdin, output: process.stdout });
    try { await terminal.question('The demo browser windows remain open. Press Enter here to close them. '); }
    finally { terminal.close(); }
  }
} catch (error) {
  if (stage === 'actual-explorer-reads') {
    const views = [];
    for (const [persona, user] of users) { views.push({ persona, path: new URL(user.page.url()).pathname, alerts: (await user.page.getByRole('alert').allTextContents()).map(text => text.slice(0, 512)) }); }
    await writeFile(path.join(directory, 'failed-explorer-reads.json'), JSON.stringify({ stage, views, failedReads }, null, 2) + '\n', { mode: 0o600 });
    await users.get('deployer')?.page.screenshot({ path: path.join(directory, 'failed-explorer-reads.png'), fullPage: true });
  }
  // Never print request headers, token bodies, cookies, DSNs or SDK internals.
  const location = /check\.mjs:(\d+):(\d+)/.exec(error?.stack ?? '');
  console.error('FAIL native V2 walkthrough stage=' + stage + ' category=' + (error?.name ?? 'Error') + (location ? ' line=' + location[1] : ''));
  process.exitCode = 1;
} finally {
  if (readerRevoked) {
    try { demoCommand(['revision', 'on'], 'Restore reader after failed check'); }
    catch { await rm(resultsFile, { force: true }); console.error('Reader grant restoration failed; run make demo-v2-restore-reader.'); process.exitCode = 1; }
  }
  try { for (const context of contexts) await context.close(); await browser.close(); }
  catch { await rm(resultsFile, { force: true }); console.error('FAIL browser cleanup'); process.exitCode = 1; }
}
