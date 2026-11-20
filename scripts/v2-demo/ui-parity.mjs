// Assertions against the actual native browser and its own authorized API.
// No mock response, injected identity, policy mutation or address resolver.
import assert from 'node:assert/strict';
import { mkdir } from 'node:fs/promises';
import path from 'node:path';
import { demoAccount } from '../../tools/v2-demo-wallet/accounts.mjs';

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
    await admin.page.getByText('revoked', { exact: true }).waitFor();
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
  return { cases, screenshots, isolation, clipboard: 'Real rendered CopyButton with a page-local Clipboard API substitute; OS clipboard untouched', limits: ['The unmapped outsider has no organization; a second-organization browser fixture is not claimed.', 'The Admin case recipient already has ordinary emitter authority. The full-case canary check establishes isolation from another principal (Reader), not an otherwise deprived case recipient.', 'Server reorg acquisition/delivery regressions are separate; this browser run does not mutate chain canonicality.'] };
}
