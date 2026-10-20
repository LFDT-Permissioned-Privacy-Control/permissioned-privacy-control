import { test, expect } from '@playwright/test';
import { assertNoCanary, explorerGet, proxyRpc, setExplorerAuthCookie } from '../../helpers/demo/api';
import { readDemoManifest } from '../../helpers/demo/state';

const COUNT = '0x06661abd';
const INCREMENT = '0xd09de08a';

test.describe('RBAC and explorer parity', () => {
  test('reader can call the allowlisted function but cannot write', async ({ request }) => {
    const m = await readDemoManifest();
    const read = await proxyRpc<string>(request, m.personas.reader.token, m.orgs.a.id, 'eth_call', [{
      from: m.personas.reader.address,
      to: m.contracts.counter.address,
      data: COUNT,
    }, 'latest']);
    expect(read.status, JSON.stringify(read.raw)).toBe(200);
    // Setup performs two direct increments and then one increment through the
    // Forwarder to exercise the internal-transaction path. RBAC reads must
    // observe the actual final state, not the pre-forwarder fixture value.
    expect(BigInt(read.result!)).toBe(3n);

    const write = await proxyRpc<string>(request, m.personas.reader.token, m.orgs.a.id, 'eth_sendTransaction', [{
      from: m.personas.reader.address,
      to: m.contracts.counter.address,
      data: INCREMENT,
    }]);
    expect(write.result).toBeUndefined();
    expect(write.status).toBe(404);
    assertNoCanary(
      write.raw,
      [...m.canaries.transactionHashes, ...m.canaries.calldata],
      'reader denial',
    );
  });

  test('event rules hide normal logs but visibleTo unlock exposes exactly one matching log', async ({ request }) => {
    const m = await readDemoManifest();
    const hash = m.transactions.writerIncrement.hash;

    const reader = await proxyRpc<unknown>(request, m.personas.reader.token, m.orgs.a.id, 'eth_getTransactionReceipt', [hash]);
    expect(reader.status).toBe(200);
    expect(reader.result).toBeNull();

    const observer = await proxyRpc<{ logs: Array<{ topics: string[]; transactionHash: string }> }>(
      request, m.personas.observer.token, m.orgs.a.id, 'eth_getTransactionReceipt', [hash],
    );
    expect(observer.status, JSON.stringify(observer.raw)).toBe(200);
    expect(observer.result?.logs).toHaveLength(1);
    expect(observer.result?.logs[0].topics[0].toLowerCase()).toBe(m.eventTopics.countIncremented.toLowerCase());
    expect(observer.result?.logs[0].transactionHash.toLowerCase()).toBe(hash.toLowerCase());

    const outsider = await proxyRpc<unknown>(request, m.personas.outsider.token, m.orgs.a.id, 'eth_getTransactionReceipt', [hash]);
    expect(outsider.result).toBeNull();
    assertNoCanary(outsider.raw, [hash, m.personas.writer.address], 'non-visibleTo receipt');
  });

  test('participant explorer detail, labels, logs, and counters agree with BFF data', async ({ page, context }) => {
    const m = await readDemoManifest();
    await setExplorerAuthCookie(context, m.personas.writer.token);

    const detail = await explorerGet(context, `/api/transactions/${m.transactions.writerIncrement.hash}`);
    expect(detail.status, detail.text).toBe(200);
    const tx = detail.body as Record<string, unknown>;
    expect(String(tx.hash).toLowerCase()).toBe(m.transactions.writerIncrement.hash.toLowerCase());
    expect(String(tx.from).toLowerCase()).toBe(m.personas.writer.address.toLowerCase());
    expect(String(tx.to).toLowerCase()).toBe(m.contracts.counter.address.toLowerCase());
    expect(`0x${String(tx.inputData).replace(/^0x/, '')}`).toBe(INCREMENT);

    const logs = await explorerGet(context, `/api/transactions/${m.transactions.writerIncrement.hash}/logs`);
    expect(logs.status, logs.text).toBe(200);
    expect(logs.body).toHaveLength(1);
    expect(JSON.stringify(logs.body).toLowerCase()).toContain(m.eventTopics.countIncremented.toLowerCase());

    const stats = await explorerGet(context, '/api/stats');
    const list = await explorerGet(context, '/api/transactions?page=1&pageSize=100');
    expect(stats.status).toBe(200);
    expect(list.status).toBe(200);
    expect((stats.body as { totalTransactions: number }).totalTransactions)
      .toBe((list.body as { total: number }).total);

    await page.goto(`/tx/${m.transactions.writerIncrement.hash}`);
    await expect(page.getByText(m.transactions.writerIncrement.hash, { exact: false }).first()).toBeVisible();
    await expect(page.getByRole('tab', { name: /Logs\s*\(1\)/i })).toBeVisible();
    await expect(page.getByText('Mine', { exact: true })).toBeVisible();
    await expect(page.getByText('My Org', { exact: true })).toBeVisible();
    await page.goto(`/address/${m.personas.writer.address}`);
    await expect(page.getByRole('heading', { name: /Address Restricted/i })).not.toBeVisible();
  });

  test('same-org ungranted and cross-org viewers receive an opaque restriction with no leak', async ({ page, context }) => {
    const m = await readDemoManifest();
    for (const persona of [m.personas.outsider, m.personas.orgBMember]) {
      await setExplorerAuthCookie(context, persona.token);
      const detail = await explorerGet(context, `/api/transactions/${m.transactions.writerIncrement.hash}`);
      expect(detail.status).toBe(404);
      assertNoCanary(
        detail.text,
        // The protected transaction's `to` is the counter contract. A regression
        // that hides the two user addresses but returns the contract address must
        // still fail, so forbid it explicitly alongside the user-address canaries.
        [m.contracts.counter.address, ...m.canaries.protectedAddresses, ...m.canaries.transactionHashes, ...m.canaries.calldata],
        `${persona.did} transaction detail`,
      );

      await page.goto(`/address/${m.contracts.counter.address}`);
      await expect(page.getByRole('heading', { name: /Address Restricted/i })).toBeVisible();
      const body = await page.locator('body').innerText();
      assertNoCanary(
        body,
        [...m.canaries.transactionHashes, ...m.canaries.calldata],
        `${persona.did} restricted page`,
      );
    }
  });
});
