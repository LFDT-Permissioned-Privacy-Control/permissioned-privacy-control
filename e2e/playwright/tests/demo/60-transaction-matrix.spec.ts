import { test, expect } from '@playwright/test';
import { encodeAddressWord, encodeUintWord, explorerGet, setExplorerAuthCookie } from '../../helpers/demo/api';
import { readDemoManifest } from '../../helpers/demo/state';
import type { DemoContract, DemoScenarioManifest } from '../../helpers/demo/types';

const COUNT = '0x06661abd';
const INCREMENT = '0xd09de08a';
const TRANSFER = '0xa9059cbb';
const MINT = '0x40c10f19';
const FORWARD = '0x6fadcf72';

type DemoMatrixManifest = DemoScenarioManifest & {
  contracts: DemoScenarioManifest['contracts'] & {
    forwarder: DemoContract;
  };
  transactions: DemoScenarioManifest['transactions'] & {
    writerForwardedIncrement: { hash: string; blockNumber: number; from: string; to: string; value: string; input: string };
    writerMint: { hash: string; blockNumber: number; from: string; to: string; value: string; input: string };
  };
};

function encodeBytes(data: string): string {
  const hex = data.replace(/^0x/, '');
  const byteLength = hex.length / 2;
  const paddedLength = Math.ceil(byteLength / 32) * 32;
  return `${encodeUintWord(BigInt(byteLength))}${hex.padEnd(paddedLength * 2, '0')}`;
}

function encodeForwardCall(target: string, data: string): string {
  return `${FORWARD}${encodeAddressWord(target)}${encodeUintWord(64n)}${encodeBytes(data)}`;
}

test.describe('demo transaction matrix', () => {
  test('internal calls, mint transfers, and address counters stay exact', async ({ page, context }) => {
    const m = await readDemoManifest() as DemoMatrixManifest;
    await setExplorerAuthCookie(context, m.personas.writer.token);

    const forwarded = await explorerGet(context, `/api/transactions/${m.transactions.writerForwardedIncrement.hash}`);
    expect(forwarded.status, forwarded.text).toBe(200);
    const forwardedBody = forwarded.body as {
      hash: string;
      from: string;
      to: string;
      inputData: string;
    };
    expect(forwardedBody.hash.toLowerCase()).toBe(m.transactions.writerForwardedIncrement.hash.toLowerCase());
    expect(forwardedBody.from.toLowerCase()).toBe(m.personas.writer.address.toLowerCase());
    expect(forwardedBody.to.toLowerCase()).toBe(m.contracts.forwarder.address.toLowerCase());
    expect(`0x${String(forwardedBody.inputData).replace(/^0x/, '').toLowerCase()}`)
      .toBe(encodeForwardCall(m.contracts.counter.address, INCREMENT));

    const forwardedInternal = await explorerGet(context, `/api/transactions/${m.transactions.writerForwardedIncrement.hash}/internal`);
    expect(forwardedInternal.status, forwardedInternal.text).toBe(200);
    const internalRows = forwardedInternal.body as Array<{
      txHash: string;
      from: string;
      to: string | null;
      callType: string;
      input?: string;
    }>;
    expect(internalRows).toHaveLength(1);
    expect(internalRows[0].txHash.toLowerCase()).toBe(m.transactions.writerForwardedIncrement.hash.toLowerCase());
    expect(internalRows[0].from.toLowerCase()).toBe(m.contracts.forwarder.address.toLowerCase());
    expect(internalRows[0].to?.toLowerCase()).toBe(m.contracts.counter.address.toLowerCase());
    expect(internalRows[0].callType.toLowerCase()).toBe('call');
    expect(`0x${String(internalRows[0].input ?? '').replace(/^0x/, '').toLowerCase()}`).toBe(INCREMENT);

    const forwarderAddress = await explorerGet(context, `/api/addresses/${m.contracts.forwarder.address}`);
    expect(forwarderAddress.status, forwarderAddress.text).toBe(200);
    const forwarderInfo = forwarderAddress.body as { txCount: number; internalTxCount: number };

    const forwarderInternal = await explorerGet(context, `/api/addresses/${m.contracts.forwarder.address}/internal?page=1&pageSize=25`);
    expect(forwarderInternal.status, forwarderInternal.text).toBe(200);
    const forwarderInternalBody = forwarderInternal.body as { total: number; data: Array<{ txHash: string }> };
    expect(forwarderInternalBody.total).toBe(forwarderInfo.internalTxCount);
    expect(forwarderInternalBody.data).toHaveLength(forwarderInfo.internalTxCount);

    const counterAddress = await explorerGet(context, `/api/addresses/${m.contracts.counter.address}`);
    expect(counterAddress.status, counterAddress.text).toBe(200);
    const counterInfo = counterAddress.body as { txCount: number; internalTxCount: number };

    const counterInternal = await explorerGet(context, `/api/addresses/${m.contracts.counter.address}/internal?page=1&pageSize=25`);
    expect(counterInternal.status, counterInternal.text).toBe(200);
    const counterInternalBody = counterInternal.body as { total: number; data: Array<{ txHash: string }> };
    expect(counterInternalBody.total).toBe(counterInfo.internalTxCount);
    expect(counterInternalBody.data).toHaveLength(counterInfo.internalTxCount);
    expect(counterInfo.internalTxCount).toBe(1);

    await page.goto(`/tx/${m.transactions.writerForwardedIncrement.hash}`);
    await expect(page.getByRole('tab', { name: /Logs \(1\)/i })).toBeVisible();
    await expect(page.getByRole('tab', { name: /Internal Txns \(1\)/i })).toBeVisible();
    await page.getByRole('tab', { name: /Internal Txns \(1\)/i }).click();
    await expect(page.getByText('Call Trace', { exact: true })).toBeVisible();
    await expect(page.getByText('1 internal call', { exact: false })).toBeVisible();
    const rows = page.locator('[data-testid="trace-row"]');
    await expect(rows).toHaveCount(2);
    await expect(rows.nth(1).getByText(INCREMENT, { exact: true })).toBeVisible();
    await expect(rows.nth(1).locator('[data-testid="address-label"]')).toHaveCount(2);
    await expect(rows.nth(1).getByText('My Org', { exact: true })).toHaveCount(2);

    await setExplorerAuthCookie(context, m.personas.admin.token);
    await page.goto(`/tx/${m.transactions.writerMint.hash}`);
    await expect(page.getByRole('heading', { name: /Transaction Details/i })).toBeVisible();
    await expect(page.getByText(new RegExp(MINT, 'i'))).toBeVisible();
    await expect(page.getByRole('tab', { name: /Logs \(1\)/i })).toBeVisible();
    await expect(page.getByText('ERC-20 Tokens Transferred', { exact: false })).toBeVisible();
    await expect(page.getByText('Mine', { exact: true })).toBeVisible();
    await expect(page.getByText('My Org', { exact: true })).toBeVisible();
    await page.getByRole('tab', { name: /Logs \(1\)/i }).click();
    await expect(page.getByText('Transfer', { exact: true })).toBeVisible();

    const mintDetail = await explorerGet(context, `/api/transactions/${m.transactions.writerMint.hash}`);
    expect(mintDetail.status, mintDetail.text).toBe(200);
    const mintBody = mintDetail.body as { hash: string; from: string; to: string; inputData: string; txCategories?: string[] };
    expect(mintBody.hash.toLowerCase()).toBe(m.transactions.writerMint.hash.toLowerCase());
    expect(mintBody.from.toLowerCase()).toBe(m.personas.admin.address.toLowerCase());
    expect(mintBody.to.toLowerCase()).toBe(m.contracts.token.address.toLowerCase());
    expect(`0x${String(mintBody.inputData).replace(/^0x/, '').toLowerCase()}`).toContain(MINT.slice(2));
    expect(mintBody.txCategories ?? []).toEqual(expect.arrayContaining(['contract_call', 'token_transfer']));

    const mintTransfers = await explorerGet(context, `/api/transactions/${m.transactions.writerMint.hash}/transfers`);
    expect(mintTransfers.status, mintTransfers.text).toBe(200);
    const transfers = mintTransfers.body as Array<{ from: string; to: string; value: string }>;
    expect(transfers).toHaveLength(1);
    expect(transfers[0].from.toLowerCase()).toBe('0x0000000000000000000000000000000000000000');
    // An org admin can inspect the contract event but does not automatically
    // gain the member's wallet identity. This must remain redacted unless the
    // member explicitly discloses it; otherwise the transfer endpoint becomes
    // a same-org address-discovery oracle.
    expect(transfers[0].to).toBe('[PRIVATE]');

    await setExplorerAuthCookie(context, m.personas.writer.token);
    const writerMintTransfers = await explorerGet(context, `/api/transactions/${m.transactions.writerMint.hash}/transfers`);
    expect(writerMintTransfers.status, writerMintTransfers.text).toBe(200);
    const writerTransfers = writerMintTransfers.body as Array<{ from: string; to: string; value: string }>;
    expect(writerTransfers).toHaveLength(1);
    expect(writerTransfers[0].from.toLowerCase()).toBe('0x0000000000000000000000000000000000000000');
    expect(writerTransfers[0].to.toLowerCase()).toBe(m.personas.writer.address.toLowerCase());

    const writerAddress = await explorerGet(context, `/api/addresses/${m.personas.writer.address}`);
    expect(writerAddress.status, writerAddress.text).toBe(200);
    const writerInfo = writerAddress.body as { txCount: number; internalTxCount: number };
    expect(writerInfo.txCount).toBeGreaterThanOrEqual(1);
    expect(writerInfo.internalTxCount).toBe(0);

    await page.goto(`/address/${m.contracts.forwarder.address}`);
    await expect(page.getByTestId('tab-internal')).toContainText(`Internal txns${forwarderInfo.internalTxCount}`);
    await expect(page.getByTestId('tab-transactions')).toContainText(`Transactions${forwarderInfo.txCount}`);
    await page.getByTestId('tab-internal').click();
    await expect(page.locator('table tbody tr')).toHaveCount(1);
    await expect(page.getByText('call', { exact: true })).toBeVisible();
    await expect(page.getByText('My Org', { exact: true })).toBeVisible();

    await page.goto(`/address/${m.contracts.counter.address}`);
    await expect(page.getByTestId('tab-internal')).toContainText('Internal txns1');
    await page.getByTestId('tab-internal').click();
    await expect(page.locator('table tbody tr')).toHaveCount(1);
    await expect(page.getByText('My Org', { exact: true })).toBeVisible();
  });
});
