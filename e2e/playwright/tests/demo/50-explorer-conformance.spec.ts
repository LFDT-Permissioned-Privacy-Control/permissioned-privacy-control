import { test, expect } from '@playwright/test';
import { assertNoCanary, explorerGet, setExplorerAuthCookie } from '../../helpers/demo/api';
import { readDemoManifest } from '../../helpers/demo/state';

test.describe('explorer negative-space conformance', () => {
  test('transaction list and detail contain the same visible record and exact address metadata', async ({ context }) => {
    const m = await readDemoManifest();
    await setExplorerAuthCookie(context, m.personas.writer.token);
    const list = await explorerGet(context, '/api/transactions?page=1&pageSize=100');
    expect(list.status, list.text).toBe(200);
    const rows = (list.body as { data: Array<Record<string, unknown>> }).data;
    const matching = rows.filter(tx => String(tx.hash).toLowerCase() === m.transactions.writerIncrement.hash.toLowerCase());
    expect(matching).toHaveLength(1);

    const detail = await explorerGet(context, `/api/transactions/${m.transactions.writerIncrement.hash}`);
    expect(detail.status, detail.text).toBe(200);
    for (const key of ['hash', 'from', 'to', 'value', 'status', 'inputData']) {
      expect(matching[0][key], `list/detail mismatch for ${key}`).toEqual((detail.body as Record<string, unknown>)[key]);
    }
    const metadata = (detail.body as { addressMetadata?: Record<string, string> }).addressMetadata ?? {};
    expect(metadata[m.personas.writer.address.toLowerCase()]).toMatch(/own|participant/i);
  });

  test('search cannot be used to enumerate an inaccessible user wallet or transaction', async ({ context }) => {
    const m = await readDemoManifest();
    await setExplorerAuthCookie(context, m.personas.outsider.token);
    for (const canary of [m.personas.writer.address, m.transactions.writerIncrement.hash]) {
      const result = await explorerGet(context, `/api/search?q=${encodeURIComponent(canary)}`);
      expect([200, 404]).toContain(result.status);
      assertNoCanary(result.text, [canary], `search for protected ${canary}`);
    }
  });
});
