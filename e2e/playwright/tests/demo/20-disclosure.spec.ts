import { test, expect } from '@playwright/test';
import { assertNoCanary, explorerGet, setExplorerAuthCookie } from '../../helpers/demo/api';
import { readDemoManifest } from '../../helpers/demo/state';

interface DisclosedAddress {
  address: string;
  address_id: string;
  disclosure_level: 'full' | 'pseudonymous' | 'redacted';
  grant_id: string;
}

test.describe('selective disclosure', () => {
  for (const requester of ['fullAuditor', 'pseudonymousAuditor', 'redactedAuditor'] as const) {
    test(`${requester} sees exactly the granted target at the requested level`, async ({ page, context }) => {
      const m = await readDemoManifest();
      const persona = m.personas[requester];
      const expectedLevel = requester === 'fullAuditor'
        ? 'full'
        : requester === 'pseudonymousAuditor' ? 'pseudonymous' : 'redacted';
      await setExplorerAuthCookie(context, persona.token);

      const response = await explorerGet(context, '/api/privacy/viewable-addresses');
      expect(response.status, response.text).toBe(200);
      const body = response.body as {
        viewer_did: string;
        own_addresses: Array<{ address: string }>;
        disclosed_addresses: DisclosedAddress[];
      };
      expect(body.viewer_did).toBe(persona.did);
      expect(body.own_addresses).toHaveLength(1);
      expect(body.own_addresses[0].address.toLowerCase()).toBe(persona.address.toLowerCase());
      expect(body.disclosed_addresses).toHaveLength(1);
      const disclosed = body.disclosed_addresses[0];
      expect(disclosed.disclosure_level).toBe(expectedLevel);
      expect(disclosed.grant_id).toBe(m.disclosures.find(g => g.requester === requester)?.grantId);

      let expectedDisplay: string;

      if (expectedLevel === 'full') {
        expect(disclosed.address.toLowerCase()).toBe(m.personas.target.address.toLowerCase());
        expectedDisplay = m.personas.target.address;
      } else if (expectedLevel === 'pseudonymous') {
        expect(disclosed.address).toMatch(/^Address-[A-Z0-9]+$/i);
        expectedDisplay = disclosed.address;
        assertNoCanary(response.text, [m.personas.target.address], 'pseudonymous address list');
      } else {
        expect(disclosed.address).toBe('[PRIVATE]');
        expectedDisplay = '[PRIVATE]';
        assertNoCanary(response.text, [m.personas.target.address], 'redacted address list');
      }

      const grant = await explorerGet(
        context,
        `/api/privacy/grant/${disclosed.grant_id}/${disclosed.address_id}`,
      );
      expect(grant.status, grant.text).toBe(200);
      const grantBody = grant.body as {
        disclosure_level: string;
        display_address: string;
        scope_methods: string[];
      };
      expect(grantBody.disclosure_level).toBe(expectedLevel);
      expect(grantBody.display_address.toLowerCase()).toBe(expectedDisplay.toLowerCase());
      expect(grantBody.scope_methods).toEqual(expect.arrayContaining([
        'transaction_history',
        'activity_logs',
      ]));
      if (expectedLevel !== 'full') {
        assertNoCanary(grant.text, [m.personas.target.address], `${expectedLevel} grant detail`);
      }

      const history = await explorerGet(
        context,
        `/api/privacy/grant/${disclosed.grant_id}/${disclosed.address_id}/transactions?limit=25`,
      );
      expect(history.status, history.text).toBe(200);
      const historyBody = history.body as {
        transactions: Array<{
          tx_hash?: string;
          from: string;
          to?: string;
          value: string;
        }>;
        address_labels: Record<string, string>;
      };
      const txs = historyBody.transactions;
      // A disclosure grant covers the target address's history, not only the
      // one canary transaction created for this scenario. The fixture's target
      // wallet also participates in setup transactions, so assert the
      // authorization boundary and required canary rather than an accidental
      // chain-history cardinality.
      expect(txs.length).toBeGreaterThanOrEqual(1);
      if (expectedLevel === 'full') {
        expect(history.text.toLowerCase()).toContain(m.transactions.targetIncrement.hash.toLowerCase());
        expect(txs.map(tx => tx.tx_hash?.toLowerCase())).toContain(m.transactions.targetIncrement.hash.toLowerCase());
      } else {
        expect(txs.every(tx => tx.tx_hash === undefined && tx.value === 'hidden')).toBe(true);
        assertNoCanary(history.text, [
          m.personas.target.address,
          m.transactions.targetIncrement.hash,
          // The disclosed transaction's counterparty is the counter contract.
          // A grant that pseudonymizes/redacts `from` but leaks the real
          // contract address in `to` must still fail this level's check.
          m.contracts.counter.address,
        ], `${expectedLevel} transaction history`);
        if (expectedLevel === 'pseudonymous') {
          expect(txs.some(tx => [tx.from, tx.to].includes(expectedDisplay))).toBe(true);
          expect(historyBody.address_labels[expectedDisplay]).toBe('disclosed');
        } else {
          expect(txs.every(tx => tx.from === '[PRIVATE]' && tx.to === '[PRIVATE]')).toBe(true);
          expect(historyBody.address_labels).toEqual({});
        }
      }

      const activity = await explorerGet(
        context,
        `/api/privacy/grant/${disclosed.grant_id}/activity?limit=25&offset=0`,
      );
      expect(activity.status, activity.text).toBe(200);
      const activityBody = activity.body as {
        logs: Array<{ method: string; status_code: number }>;
      };
      expect(activityBody.logs.filter(log => log.method === 'eth_call')).toHaveLength(1);
      assertNoCanary(
        activity.text,
        [m.personas.target.address, m.contracts.counter.address, ...m.canaries.calldata],
        `${expectedLevel} activity logs`,
      );

      await page.goto('/privacy');
      await page.getByText(/Disclosed to You/i).first().click();
      await expect(page.locator('table tbody tr, [data-testid="disclosed-item"]')).toHaveCount(1);
      const dashboardText = await page.locator('body').innerText();
      if (expectedLevel !== 'full') {
        assertNoCanary(dashboardText, [m.personas.target.address], `${expectedLevel} dashboard`);
      }

      await page.goto(`/grant/${disclosed.grant_id}/${disclosed.address_id}`);
      await expect(page.getByText(expectedDisplay, { exact: true }).first()).toBeVisible();
      await expect(page.getByRole('tab', { name: 'Transactions', exact: true })).toBeVisible();
      await expect(page.locator('table tbody tr')).toHaveCount(txs.length);
      if (expectedLevel !== 'full') {
        await expect(page.getByText('hidden', { exact: true }).first()).toBeVisible();
      }
      await page.getByRole('tab', { name: 'Activity Logs', exact: true }).click();
      await expect(page.getByText('eth_call', { exact: true })).toBeVisible();
      const grantPageText = await page.locator('body').innerText();
      if (expectedLevel !== 'full') {
        assertNoCanary(grantPageText, [
          m.personas.target.address,
          m.transactions.targetIncrement.hash,
        ], `${expectedLevel} granted-address page`);
      }
    });
  }

  test('an authenticated user without a grant sees no disclosed targets', async ({ context }) => {
    const m = await readDemoManifest();
    await setExplorerAuthCookie(context, m.personas.outsider.token);
    const response = await explorerGet(context, '/api/privacy/viewable-addresses');
    expect(response.status, response.text).toBe(200);
    expect((response.body as { disclosed_addresses: unknown[] }).disclosed_addresses).toEqual([]);
    assertNoCanary(response.text, [m.personas.target.address], 'ungranted disclosure list');
  });
});
