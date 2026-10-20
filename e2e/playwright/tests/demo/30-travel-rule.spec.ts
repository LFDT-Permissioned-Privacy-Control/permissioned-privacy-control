import { test, expect, type APIRequestContext } from '@playwright/test';
import { encodeAddressWord, encodeUintWord, proxyRpc, waitForReceipt } from '../../helpers/demo/api';
import { readDemoManifest } from '../../helpers/demo/state';

const PROXY_URL = process.env.PROXY_URL || 'http://localhost:8080';
const TRANSFER = '0xa9059cbb';
const amountTokens = 300n;
const amountWei = amountTokens * 10n ** 18n;

async function adminRequest(
  request: APIRequestContext,
  token: string,
  method: 'get' | 'put' | 'post',
  path: string,
  data?: unknown,
) {
  const response = await request[method](`${PROXY_URL}${path}`, {
    headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
    ...(data === undefined ? {} : { data }),
  });
  const text = await response.text();
  let body: unknown = text;
  try { body = JSON.parse(text); } catch { /* diagnostic text */ }
  return { status: response.status(), body, text };
}

function transferData(to: string): string {
  return `${TRANSFER}${encodeAddressWord(to)}${encodeUintWord(amountWei)}`;
}

test.describe.serial('travel-rule enforcement and currency valuation', () => {
  test('USD valuation below threshold is allowed without a travel-rule record', async ({ request }) => {
    const m = await readDemoManifest();
    const result = await proxyRpc<string>(request, m.personas.writer.token, m.orgs.a.id, 'eth_sendTransaction', [{
      from: m.personas.writer.address,
      to: m.contracts.token.address,
      data: transferData(m.personas.target.address),
      gas: '0x30d40',
    }]);
    expect(result.status, JSON.stringify(result.raw)).toBe(200);
    expect(result.result).toMatch(/^0x[0-9a-f]{64}$/i);
    await waitForReceipt(request, result.result!);
  });

  test('switching to EUR revalues the same token amount and enforce mode blocks it', async ({ request }) => {
    const m = await readDemoManifest();
    const config = await adminRequest(
      request, m.personas.admin.token, 'put',
      `/api/v1/admin/orgs/${m.orgs.a.id}/compliance/config`,
      { currency: 'eur', enforcement_mode: 'enforce' },
    );
    expect(config.status, config.text).toBe(200);
    expect((config.body as { currency: string }).currency).toBe('eur');

    const denied = await proxyRpc<string>(request, m.personas.writer.token, m.orgs.a.id, 'eth_sendTransaction', [{
      from: m.personas.writer.address,
      to: m.contracts.token.address,
      data: transferData(m.personas.target.address),
      gas: '0x30d40',
    }]);
    expect(denied.result).toBeUndefined();
    expect([400, 403]).toContain(denied.status);
    expect(JSON.stringify(denied.raw)).toMatch(/travel rule|compliance|threshold/i);
  });

  test('a matching EUR travel-rule record permits exactly one above-threshold transfer', async ({ request }) => {
    const m = await readDemoManifest();
    const record = await adminRequest(
      request, m.personas.admin.token, 'post',
      `/api/v1/admin/orgs/${m.orgs.a.id}/compliance/travel-rule-records`,
      {
        originator_user_id: m.personas.writer.id,
        originator_data: { name: 'Demo Originator', country: 'ES' },
        beneficiary_data: { name: 'Demo Beneficiary', country: 'FR' },
        transfer_type: 'erc20', token_address: m.contracts.token.address,
        beneficiary_address: m.personas.target.address, amount_wei: amountWei.toString(),
      },
    );
    expect(record.status, record.text).toBe(201);
    expect((record.body as { amount_fiat: number; currency: string }).amount_fiat).toBe(1200);
    expect((record.body as { currency: string }).currency).toBe('eur');

    const allowed = await proxyRpc<string>(request, m.personas.writer.token, m.orgs.a.id, 'eth_sendTransaction', [{
      from: m.personas.writer.address,
      to: m.contracts.token.address,
      data: transferData(m.personas.target.address),
      gas: '0x30d40',
    }]);
    expect(allowed.status, JSON.stringify(allowed.raw)).toBe(200);
    expect(allowed.result).toMatch(/^0x[0-9a-f]{64}$/i);
    await waitForReceipt(request, allowed.result!);

    const records = await adminRequest(
      request, m.personas.admin.token, 'get',
      `/api/v1/admin/orgs/${m.orgs.a.id}/compliance/travel-rule-records?limit=20`,
    );
    expect(records.status, records.text).toBe(200);
    const used = (records.body as { data: Array<{ id: string; used_at?: string }> }).data
      .find(item => item.id === (record.body as { id: string }).id);
    expect(used?.used_at).toBeTruthy();

    // "Exactly one": a second identical transfer, still in enforce mode with the
    // record now consumed, must be denied. Without this a reused-record
    // implementation would satisfy the story on the marked-used check alone.
    const reused = await proxyRpc<string>(request, m.personas.writer.token, m.orgs.a.id, 'eth_sendTransaction', [{
      from: m.personas.writer.address,
      to: m.contracts.token.address,
      data: transferData(m.personas.target.address),
      gas: '0x30d40',
    }]);
    expect(reused.result).toBeUndefined();
    expect([400, 403]).toContain(reused.status);
    expect(JSON.stringify(reused.raw)).toMatch(/travel rule|compliance|threshold/i);
  });

  test('monitor mode allows the same missing-record transfer and writes a would-block log', async ({ request }) => {
    const m = await readDemoManifest();
    const config = await adminRequest(
      request, m.personas.admin.token, 'put',
      `/api/v1/admin/orgs/${m.orgs.a.id}/compliance/config`,
      { enforcement_mode: 'monitor' },
    );
    expect(config.status, config.text).toBe(200);

    const monitored = await proxyRpc<string>(request, m.personas.writer.token, m.orgs.a.id, 'eth_sendTransaction', [{
      from: m.personas.writer.address,
      to: m.contracts.token.address,
      data: transferData(m.personas.target.address),
      gas: '0x30d40',
    }]);
    expect(monitored.status, JSON.stringify(monitored.raw)).toBe(200);
    expect(monitored.result).toMatch(/^0x[0-9a-f]{64}$/i);
    await waitForReceipt(request, monitored.result!);

    const logs = await adminRequest(
      request, m.personas.admin.token, 'get',
      `/api/v1/admin/orgs/${m.orgs.a.id}/compliance/logs?limit=20`,
    );
    expect(logs.status, logs.text).toBe(200);
    // Assert a would-block decision was actually recorded, not merely that the
    // serialized rows contain the always-present would_block field. The old
    // /would.block|monitor/ regex matched every row (`.` matches `_`, and
    // `"would_block":false` satisfied it), so a monitor that never logged the
    // transfer still passed.
    expect(logs.text).toMatch(/["']would_?block["']\s*:\s*true/i);
  });
});
