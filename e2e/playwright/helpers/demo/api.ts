import { expect, type APIRequestContext, type BrowserContext } from '@playwright/test';

const PROXY_URL = process.env.PROXY_URL || 'http://localhost:8080';
const ANVIL_URL = process.env.ANVIL_URL || 'http://localhost:8545';
const EXPLORER_URL = process.env.EXPLORER_URL || 'http://localhost:3001';

export interface JsonRpcResult<T = unknown> {
  status: number;
  result?: T;
  error?: { code: number; message: string };
  raw: unknown;
}

async function requireOk(
  response: { ok(): boolean; status(): number; text(): Promise<string> },
  action: string,
): Promise<void> {
  if (!response.ok()) {
    throw new Error(`${action} failed (${response.status()}): ${await response.text()}`);
  }
}

export async function linkAddress(
  request: APIRequestContext,
  token: string,
  address: string,
): Promise<void> {
  const headers = { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' };
  const challenge = await request.post(`${PROXY_URL}/api/v1/eth/link/challenge`, { headers });
  await requireOk(challenge, 'Create address-link challenge');
  const { nonce } = (await challenge.json()) as { nonce: string };
  const verify = await request.post(`${PROXY_URL}/api/v1/eth/link/verify`, {
    headers,
    data: { nonce, address, signature: `0x${'aa'.repeat(65)}` },
  });
  await requireOk(verify, 'Verify linked address');
}

export async function proxyRpc<T = unknown>(
  request: APIRequestContext,
  token: string,
  orgId: string,
  method: string,
  params: unknown[] = [],
  visibleTo?: string[],
): Promise<JsonRpcResult<T>> {
  const response = await request.post(`${PROXY_URL}/rpc/${orgId}`, {
    headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
    data: {
      jsonrpc: '2.0',
      id: 1,
      method,
      params,
      ...(visibleTo ? { visibleTo } : {}),
    },
  });
  const raw = await response.json();
  const body = raw as { result?: T; error?: { code: number; message: string } };
  return { status: response.status(), result: body.result, error: body.error, raw };
}

export async function anvilRpc<T = unknown>(
  request: APIRequestContext,
  method: string,
  params: unknown[] = [],
): Promise<T> {
  const response = await request.post(ANVIL_URL, {
    data: { jsonrpc: '2.0', id: 1, method, params },
  });
  await requireOk(response, `Anvil ${method}`);
  const body = (await response.json()) as { result?: T; error?: { message: string } };
  if (body.error) throw new Error(`Anvil ${method}: ${body.error.message}`);
  return body.result as T;
}

export async function waitForReceipt(
  request: APIRequestContext,
  hash: string,
  timeoutMs = 30_000,
): Promise<{ status: string; blockNumber: string; contractAddress: string | null; logs: unknown[] }> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const receipt = await anvilRpc<{
      status: string;
      blockNumber: string;
      contractAddress: string | null;
      logs: unknown[];
    } | null>(request, 'eth_getTransactionReceipt', [hash]);
    if (receipt) {
      // A mined receipt is not a successful one: reverted transactions also
      // produce a hash and a receipt. Callers treat "receipt exists" as
      // "the transfer succeeded", so fail loudly on a revert instead of
      // letting an allow-story pass on a reverted transfer.
      if (receipt.status !== '0x1') {
        throw new Error(`Transaction ${hash} did not succeed (receipt status ${receipt.status})`);
      }
      return receipt;
    }
    await new Promise(resolve => setTimeout(resolve, 250));
  }
  throw new Error(`Timed out waiting for receipt ${hash}`);
}

export async function waitForExplorerTransaction(
  request: APIRequestContext,
  token: string,
  hash: string,
  timeoutMs = 60_000,
): Promise<unknown> {
  const deadline = Date.now() + timeoutMs;
  let lastStatus = 0;
  while (Date.now() < deadline) {
    const response = await request.get(`${PROXY_URL}/api/v1/explorer/transactions/${hash}`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    lastStatus = response.status();
    if (response.ok()) return response.json();
    await new Promise(resolve => setTimeout(resolve, 500));
  }
  throw new Error(`Indexer did not expose ${hash}; last status ${lastStatus}`);
}

export async function setExplorerAuthCookie(
  context: BrowserContext,
  token: string,
): Promise<void> {
  const url = new URL(EXPLORER_URL);
  await context.clearCookies({ name: 'explorer_auth' });
  await context.addCookies([{
    name: 'explorer_auth',
    value: token,
    domain: url.hostname,
    path: '/',
    httpOnly: true,
    sameSite: 'Lax',
    expires: Math.floor(Date.now() / 1000) + 1800,
  }]);
}

export async function explorerGet(
  context: BrowserContext,
  path: string,
): Promise<{ status: number; body: unknown; text: string }> {
  const response = await context.request.get(`${EXPLORER_URL}${path}`);
  const text = await response.text();
  let body: unknown = text;
  try {
    body = JSON.parse(text);
  } catch {
    // Preserve non-JSON bodies for diagnostics.
  }
  return { status: response.status(), body, text };
}

export function assertNoCanary(payload: unknown, canaries: string[], context: string): void {
  const serialized = typeof payload === 'string' ? payload : JSON.stringify(payload);
  const lower = serialized.toLowerCase();
  for (const canary of canaries) {
    expect(lower, `${context} leaked ${canary}`).not.toContain(canary.toLowerCase());
  }
}

export function encodeAddressWord(address: string): string {
  return address.toLowerCase().replace(/^0x/, '').padStart(64, '0');
}

export function encodeUintWord(value: bigint): string {
  return value.toString(16).padStart(64, '0');
}

export function encodeBytesData(value: string): string {
  const hex = value.replace(/^0x/, '');
  const byteLength = hex.length / 2;
  const paddedLength = Math.ceil(byteLength / 32) * 32;
  return `${encodeUintWord(BigInt(byteLength))}${hex.padEnd(paddedLength * 2, '0')}`;
}
