import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
const runtime = JSON.parse(await readFile('/demo/runtime.json', 'utf8'));
const url = new URL(runtime.rpcUrl);
assert.equal(url.protocol, 'http:'); assert.equal(url.hostname, '127.0.0.1');
for (let attempt = 0; attempt < 60; attempt++) {
  try {
    const response = await fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'eth_chainId', params: [] }), signal: AbortSignal.timeout(1000), redirect: 'error' });
    const raw = await response.text(); assert.ok(raw.length < 4096);
    assert.equal(response.status, 200); assert.equal(BigInt(JSON.parse(raw).result).toString(), runtime.chainId);
    process.exit(0);
  } catch { await new Promise(resolve => setTimeout(resolve, 1000)); }
}
throw Error('The real demo Reth did not become ready on the selected loopback port');
