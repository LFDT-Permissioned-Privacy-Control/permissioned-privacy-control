#!/usr/bin/env node
// Actual public UI/provider + production API walkthrough. No test-control
// routes, manufactured tokens, SQL-seeded identities or fake application node.
import assert from 'node:assert/strict';
import { readFile, writeFile, rename, rm } from 'node:fs/promises';
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
assert.ok(['walkthrough', 'reader-admin', 'reader-reader', 'disclosure'].includes(mode), 'Unknown demo check mode');
const interactive = process.env.OPS_DEMO_INTERACTIVE === '1';
assert.ok(!interactive || process.stdin.isTTY, 'Run the visible walkthrough in an interactive terminal');
const resultsFile = path.join(directory, mode === 'walkthrough' ? 'check-results.json' : 'mapping-results.json');
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
const contexts = [], users = new Map();
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
async function login(persona) {
  stage = 'login-' + persona;
  const context = await browser.newContext({ ignoreHTTPSErrors: true }); // This isolated demo's generated certificate only.
  contexts.push(context);
  const page = await context.newPage();
  stage = persona + '-open-explorer';
  await page.goto(runtime.explorerOrigin);
  stage = persona + '-start-SSO';
  await page.getByRole('button', { name: 'Sign in', exact: true }).click();
  stage = persona + '-select-native-profile';
  await page.getByRole('button', { name: 'Sign in with Privado · demo-' + persona, exact: true }).click();
  const request = page.locator('[data-field=requestUri]'); await request.waitFor({ state: 'attached' });
  const requestUri = await request.textContent();
  assert.ok(requestUri.startsWith(runtime.opsOrigin + '/api/v2/auth/privado/requests/'));
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
  const delivered = page.waitForResponse(r => r.url() === runtime.opsOrigin + '/api/v2/auth/privado/complete' && r.request().method() === 'POST');
  stage = persona + '-confirm-native-identity';
  await page.getByRole('button', { name: 'Use this identity', exact: true }).click();
  const access = await json(await delivered);
  assert.equal(access.sourceProfile, 'demo-' + persona); assert.equal(access.provider, 'privado');
  assert.match(access.accessToken, /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/);
  stage = persona + '-explicit-app-handoff';
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
  await admin.page.getByLabel('From (local time)', { exact: true }).fill(localDate(now - 3600));
  await admin.page.getByLabel('Through (local time)', { exact: true }).fill(localDate(now + 120));
  for (const label of ['Addresses', 'Activity', 'Activity summary', 'Sanctions', 'Compliance']) await admin.page.getByLabel(label, { exact: true }).uncheck();
  await admin.page.getByLabel('Detail level').selectOption('full');
  stage = 'disclosure-create-case';
  await admin.page.getByRole('button', { name: 'Open case', exact: true }).click();
  await admin.page.getByRole('heading', { name: reference, exact: true }).waitFor();
  const caseUrl = admin.page.url();
  stage = 'disclosure-read-transactions';
  const readResponse = admin.page.waitForResponse(r => r.request().method() === 'POST' && new URL(r.url()).pathname.endsWith('/disclosure/cases/' + new URL(caseUrl).pathname.split('/').at(-1) + '/read'));
  await admin.page.getByRole('button', { name: 'Transactions', exact: true }).click();
  const read = await readResponse;
  const protectedData = await read.json();
  console.log('Disclosure transaction read: HTTP ' + read.status() + ', rows=' + (protectedData.result?.items?.length ?? 'unavailable'));
  assert.equal(read.status(), 200);
  assert.ok(protectedData.result.items.some(row => row.transactionHash === hash), 'Disclosure did not include the sample transaction');
  await admin.page.locator('a[href$="/transactions/' + hash + '"]').first().waitFor({ timeout: 30_000 });
  assert.equal(await admin.page.getByRole('alert').count(), 0);
  stage = 'disclosure-reader-denied';
  const caseId = new URL(caseUrl).pathname.split('/').at(-1);
  const deniedCase = reader.page.waitForResponse(r => r.request().method() === 'GET' && new URL(r.url()).pathname.endsWith('/disclosure/cases/' + caseId));
  await reader.page.goto(caseUrl);
  assert.equal((await deniedCase).status(), 404, 'Another recipient case must be unavailable, with a valid reader session');
  await reader.page.getByRole('alert').waitFor();
  assert.equal(await reader.page.locator('a[href$="/transactions/' + hash + '"]').count(), 0);
  assert.equal((await bff(reader, '/transactions/' + hash)).status, 200);
  passed('admin opens a standing-rule disclosure and reads its transaction without customer approval; reader cannot use the case');
  return caseUrl;
}
try {
  await (async () => {
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
  await deployer.page.getByRole('link', { name: hash, exact: true }).first().waitFor();
  assert.equal(await deployer.page.getByRole('alert').count(), 0);
  await reader.page.goto(runtime.explorerOrigin + '/transactions/' + hash);
  await reader.page.getByText('This record is unavailable.', { exact: true }).waitFor();
  assert.equal(await reader.page.getByRole('link', { name: hash, exact: true }).count(), 0);
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
  await reader.page.getByRole('link', { name: sharedHash, exact: true }).first().waitFor();
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
