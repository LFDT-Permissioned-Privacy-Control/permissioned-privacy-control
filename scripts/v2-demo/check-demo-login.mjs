#!/usr/bin/env node
// Actual buttons, actual proof job, normal Chrome certificate exception.
// No harness /prove request, fabricated candidate, token paste or TLS bypass.
import assert from 'node:assert/strict';
import { readFile, writeFile, mkdir } from 'node:fs/promises';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import tls from 'node:tls';
import { X509Certificate } from 'node:crypto';
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const directory = path.resolve(process.argv[2] ?? '');
assert.ok(directory.startsWith(path.join(root, '.tmp/v2-demo') + path.sep));
const runtime = JSON.parse(await readFile(path.join(directory, 'runtime.json')));
const metadata = JSON.parse(await readFile(path.join(directory, 'wallet-metadata.json')));
assert.equal(runtime.testOnly, true); assert.equal(metadata.testOnly, true);
const ca = await readFile(path.join(directory, 'ca.crt'));
const leaf = new X509Certificate(await readFile(path.join(directory, 'tls.crt')));
const origins = ['opsOrigin', 'walletOrigin', 'explorerOrigin'].map(key => {
  const url = new URL(runtime[key]); assert.equal(url.protocol, 'https:'); assert.equal(url.hostname, 'localhost'); assert.equal(url.origin, runtime[key]); return url;
});
for (const url of origins) await new Promise((resolve, reject) => {
  const socket = tls.connect({ host: url.hostname, port: Number(url.port), servername: 'localhost', ca, rejectUnauthorized: true }, () => {
    try { assert.equal(new X509Certificate(socket.getPeerCertificate().raw).fingerprint256, leaf.fingerprint256); socket.end(); resolve(); } catch (error) { socket.destroy(); reject(error); }
  }); socket.on('error', reject); socket.setTimeout(5000, () => socket.destroy(Error('owned certificate probe timed out')));
});
const require = createRequire(path.join(root, 'e2e/playwright/package.json'));
const { chromium } = require('@playwright/test');
const browser = await chromium.launch({ channel: process.env.OPS_TEST_BROWSER_CHANNEL ?? 'chrome', headless: process.env.OPS_DEMO_INTERACTIVE !== '1', args: ['--no-proxy-server'] });
const output = path.join(directory, 'demo-login'); await mkdir(output, { recursive: true });
const results = []; let stage = 'start';
const selectedCase = process.env.OPS_DEMO_LOGIN_CASE ?? 'all';
assert.ok(['all', 'first-use', 'cancel-then-different-persona'].includes(selectedCase));
const resultsFile = selectedCase === 'all' ? 'results.json' : selectedCase === 'first-use' ? 'first-use-results.json' : 'cancel-results.json';
const contexts = [];
async function context() { const c = await browser.newContext({ ignoreHTTPSErrors: false }); contexts.push(c); return c; }
async function ownedPage(c, address) {
  const page = await c.newPage(); page.setDefaultTimeout(20000);
  let certificateError = false;
  try { await page.goto(address, { timeout: 15000 }); }
  catch (error) { assert.match(error.message, /ERR_CERT_AUTHORITY_INVALID/); certificateError = true; }
  if (certificateError) {
    // The exact leaf was independently verified against the owned CA above.
    // This is Chrome's normal user exception in a temporary browser profile.
    await page.locator('#details-button').waitFor({ state: 'visible' });
    await page.locator('#details-button').click(); await page.locator('#proceed-link').click();
  }
  return page;
}
async function trustedOPS(c) {
  // Chrome's certificate exceptions are port-scoped. Establish the normal
  // user exception for the owned wallet before testing the one-click flow.
  const wallet = await ownedPage(c, runtime.walletOrigin + '/');
  await wallet.close();
  const page = await ownedPage(c, runtime.opsOrigin + '/login');
  await page.getByTestId('demo-persona-admin').waitFor();
  return page;
}
function observe(page) {
  const data = { starts: [], completes: [], candidates: [], self: null };
  page.on('response', async response => {
    try {
      if (response.status() !== 200 || new URL(response.url()).origin !== runtime.opsOrigin) return;
      const route = new URL(response.url()).pathname;
      if (!['/api/v2/auth/privado/start', '/api/v2/auth/privado/preview', '/api/v2/auth/privado/complete', '/api/v2/self'].includes(route)) return;
      const value = await response.json();
      if (route.endsWith('/start')) data.starts.push(value);
      if (route.endsWith('/complete')) data.completes.push(value);
      if (route.endsWith('/preview') && value.status === 'candidate') data.candidates.push(value);
      if (route === '/api/v2/self') data.self = value;
    } catch { /* A canceled old read cannot become evidence of success. */ }
  }); return data;
}
async function finish(page, data, persona) {
  const expected = metadata.personas.find(p => p.id === persona);
  await page.waitForURL(url => url.origin === runtime.opsOrigin && ['/admin/account', '/admin/rbac/organizations'].includes(url.pathname), { timeout: 170000 });
  await page.waitForFunction(() => { const text = document.body.textContent?.toLowerCase() ?? ''; return text.includes('ops identity') || text.includes('policy source workspace'); });
  const until = Date.now() + 10000;
  while ((!data.self || !data.completes.length || !data.candidates.length) && Date.now() < until) await page.waitForTimeout(50);
  const access = data.completes.at(-1), candidate = data.candidates.at(-1), self = data.self;
  assert.ok(access && candidate && self, 'real complete, verified preview and Self must all be observed');
  assert.equal(access.sourceProfile, expected.profileId); assert.equal(candidate.sourceProfile, expected.profileId);
  assert.equal(candidate.holderDid, expected.holderDid); assert.equal(candidate.network, metadata.network);
  assert.equal(candidate.actorId, access.actorId); assert.equal(self.actorId, access.actorId); assert.equal(self.sourceProfile, expected.profileId);
  const admin = self.organizations.some(org => org.isOrgAdmin || org.isOrgReadonlyAdmin);
  assert.equal(new URL(page.url()).pathname, admin ? '/admin/rbac/organizations' : '/admin/account');
  assert.equal(data.completes.filter(x => x.sourceProfile === expected.profileId).length, 1);
  await page.screenshot({ path: path.join(output, persona + '-signed-in.png'), fullPage: true });
  return { persona, profile: self.sourceProfile, path: new URL(page.url()).pathname, verifiedHolder: candidate.holderDid, popupClosed: true };
}
try {
  if (selectedCase === 'all' || selectedCase === 'first-use') {
    stage = 'first-use-certificate-and-demo-entry';
    const c = await context(), page = await ownedPage(c, runtime.opsOrigin + '/login'), data = observe(page);
    let nativeStartRequests = 0, walletProofRequests = 0;
    c.on('request', request => {
      if (request.method() !== 'POST') return;
      const url = new URL(request.url());
      if (url.origin === runtime.opsOrigin && url.pathname === '/api/v2/auth/privado/start') nativeStartRequests++;
      if (url.origin === runtime.walletOrigin && url.pathname === '/prove') walletProofRequests++;
    });
    await page.getByTestId('demo-persona-admin').waitFor();
    assert.equal(await page.getByTestId('manual-wallet-login').getAttribute('open'), null);
    assert.equal(await page.getByRole('button', { name: 'Continue with Privado ID', exact: true }).count(), 0);
    assert.equal(await page.getByRole('button', { name: /^Demo (Admin|Deployer|Reader|Outsider)$/ }).count(), 4);
    await page.getByText('Use a wallet manually', { exact: true }).click();
    assert.equal(await page.getByRole('button', { name: 'Continue with Privado ID', exact: true }).count(), 1);
    await page.getByText('Use a wallet manually', { exact: true }).click();
    await page.setViewportSize({ width: 390, height: 844 });
    assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth));
    await page.screenshot({ path: path.join(output, 'first-use-mobile-entry.png'), fullPage: true });
    await page.setViewportSize({ width: 1280, height: 900 });
    await page.screenshot({ path: path.join(output, 'first-use-entry.png'), fullPage: true });
    const opened = page.waitForEvent('popup'); await page.getByTestId('demo-persona-admin').click(); const child = await opened;
    await child.locator('#details-button').waitFor({ state: 'visible' });
    // Reproduce a user reading Chrome's warning for longer than the old 15s
    // timeout. No wallet certificate exception was established beforehand.
    await page.waitForTimeout(17000);
    assert.equal(child.isClosed(), false); assert.equal(nativeStartRequests, 0); assert.equal(walletProofRequests, 0); assert.equal(data.completes.length, 0);
    await child.locator('#details-button').click(); await child.locator('#proceed-link').click();
    await child.locator('#status').waitFor(); assert.equal(await child.evaluate(() => !!window.opener), true);
    const item = await finish(page, data, 'admin');
    await child.waitForEvent('close', { timeout: 10000 }).catch(() => { assert.equal(child.isClosed(), true); });
    assert.equal(nativeStartRequests, 1); assert.equal(walletProofRequests, 1); assert.equal(data.starts.length, 1); assert.equal(data.completes.length, 1);
    results.push({ case: stage, passed: true, ...item, certificateWaitMilliseconds: 17000, nativeStartRequestsBeforeCertificateAcceptance: 0, walletProofRequestsBeforeCertificateAcceptance: 0, nativeStartRequests, walletProofRequests, httpsErrorBypass: false });
    await c.close(); console.log('PASS ' + stage);
  }
  if (selectedCase === 'all') {
  stage = 'untrusted-certificate';
  const untrusted = await context(), untrustedPage = await untrusted.newPage(); let starts = 0;
  untrustedPage.on('request', request => { if (request.method() === 'POST') starts++; });
  await assert.rejects(untrustedPage.goto(runtime.walletOrigin + '/bridge#' + 'a'.repeat(64), { timeout: 15000 }), /ERR_CERT_AUTHORITY_INVALID/);
  assert.equal(starts, 0); results.push({ case: stage, passed: true, proofStarts: 0, httpsErrorBypass: false }); await untrusted.close();
  for (const persona of ['admin', 'deployer', 'reader', 'outsider']) {
    stage = persona + '-button-only'; const c = await context(), page = await trustedOPS(c), data = observe(page);
    const popup = page.waitForEvent('popup'); await page.getByTestId('demo-persona-' + persona).click(); const child = await popup;
    const item = await finish(page, data, persona);
    await child.waitForEvent('close', { timeout: 10000 }).catch(() => { assert.equal(child.isClosed(), true); });
    results.push({ case: stage, passed: true, ...item, httpsErrorBypass: false }); await c.close(); console.log('PASS ' + stage);
  }
  stage = 'blocked-popup';
  { const c = await context(); await c.addInitScript(() => { window.open = () => null; }); const page = await trustedOPS(c), data = observe(page);
    await page.getByTestId('demo-persona-admin').click(); await page.getByText('The demo wallet could not open. Allow this local popup, then try again.', { exact: true }).waitFor();
    assert.equal(data.starts.length, 0); assert.equal(data.completes.length, 0); results.push({ case: stage, passed: true }); await c.close(); }
  }
  if (selectedCase === 'all' || selectedCase === 'cancel-then-different-persona') {
  stage = 'cancel-then-different-persona';
  { const c = await context(), page = await trustedOPS(c), data = observe(page);
    let held, release; const candidateHeld = new Promise(resolve => { held = resolve; }); const released = new Promise(resolve => { release = resolve; }); let first = true;
    await page.route(runtime.opsOrigin + '/api/v2/auth/privado/preview', async route => {
      try {
        const response = await route.fetch(), value = await response.json();
        if (first && value.status === 'candidate') { first = false; held(); await released; }
        await route.fulfill({ response }).catch(() => {});
      } catch { await route.abort().catch(() => {}); }
    });
    await page.getByTestId('demo-persona-admin').click();
    let candidateTimer;
    try { await Promise.race([candidateHeld, new Promise((_, reject) => { candidateTimer = setTimeout(() => reject(Error('candidate not held')), 150000); })]); }
    finally { clearTimeout(candidateTimer); }
    await page.getByRole('button', { name: 'Cancel demo sign in', exact: true }).click();
    await page.getByTestId('demo-persona-reader').click(); release();
    await finish(page, data, 'reader');
    const expectedReader = metadata.personas.find(p => p.id === 'reader');
    const readerCandidate = data.candidates.find(x => x.holderDid === expectedReader.holderDid);
    assert.ok(readerCandidate, 'the reader holder must actually be verified');
    assert.ok(data.completes.every(x => x.actorId === readerCandidate.actorId), 'the canceled admin must never complete');
    results.push({ case: stage, passed: true }); await c.close(); }
  }
  await writeFile(path.join(output, resultsFile), JSON.stringify({ passed: true, cases: results.length, httpsErrorBypass: false, certificateLeafSHA256: leaf.fingerprint256, results }, null, 2) + '\n');
  console.log('PASS ' + results.length + ' actual demo-login cases');
} catch (error) {
  for (const [i, c] of contexts.entries()) for (const [j, page] of c.pages().entries()) {
    if (!page.isClosed()) {
      await page.screenshot({ path: path.join(output, 'failure-' + i + '-' + j + '.png'), fullPage: true }).catch(() => {});
      const visible = await page.locator('body').innerText({ timeout: 1000 }).catch(() => '');
      await writeFile(path.join(output, 'failure-' + i + '-' + j + '.txt'), visible);
    }
  }
  await writeFile(path.join(output, resultsFile), JSON.stringify({ passed: false, stage, completed: results, category: error.name }, null, 2) + '\n');
  console.error('FAIL demo-login stage=' + stage + ' category=' + error.name); process.exitCode = 1;
} finally { for (const c of contexts) await c.close().catch(() => {}); await browser.close(); }
