import assert from 'node:assert/strict'
import { chromium } from '@playwright/test'
import { browserChannel } from './v2-browser-options.mjs'

const [ops, app, kind, instant] = process.argv.slice(2)
assert.match(ops ?? '', /^https:\/\/ops\.test:[0-9]+$/)
assert.match(app ?? '', /^https:\/\/app\.test:[0-9]+$/)
assert.ok(['azure', 'privado'].includes(kind))
const browser = await chromium.launch({ channel: browserChannel, headless: true, args: ['--host-resolver-rules=MAP ops.test 127.0.0.1,MAP app.test 127.0.0.1,MAP wallet.test 127.0.0.1', '--no-proxy-server'] })
const context = await browser.newContext({ ignoreHTTPSErrors: true }) // Owned fixture TLS only.
const localOPS = ops.replace('ops.test', '127.0.0.1'), localAPP = app.replace('app.test', '127.0.0.1')
const controls = { ops: { Origin: ops, Host: new URL(ops).host }, app: { Origin: app, Host: new URL(app).host } }
const paths = [], lifecycle = [], responses = []
context.on('request', r => paths.push(new URL(r.url()).pathname))
context.on('response', r => { responses.push({ path: new URL(r.url()).pathname, status: r.status() }); if (responses.length > 32) responses.shift() })
await context.exposeBinding('__e2bLifecycle', ({ page }, event) => { lifecycle.push({ page, ...event }) })
await context.addInitScript(() => { for (const type of ['pagehide','pageshow']) addEventListener(type, event => { queueMicrotask(() => { void window.__e2bLifecycle({ type, persisted: event.persisted, privateCount: document.querySelectorAll('[data-field=app-actor]').length }).catch(() => undefined) }) }) })
let stage = 'startup', cases = 0, subject = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
const note = label => { cases++; process.stdout.write(`PASS ${label}\n`) }
const page = await context.newPage()
if (kind === 'azure') await page.clock.install({ time: Date.parse(instant) })
const status = p => p.evaluate(async () => { const r = await fetch('/api/auth/status', { credentials: 'include', cache: 'no-store' }); return r.json() })
const currentActor = async p => { const element = p.locator('[data-field=app-actor]'); await element.waitFor(); return element.textContent() }
const advance = async seconds => {
  assert.equal((await context.request.post(localOPS + '/__test/control', { headers: controls.ops, data: { AdvanceSeconds: seconds } })).status(), 204)
  assert.equal((await context.request.post(localAPP + '/__test/advance', { headers: controls.app, data: { Seconds: seconds } })).status(), 204)
}
let wallet
const offerProof = async () => {
  stage = 'fresh-privado-request'; await page.bringToFront()
  const element = page.locator('[data-field=requestUri]'); await element.waitFor({ state: 'attached' })
  const uri = await element.textContent(); assert.ok(uri.startsWith(ops + '/api/v2/auth/privado/requests/'))
  const produced = await context.request.post(localOPS + '/__test/proof', { headers: controls.ops, data: { RequestID: uri.split('/').pop(), Holder: 'a' }, timeout: 65000 })
  assert.equal(produced.status(), 200); const { compact } = await produced.json()
  assert.equal(await wallet.evaluate(async ({ uri, compact }) => (await fetch(uri.replace('/requests/', '/proofs/'), { method: 'POST', credentials: 'omit', headers: { 'Content-Type': 'text/plain' }, body: compact })).status, { uri, compact }), 200)
  await page.locator('[data-field=holderDid]').waitFor({ timeout: 10000 })
  assert.equal(await page.locator('[data-field=actorId]').count(), 0)
  await page.getByRole('button', { name: 'Use this identity', exact: true }).click()
}
try {
  process.stdout.write(`Owned actual OPS/E1 + Explorer/BFF built Chrome ${browser.version()} / ${kind}; history DTOs not qualified by fixture echo\n`)
  if (kind === 'azure') await context.route('https://login.microsoftonline.com/**', async route => {
    const u = new URL(route.request().url())
    assert.equal((await context.request.post(localOPS + '/__test/control', { headers: controls.ops, data: { AuthorizationURL: u.href, Subject: subject } })).status(), 204)
    const callback = new URL(ops + '/auth/azure/callback'); callback.searchParams.set('state', u.searchParams.get('state')); callback.searchParams.set('code', 'owned-browser-code')
    await route.fulfill({ status: 302, headers: { Location: callback.href }, body: '' })
  })
  stage = 'public-setup'; await page.goto(app)
  await page.getByRole('button', { name: 'Sign in', exact: true }).waitFor()
  const setup = await page.evaluate(async () => (await fetch('/api/chain-info')).json())
  assert.equal(setup.protocol, 'ops-v2'); assert.equal(typeof setup.chainIdDecimal, 'string'); assert.equal(Object.keys(setup).length, 6)
  assert.equal(await page.getByText('Node is fully synced', { exact: true }).count(), 0); note('public approved setup has no invented live status')
  stage = 'initial-login'; await page.getByRole('button', { name: 'Sign in', exact: true }).click()
  stage = 'initial-provider-choice'; await page.getByRole('button', { name: new RegExp('Sign in with ' + (kind === 'azure' ? 'Azure' : 'Privado')) }).click()
  if (kind === 'privado') { wallet = await context.newPage(); await wallet.goto(ops.replace('ops.test', 'wallet.test') + '/__test/wallet'); await offerProof() }
  stage = 'initial-explicit-handoff'; await page.getByRole('button', { name: 'Continue to application', exact: true }).click()
  stage = 'initial-app-callback'
  await page.waitForURL(app + '/')
  const a = await currentActor(page), original = await status(page)
  assert.equal(original.did, a); assert.equal(original.protocol, 'ops-v2'); assert.ok(original.session_id)
  const cookies = await context.cookies(app)
  for (const cookie of cookies.filter(c => c.name.startsWith('__Host-explorer-'))) { assert.ok(cookie.secure && cookie.httpOnly); assert.equal(cookie.path, '/'); assert.ok(cookie.name === '__Host-explorer-oauth' ? cookie.value.length <= 3596 : cookie.value.length === 43); assert.ok(cookie.value.split('.').length !== 3 || cookie.name === '__Host-explorer-oauth') }
  assert.equal(await page.evaluate(() => document.cookie), ''); note('actual signed provider/E1 callback stores only opaque browser cookies')
  stage = 'owned-renewal'
  if (kind === 'azure') { await advance(295); await page.clock.fastForward(295000) }
  else { await page.getByRole('button', { name: 'Refresh identity', exact: true }).click(); await offerProof(); await page.getByRole('button', { name: 'Continue to application', exact: true }).click() }
  await page.waitForURL(url => url.origin === app && url.pathname === '/')
  await page.waitForFunction(previous => !!document.querySelector('[data-field=app-actor]') && !document.body.textContent.includes('Checking your session'), original.session_id)
  // Wait for a genuinely new server activation, not merely a reload of A.
  for (let i = 0; i < 100; i++) { const value = page.url().startsWith(app) ? await status(page).catch(() => null) : null; if (value?.session_id && value.session_id !== original.session_id) break; await page.waitForTimeout(50) }
  const renewed = await status(page); assert.equal(renewed.did, a); assert.equal(renewed.source_profile, original.source_profile); assert.notEqual(renewed.session_id, original.session_id); assert.ok(renewed.expires_at > original.expires_at)
  note(kind === 'azure' ? 'owned same Azure pair genuinely refreshes and returns without another human Continue' : 'owned Privado renewal requires another genuine fresh proof and explicit holder confirmation')
  if (kind === 'azure') {
  stage = 'account-switch'; const other = await context.newPage(); await other.clock.install({ time: Date.parse(instant) + 295000 }); await other.goto(ops + '/login')
  subject = 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb'
  await other.getByRole('button', { name: /Sign in with Azure/ }).click(); await other.locator('[data-field=actorId]').waitFor()
  await other.goto(app); await other.getByRole('button', { name: 'Switch account', exact: true }).click(); await other.getByRole('button', { name: 'Continue to application', exact: true }).click(); await other.waitForURL(app + '/')
  const b = await currentActor(other), switched = await status(other); assert.notEqual(b, a)
  await page.bringToFront(); await page.getByRole('button', { name: 'Use the current app session', exact: true }).waitFor(); assert.equal(await page.locator('[data-field=app-actor]').count(), 0)
  const stale = await page.evaluate(async old => { const r = await fetch('/__test/private', { headers: { 'X-OPS-App-Session': old }, credentials: 'include' }); return { status: r.status, body: await r.text() } }, renewed.session_id)
  assert.equal(stale.status, 409); assert.ok(!stale.body.includes(a) && !stale.body.includes(b)); note('cross-tab activation changes clear private DOM and refuse stale caller scope')
  await page.getByRole('button', { name: 'Use the current app session', exact: true }).click(); assert.equal(await currentActor(page), b)
  const privateEcho = await page.evaluate(async activation => { const r = await fetch('/__test/private', { headers: { 'X-OPS-App-Session': activation }, credentials: 'include' }); return r.json() }, switched.session_id)
  assert.equal(privateEcho.actor, b); assert.match(privateEcho.tokenDigest, /^[0-9a-f]{64}$/); note('only explicit adoption publishes the new verified app context')
  stage = 'stale-logout'; const staleLogout = await page.evaluate(async activation => { const r = await fetch('/api/auth/logout', { method: 'POST', credentials: 'include', headers: { 'Content-Type': 'application/json', 'X-OPS-App-Session': activation }, body: '{}' }); return r.status }, renewed.session_id)
  assert.equal(staleLogout, 409); assert.equal((await status(page)).session_id, switched.session_id); note('stale logout cannot clear another activation')
  stage = 'actual-away-back-expiry'; const lifecycleStart = lifecycle.length
  await page.evaluate(() => addEventListener('pagehide', event => { const value = { type: 'after-clear', persisted: event.persisted, privateCount: document.querySelectorAll('[data-field=app-actor]').length }; sessionStorage.setItem('__owned-e2b-lifecycle', JSON.stringify(value)); void window.__e2bLifecycle(value).catch(() => undefined) }, { once: true }))
  await page.goto(ops + '/__test/away'); await advance(301); await page.clock.fastForward(301000); await page.goBack()
  await page.getByRole('button', { name: 'Sign in', exact: true }).waitFor(); assert.equal(await page.locator('[data-field=app-actor]').count(), 0)
  const observed = lifecycle.slice(lifecycleStart).filter(event => event.page === page)
  const durableObservation = await page.evaluate(() => { const value = sessionStorage.getItem('__owned-e2b-lifecycle'); sessionStorage.removeItem('__owned-e2b-lifecycle'); return value === null ? null : JSON.parse(value) })
  if (durableObservation) observed.push(durableObservation)
  process.stdout.write(`Observed actual lifecycle=${JSON.stringify(observed.map(({type,persisted,privateCount})=>({type,persisted,privateCount})))}\n`)
  stage = 'actual-pagehide-private-dom'
  assert.ok(observed.some(event => event.type === 'after-clear' && event.privateCount === 0))
  assert.ok(observed.filter(event => event.type === 'after-clear').every(event => event.privateCount === 0))
  note('actual Chrome away/back clears private DOM before suspension and refuses the original expired token')
  process.stdout.write(`Observed actual pageshow.persisted=${JSON.stringify(observed.filter(event => event.type === 'pageshow').map(event => event.persisted))}; no synthetic BFCache claim\n`)
  await page.getByRole('button', { name: 'Sign in', exact: true }).click(); await page.waitForURL(app + '/'); assert.equal(await currentActor(page), b)
  stage = 'local-logout'; await page.getByRole('button', { name: 'Sign out', exact: true }).click(); await page.getByRole('button', { name: 'Sign in', exact: true }).waitFor(); assert.equal((await status(page)).authenticated, false)
  await other.goto(ops + '/login'); await other.locator('[data-field=actorId]').waitFor(); note('app logout clears app state without revoking the genuine OPS family')
  } else {
    const staleLogout = await page.evaluate(async activation => (await fetch('/api/auth/logout', { method: 'POST', credentials: 'include', headers: { 'Content-Type': 'application/json', 'X-OPS-App-Session': activation }, body: '{}' })).status, original.session_id)
    assert.equal(staleLogout, 409); assert.equal((await status(page)).session_id, renewed.session_id); note('stale pre-proof activation cannot clear its renewed successor')
    await page.getByRole('button', { name: 'Sign out', exact: true }).click(); await page.getByRole('button', { name: 'Sign in', exact: true }).waitFor(); assert.equal((await status(page)).authenticated, false); note('Privado app logout clears operational app authority')
  }
  assert.ok(!paths.some(p => p.startsWith('/oauth/') || p.includes('/impersonation') || p.includes('/users')))
  process.stdout.write(`PASS ${cases} actual cross-origin enterprise app cases; no history delivery claim\n`)
} catch (error) { process.stderr.write(`FAIL stage=${stage} category=${error?.name ?? 'Error'} statuses=${JSON.stringify(responses)}\n`); process.exitCode = 1 }
finally { await context.close(); await browser.close() }
