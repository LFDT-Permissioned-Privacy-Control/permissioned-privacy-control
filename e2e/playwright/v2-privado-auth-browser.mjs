import assert from 'node:assert/strict'
import { chromium } from '@playwright/test'

// This driver uses the owned real Go/PG/provider harness, never a mock grant.
const [origin, seconds] = process.argv.slice(2)
assert.match(origin ?? '', /^https:\/\/ops\.test:[0-9]+$/)
assert.match(seconds ?? '', /^[0-9]+$/)
const walletOrigin = origin.replace('ops.test', 'wallet.test')
const markerKey = 'ops-v2.browser-context'
const browser = await chromium.launch({ channel: 'chrome', headless: true,
  args: ['--host-resolver-rules=MAP ops.test 127.0.0.1,MAP wallet.test 127.0.0.1', '--no-proxy-server'] })
const context = await browser.newContext({ ignoreHTTPSErrors: true }) // Owned test certificate ONLY.
let cases = 0
const run = (page, name, ...args) => page.evaluate(async ({ name, args }) => {
  try { return { ok: true, value: await window.multiAuthHarness[name](...args) } }
  catch (error) { return { ok: false, code: error.code ?? 'unexpected_error' } }
}, { name, args })
const call = async (page, name, ...args) => {
  const value = await run(page, name, ...args)
  assert.equal(value.ok, true, `${name}: ${value.code}`)
  return value.value
}
const deny = async (page, name, args = [], code) => {
  const value = await run(page, name, ...args)
  assert.equal(value.ok, false, `${name} unexpectedly succeeded`)
  if (code) assert.equal(value.code, code, name)
}
const load = async page => {
  await page.goto(origin + '/auth/complete')
  await page.waitForFunction(() => !!window.multiAuthHarness)
}
const marker = page => page.evaluate(key => JSON.parse(localStorage.getItem(key)), markerKey)
const control = (page, body) => page.evaluate(async body => {
  const response = await fetch('/__test/control', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) })
  if (!response.ok) throw new Error('owned_fixture_control')
  return response.status === 204 ? null : response.json()
}, body)
const apiCount = async (page, path) => (await call(page, 'requests')).filter(r => r.path === '/api/v2/auth/' + path).length
const cookies = async () => (await context.cookies(origin)).map(c => ({ name: c.name, value: c.value })).sort((a, b) => a.name.localeCompare(b.name))
const confirm = async page => {
  await page.locator('#confirm-privado').click()
  await page.waitForFunction(() => ['complete', 'error'].includes(window.multiAuthHarness.confirmationResult().status))
  const result = await call(page, 'confirmationResult')
  assert.equal(result.status, 'complete', result.code)
  return result.session
}
const note = label => { cases++; process.stdout.write(`PASS ${label}\n`) }

try {
  process.stdout.write(`Owned Chrome ${browser.version()} / Playwright1.58.0\n`)
  const a = await context.newPage(), b = await context.newPage(), wallet = await context.newPage()
  await load(a); await load(b); await wallet.goto(walletOrigin + '/__test/wallet')
  const fixture = await a.evaluate(async () => (await fetch('/__test/config')).json())
  const { profileId, holderA, holderB } = fixture
  assert.equal(typeof profileId, 'string'); assert.match(holderA, /^did:/); assert.notEqual(holderA, holderB)
  const providers = await call(a, 'providers')
  assert.equal(providers.profiles.find(p => p.id === profileId)?.provider, 'privado')

  const offer = async (page, flow, holder = 'a') => {
    // Proving is OUTSIDE the browser WebLock. The actual pinned JS client lives
    // in the owned fixture process; this does not manufacture a VerifiedProof.
    const producing = control(page, { action: 'proof', requestId: flow.requestId, holder })
    await call(b, 'providers') // Another tab remains usable while proving.
    const proof = await producing
    const ack = await wallet.evaluate(async ({ target, compact }) => {
      const response = await fetch(target, { method: 'POST', credentials: 'omit',
        headers: { 'Content-Type': 'text/plain' }, body: compact })
      return { status: response.status, body: await response.text() }
    }, { target: origin + '/api/v2/auth/privado/proofs/' + flow.requestId, compact: proof.compact })
    assert.deepEqual(ack, { status: 200, body: '' })
  }
  const preview = async (page, flow, expectedHolder) => {
    const value = await call(page, 'preview', flow.requestId)
    assert.equal(value.status, 'candidate'); assert.equal(value.holderDid, expectedHolder)
    assert.equal(await page.locator('[data-field=holderDid]').textContent(), expectedHolder)
    assert.equal(await page.locator('[data-field=network]').textContent(), value.network)
    assert.equal(await page.locator('[data-field=provider]').textContent(), 'Privado')
    assert.equal(await page.locator('[data-field=sourceProfile]').textContent(), profileId)
    return value
  }
  const login = async (page, holder = 'a') => {
    const flow = await call(page, 'startPrivado', profileId)
    await offer(page, flow, holder); await preview(page, flow, holder === 'a' ? holderA : holderB)
    return confirm(page)
  }

  let flow = await call(a, 'startPrivado', profileId)
  const publicRequest = await wallet.evaluate(async target => {
    const r = await fetch(target, { credentials: 'omit' })
    return { status: r.status, json: await r.json() }
  }, flow.requestUri)
  assert.equal(publicRequest.status, 200)
  assert.equal(typeof publicRequest.json, 'object')
  const beforeInclude = await cookies()
  assert.equal(await wallet.evaluate(async target => {
    try { await fetch(target, { credentials: 'include' }); return 'readable' } catch { return 'unreadable' }
  }, flow.requestUri), 'unreadable')
  for (const path of ['preview', 'complete', 'renew', 'logout']) {
    assert.equal(await wallet.evaluate(async target => {
      try { await fetch(target, { method: 'POST', credentials: 'include', headers: { 'Content-Type': 'application/json' }, body: '{}' }); return 'readable' }
      catch { return 'unreadable' }
    }, origin + '/api/v2/auth/' + (['preview', 'complete'].includes(path) ? 'privado/' : '') + path), 'unreadable')
  }
  assert.deepEqual(await cookies(), beforeInclude)
  note('separate-origin public request is readable without credentials; credentialed/public and every private cross-origin path remain unreadable')

  const starts = await apiCount(a, 'privado/start')
  await a.reload(); await a.waitForFunction(() => !!window.multiAuthHarness)
  const restored = await call(a, 'restore')
  assert.equal(restored.status, 'login_in_progress'); assert.equal(restored.requestId, flow.requestId)
  assert.equal(await apiCount(a, 'privado/start'), 0)
  assert.equal(starts, 1)
  await offer(a, flow)
  await a.reload(); await a.waitForFunction(() => !!window.multiAuthHarness)
  assert.equal((await call(a, 'restore')).requestId, flow.requestId)
  const beforeConfirm = await cookies()
  await preview(a, flow, holderA)
  assert.deepEqual(await cookies(), beforeConfirm) // Preview never delivers credentials.
  const first = await confirm(a)
  assert.equal(first.provider, 'privado'); assert.equal(first.sourceProfile, profileId)
  assert.equal((await call(a, 'own', first)).status, 'completed')
  assert.equal(await a.evaluate(() => document.cookie), '')
  for (const c of await context.cookies(origin)) { assert.equal(c.httpOnly, true); assert.equal(c.secure, true); assert.equal(c.sameSite, 'Lax'); assert.equal(c.path, '/') }
  note('reload before and after proof resumes one PUBLIC UUID; full holder identity requires explicit confirmation before access')

  const cookieBeforeRenew = await cookies()
  const renews = await apiCount(a, 'renew')
  const pending = await call(a, 'restore')
  assert.equal(pending.status, 'proof_required'); assert.equal(pending.browserSessionId, first.browserSessionId)
  assert.deepEqual(await cookies(), cookieBeforeRenew)
  const [again, other] = await Promise.all([call(a, 'need', first), call(b, 'restore')])
  assert.equal(again.requestId, pending.requestId); assert.equal(other.requestId, pending.requestId)
  assert.equal((await call(b, 'own', first)).status, 'proof_required')
  assert.equal(await apiCount(a, 'renew'), renews + 1); assert.equal(await apiCount(b, 'renew'), 0)
  await b.reload(); await b.waitForFunction(() => !!window.multiAuthHarness)
  assert.equal((await call(b, 'restore')).requestId, pending.requestId)
  await offer(a, pending); await preview(b, pending, holderA)
  const renewed = await confirm(b)
  assert.deepEqual(renewed, first)
  assert.equal((await call(b, 'own', renewed)).status, 'completed')
  const markerValue = await marker(b)
  assert.equal(markerValue.version, 2); assert.equal(markerValue.pendingFlow, null)
  for (const forbidden of ['accessToken', 'proofDigest', 'holderDid', 'nonce', 'roles']) assert.equal(JSON.stringify(markerValue).includes(forbidden), false)
  note('fresh same-family proof renewal has ZERO pending cookie rotation/business work, reuses one UUID across tabs/reload, then rotates once after explicit completion')

  flow = await call(a, 'startPrivado', profileId)
  const noGrantCookies = await cookies()
  await offer(a, flow, 'b'); await preview(a, flow, holderB)
  assert.deepEqual(await cookies(), noGrantCookies)
  await a.locator('#reject-privado').click()
  await a.waitForFunction(key => JSON.parse(localStorage.getItem(key)).pendingFlow === null, markerKey)
  await a.reload(); await a.waitForFunction(() => !!window.multiAuthHarness)
  await deny(a, 'restore', [], 'login_required')
  assert.equal(await apiCount(a, 'renew'), 0)
  note('first valid public holderB cannot inject an account: full DID is displayed and Reject prevents credential/reload adoption')

  const oldFamily = await login(a)
  const oldMarker = await marker(a)
  const replacement = await login(b)
  assert.equal(oldFamily.actorId, replacement.actorId); assert.notEqual(oldFamily.browserSessionId, replacement.browserSessionId)
  const beforeStale = await call(a, 'requests'), replacementMarker = await marker(b)
  await deny(a, 'own', [oldFamily], 'session_changed')
  await deny(a, 'logout', [oldFamily], 'session_changed')
  assert.deepEqual(await call(a, 'requests'), beforeStale)
  assert.deepEqual(await marker(b), replacementMarker)
  assert.equal((await call(b, 'own', replacement)).status, 'completed')
  note('same Actor/new family replacement rejects stale cached tab work/logout before HTTP and preserves current family')

  // A restored NONcredential marker must not turn cookieB into an unbound
  // bootstrap/adoption. Exercise the real server's expected-pair gate too.
  await a.evaluate(({ key, value }) => localStorage.setItem(key, JSON.stringify(value)), { key: markerKey, value: oldMarker })
  await call(a, 'reset')
  const beforeWrongCookie = await cookies()
  await deny(a, 'restore', [], 'session_changed')
  assert.deepEqual(await cookies(), beforeWrongCookie)
  assert.equal((await marker(a)).phase, 'require-login')
  await b.evaluate(({ key, value }) => localStorage.setItem(key, JSON.stringify(value)), { key: markerKey, value: replacementMarker })
  const stillCurrent = await call(b, 'restore')
  assert.equal(stillCurrent.status, 'proof_required')
  assert.equal(stillCurrent.browserSessionId, replacement.browserSessionId)
  assert.deepEqual(await cookies(), beforeWrongCookie)
  note('markerA/cookieB rejects through the real expected-family gate without bootstrap, cookie mutation or revoking B')

  flow = await call(b, 'restore')
  assert.equal(flow.status, 'proof_required')
  await call(b, 'logout', replacement)
  assert.equal((await marker(b)).pendingFlow, null)
  await deny(b, 'preview', [flow.requestId], 'login_required')
  await b.reload(); await b.waitForFunction(() => !!window.multiAuthHarness)
  await deny(b, 'restore', [], 'login_required')
  assert.equal(await apiCount(b, 'renew'), 0)
  note('logout during renewal invalidates continuation; no old callback/UUID or reload can bootstrap it back')

  const current = await login(b)
  flow = await call(b, 'restore'); await offer(b, flow); await preview(b, flow, holderA)
  await control(b, { action: 'fault', kind: 'lost-complete' })
  await b.locator('#confirm-privado').click()
  await b.waitForFunction(() => window.multiAuthHarness.confirmationResult().status === 'error')
  assert.equal((await marker(b)).phase, 'require-login'); assert.equal((await marker(b)).pendingFlow, null)
  await b.reload(); await b.waitForFunction(() => !!window.multiAuthHarness)
  await deny(b, 'restore', [], 'login_required')
  assert.equal(await apiCount(b, 'renew'), 0)
  assert.equal((await login(b)).actorId, current.actorId)
  note('ambiguous final completion leaves hard-denied context across reload; only explicit fresh login recovers')

  const beforeStorage = await call(b, 'requests')
  await b.evaluate(() => { window.savedStorageSet = Storage.prototype.setItem; Storage.prototype.setItem = () => { throw new DOMException('fixture denied', 'SecurityError') } })
  await deny(b, 'restore', [], 'unsupported_browser')
  assert.deepEqual(await call(b, 'requests'), beforeStorage)
  await b.evaluate(() => { Storage.prototype.setItem = window.savedStorageSet })
  note('storage failure denies before any cookie/provider work; proof/access is never persisted')

  process.stdout.write(`PASS ${cases} real multi-provider browser qualification cases\n`)
} finally { await context.close(); await browser.close() }
