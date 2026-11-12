import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { chromium } from '@playwright/test'
import { browserChannel } from './v2-browser-options.mjs'

const [origin, kind, instant] = process.argv.slice(2)
assert.match(origin ?? '', /^https:\/\/ops\.test:[0-9]+$/)
assert.ok(['azure', 'privado'].includes(kind))
assert.ok(Number.isFinite(Date.parse(instant)))
const browser = await chromium.launch({ channel: browserChannel, headless: true,
  args: ['--host-resolver-rules=MAP ops.test 127.0.0.1,MAP wallet.test 127.0.0.1', '--no-proxy-server'] })
const context = await browser.newContext({ ignoreHTTPSErrors: true }) // Owned TLS certificate only.
let cases = 0
let stage = 'startup'
const paths = [], errors = []
const lifecycle = []
const localOrigin = origin.replace('ops.test', '127.0.0.1')
const controlHeaders = { Origin: origin, Host: new URL(origin).host }
context.on('request', r => paths.push(new URL(r.url()).pathname))
context.on('page', page => page.on('pageerror', e => errors.push(e.name)))
await context.exposeBinding('__ownedPageLifecycle', ({ page }, event) => { lifecycle.push({ page, ...event }) })
await context.addInitScript(() => {
  for (const type of ['pagehide','pageshow']) addEventListener(type, event => {
    void window.__ownedPageLifecycle({ type, persisted: event.persisted }).catch(() => undefined)
  })
})
const note = label => { cases++; process.stdout.write(`PASS ${label}\n`) }
const makePage = async () => {
  const page = await context.newPage()
  if (kind === 'azure') await page.clock.install({ time: Date.parse(instant) })
  return page
}
const loaded = async page => {
  await page.goto(origin + '/login')
  await page.getByRole('button', { name: new RegExp('Sign in with ' + (kind === 'azure' ? 'Azure' : 'Privado')) }).waitFor()
}
const actor = async page => {
  const element = page.locator('[data-field=actorId]'); await element.waitFor(); return element.textContent()
}
const storageClean = async page => {
  const storage = await page.evaluate(() => ({ local: { ...localStorage }, session: { ...sessionStorage }, cookie: document.cookie }))
  assert.equal(storage.cookie, '')
  assert.ok(Object.keys(storage.local).every(k => k === 'ops-v2.browser-context'))
  assert.ok(Object.keys(storage.session).every(k => k === 'ops-v2.sso-continuation'))
  assert.ok(!/accessToken|refreshToken|access_token|refresh_token|proofDigest|code_verifier/.test(JSON.stringify(storage)))
}

try {
  process.stdout.write(`Owned built V2 UI / Chrome ${browser.version()} / Playwright1.58.0 / ${kind}\n`)
  const a = await makePage(), b = await makePage()
  if (kind === 'azure') {
    let subject = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
    await context.route('https://login.microsoftonline.com/**', async route => {
      try {
      const u = new URL(route.request().url())
      const prepared = await context.request.post(localOrigin + '/__test/control', {
        headers: controlHeaders, data: { AuthorizationURL: u.href, Subject: subject } })
      assert.equal(prepared.status(), 204)
      const callback = new URL(origin + '/auth/azure/callback')
      callback.searchParams.set('state', u.searchParams.get('state')); callback.searchParams.set('code', 'owned-browser-code')
      await route.fulfill({ status: 302, headers: { Location: callback.href }, body: '' })
      } catch { errors.push('owned_provider_control'); await route.abort().catch(() => undefined) }
    })
    const login = async page => { await page.getByRole('button', { name: /Sign in with Azure/ }).click(); return actor(page) }
    await loaded(a); const first = await login(a)
    assert.ok(first.startsWith('ops:p1:'))
    assert.equal(await a.getByRole('region', { name: 'Current account' }).locator('li').count(), 2)
    assert.ok(new URL(a.url()).search === '' && new URL(a.url()).pathname === '/auth/azure/callback')
    assert.equal(await a.evaluate(() => isSecureContext && !!navigator.locks), true)
    await storageClean(a)
    note('shipped Azure entry performs actual signed code exchange, synchronously removes callback query and renders Core verified own facts')

    const before = paths.filter(p => p === '/api/v2/auth/renew').length
    await loaded(b); assert.equal(await actor(b), first)
    assert.equal(paths.filter(p => p === '/api/v2/auth/renew').length, before + 1)
    note('new built document genuinely renews once; React StrictMode does not duplicate restoration')

    subject = 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb'
    const second = await login(b); assert.notEqual(first, second)
    await a.getByRole('heading', { name: 'The account changed in another tab' }).waitFor()
    assert.equal(await a.locator('[data-field=actorId]').count(), 0)
    await a.getByRole('button', { name: 'Use current session' }).click()
    assert.equal(await actor(a), second)
    note('account replacement clears old private display and requires explicit current-session acceptance')

    // Real recipient-bound E1 authorize -> shipped SSO page -> one complete ->
    // registered callback. E2b qualifies the actual app BFF separately.
    const verifier = 'v'.repeat(43), state = 'owned-sso-state+%&'
    const challenge = createHash('sha256').update(verifier).digest('base64url')
    const start = new URL(origin + '/api/v2/sso/authorize')
    for (const [key, value] of Object.entries({ client_id: 'app-a', redirect_uri: 'https://app.test/callback', response_type: 'code', state, code_challenge: challenge, code_challenge_method: 'S256' })) start.searchParams.set(key, value)
    let received = null
    await context.route('https://app.test/callback?**', async route => {
      const u = new URL(route.request().url())
      received = { code: u.searchParams.get('code'), state: u.searchParams.get('state') }
      await route.fulfill({ status: 200, contentType: 'text/html', body: '<!doctype html><title>Owned app callback checkpoint</title>' })
    })
    await a.goto(start.href)
    await a.getByRole('button', { name: 'Continue to application' }).waitFor()
    await a.getByRole('button', { name: 'Continue to application' }).click()
    await a.waitForURL(u => u.hostname === 'app.test')
    assert.ok(received && /^[A-Za-z0-9_-]{43}$/.test(received.code) && received.state === state)
    assert.equal(paths.filter(p => p === '/api/v2/sso/flow').length >= 2, true)
    note('actual E1 recipient/PKCE flow is inspected and explicitly completed once through the built page')

    // Real browser navigation, not a claim that Chrome grants BFCache to this
    // particular WebLocks/HTTP fixture. Both full reload and persisted return
    // must genuinely reverify after the original token expires while away.
    stage = 'actual navigate-away/back lifecycle'
    await b.goto(origin + '/auth/complete'); assert.equal(await actor(b), second)
    await b.evaluate(() => {
      // Registered AFTER the production handler: observe actual DOM after its
      // synchronous suspension clear, without exposing any identity contents.
      addEventListener('pagehide', event => {
        void window.__ownedPageLifecycle({ type: 'after-clear', persisted: event.persisted,
          privateNodes: document.querySelectorAll('[data-field=actorId],[data-field=holderDid]').length }).catch(() => undefined)
      }, { once: true })
    })
    const renewBeforeReturn = paths.filter(p => p === '/api/v2/auth/renew').length
    await b.goto(origin + '/__test/away') // Owned 404, no authentication code.
    const advanced = await context.request.post(localOrigin + '/__test/control', { headers: controlHeaders, data: { AdvanceSeconds: 301 } })
    assert.equal(advanced.status(), 204)
    await b.clock.setSystemTime(new Date(Date.parse(instant) + 301000))
    await b.goBack(); assert.equal(await actor(b), second)
    assert.ok(paths.filter(p => p === '/api/v2/auth/renew').length > renewBeforeReturn)
    assert.ok(lifecycle.some(e => e.page === b && e.type === 'after-clear' && e.privateNodes === 0))
    const observedPersisted = lifecycle.some(e => e.page === b && e.type === 'pageshow' && e.persisted)
    note(`actual built navigate-away/back after original expiry genuinely renews; observed pageshow.persisted=${observedPersisted}`)

    // A callback reload is never reconstructed from a renewal cookie.
    await b.goto(origin + '/auth/azure/callback?state=bad&code=never-log')
    await b.getByRole('alert').waitFor(); assert.equal(new URL(b.url()).search, '')
    assert.equal(await b.locator('[data-field=actorId]').count(), 0)
    note('malformed callback scrubs query and fails closed without V1 recovery')
  } else {
    await loaded(a)
    const fixtureResponse = await context.request.get(localOrigin + '/__test/config', { headers: controlHeaders })
    const fixture = await fixtureResponse.json()
    const wallet = await context.newPage(); await wallet.goto(origin.replace('ops.test', 'wallet.test') + '/__test/wallet')
    const flow = async page => {
      stage = 'read public request link'
      const element = page.locator('[data-field=requestUri]'); await element.waitFor({ state: 'attached' })
      const uri = await element.textContent(); assert.ok(uri.startsWith(origin + '/api/v2/auth/privado/requests/'))
      assert.equal(await page.getByRole('link', { name: 'Open mobile wallet' }).getAttribute('href'), 'iden3comm://?request_uri=' + encodeURIComponent(uri))
      assert.equal(await page.getByRole('link', { name: 'Open web wallet' }).getAttribute('href'), 'https://wallet.privado.id/#request_uri=' + encodeURIComponent(uri))
      assert.equal(await page.locator('svg[aria-label="Open the Privado verification request"]').count(), 1)
      return uri
    }
    const offer = async (page, holder = 'a') => {
      await page.bringToFront() // The shipped UI intentionally does not poll a hidden tab.
      const uri = await flow(page), requestId = uri.split('/').pop()
      stage = 'produce actual fresh wallet proof'
      const produced = await context.request.post(localOrigin + '/__test/proof', { headers: controlHeaders, data: { RequestID: requestId, Holder: holder }, timeout: 65000 })
      assert.equal(produced.status(), 200)
      const { compact } = await produced.json()
      stage = 'post separate-origin wallet proof'
      assert.equal(await wallet.evaluate(async ({ uri, compact }) => {
        const response = await fetch(uri.replace('/requests/', '/proofs/'), { method: 'POST', credentials: 'omit', headers: { 'Content-Type': 'text/plain' }, body: compact })
        return response.status
      }, { uri, compact }), 200)
      stage = 'visible OPS tab previews proof'
      await page.locator('[data-field=holderDid]').waitFor({ timeout: 10000 })
      assert.equal(await page.locator('[data-field=holderDid]').textContent(), holder === 'a' ? fixture.holderA : fixture.holderB)
      assert.equal(await page.locator('[data-field=network]').textContent(), (holder === 'a' ? fixture.holderA : fixture.holderB).split(':').slice(2, 4).join(':'))
      assert.equal(await page.locator('[data-field=actorId]').count(), 0)
    }
    await a.getByRole('button', { name: /Sign in with Privado/ }).click()
    const firstURI = await flow(a)
    await a.reload(); await a.locator('[data-field=requestUri]').waitFor({ state: 'attached' }); assert.equal(await flow(a), firstURI)
    await offer(a); assert.equal(await a.locator('[data-field=actorId]').count(), 0)
    await a.getByRole('button', { name: 'Use this identity' }).click(); const first = await actor(a)
    await storageClean(a)
    note('built Privado QR/universal links resume the same UUID after reload; fresh SDK proof shows full holder/network and requires explicit selection')

    await loaded(b); await b.locator('[data-field=requestUri]').waitFor({ state: 'attached' })
    await offer(b); await b.getByRole('button', { name: 'Use this identity' }).click(); assert.equal(await actor(b), first)
    note('new built document requires a fresh same-family Privado proof rather than reconstructing or extending a JWT')

    await b.getByRole('button', { name: /Sign in with Privado/ }).click()
    await offer(b, 'b'); await b.getByRole('button', { name: 'Use this identity' }).click()
    const second = await actor(b); assert.notEqual(second, first)
    await a.getByRole('heading', { name: 'The account changed in another tab' }).waitFor(); assert.equal(await a.locator('[data-field=actorId]').count(), 0)
    note('explicit fresh Privado account selection invalidates the old tab; polling never adopts another holder')
  }
  assert.equal(errors.length, 0)
  assert.ok(!paths.some(p => /^\/api\/v1\//.test(p) || /^\/oauth\//.test(p)))
  assert.ok(paths.some(p => /^\/assets-v2\/.+\.js$/.test(p)))
  for (const cookie of await context.cookies(origin)) { assert.equal(cookie.httpOnly, true); assert.equal(cookie.secure, true); assert.equal(cookie.sameSite, 'Lax'); assert.equal(cookie.path, '/') }
  note('actual bundle loads under CSP with no V1 endpoints, token storage, or JavaScript-readable auth cookies')
  process.stdout.write(`${cases} built-browser cases passed\n`)
} catch (error) {
  // Playwright diagnostics may include credential-bearing request URLs/cookies.
  // Keep failures categorical; no traces, request headers or bodies are saved.
  process.stderr.write(`FAIL built-browser case ${cases + 1}, ${stage}: ${error.name}\n`)
  process.exitCode = 1
} finally { await context.close(); await browser.close() }
