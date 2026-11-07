import assert from 'node:assert/strict'
import { chromium } from '@playwright/test'

const [origin, seconds] = process.argv.slice(2)
assert.match(origin ?? '', /^https:\/\/ops\.test:[0-9]+$/)
assert.match(seconds ?? '', /^[0-9]+$/)
const now = Number(seconds) * 1000
const markerKey = 'ops-v2.browser-context'
const browser = await chromium.launch({
  channel: 'chrome', // installed browser; no download or dependency mutation
  headless: true,
  args: ['--host-resolver-rules=MAP ops.test 127.0.0.1', '--no-proxy-server'],
})
const context = await browser.newContext({ ignoreHTTPSErrors: true }) // owned httptest certificate ONLY
let cases = 0
const run = async (page, name, ...args) => page.evaluate(async ({ name, args }) => {
  try { return { ok: true, value: await window.authHarness[name](...args) } }
  catch (error) { return { ok: false, code: error.code ?? 'unexpected_error' } }
}, { name, args })
const call = async (page, name, ...args) => {
  const result = await run(page, name, ...args)
  assert.equal(result.ok, true, `${name}: ${result.code}`)
  return result.value
}
const deny = async (page, name, args = [], expected) => {
  const result = await run(page, name, ...args)
  assert.equal(result.ok, false, `${name} unexpectedly succeeded`)
  if (expected) assert.equal(result.code, expected, name)
}
const load = async page => {
  await page.clock.install({ time: now })
  await page.goto(origin + '/auth/complete')
  await page.waitForFunction(() => !!window.authHarness)
}
const marker = page => page.evaluate(key => JSON.parse(localStorage.getItem(key)), markerKey)
const count = page => call(page, 'requests')
const control = async (page, body) => page.evaluate(async body => {
  const r = await fetch('/__test/control', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) })
  if (r.status !== 204) throw new Error('owned_fixture_control')
}, body)
const begin = page => call(page, 'start', 'azure')
const complete = async (page, start, subject) => {
  await control(page, { authorizationUrl: start.authorizationUrl, subject })
  return call(page, 'callback', new URL(start.authorizationUrl).searchParams.get('state'), 'browser-fixture-code')
}
const login = async (page, subject) => complete(page, await begin(page), subject)
const note = label => { cases++; process.stdout.write(`PASS ${label}\n`) }

try {
  process.stdout.write(`Owned Chrome ${browser.version()} / Playwright 1.58.0\n`)
  const a = await context.newPage(), b = await context.newPage()
  await load(a); await load(b)
  assert.equal(await a.evaluate(() => isSecureContext && !!navigator.locks), true)
  const providers = await call(a, 'providers')
  assert.equal(providers.profiles[0].id, 'azure')
  const first = await login(a)
  assert.equal((await call(a, 'own', first)).actorId, first.actorId)
  assert.deepEqual(await call(b, 'restore'), first)
  let requestsBeforeSingleflight = await count(a)
  assert.deepEqual(await Promise.all([call(a, 'restore'), call(a, 'restore')]), [first, first])
  assert.equal(await count(a), requestsBeforeSingleflight + 1)
  assert.deepEqual(await Promise.all([call(a, 'restore'), call(b, 'restore')]), [first, first])
  assert.equal((await call(b, 'own', first)).actorId, first.actorId)
  const cookies = await context.cookies(origin)
  assert.equal(cookies.length, 2)
  for (const c of cookies) {
    assert.equal(c.httpOnly, true); assert.equal(c.secure, true); assert.equal(c.sameSite, 'Lax'); assert.equal(c.path, '/')
  }
  assert.equal(await a.evaluate(() => document.cookie), '')
  assert.deepEqual(await a.evaluate(() => Object.keys(localStorage)), [markerKey])
  assert.deepEqual(Object.keys(await marker(a)).sort(), ['actorId', 'browserSessionId', 'pendingLoginHash', 'phase', 'version'])
  note('actual secure-context Web Locks, serialized two-tab renewal, RSA/Core/SQL and HttpOnly-only credentials')

  // No BroadcastChannel/storage-event delivery is needed for authorization.
  const sameActor = await login(b)
  assert.equal(first.actorId, sameActor.actorId)
  assert.notEqual(first.browserSessionId, sameActor.browserSessionId)
  let before = await count(a)
  const replacementMarker = await marker(b)
  await deny(a, 'own', [first], 'session_changed')
  await deny(a, 'logout', [first])
  assert.equal(await count(a), before)
  assert.deepEqual(await marker(b), replacementMarker)
  const otherActor = await login(b, 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb')
  assert.notEqual(otherActor.actorId, sameActor.actorId)
  before = await count(a)
  await deny(a, 'own', [sameActor])
  assert.equal(await count(a), before)
  assert.equal((await call(b, 'own', otherActor)).actorId, otherActor.actorId)
  note('cached stale actor AND same-actor/new-family cannot make an authenticated call or alter replacement context')

  const pending = await begin(b)
  await control(b, { fault: 1 })
  await deny(b, 'logout', [otherActor], 'authentication_unavailable')
  assert.equal((await marker(b)).phase, 'require-login')
  assert.equal((await marker(b)).pendingLoginHash, null)
  await b.reload(); await b.waitForFunction(() => !!window.authHarness)
  before = await count(b)
  await deny(b, 'restore', [], 'login_required')
  await deny(b, 'callback', [new URL(pending.authorizationUrl).searchParams.get('state'), 'old-code'], 'invalid_callback')
  assert.equal(await count(b), before)
  assert.equal(new URL(b.url()).search, '')
  note('failed logout plus reload and an older pending provider callback cannot silently log back in')

  const recovered = await login(b)
  const oldStart = await begin(b), newStart = await begin(b)
  const newMarker = await marker(b)
  before = await count(b)
  await deny(b, 'callback', [new URL(oldStart.authorizationUrl).searchParams.get('state'), 'old-code'], 'invalid_callback')
  assert.equal(await count(b), before)
  assert.deepEqual(await marker(b), newMarker)
  // A known same-family renewal preserves the current explicit pending flow.
  assert.deepEqual(await call(b, 'restore'), recovered)
  assert.equal((await marker(b)).pendingLoginHash, newMarker.pendingLoginHash)
  const newer = await complete(b, newStart)
  before = await count(b)
  await deny(b, 'callback', [new URL(newStart.authorizationUrl).searchParams.get('state'), 'duplicate-code'], 'invalid_callback')
  assert.equal(await count(b), before)
  note('only the newest explicit login flow completes; successful same-family renewal preserves its pending flow')

  await control(b, { fault: 2 })
  await deny(b, 'restore', [], 'authentication_unavailable')
  assert.equal((await marker(b)).phase, 'require-login')
  await b.reload(); await b.waitForFunction(() => !!window.authHarness)
  before = await count(b)
  await deny(b, 'restore', [], 'login_required')
  assert.equal(await count(b), before)
  // Explicit login recovers without replaying the predecessor renewal handle.
  const afterLostCommit = await login(b)
  assert.notEqual(afterLostCommit.browserSessionId, newer.browserSessionId)
  note('real SQL renewal COMMIT with lost response stays denied across reload; fresh login recovers')

  before = await count(b)
  await b.evaluate(() => {
    window.fixtureStorageSet = Storage.prototype.setItem
    Storage.prototype.setItem = function () { throw new DOMException('fixture denied', 'SecurityError') }
  })
  await deny(b, 'restore', [], 'unsupported_browser')
  assert.equal(await count(b), before)
  await b.evaluate(() => { Storage.prototype.setItem = window.fixtureStorageSet })
  note('unavailable browser storage fails before any provider or cookie mutation')
  await login(b)

  // Failure at the final active-marker write happens AFTER actual SQL commit.
  await b.evaluate(() => {
    window.fixtureStorageSet = Storage.prototype.setItem
    Storage.prototype.setItem = function (key, value) {
      if (key === 'ops-v2.browser-context' && JSON.parse(value).phase === 'active') {
        throw new DOMException('fixture activation quota', 'QuotaExceededError')
      }
      return window.fixtureStorageSet.call(this, key, value)
    }
  })
  await deny(b, 'restore', [], 'login_required')
  assert.equal((await marker(b)).phase, 'require-login')
  await b.evaluate(() => { Storage.prototype.setItem = window.fixtureStorageSet })
  before = await count(b)
  await deny(b, 'restore', [], 'login_required')
  assert.equal(await count(b), before)
  await login(b)
  note('postcommit marker-write failure releases no bearer and requires a new explicit login')

  // Missing/malformed marker never implicitly bootstraps a remembered actor.
  await b.evaluate(key => localStorage.removeItem(key), markerKey)
  before = await count(b)
  await deny(b, 'restore', [], 'login_required')
  assert.equal(await count(b), before)
  await login(b)
  await b.evaluate(key => localStorage.setItem(key, '{"version":1,"version":1}'), markerKey)
  before = await count(b)
  await deny(b, 'restore', [], 'login_required')
  assert.equal(await count(b), before)
  // Only explicit Start may repair malformed NONcredential local metadata.
  await control(b, { fault: 3 })
  await deny(b, 'start', ['azure'], 'authentication_unavailable')
  assert.equal((await marker(b)).phase, 'require-login')
  assert.equal((await marker(b)).pendingLoginHash, null)
  await login(b)
  note('missing/malformed context denies ordinary work; explicit Start repairs it but failed Start stays denied')

  const readable = await login(b)
  before = await count(b)
  await b.evaluate(() => {
    window.fixtureStorageGet = Storage.prototype.getItem
    Storage.prototype.getItem = function (key) {
      if (key === 'ops-v2.browser-context') throw new DOMException('fixture read denied', 'SecurityError')
      return window.fixtureStorageGet.call(this, key)
    }
  })
  await deny(b, 'own', [readable], 'login_required')
  assert.equal(await count(b), before)
  await b.evaluate(() => { Storage.prototype.getItem = window.fixtureStorageGet })
  // The earlier successful active write was not transactionally rolled back.
  assert.equal((await marker(b)).phase, 'active')
  await deny(b, 'restore', [], 'login_required')
  assert.equal(await count(b), before)
  await login(b)
  note('later storage read loss blocks this document without pretending to undo an earlier successful write')

  const flow = await begin(b)
  const flowState = new URL(flow.authorizationUrl).searchParams.get('state')
  await b.evaluate(state => history.replaceState(null, '', '/auth/azure/callback?code=x&state=' + state + '&state=' + state), flowState)
  before = await count(b)
  await deny(b, 'currentCallback', [], 'invalid_callback')
  assert.equal(new URL(b.url()).search, '')
  assert.equal(await count(b), before)
  await b.evaluate(state => history.replaceState(null, '', '/auth/azure/callback?code=x&state=' + state + '#access_token=unsupported'), flowState)
  await deny(b, 'currentCallback', [], 'invalid_callback')
  assert.equal(new URL(b.url()).hash, '')
  assert.equal(await count(b), before)
  // A provider error for a different flow must not clear the current flow.
  const beforeError = await marker(b)
  await b.evaluate(() => history.replaceState(null, '', '/auth/azure/callback?error=access_denied&state=' + 'A'.repeat(43)))
  await deny(b, 'currentCallback', [], 'invalid_callback')
  assert.deepEqual(await marker(b), beforeError)
  await b.evaluate(state => history.replaceState(null, '', '/auth/azure/callback?error=access_denied&error_uri=https%3A%2F%2Fexample.invalid%2Fignored&state=' + state), flowState)
  await deny(b, 'currentCallback', [], 'provider_rejected')
  assert.equal((await marker(b)).pendingLoginHash, null)
  assert.equal(await count(b), before)
  note('bounded code-query callbacks scrub secrets, reject duplicate/fragment input and isolate provider errors to their own flow')

  // Abandon a live document after its deny marker is persisted but before its
  // renewal can reach the server. Browser teardown releases the real lock.
  await login(b)
  let entered
  const intercepted = new Promise(resolve => { entered = resolve })
  await b.route('**/api/v2/auth/renew', async route => { entered(); await new Promise(resolve => b.once('close', resolve)); await route.abort().catch(() => {}) })
  const abandoned = run(b, 'restore').catch(() => undefined)
  await intercepted
  assert.equal((await marker(a)).phase, 'require-login')
  await b.close(); await abandoned
  const c = await context.newPage(); await load(c)
  before = await count(c)
  await deny(c, 'restore', [], 'login_required')
  assert.equal(await count(c), before)
  note('abandoned tab after pre-request marker stays denied in a new document without renewing')

  process.stdout.write(`PASS ${cases} actual-browser qualification cases\n`)
} finally { await context.close(); await browser.close() }
