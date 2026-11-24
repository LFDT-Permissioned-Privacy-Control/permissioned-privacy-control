import test from 'node:test'
import assert from 'node:assert/strict'
import { bridgeConfig } from './bridge-config.mjs'
import { runBridge } from './public/bridge.js'

const ops = 'https://localhost:8443', nonce = 'a'.repeat(64)
const metadata = { testOnly: true, network: 'polygon:mumbai', issuerDid: 'did:iden3:polygon:mumbai:issuer', verifierDid: 'did:iden3:polygon:mumbai:verifier', personas: ['admin', 'deployer', 'reader', 'outsider'].map(id => ({ id, profileId: 'demo-privado', holderDid: 'did:iden3:polygon:mumbai:holder-' + id, roleValue: 99 })) }
const config = bridgeConfig(metadata, ops)
const json = (value, status = 200) => new Response(JSON.stringify(value), { status, headers: { 'Content-Type': 'application/json' } })
function windowFixture(fragment = '#' + nonce) {
  const listeners = new Map(), messages = [], status = { textContent: '' }, timers = []
  const parent = { closed: false, postMessage: (value, origin) => messages.push({ value, origin }) }
  const win = { opener: parent, location: { hash: fragment }, document: { querySelector: () => status }, history: { replaceState: (_state, _title, path) => { win.scrubbed = path } }, addEventListener: (name, f) => listeners.set(name, f), removeEventListener: (name, f) => { if (listeners.get(name) === f) listeners.delete(name) }, setTimeout: (f, delay) => { const timer = () => { if (timer.active) { timer.active = false; f() } }; timer.active = true; timer.delay = delay; timers.push(timer); return timer }, clearTimeout: timer => { timer.active = false } }
  return { win, parent, messages, status, timers, fire: delay => { const timer = timers.find(t => t.active && t.delay === delay); assert.ok(timer, 'missing timer ' + delay); timer() }, receive: value => listeners.get('message')?.(value), leave: () => listeners.get('pagehide')?.() }
}
const prove = { v: 1, type: 'prove', nonce, persona: 'admin', requestUri: ops + '/api/v2/auth/privado/requests/11111111-2222-4333-8444-555555555555' }
const settle = async () => { for (let i = 0; i < 10; i++) await new Promise(resolve => setImmediate(resolve)) }

test('bridge public config projects only four unique prepared identities', () => {
  assert.deepEqual(Object.keys(config).sort(), ['v', 'testOnly', 'opsOrigin', 'network', 'issuerDid', 'verifierDid', 'personas'].sort())
  assert.ok(config.personas.every(p => Object.keys(p).sort().join() === 'holderDid,id,profileId'))
  for (const mutate of [x => { x.testOnly = false }, x => { x.personas.pop() }, x => { x.personas[0].profileId = 'production-admin' }, x => { x.personas[1].holderDid = x.personas[0].holderDid }, x => { x.network = 'evil/network' }]) {
    const x = structuredClone(metadata); mutate(x); assert.throws(() => bridgeConfig(x, ops))
  }
  assert.throws(() => bridgeConfig(metadata, 'https://evil.test'))
})

test('missing opener or malformed nonce never fetches or sends', async () => {
  for (const fragment of ['', '#x', '#' + 'A'.repeat(64)]) {
    const f = windowFixture(fragment); let fetched = 0
    await runBridge(f.win, async () => { fetched++; throw Error() })
    assert.equal(fetched, 0); assert.equal(f.messages.length, 0); assert.equal(f.win.scrubbed, '/bridge')
  }
})

test('exact origin, opener, nonce and closed shape own one proof; no token crosses bridge', async () => {
  const f = windowFixture(), calls = []
  const fetcher = async (url, options) => {
    calls.push({ url, options })
    assert.equal(options.mode, 'same-origin'); assert.equal(options.credentials, 'omit'); assert.equal(options.redirect, 'error')
    return url === '/bridge-config' ? json(config) : url === '/prove' ? json({ id: '11111111-2222-4333-8444-555555555555', status: 'working' }, 202) : json({ status: 'submitted' })
  }
  const stop = await runBridge(f.win, fetcher)
  assert.equal(f.win.scrubbed, '/bridge')
  assert.deepEqual(f.messages, [{ value: { v: 1, type: 'ready', nonce, config }, origin: ops }])
  for (const event of [
    { data: prove, origin: 'https://evil.test', source: f.parent },
    { data: prove, origin: ops, source: {} },
    { data: { ...prove, nonce: 'b'.repeat(64) }, origin: ops, source: f.parent },
    { data: { ...prove, token: 'never-accepted' }, origin: ops, source: f.parent },
    { data: { ...prove, requestUri: prove.requestUri + '?redirect=evil' }, origin: ops, source: f.parent },
  ]) f.receive(event)
  await settle(); assert.equal(calls.length, 1)
  f.receive({ data: prove, origin: ops, source: f.parent }); await settle()
  f.receive({ data: prove, origin: ops, source: f.parent }); await settle()
  assert.equal(calls.filter(c => c.url === '/prove').length, 1)
  assert.deepEqual(JSON.parse(calls.find(c => c.url === '/prove').options.body), { persona: 'admin', requestUri: prove.requestUri })
  f.fire(750); await settle()
  assert.deepEqual(f.messages.slice(1).map(x => x.value), [{ v: 1, type: 'status', nonce, status: 'working' }, { v: 1, type: 'status', nonce, status: 'submitted' }])
  stop(); assert.equal(f.messages.every(x => x.origin === ops), true)
})

test('uncertain proof POST is not retried, page disposal cannot revive old messages', async () => {
  const f = windowFixture(); let posts = 0
  await runBridge(f.win, async url => { if (url === '/bridge-config') return json(config); posts++; throw Error('uncertain') })
  f.receive({ data: prove, origin: ops, source: f.parent }); await settle()
  assert.equal(posts, 1); assert.equal(f.messages.at(-1).value.status, 'failed')
  f.receive({ data: prove, origin: ops, source: f.parent }); await settle(); assert.equal(posts, 1)
  f.leave(); const count = f.messages.length
  f.receive({ data: prove, origin: ops, source: f.parent }); await settle(); assert.equal(f.messages.length, count)
})

test('explicit local renewal keeps the owner and persona, rejects replay, and stops after thirty minutes', async () => {
  const originalNow = Date.now; let now = 1000000; Date.now = () => now
  try {
    const f = windowFixture(), calls = []
    await runBridge(f.win, async (url, options) => { calls.push({ url, options }); return url === '/bridge-config' ? json(config) : url === '/prove' ? json({ id: '11111111-2222-4333-8444-555555555555', status: 'working' }, 202) : json({ status: 'submitted' }) })
    f.receive({ data: { ...prove, keepAlive: true }, origin: ops, source: f.parent }); await settle(); f.fire(750); await settle()
    assert.equal(calls.filter(c => c.url === '/prove').length, 1)
    f.receive({ data: prove, origin: ops, source: f.parent }) // old request cannot be replayed
    const next = { ...prove, requestUri: ops + '/api/v2/auth/privado/requests/aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee' }
    f.receive({ data: { ...next, persona: 'reader' }, origin: ops, source: f.parent })
    f.receive({ data: next, origin: 'https://evil.test', source: f.parent }); await settle()
    assert.equal(calls.filter(c => c.url === '/prove').length, 1)
    f.receive({ data: next, origin: ops, source: f.parent }); await settle(); f.fire(750); await settle()
    assert.equal(calls.filter(c => c.url === '/prove').length, 2)
    now += 30 * 60 * 1000; f.fire(1800000); await settle()
    const third = { ...next, requestUri: ops + '/api/v2/auth/privado/requests/bbbbbbbb-bbbb-4ccc-8ddd-eeeeeeeeeeee' }
    f.receive({ data: third, origin: ops, source: f.parent }); await settle()
    assert.equal(calls.filter(c => c.url === '/prove').length, 2)
  } finally { Date.now = originalNow }
})

test('oversized or redirect-failed metadata never produces ready or proof work', async () => {
  for (const fetcher of [async () => json({ ...config, oversized: 'x'.repeat(17000) }), async () => { throw Error('certificate/redirect/connection failure') }]) {
    const f = windowFixture(); await runBridge(f.win, fetcher)
    assert.equal(f.messages.length, 0)
    assert.match(f.status.textContent, /certificate/)
  }
})

test('held metadata fetch and body reads abort at the original initialization deadline', async () => {
  for (const heldBody of [false, true]) {
    const f = windowFixture(); let signal, canceled = false
    const running = runBridge(f.win, async (_url, options) => {
      signal = options.signal
      if (heldBody) return new Response(new ReadableStream({ cancel() { canceled = true } }), { headers: { 'Content-Type': 'application/json' } })
      return new Promise((_resolve, reject) => signal.addEventListener('abort', () => reject(Error('aborted')), { once: true }))
    })
    await settle(); f.fire(45000); await running
    assert.equal(signal.aborted, true)
    if (heldBody) assert.equal(canceled, true)
    assert.equal(f.messages.length, 0)
    assert.match(f.status.textContent, /timed out/)
  }
})

test('wait-for-prove expires once, late prove cannot start work', async () => {
  const f = windowFixture(); let posts = 0
  await runBridge(f.win, async url => { if (url === '/bridge-config') return json(config); posts++; throw Error() })
  f.fire(45000)
  f.receive({ data: prove, origin: ops, source: f.parent }); await settle()
  assert.equal(posts, 0)
  assert.deepEqual(f.messages.map(m => m.value.type === 'status' ? m.value.status : m.value.type), ['ready', 'failed'])
})

test('held proof POST and job body abort without retry after the original proof deadline', async () => {
  for (const heldJob of [false, true]) {
    const f = windowFixture(); let posts = 0, signal, canceled = false
    await runBridge(f.win, async (url, options) => {
      if (url === '/bridge-config') return json(config)
      signal = options.signal
      if (url === '/prove') {
        posts++
        if (heldJob) return json({ id: '11111111-2222-4333-8444-555555555555', status: 'working' }, 202)
        return new Promise((_resolve, reject) => signal.addEventListener('abort', () => reject(Error('aborted')), { once: true }))
      }
      return new Response(new ReadableStream({ cancel() { canceled = true } }), { headers: { 'Content-Type': 'application/json' } })
    })
    f.receive({ data: prove, origin: ops, source: f.parent }); await settle()
    if (heldJob) { f.fire(750); await settle() }
    f.fire(150000); await settle()
    assert.equal(signal.aborted, true); assert.equal(posts, 1)
    if (heldJob) assert.equal(canceled, true)
    assert.equal(f.messages.filter(m => m.value.status === 'failed').length, 1)
    f.receive({ data: prove, origin: ops, source: f.parent }); await settle(); assert.equal(posts, 1)
  }
})
