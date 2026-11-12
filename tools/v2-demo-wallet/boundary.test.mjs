import test from 'node:test'
import assert from 'node:assert/strict'
import { createServer, request as httpRequest } from 'node:http'
import { once } from 'node:events'
import { checkedChallenge, requestLocation } from './boundary.mjs'
import { handler } from './server.mjs'

const ops = 'https://localhost:8443', origin = 'https://localhost:9444'
const id = '11111111-2222-4333-8444-555555555555'
const requestUri = ops + '/api/v2/auth/privado/requests/' + id
const metadata = { issuerDid: 'did:example:issuer', verifierDid: 'did:example:verifier', contextUrl: 'https://schemas.test/role.jsonld', credentialType: 'BankRole', circuitId: 'credentialAtomicQuerySigV2', stateContract: '0x1111111111111111111111111111111111111111' }
function challenge() { return { id, type: 'https://iden3-communication.io/authorization/1.0/request', from: metadata.verifierDid, created_time: 1000, expires_time: 1300, body: { callbackUrl: ops + '/api/v2/auth/privado/proofs/' + id, scope: [{ id: 1, circuitId: metadata.circuitId, optional: false, query: { allowedIssuers: [metadata.issuerDid], context: metadata.contextUrl, type: metadata.credentialType, proofType: 'BJJSignature2021', skipClaimRevocationCheck: false, credentialSubject: { role: { $eq: 3 } } } }] } } }

test('only the exact saved public request can select a source or callback', () => {
  assert.deepEqual(requestLocation(requestUri, ops), { path: '/api/v2/auth/privado/requests/' + id, id })
  for (const uri of [requestUri + '?other=1', requestUri + '#x', requestUri.replace('localhost', 'evil.test'), requestUri.replace('https:', 'http:'), requestUri.replace('/requests/', '/proofs/'), requestUri.replace('/requests/', '/requests/%2f'), requestUri.replace('localhost', 'user@localhost'), ' ' + requestUri]) assert.throws(() => requestLocation(uri, ops))
  assert.equal(checkedChallenge(challenge(), { id }, 'reader', metadata, ops, 1100), ops + '/api/v2/auth/privado/proofs/' + id)
  for (const mutate of [x => { x.body.callbackUrl = 'https://evil.test/proofs/' + id }, x => { x.id = 'other' }, x => { x.from = 'another-verifier' }, x => { x.body.scope[0].query.credentialSubject.role.$eq = 1 }, x => { x.body.scope[0].query.skipClaimRevocationCheck = true }, x => { x.expires_time = 1099 }]) {
    const value = challenge(); mutate(value)
    assert.throws(() => checkedChallenge(value, { id }, 'reader', metadata, ops, 1100))
  }
  assert.throws(() => checkedChallenge(challenge(), { id }, 'outsider', metadata, ops, 1100))
  const outsider = challenge(); outsider.body.scope = []
  assert.doesNotThrow(() => checkedChallenge(outsider, { id }, 'outsider', metadata, ops, 1100))
})

async function fixture(t, fetcher) {
  let proofs = 0
  const wallet = { ready: { rpcUrl: 'http://127.0.0.1:1' }, healthy: () => true, prove: async () => { proofs++; throw Error('unexpected proof') } }
  const server = createServer(handler({ origin, opsOrigin: ops, opsUpstream: 'https://ops:8443', stateRpcUrl: 'https://demo-wallet:9444/rpc' }, wallet, metadata, fetcher))
  server.listen(0, '127.0.0.1'); await once(server, 'listening')
  t.after(() => { server.closeAllConnections(); server.close() })
  const request = (route, body, headers = {}) => new Promise((resolve, reject) => {
    const call = httpRequest({ host: '127.0.0.1', port: server.address().port, path: route, method: body === undefined ? 'GET' : 'POST', headers: { Host: 'localhost:9444', Origin: origin, ...(body === undefined ? {} : { 'Content-Type': 'application/json' }), ...headers } }, response => {
      let raw = ''; response.setEncoding('utf8'); response.on('data', x => { raw += x }); response.on('end', () => resolve({ status: response.statusCode, json: async () => JSON.parse(raw) }))
    }); call.on('error', reject); call.end(body === undefined ? undefined : JSON.stringify(body))
  })
  return { request, proofs: () => proofs }
}
test('cross-origin, arbitrary source and unknown fields fail before network or proof work', async t => {
  let fetched = 0
  const x = await fixture(t, async () => { fetched++; throw Error('unexpected network') })
  assert.equal((await x.request('/prove', { persona: 'reader', requestUri }, { Origin: 'https://evil.test' })).status, 403)
  assert.equal((await x.request('/prove', { persona: 'reader', requestUri }, { Host: 'evil.test' })).status, 403)
  assert.equal((await x.request('/prove', { persona: 'reader', requestUri: requestUri.replace('localhost', 'evil.test') })).status, 400)
  assert.equal((await x.request('/prove', { persona: 'reader', requestUri, token: 'not-accepted' })).status, 400)
  assert.equal(fetched, 0); assert.equal(x.proofs(), 0)
})
test('upstream redirect is not followed and never invokes prover or callback', async t => {
  let fetched = 0
  const x = await fixture(t, async (_url, options) => { fetched++; assert.equal(options.redirect, 'manual'); return new Response('', { status: 302, headers: { Location: 'https://evil.test' } }) })
  const accepted = await x.request('/prove', { persona: 'reader', requestUri })
  assert.equal(accepted.status, 202)
  const { id: job } = await accepted.json()
  await new Promise(resolve => setImmediate(resolve))
  const status = await x.request('/jobs/' + job)
  assert.deepEqual(await status.json(), { status: 'failed' })
  assert.equal(fetched, 1); assert.equal(x.proofs(), 0)
})
test('completed job retention never blocks another sign-in or displaces active work', async t => {
  let finish
  const x = await fixture(t, async () => new Promise(resolve => { finish = () => resolve(new Response('', { status: 302 })) }))
  const start = () => x.request('/prove', { persona: 'reader', requestUri })
  const first = await start()
  assert.equal(first.status, 202)
  const oldest = (await first.json()).id
  assert.equal((await start()).status, 409)
  assert.deepEqual(await (await x.request('/jobs/' + oldest)).json(), { status: 'working' })
  finish(); await new Promise(resolve => setImmediate(resolve))
  let newest
  for (let i = 0; i < 8; i++) {
    const next = await start()
    assert.equal(next.status, 202)
    newest = (await next.json()).id
    finish(); await new Promise(resolve => setImmediate(resolve))
  }
  assert.equal((await x.request('/jobs/' + oldest)).status, 404)
  assert.deepEqual(await (await x.request('/jobs/' + newest)).json(), { status: 'failed' })
  assert.equal(x.proofs(), 0)
})
test('RPC adapter cannot select another target or mutate chain state', async t => {
  let fetched = 0
  const x = await fixture(t, async () => { fetched++; throw Error('unexpected network') })
  const host = { Host: 'demo-wallet:9444' }
  assert.equal((await x.request('/rpc', { jsonrpc: '2.0', id: 1, method: 'eth_sendRawTransaction', params: [] }, host)).status, 400)
  assert.equal((await x.request('/rpc', { jsonrpc: '2.0', id: 1, method: 'eth_call', params: [{ to: '0x2222222222222222222222222222222222222222' }, 'latest'] }, host)).status, 400)
  assert.equal(fetched, 0)
})
