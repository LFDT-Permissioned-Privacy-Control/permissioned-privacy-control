#!/usr/bin/env node
// Isolated public demo identities. Excluded from the production image/Core.
import assert from 'node:assert/strict'
import { createServer } from 'node:https'
import { readFile, writeFile, mkdir, rename } from 'node:fs/promises'
import { randomUUID, createHash } from 'node:crypto'
import { fileURLToPath } from 'node:url'
import path from 'node:path'
import { startWallet } from './wallet.mjs'
import { demoAccounts } from './accounts.mjs'
import { callerAllowed, checkedChallenge, exactOrigin, personas, requestLocation } from './boundary.mjs'

const here = path.dirname(fileURLToPath(import.meta.url))
function configValue(raw) {
  assert.ok(raw && typeof raw === 'object' && !Array.isArray(raw))
  assert.deepEqual(Object.keys(raw).sort(), ['listenHost', 'listenPort', 'origin', 'opsOrigin', 'opsUpstream', 'stateRpcUrl', 'tlsCertificateFile', 'tlsPrivateKeyFile', 'outputDirectory'].sort())
  for (const key of ['origin', 'opsOrigin', 'opsUpstream']) exactOrigin(raw[key])
  assert.ok(raw.listenHost === '0.0.0.0' || raw.listenHost === '127.0.0.1')
  assert.ok(Number.isInteger(raw.listenPort) && raw.listenPort > 0 && raw.listenPort <= 65535)
  const rpc = new URL(raw.stateRpcUrl)
  assert.equal(rpc.protocol, 'https:'); assert.equal(rpc.pathname, '/rpc')
  assert.equal(rpc.href, raw.stateRpcUrl); assert.equal(rpc.username + rpc.password + rpc.search + rpc.hash, '')
  for (const key of ['tlsCertificateFile', 'tlsPrivateKeyFile', 'outputDirectory']) assert.ok(path.isAbsolute(raw[key]))
  return Object.freeze(raw)
}
export async function readBounded(stream, max) {
  const chunks = []; let size = 0
  for await (const value of stream) { size += value.length; if (size > max) throw Error('bounded input exceeded'); chunks.push(value) }
  return Buffer.concat(chunks)
}
async function boundedFetch(url, options, max, fetcher) {
  const response = await fetcher(url, { ...options, redirect: 'manual', signal: AbortSignal.timeout(20_000) })
  if (response.status >= 300 && response.status < 400) { await response.body?.cancel(); throw Error('redirect rejected') }
  const raw = response.body ? await readBounded(response.body, max) : Buffer.alloc(0)
  return { response, raw }
}
function json(response, code, value) { response.writeHead(code, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' }); response.end(JSON.stringify(value)) }
export function handler(config, wallet, metadata, fetcher = fetch) {
  const jobs = new Map(); let busy = false
  const publicHost = new URL(config.origin).host, rpcHost = new URL(config.stateRpcUrl).host
  const cleanup = () => { for (const [key, job] of jobs) if (job.expires <= Date.now()) jobs.delete(key) }
  async function prove(job, persona, location) {
    try {
      const { response, raw } = await boundedFetch(config.opsUpstream + location.path,
        { headers: { Accept: 'application/json' } }, 64 << 10, fetcher)
      assert.equal(response.status, 200)
      assert.match(response.headers.get('content-type') ?? '', /^application\/json(?:;\s*charset=utf-8)?$/i)
      const request = JSON.parse(raw.toString('utf8'))
      const callback = checkedChallenge(request, location, persona, metadata, config.opsOrigin)
      // The callback must remain the exact public URI from the original saved
      // request. Only its preconfigured origin is translated to the internal
      // Docker endpoint; credentials and browser cookies are never forwarded.
      assert.equal(callback, config.opsOrigin + '/api/v2/auth/privado/proofs/' + location.id)
      const generated = await wallet.prove(persona, request)
      assert.equal(typeof generated.compact, 'string'); assert.ok(generated.compact.length <= 1 << 20)
      const posted = await boundedFetch(config.opsUpstream + new URL(callback).pathname,
        { method: 'POST', headers: { 'Content-Type': 'text/plain; charset=utf-8' }, body: generated.compact }, 4096, fetcher)
      assert.equal(posted.response.status, 200); assert.equal(posted.raw.length, 0)
      job.status = 'submitted'
    } catch { job.status = 'failed' }
    finally { busy = false }
  }
  return async (request, response) => {
    try {
      response.setHeader('Cache-Control', 'no-store')
      response.setHeader('X-Content-Type-Options', 'nosniff')
      response.setHeader('Referrer-Policy', 'no-referrer')
      const url = new URL(request.url, config.origin)
      assert.equal(url.origin, config.origin)
      if (url.pathname === '/rpc') {
        if (request.method !== 'POST' || request.headers.host !== rpcHost || (request.headers.origin && request.headers.origin !== config.origin)) return json(response, 403, { error: 'request_denied' })
        const raw = await readBounded(request, 64 << 10)
        const input = JSON.parse(raw)
        const queries = Array.isArray(input) ? input : [input]
        assert.ok(queries.length >= 1 && queries.length <= 8)
        for (const q of queries) {
          assert.ok(q && q.jsonrpc === '2.0' && ['eth_chainId', 'eth_call', 'eth_getCode'].includes(q.method))
          if (q.method === 'eth_call') assert.equal((q.params?.[0]?.to ?? '').toLowerCase(), metadata.stateContract)
          if (q.method === 'eth_getCode') assert.equal((q.params?.[0] ?? '').toLowerCase(), metadata.stateContract)
        }
        const forwarded = await boundedFetch(wallet.ready.rpcUrl, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: raw }, 64 << 10, fetcher)
        assert.equal(forwarded.response.status, 200)
        response.writeHead(200, { 'Content-Type': 'application/json' }); response.end(forwarded.raw); return
      }
      if (request.method === 'GET' && url.pathname === '/health' && !url.search && !url.hash && [publicHost, rpcHost].includes(request.headers.host)) return json(response, wallet.healthy() ? 200 : 503, { ready: wallet.healthy(), testOnly: true })
      if (request.headers.host !== publicHost || url.search || url.hash) return json(response, 403, { error: 'request_denied' })
      if (request.method === 'GET' && url.pathname === '/metadata') return json(response, 200, metadata)
      if (request.method === 'GET' && ['/', '/picker.js', '/picker.css'].includes(url.pathname)) {
        const file = url.pathname === '/' ? 'index.html' : url.pathname.slice(1)
        response.setHeader('Content-Security-Policy', "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
        response.setHeader('Content-Type', file.endsWith('.js') ? 'text/javascript; charset=utf-8' : file.endsWith('.css') ? 'text/css; charset=utf-8' : 'text/html; charset=utf-8')
        response.end(await readFile(path.join(here, 'public', file))); return
      }
      if (request.method === 'POST' && url.pathname === '/prove') {
        if (!callerAllowed(request, config.origin)) return json(response, 403, { error: 'request_denied' })
        if (request.headers['content-type'] !== 'application/json') return json(response, 415, { error: 'json_required' })
        const value = JSON.parse((await readBounded(request, 1024)).toString('utf8'))
        assert.deepEqual(Object.keys(value).sort(), ['persona', 'requestUri'])
        assert.ok(personas.includes(value.persona))
        const location = requestLocation(value.requestUri, config.opsOrigin)
        cleanup()
        if (!wallet.healthy() || busy || jobs.size >= 8) return json(response, 409, { error: 'wallet_busy' })
        const id = randomUUID(), job = { status: 'working', expires: Date.now() + 5 * 60_000 }
        jobs.set(id, job); busy = true
        // The browser request owns no long-lived secret or session. One owned
        // bounded proof job may finish while its picker tab is disconnected.
        void prove(job, value.persona, location)
        return json(response, 202, { id, status: job.status })
      }
      if (request.method === 'GET' && /^\/jobs\/[0-9a-f-]{36}$/.test(url.pathname)) {
        if ((request.headers.origin && request.headers.origin !== config.origin) || (request.headers['sec-fetch-site'] && request.headers['sec-fetch-site'] !== 'same-origin')) return json(response, 403, { error: 'request_denied' })
        cleanup(); const job = jobs.get(url.pathname.slice(6))
        return job ? json(response, 200, { status: job.status }) : json(response, 404, { error: 'job_not_found' })
      }
      return json(response, 404, { error: 'not_found' })
    } catch { return json(response, 400, { error: 'invalid_demo_request' }) }
  }
}
async function atomicJSON(file, value) {
  const temporary = file + '.' + randomUUID()
  await writeFile(temporary, JSON.stringify(value, null, 2) + '\n', { mode: 0o600, flag: 'wx' })
  await rename(temporary, file)
}
async function main() {
  assert.equal(process.argv.length, 4); assert.equal(process.argv[2], '--config')
  const config = configValue(JSON.parse(await readFile(process.argv[3], 'utf8')))
  const wallet = await startWallet()
  const ready = wallet.ready
  await mkdir(config.outputDirectory, { recursive: true, mode: 0o700 })
  const state = { version: 1, testOnly: true, network: ready.network, chainId: ready.chainId, stateContract: ready.stateContract,
    issuerDid: ready.issuerDid, verifierDid: ready.verifierDid, personas: ready.personas, states: ready.states }
  const stateFile = path.join(config.outputDirectory, 'identity-state.json')
  try { assert.deepEqual(JSON.parse(await readFile(stateFile, 'utf8')), state) }
  catch (error) { if (error.code !== 'ENOENT') { wallet.close(); throw Error('demo identity state changed; use explicit demo reset') }; await atomicJSON(stateFile, state) }
  const context = Buffer.from(JSON.stringify(ready.context))
  const contextFile = path.join(config.outputDirectory, 'role-context.json')
  await writeFile(contextFile, context, { mode: 0o600 })
  const metadata = { version: 1, testOnly: true, network: ready.network, chainId: ready.chainId, stateContract: ready.stateContract,
    stateRpcUrl: config.stateRpcUrl, issuerDid: ready.issuerDid, verifierDid: ready.verifierDid, contextUrl: ready.contextUrl,
    contextPath: 'role-context.json', contextSHA256: 'sha256:' + createHash('sha256').update(context).digest('hex'),
    credentialType: 'BankRole', circuitId: 'credentialAtomicQuerySigV2', personas: ready.personas }
  await atomicJSON(path.join(config.outputDirectory, 'metadata.json'), metadata)
  await atomicJSON(path.join(config.outputDirectory, 'evm-wallets.json'), { version: 1, testOnly: true, accounts: demoAccounts() })
  const server = createServer({ cert: await readFile(config.tlsCertificateFile), key: await readFile(config.tlsPrivateKeyFile) }, handler(config, wallet, metadata))
  server.requestTimeout = 25_000; server.headersTimeout = 5000; server.maxHeadersCount = 32
  let stopping = false
  const stop = () => { if (stopping) return; stopping = true; wallet.close(); server.closeAllConnections(); server.close() }
  for (const signal of ['SIGINT', 'SIGTERM']) process.on(signal, stop)
  await new Promise((resolve, reject) => { server.once('error', reject); server.listen(config.listenPort, config.listenHost, resolve) })
  console.log(JSON.stringify({ ready: true, testOnly: true, origin: config.origin, metadata: path.join(config.outputDirectory, 'metadata.json') }))
}
if (process.argv[1] === fileURLToPath(import.meta.url)) main().catch(() => { console.error('Demo wallet could not start; check the explicit config, owned CA, pinned SDK and circuit files.'); process.exit(1) })
