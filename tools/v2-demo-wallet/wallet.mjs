// Adapter around the same pinned, real-crypto wallet used by qualification.
import assert from 'node:assert/strict'
import { spawn } from 'node:child_process'
import { createInterface } from 'node:readline'
import { randomUUID } from 'node:crypto'
import { fileURLToPath } from 'node:url'

export async function startWallet() {
  const script = fileURLToPath(new URL('../../e2e/playwright/v2-privado-wallet-fixture.mjs', import.meta.url))
  const child = spawn(process.execPath, ['--max-old-space-size=1024', script], {
    env: { ...process.env, OPS_PRIVADO_WALLET_DEMO: '1' }, stdio: ['pipe', 'pipe', 'pipe'],
  })
  let closed = false, pending, resolveReady, rejectReady
  const readyPromise = new Promise((resolve, reject) => { resolveReady = resolve; rejectReady = reject })
  const stop = () => { if (!closed) { closed = true; child.kill('SIGTERM') } }
  // SDK diagnostics can include credential/proof details. Never forward them.
  child.stderr.resume()
  const fail = () => { rejectReady(Error('demo wallet failed to start')); pending?.reject(Error('demo wallet unavailable')); pending = null; stop() }
  child.on('error', fail)
  child.on('exit', fail)
  const lines = createInterface({ input: child.stdout, crlfDelay: Infinity })
  void (async () => {
    for await (const line of lines) {
      try {
        assert.ok(Buffer.byteLength(line) <= 2 << 20)
        const result = JSON.parse(line)
        if (result.type === 'ready') { resolveReady(result); continue }
        if (!pending || result.id !== pending.id) throw Error('unexpected demo wallet response')
        const task = pending; pending = null
        if (result.error) task.reject(Error('demo proof could not be generated'))
        else task.resolve(result)
      } catch { fail() }
    }
  })().catch(fail)
  const startup = setTimeout(fail, 45_000)
  let ready
  try { ready = await readyPromise } finally { clearTimeout(startup) }
  assert.equal(ready.sdkVersion, '1.43.0')
  const internalRPC = new URL(ready.rpcUrl)
  assert.equal(internalRPC.protocol, 'http:')
  assert.equal(internalRPC.hostname, '127.0.0.1')
  assert.equal(internalRPC.pathname, '/')
  assert.equal(internalRPC.search + internalRPC.hash + internalRPC.username + internalRPC.password, '')
  assert.deepEqual(ready.personas.map(x => x.id), ['admin', 'deployer', 'reader', 'outsider'])
  return { ready, close: stop, healthy: () => !closed, async prove(persona, request) {
    if (closed || pending) throw Error('demo wallet busy')
    return new Promise((resolve, reject) => {
      const id = randomUUID()
      const timer = setTimeout(() => { reject(Error('demo proof generation timed out')); stop() }, 90_000)
      pending = { id, resolve: x => { clearTimeout(timer); resolve(x) }, reject: e => { clearTimeout(timer); reject(e) } }
      child.stdin.write(JSON.stringify({ id, holder: persona, request }) + '\n', error => { if (error) fail() })
    })
  } }
}
