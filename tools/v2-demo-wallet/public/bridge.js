const noncePattern = /^[0-9a-f]{64}$/
const personas = ['admin', 'deployer', 'reader', 'outsider']
const keys = (value, expected) => value && typeof value === 'object' && !Array.isArray(value) && Object.keys(value).sort().join() === expected.sort().join()

async function boundedJSON(fetcher, path, options, max) {
  const response = await fetcher(path, { ...options, credentials: 'omit', mode: 'same-origin', redirect: 'error', cache: 'no-store' })
  if (!response.ok || !/^application\/json(?:;\s*charset=utf-8)?$/i.test(response.headers.get('content-type') ?? '')) throw Error('request failed')
  options?.signal?.throwIfAborted()
  const reader = response.body.getReader(), chunks = []; let size = 0
  const cancel = () => { void reader.cancel().catch(() => {}) }
  options?.signal?.addEventListener('abort', cancel, { once: true })
  try {
    for (;;) {
      const { done, value } = await reader.read()
      options?.signal?.throwIfAborted()
      if (done) break
      size += value.byteLength
      if (size > max) throw Error('response too large')
      chunks.push(value)
    }
  } finally { options?.signal?.removeEventListener('abort', cancel); await reader.cancel().catch(() => {}) }
  const bytes = new Uint8Array(size); let offset = 0
  for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength }
  return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes))
}

// Exported for protocol tests; the served module starts only in its own page.
export async function runBridge(win = window, fetcher = fetch) {
  const status = win.document.querySelector('#status')
  const nonce = win.location.hash.slice(1), parent = win.opener
  win.history.replaceState(null, '', '/bridge')
  let config, timer, used = false, stopped = false, failed = false, renewable = false, persona, renewableUntil = 0
  const seenRequests = new Set()
  const abort = new AbortController()
  const report = text => { status.textContent = text }
  const stop = () => { stopped = true; abort.abort(); if (timer !== undefined) win.clearTimeout(timer); win.removeEventListener('message', receive); win.removeEventListener('pagehide', stop) }
  const send = (type, extra) => {
    if (!stopped && parent && !parent.closed) parent.postMessage({ v: 1, type, nonce, ...extra }, config.opsOrigin)
  }
  const fail = text => {
    if (stopped || failed) return
    failed = true; report(text)
    if (config) send('status', { status: 'failed' })
    stop()
  }
  const arm = milliseconds => {
    if (timer !== undefined) win.clearTimeout(timer)
    timer = win.setTimeout(() => fail('Demo sign-in timed out. Return to OPS and start a fresh sign-in.'), milliseconds)
  }
  const receive = event => {
    if (stopped || used || !config || event.source !== parent || event.origin !== config.opsOrigin) return
    const value = event.data
    const first = !renewable && seenRequests.size === 0
    if (!(keys(value, ['v', 'type', 'nonce', 'persona', 'requestUri']) || first && keys(value, ['v', 'type', 'nonce', 'persona', 'requestUri', 'keepAlive']) && value.keepAlive === true) || value.v !== 1 || value.type !== 'prove' || value.nonce !== nonce || !personas.includes(value.persona) || typeof value.requestUri !== 'string' || value.requestUri.length > 400) return
    let uri
    try { uri = new URL(value.requestUri) } catch { return }
    if (uri.origin !== config.opsOrigin || uri.href !== value.requestUri || uri.username || uri.password || uri.search || uri.hash || !/^\/api\/v2\/auth\/privado\/requests\/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(uri.pathname) || uri.pathname.endsWith('/00000000-0000-0000-0000-000000000000')) return
    if (seenRequests.has(uri.href) || seenRequests.size >= 16 || renewable && (value.persona !== persona || Date.now() >= renewableUntil)) return
    if (first && value.keepAlive === true) { renewable = true; persona = value.persona; renewableUntil = Date.now() + 30 * 60 * 1000 }
    seenRequests.add(uri.href)
    used = true
    arm(Math.min(150000, renewable ? renewableUntil - Date.now() : 150000))
    void prove(value)
  }
  const prove = async value => {
    try {
      report('Generating a fresh cryptographic proof…'); send('status', { status: 'working' })
      // One submission only. An uncertain POST is never retried.
      const job = await boundedJSON(fetcher, '/prove', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ persona: value.persona, requestUri: value.requestUri }), signal: abort.signal }, 4096)
      if (!keys(job, ['id', 'status']) || job.status !== 'working' || !/^[0-9a-f-]{36}$/.test(job.id)) throw Error('invalid job')
      const deadline = Date.now() + 150000
      for (;;) {
        await new Promise(resolve => win.setTimeout(resolve, 750))
        if (stopped || !parent || parent.closed || Date.now() >= deadline) throw Error('expired')
        const result = await boundedJSON(fetcher, '/jobs/' + job.id, { signal: abort.signal }, 4096)
        if (!keys(result, ['status']) || !['working', 'submitted', 'failed'].includes(result.status)) throw Error('invalid status')
        if (result.status === 'failed') throw Error('proof failed')
        if (result.status === 'submitted') {
          report('Proof submitted. Finishing the original OPS sign-in…'); send('status', { status: 'submitted' })
          // Restore the original tab's ordinary visible-document polling if
          // the browser presented this popup as a foreground tab. Progress
          // never substitutes for Core's verified candidate.
          try { parent.focus() } catch {}
          if (!renewable) { stop(); return }
          if (Date.now() >= renewableUntil) { stop(); return }
          used = false
          report('Demo session active. Keep this window open for automatic re-verification.')
          arm(renewableUntil - Date.now())
          return
        }
      }
    } catch {
      fail('Demo sign-in could not finish. Return to OPS and start a fresh sign-in.')
    }
  }
  try {
    if (!noncePattern.test(nonce) || !parent || parent.closed) throw Error('missing owner')
    win.addEventListener('pagehide', stop, { once: true })
    arm(45000)
    const candidate = await boundedJSON(fetcher, '/bridge-config', { signal: abort.signal }, 16384)
    if (!keys(candidate, ['v', 'testOnly', 'opsOrigin', 'network', 'issuerDid', 'verifierDid', 'personas']) || candidate.v !== 1 || candidate.testOnly !== true) throw Error('invalid config')
    const origin = new URL(candidate.opsOrigin)
    if (origin.origin !== candidate.opsOrigin || origin.protocol !== 'https:' || origin.hostname !== 'localhost') throw Error('invalid origin')
    if (stopped) return stop
    config = candidate
    win.addEventListener('message', receive)
    send('ready', { config })
    report('Connected. Waiting for the selected OPS sign-in…')
    return stop
  } catch { fail('Open this window using a demo identity button in OPS. Check the local certificate if sign-in could not connect.'); return stop }
}
if (typeof window !== 'undefined') void runBridge()
