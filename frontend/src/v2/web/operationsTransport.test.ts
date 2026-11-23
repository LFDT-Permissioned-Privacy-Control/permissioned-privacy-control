import { afterEach, beforeAll, expect, it, vi } from 'vitest'
import { operationEndpoint, operationRequest, OperationHTTPError } from './operationsTransport'
const org = '11111111-1111-4111-8111-111111111111',
  id = '22222222-2222-4222-8222-222222222222'
beforeAll(() => {
  // jsdom23 predates the browser API required by the native entrypoint.
  if (!AbortSignal.any)
    Object.defineProperty(AbortSignal, 'any', {
      configurable: true,
      value: (signals: AbortSignal[]) => {
        const controller = new AbortController()
        for (const signal of signals) {
          if (signal.aborted) controller.abort()
          else signal.addEventListener('abort', () => controller.abort(), { once: true })
        }
        return controller.signal
      },
    })
})
afterEach(() => vi.unstubAllGlobals())
it('accepts only finite native operations and their exact query/method contracts', () => {
  for (const [path, method] of [
    [`/api/v2/orgs/${org}/compliance/config`, 'GET'],
    [`/api/v2/orgs/${org}/diagnostics`, 'GET'],
    [`/api/v2/orgs/${org}/compliance/travel-rule-records`, 'POST'],
    [`/api/v2/orgs/${org}/compliance/travel-rule-records/${id}`, 'DELETE'],
    [`/api/v1/disclosure/cases?role=data-org-admin&organizationId=${org}&limit=25`, 'GET'],
    [`/api/v1/disclosure/cases/${id}/read`, 'POST'],
    ['/health/ready', 'GET'],
    ['/api/v2/configuration/sources', 'GET'],
    ['/api/v2/configuration/sources/current', 'GET'],
    [`/rpc/${org}`, 'POST'],
  ])
    expect(operationEndpoint(path, method), path).toBe(true)
  for (const [path, method] of [
    [`/api/v2/orgs/${org}/compliance/config`, 'POST'],
    [`/api/v2/orgs/${org}/diagnostics`, 'POST'],
    [`/api/v2/orgs/${org}/diagnostics?url=other`, 'GET'],
    ['https://evil.test/api', 'GET'],
    ['//evil.test/api', 'GET'],
    ['/api/v1/users', 'GET'],
    ['/api/v2/self/selection', 'GET'],
    ['/api/v2/self/selection?org=other', 'GET'],
    ['/api/v2/configuration/sources', 'POST'],
    ['/api/v2/configuration/sources/current', 'POST'],
    ['/api/v2/configuration/sources/current', 'DELETE'],
    ['/api/v2/configuration/sources?path=other', 'GET'],
    ['/api/v2/configuration/sources/current?', 'GET'],
    ['/api/v2/configuration/sources/current?refresh=true', 'GET'],
    ['/api/v2/configuration/sources/../secrets', 'GET'],
    ['/api/v2/configuration/sources/%63urrent', 'GET'],
    ['/api/v2/configuration/sources/current/file.json', 'GET'],
    ['/api/v2/self/selection', 'POST'],
    [`/api/v1/disclosure/cases?role=recipient&organizationId=${org}`, 'GET'],
    [`/api/v1/disclosure/cases?limit=1&limit=2`, 'GET'],
    [`/api/v1/disclosure/cases?offset=1`, 'GET'],
    [`/api/v1/disclosure/cases/${id}/approve`, 'POST'],
    [`/rpc/${org}?target=evil`, 'POST'],
    [`/api/v2/orgs/${org}/compliance/events?cursor=%00`, 'GET'],
  ])
    expect(operationEndpoint(path, method), path).toBe(false)
})
it('keeps the bearer in one fixed same-origin request and preserves business errors', async () => {
  const fetch = vi.fn(
    async () =>
      new Response('{"error":"operational state conflict"}', {
        status: 409,
        headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' },
      }),
  )
  vi.stubGlobal('fetch', fetch)
  const check = vi.fn()
  await expect(
    operationRequest(
      'private-test-token',
      `/api/v2/orgs/${org}/compliance/travel-rule-records`,
      { method: 'POST', body: '{}' },
      new AbortController().signal,
      check,
    ),
  ).rejects.toMatchObject({ status: 409, mutation: true })
  expect(fetch).toHaveBeenCalledTimes(1)
  expect(fetch.mock.calls[0][0]).toBe(`/api/v2/orgs/${org}/compliance/travel-rule-records`)
  expect(fetch.mock.calls[0][1]).toMatchObject({
    credentials: 'same-origin',
    mode: 'same-origin',
    redirect: 'error',
    cache: 'no-store',
    headers: { Authorization: 'Bearer private-test-token' },
  })
  expect(check.mock.calls.length).toBeGreaterThan(1)
})
it('never forwards unsupported diagnostics or retries an uncertain mutation', async () => {
  const fetch = vi.fn(async () => {
    throw Error('connection lost')
  })
  vi.stubGlobal('fetch', fetch)
  await expect(
    operationRequest(
      'private',
      `/rpc/${org}`,
      {
        method: 'POST',
        body: '{"jsonrpc":"2.0","id":"one","method":"eth_sendTransaction","params":[]}',
      },
      new AbortController().signal,
      () => {},
    ),
  ).rejects.toThrow('Unsupported')
  expect(fetch).not.toHaveBeenCalled()
  await expect(
    operationRequest(
      'private',
      '/api/v1/disclosure/cases',
      { method: 'POST', body: '{}' },
      new AbortController().signal,
      () => {},
    ),
  ).rejects.toThrow('connection lost')
  expect(fetch).toHaveBeenCalledTimes(1)
})
it('rejects a private result when the original operation changes while reading', async () => {
  let valid = true
  vi.stubGlobal(
    'fetch',
    vi.fn(
      async () =>
        new Response(
          new ReadableStream({
            start(controller) {
              controller.enqueue(new TextEncoder().encode('{"secret":"old"}'))
              valid = false
              controller.close()
            },
          }),
          { headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' } },
        ),
    ),
  )
  await expect(
    operationRequest(
      'private',
      `/api/v2/orgs/${org}/compliance/config`,
      {},
      new AbortController().signal,
      () => {
        if (!valid) throw Error('context changed')
      },
    ),
  ).rejects.toThrow('context changed')
})
it('maps real empty health responses without fabricated component state', async () => {
  vi.stubGlobal(
    'fetch',
    vi.fn(
      async () => new Response(null, { status: 204, headers: { 'Cache-Control': 'no-store' } }),
    ),
  )
  await expect(
    operationRequest('private', '/health/ready', {}, new AbortController().signal, () => {}),
  ).resolves.toEqual({ ready: true, status: 204 })
  expect(new OperationHTTPError(403, false).message).toContain('role')
})

it('admits only the direct read-only access-log route with explicit bounded server filters', () => {
  const base = `/api/v2/orgs/${org}/access-logs`, range = 'from=2026-11-20T10%3A00%3A00Z&to=2026-11-20T12%3A00%3A00Z'
  expect(operationEndpoint(base + '?' + range + '&method=eth_call&outcome=denied&limit=50&requestReference=' + id, 'GET')).toBe(true)
  for (const [path, method] of [[base, 'GET'], [base + '?' + range, 'POST'], [base + '?' + range + '&offset=50', 'GET'], [base + '?' + range + '&method=eth_call&method=eth_getLogs', 'GET'], [base + '?' + range + '&actorId=untrusted-directory-name', 'GET'], [base + '?' + range + '&outcome=unknown', 'GET']]) expect(operationEndpoint(path, method)).toBe(false)
})
it('preserves typed retention/source/cursor errors without trusting arbitrary remote diagnostic text', async () => {
  const endpoint = `/api/v2/orgs/${org}/access-logs?from=2026-11-20T10%3A00%3A00Z&to=2026-11-20T12%3A00%3A00Z`
  for (const [code, status, message] of [['history_pruned', 410, 'pruned'], ['source_unavailable', 503, 'source is unavailable'], ['cursor_mismatch', 409, 'Search again']] as const) {
    vi.stubGlobal('fetch', vi.fn(async () => new Response(JSON.stringify({ error: { code, message: 'untrusted raw SQL or credential data', ...(code === 'history_pruned' ? { retainedFrom: '2026-11-20T11:00:00Z' } : {}) } }), { status, headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' } })))
    try { await operationRequest('private', endpoint, {}, new AbortController().signal, () => {}); throw Error('Expected rejection') }
    catch (error) {
      expect(error).toBeInstanceOf(OperationHTTPError)
      expect(error).toMatchObject({ status, mutation: false, code })
      expect((error as Error).message).toContain(message)
      expect((error as Error).message).not.toContain('untrusted raw')
      if (code === 'history_pruned') expect(error).toMatchObject({ retainedFrom: '2026-11-20T11:00:00Z' })
    }
  }
})
it('composes caller cancellation with mandatory scope cancellation for an explicit record detail', async () => {
  const caller = new AbortController(), owner = new AbortController()
  let passed: AbortSignal | undefined
  vi.stubGlobal('fetch', vi.fn(async (_path: string, options: RequestInit) => {
    passed = options.signal as AbortSignal
    return new Promise((_resolve, reject) => passed!.addEventListener('abort', () => reject(Error('aborted')), { once: true }))
  }))
  const request = operationRequest('private', `/api/v2/orgs/${org}/compliance/travel-rule-records/${id}`, { signal: caller.signal }, owner.signal, () => {})
  expect(passed?.aborted).toBe(false)
  caller.abort()
  await expect(request).rejects.toThrow('aborted')
  expect(passed?.aborted).toBe(true)
})

const sourceEndpoint = '/api/v2/configuration/sources/current', sourceETag = '"' + 'a'.repeat(64) + '"'
const sourceHeaders = { 'Content-Type': 'application/json', 'Cache-Control': 'no-store', ETag: sourceETag }
it('keeps conditional source headers narrow and cannot override native authentication', async () => {
  const fetch = vi.fn(async () => new Response('{"apiVersion":"ops.ui-source-package/v1","roots":[]}', { headers: sourceHeaders }))
  vi.stubGlobal('fetch', fetch)
  await expect(operationRequest('private-token', sourceEndpoint, { headers: { 'If-None-Match': sourceETag, 'Cache-Control': 'no-cache' } }, new AbortController().signal, () => {})).resolves.toMatchObject({ notModified: false, etag: sourceETag })
  expect(fetch.mock.calls[0][1]).toMatchObject({ credentials: 'same-origin', mode: 'same-origin', redirect: 'error', cache: 'no-store', headers: { Authorization: 'Bearer private-token', 'If-None-Match': sourceETag, 'Cache-Control': 'no-cache' } })
  fetch.mockClear()
  for (const [endpoint, headers] of [
    [sourceEndpoint, { Authorization: 'Bearer attacker' }],
    [sourceEndpoint, { 'If-None-Match': '*' }],
    [sourceEndpoint, { 'If-None-Match': 'W/' + sourceETag }],
    [sourceEndpoint, { 'If-None-Match': sourceETag + ', ' + sourceETag }],
    [sourceEndpoint, { 'Cache-Control': 'max-age=100' }],
    [sourceEndpoint, { 'X-Source-Path': '/etc/secret' }],
    ['/api/v2/configuration/sources', { 'If-None-Match': sourceETag }],
    [`/api/v2/orgs/${org}/diagnostics`, { 'If-None-Match': sourceETag }],
  ] as const) await expect(operationRequest('private-token', endpoint, { headers }, new AbortController().signal, () => {})).rejects.toThrow(/headers/)
  expect(fetch).not.toHaveBeenCalled()
})
it('accepts only the exact previously requested source ETag on a bodyless unchanged response', async () => {
  vi.stubGlobal('fetch', vi.fn(async () => new Response(null, { status: 304, headers: { 'Cache-Control': 'no-store', ETag: sourceETag } })))
  await expect(operationRequest('private', sourceEndpoint, { headers: { 'If-None-Match': sourceETag } }, new AbortController().signal, () => {})).resolves.toEqual({ notModified: true, etag: sourceETag })
  await expect(operationRequest('private', sourceEndpoint, {}, new AbortController().signal, () => {})).rejects.toThrow('unchanged')
  for (const tag of [undefined, 'invalid', '"' + 'b'.repeat(64) + '"']) {
    vi.stubGlobal('fetch', vi.fn(async () => new Response(null, { status: 304, headers: { 'Cache-Control': 'no-store', ...(tag ? { ETag: tag } : {}) } })))
    await expect(operationRequest('private', sourceEndpoint, { headers: { 'If-None-Match': sourceETag } }, new AbortController().signal, () => {})).rejects.toThrow('unchanged')
  }
})
it('rechecks original ownership immediately before publishing unchanged source data', async () => {
  let valid = true
  const response = new Response(null, { status: 304, headers: { 'Cache-Control': 'no-store', ETag: sourceETag } })
  const get = response.headers.get.bind(response.headers)
  vi.spyOn(response.headers, 'get').mockImplementation(name => { if (name === 'ETag') valid = false; return get(name) })
  vi.stubGlobal('fetch', vi.fn(async () => response))
  await expect(operationRequest('private', sourceEndpoint, { headers: { 'If-None-Match': sourceETag } }, new AbortController().signal, () => { if (!valid) throw Error('original credential expired') })).rejects.toThrow('original credential expired')
})
it('requires a canonical source tag and uncached source response', async () => {
  for (const headers of [
    { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' },
    { ...sourceHeaders, ETag: 'W/' + sourceETag },
    { ...sourceHeaders, 'Cache-Control': 'public' },
  ]) {
    vi.stubGlobal('fetch', vi.fn(async () => new Response('{}', { headers })))
    await expect(operationRequest('private', sourceEndpoint, {}, new AbortController().signal, () => {})).rejects.toThrow(/response/)
  }
})
it('allows a large source response without raising the ordinary operation or source-list budget', async () => {
  const raw = JSON.stringify({ text: 'x'.repeat(3 << 20) })
  vi.stubGlobal('fetch', vi.fn(async () => new Response(raw, { headers: sourceHeaders })))
  await expect(operationRequest('private', sourceEndpoint, {}, new AbortController().signal, () => {})).resolves.toMatchObject({ notModified: false, value: { text: 'x'.repeat(3 << 20) } })
  for (const endpoint of ['/api/v2/configuration/sources', `/api/v2/orgs/${org}/diagnostics`]) {
    vi.stubGlobal('fetch', vi.fn(async () => new Response(raw, { headers: sourceHeaders })))
    await expect(operationRequest('private', endpoint, {}, new AbortController().signal, () => {})).rejects.toThrow('too large')
  }
})
it('rejects an oversized source stream before decoding or publishing it and cancels the reader', async () => {
  let canceled = false
  vi.stubGlobal('fetch', vi.fn(async () => new Response(new ReadableStream({ start(controller) { controller.enqueue(new Uint8Array((90 << 20) + 1)) }, cancel() { canceled = true } }), { headers: sourceHeaders })))
  await expect(operationRequest('private', sourceEndpoint, {}, new AbortController().signal, () => {})).rejects.toThrow('too large')
  expect(canceled).toBe(true)
})
it('rejects source bytes if the owning credential changes while the response is consumed', async () => {
  let valid = true
  const reader = { read: vi.fn(async () => { valid = false; return { done: false, value: new TextEncoder().encode('{"private":"old-owner"}') } }), cancel: vi.fn(async () => {}), releaseLock: vi.fn() }
  vi.stubGlobal('fetch', vi.fn(async () => ({ redirected: false, status: 200, headers: new Headers(sourceHeaders), body: { getReader: () => reader } })))
  await expect(operationRequest('private', sourceEndpoint, {}, new AbortController().signal, () => { if (!valid) throw Error('source owner changed') })).rejects.toThrow('source owner changed')
  expect(reader.cancel).toHaveBeenCalledOnce()
  expect(reader.releaseLock).toHaveBeenCalledOnce()
})
