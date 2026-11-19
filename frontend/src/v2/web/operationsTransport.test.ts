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
    [`/api/v2/orgs/${org}/compliance/travel-rule-records`, 'POST'],
    [`/api/v2/orgs/${org}/compliance/travel-rule-records/${id}`, 'DELETE'],
    [`/api/v1/disclosure/cases?role=data-org-admin&organizationId=${org}&limit=25`, 'GET'],
    [`/api/v1/disclosure/cases/${id}/read`, 'POST'],
    ['/health/ready', 'GET'],
    [`/rpc/${org}`, 'POST'],
  ])
    expect(operationEndpoint(path, method), path).toBe(true)
  for (const [path, method] of [
    [`/api/v2/orgs/${org}/compliance/config`, 'POST'],
    ['https://evil.test/api', 'GET'],
    ['//evil.test/api', 'GET'],
    ['/api/v1/users', 'GET'],
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
      { method: 'POST', body: '{}', headers: { Authorization: 'forbidden' } },
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
