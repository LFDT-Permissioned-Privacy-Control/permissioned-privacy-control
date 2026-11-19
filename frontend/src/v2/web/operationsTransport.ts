import { closedJSON } from '../auth/protocol'

const uuid = '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'
const canonicalUUID = (value: string) =>
  new RegExp('^' + uuid + '$').test(value) && value !== '00000000-0000-0000-0000-000000000000'
export class OperationHTTPError extends Error {
  constructor(
    readonly status: number,
    readonly mutation: boolean,
  ) {
    super(
      status === 401
        ? 'Your session expired. Sign in again.'
        : status === 403
          ? 'Your current organization role does not allow this operation.'
          : status === 404
            ? 'The record is unavailable for this identity.'
            : status === 409
              ? 'This operation conflicts with the current state. Reload before making another change.'
              : status === 400
                ? 'Check the request fields and approved rule limits.'
                : status === 422
                  ? 'This scope cannot be qualified. Narrow the request or check the configured source.'
                  : mutation
                    ? 'The result is uncertain. Check the current records before submitting again.'
                    : 'The operational service is temporarily unavailable.',
    )
  }
}

// Full canonical native paths only. This is not the wallet-only endpoint map.
export function operationEndpoint(endpoint: string, method: string): boolean {
  if (
    !endpoint.startsWith('/') ||
    endpoint.startsWith('//') ||
    endpoint.length > 17000 ||
    /[\\#\u0000-\u0020\u007f]/.test(endpoint)
  )
    return false
  const [path, raw = '', extra] = endpoint.split('?')
  if (extra !== undefined || path.includes('%') || /%(?![0-9a-fA-F]{2})/.test(raw)) return false
  let allowed: string[] = [],
    valid = false
  const compliance = new RegExp(
    '^/api/v2/orgs/(' +
      uuid +
      ')/compliance/(config|tokens|address-thresholds|sanctions|quotes|events|travel-rule-records|preview)(?:/(' +
      uuid +
      '))?$',
  ).exec(path)
  const disclosure = new RegExp(
    '^/api/v1/disclosure/cases(?:/(' + uuid + ')(?:/(audit|read|revoke))?)?$',
  ).exec(path)
  if (compliance && canonicalUUID(compliance[1])) {
    const [, , section, id] = compliance
    if (id && !canonicalUUID(id)) return false
    if (id) valid = section === 'travel-rule-records' && (method === 'GET' || method === 'DELETE')
    else if (section === 'preview') valid = method === 'POST'
    else if (section === 'travel-rule-records') {
      valid = method === 'GET' || method === 'POST'
      if (method === 'GET') allowed = ['limit', 'cursor']
    } else {
      valid = method === 'GET'
      if (section === 'events') allowed = ['limit', 'cursor']
    }
  } else if (disclosure) {
    const [, id, action] = disclosure
    if (id && !canonicalUUID(id)) return false
    if (!id) {
      valid = method === 'GET' || method === 'POST'
      if (method === 'GET') allowed = ['role', 'organizationId', 'limit', 'cursor']
    } else if (action === 'read' || action === 'revoke') valid = method === 'POST'
    else {
      valid = method === 'GET'
      if (action === 'audit') allowed = ['limit', 'cursor']
    }
  } else if (path === '/health/live' || path === '/health/ready') valid = method === 'GET'
  else if (new RegExp('^/rpc/' + uuid + '$').test(path))
    valid = method === 'POST' && canonicalUUID(path.slice(5))
  if (!valid || (method !== 'GET' && raw !== '')) return false
  const query = new URLSearchParams(raw)
  for (const [key, value] of query) {
    if (!allowed.includes(key) || !value || query.getAll(key).length !== 1) return false
    if (key === 'limit' && (!/^[1-9][0-9]{0,2}$/.test(value) || Number(value) > 100)) return false
    if (key === 'cursor' && (value.length > 8192 || /[^\x21-\x7e]/.test(value))) return false
    if (key === 'organizationId' && !canonicalUUID(value)) return false
    if (key === 'role' && value !== 'recipient' && value !== 'data-org-admin') return false
  }
  if (
    (query.get('role') === 'data-org-admin' && !query.has('organizationId')) ||
    (query.has('organizationId') && query.get('role') !== 'data-org-admin')
  )
    return false
  return true
}

export async function operationRequest(
  token: string,
  endpoint: string,
  options: RequestInit,
  signal: AbortSignal,
  check: () => void,
): Promise<unknown> {
  const method = options.method ?? 'GET'
  if (
    !operationEndpoint(endpoint, method) ||
    (options.body !== undefined && typeof options.body !== 'string') ||
    (method !== 'POST' && options.body !== undefined) ||
    (method === 'POST' && !options.body) ||
    (typeof options.body === 'string' && new TextEncoder().encode(options.body).length > 256 << 10)
  )
    throw Error('Invalid native operation')
  if (typeof options.body === 'string') {
    const body = closedJSON(options.body, 256 << 10)
    if (!body || typeof body !== 'object' || Array.isArray(body))
      throw Error('A single operation object is required')
    if (endpoint.startsWith('/rpc/')) {
      const v = body as Record<string, unknown>
      if (
        Object.keys(v).sort().join() !== 'id,jsonrpc,method,params' ||
        v.jsonrpc !== '2.0' ||
        typeof v.id !== 'string' ||
        !Array.isArray(v.params) ||
        ![
          'eth_chainId',
          'net_version',
          'eth_syncing',
          'eth_blockNumber',
          'eth_call',
          'eth_estimateGas',
          'eth_getTransactionReceipt',
        ].includes(String(v.method))
      )
        throw Error('Unsupported diagnostic request')
    }
  }
  check()
  const response = await fetch(endpoint, {
    method,
    mode: 'same-origin',
    credentials: 'same-origin',
    redirect: 'error',
    cache: 'no-store',
    headers: {
      Authorization: 'Bearer ' + token,
      Accept: 'application/json',
      ...(method === 'POST' ? { 'Content-Type': 'application/json' } : {}),
    },
    body: options.body,
    signal: AbortSignal.any([
      signal,
      AbortSignal.timeout(endpoint.startsWith('/rpc/') ? 25000 : 5000),
    ]),
  })
  check()
  if (response.redirected || response.headers.get('Cache-Control') !== 'no-store')
    throw Error('Invalid native response')
  if (endpoint.startsWith('/health/'))
    return { ready: response.status === 204 || response.status === 200, status: response.status }
  if (
    !/^application\/json(?:;\s*charset=utf-8)?$/i.test(
      response.headers.get('Content-Type') ?? '',
    ) ||
    !response.body
  )
    throw Error('Invalid native response')
  const reader = response.body.getReader(),
    decoder = new TextDecoder('utf-8', { fatal: true })
  let raw = '',
    bytes = 0
  try {
    for (;;) {
      const next = await reader.read()
      check()
      if (next.done) break
      bytes += next.value.byteLength
      if (bytes > 2 << 20) throw Error('Native response too large')
      raw += decoder.decode(next.value, { stream: true })
    }
    raw += decoder.decode()
    check()
  } finally {
    void reader.cancel().catch(() => undefined)
    reader.releaseLock()
  }
  if (response.status < 200 || response.status >= 300)
    throw new OperationHTTPError(response.status, method !== 'GET')
  const value: unknown = JSON.parse(raw)
  check()
  return value
}
