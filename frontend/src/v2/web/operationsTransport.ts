import { closedJSON } from '../auth/protocol'
import { accessLogError, validAccessLogQuery, type AccessLogErrorCode } from './accessLogsModels'

const uuid = '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'
const canonicalUUID = (value: string) =>
  new RegExp('^' + uuid + '$').test(value) && value !== '00000000-0000-0000-0000-000000000000'
interface OperationErrorDetail { code: AccessLogErrorCode; retainedFrom?: string }
function operationErrorMessage(status: number, mutation: boolean, detail?: OperationErrorDetail): string {
  if (detail?.code === 'history_pruned')
    return 'Requested history has been pruned. Choose a later start time' + (detail.retainedFrom ? ' at or after ' + detail.retainedFrom : '') + '.'
  if (detail?.code === 'cursor_expired' || detail?.code === 'cursor_mismatch')
    return 'This page is no longer valid for the selected filters or source. Search again for a fresh snapshot.'
  if (detail?.code === 'source_unavailable')
    return 'The access-log source is unavailable. This is not an empty result; try again after the source recovers.'
  switch (status) {
    case 401: return 'Your session expired. Sign in again.'
    case 403: return 'Your current organization role does not allow this operation.'
    case 404: return 'The record is unavailable for this identity.'
    case 409: return 'This operation conflicts with the current state. Reload before making another change.'
    case 400: return 'Check the request fields and approved rule limits.'
    case 422: return 'This scope cannot be qualified. Narrow the request or check the configured source.'
    default: return mutation
      ? 'The result is uncertain. Check the current records before submitting again.'
      : 'The operational service is temporarily unavailable.'
  }
}
export class OperationHTTPError extends Error {
  readonly code?: AccessLogErrorCode
  readonly retainedFrom?: string
  constructor(
    readonly status: number,
    readonly mutation: boolean,
    detail?: OperationErrorDetail,
  ) {
    super(operationErrorMessage(status, mutation, detail))
    this.code = detail?.code
    this.retainedFrom = detail?.retainedFrom
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
  const accessLogs = new RegExp('^/api/v2/orgs/(' + uuid + ')/access-logs$').exec(path)
  if (accessLogs && canonicalUUID(accessLogs[1])) {
    valid = method === 'GET'
    allowed = ['from', 'to', 'actorId', 'method', 'outcome', 'requestReference', 'limit', 'cursor']
  } else if (compliance && canonicalUUID(compliance[1])) {
    const [, , section, id] = compliance
    if (id && !canonicalUUID(id)) return false
    if (id) valid = section === 'travel-rule-records' && (method === 'GET' || method === 'DELETE')
    else if (section === 'preview') valid = method === 'POST'
    else if (section === 'travel-rule-records') {
      valid = method === 'GET' || method === 'POST'
      if (method === 'GET') allowed = ['limit', 'cursor']
    } else {
      valid = method === 'GET'
      if (section === 'events') allowed = ['limit', 'cursor', 'decision', 'transferType', 'actorId']
    }
  } else if (disclosure) {
    const [, id, action] = disclosure
    if (id && !canonicalUUID(id)) return false
    if (!id) {
      valid = method === 'GET' || method === 'POST'
      if (method === 'GET') allowed = ['role', 'organizationId', 'limit', 'cursor', 'status', 'privacyLevel', 'recipientActorId', 'createdFrom', 'createdTo']
    } else if (action === 'read' || action === 'revoke') valid = method === 'POST'
    else {
      valid = method === 'GET'
      if (action === 'audit') allowed = ['limit', 'cursor']
    }
  } else if (path === '/api/v2/self/selection' || path === '/health/live' || path === '/health/ready') valid = method === 'GET'
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
    if (key === 'decision' && !['allowed', 'denied', 'monitored'].includes(value)) return false
    if (key === 'transferType' && !['eth', 'erc20'].includes(value)) return false
    if (key === 'status' && !['active', 'expired', 'revoked'].includes(value)) return false
    if (key === 'privacyLevel' && !['redacted', 'pseudonymous', 'full'].includes(value)) return false
    if (key === 'recipientActorId' && !/^ops:p1:[A-Za-z0-9_-]{43}$/.test(value)) return false
    if ((key === 'createdFrom' || key === 'createdTo') && (!/^[1-9][0-9]{0,11}$/.test(value) || Number(value) > 253402300799)) return false
  }
  if (
    (query.get('role') === 'data-org-admin' && !query.has('organizationId')) ||
    (query.has('organizationId') && query.get('role') !== 'data-org-admin')
  )
    return false
  if (accessLogs && !validAccessLogQuery(query)) return false
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
          'eth_getBalance',
          'web3_clientVersion',
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
      ...(options.signal ? [options.signal] : []),
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
  if (response.status < 200 || response.status >= 300) {
    let detail
    if (new RegExp('^/api/v2/orgs/' + uuid + '/access-logs(?:\\?|$)').test(endpoint)) {
      try { detail = accessLogError(JSON.parse(raw), response.status) } catch { /* Keep the bounded generic HTTP error. */ }
    }
    throw new OperationHTTPError(response.status, method !== 'GET', detail)
  }
  const value: unknown = JSON.parse(raw)
  check()
  return value
}
