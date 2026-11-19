import { actorID, record } from './operationsModels'

export const accessLogOutcomes = ['success', 'invalid', 'unauthenticated', 'denied', 'evaluation-failed', 'unavailable', 'unconfirmed'] as const
export type AccessLogOutcome = typeof accessLogOutcomes[number]
export const outcomeLabels: Record<AccessLogOutcome, string> = { success: 'Success', invalid: 'Invalid request', unauthenticated: 'Unauthenticated', denied: 'Denied', 'evaluation-failed': 'Evaluation failed', unavailable: 'Unavailable', unconfirmed: 'Unconfirmed' }
export const logUUID = (value: unknown): value is string => typeof value === 'string' && /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(value) && value !== '00000000-0000-0000-0000-000000000000'
const digest = (value: unknown): value is string => typeof value === 'string' && /^sha256:[0-9a-f]{64}$/.test(value)
const method = (value: unknown): value is string => typeof value === 'string' && /^[A-Za-z][A-Za-z0-9_.]{0,99}$/.test(value)
function exact(value: unknown, keys: string[], optional: string[] = []) {
  const row = record(value)
  if (keys.some(key => !(key in row)) || Object.keys(row).some(key => !keys.includes(key) && !optional.includes(key))) throw Error('Invalid access-log response')
  return row
}
// Preserve fractional precision when comparing a recorded instant or filter.
// Date is used only for whole seconds; no nanosecond value passes through Number.
export function logTime(value: unknown): bigint {
  if (typeof value !== 'string') throw Error('Invalid access-log time')
  const parts = /^(\d{4})-(\d{2})-(\d{2})T([01]\d|2[0-3]):([0-5]\d):([0-5]\d)(?:\.(\d{1,9}))?(Z|[+-](?:[01]\d|2[0-3]):[0-5]\d)$/.exec(value)
  if (!parts) throw Error('Use a valid RFC3339 time')
  const day = new Date(`${parts[1]}-${parts[2]}-${parts[3]}T00:00:00Z`)
  if (!Number.isFinite(day.getTime()) || day.toISOString().slice(0, 10) !== `${parts[1]}-${parts[2]}-${parts[3]}`) throw Error('Invalid access-log date')
  const seconds = Date.parse(`${parts[1]}-${parts[2]}-${parts[3]}T${parts[4]}:${parts[5]}:${parts[6]}${parts[8]}`)
  if (!Number.isFinite(seconds)) throw Error('Invalid access-log time')
  return BigInt(seconds) * 1000000n + BigInt((parts[7] ?? '').padEnd(9, '0'))
}
export interface AccessLogQuery { from: string; to: string; actorId?: string; method?: string; outcome?: AccessLogOutcome; requestReference?: string; limit: number }
export function validAccessLogQuery(query: URLSearchParams): boolean {
  try {
    const keys = ['from', 'to', 'actorId', 'method', 'outcome', 'requestReference', 'limit', 'cursor']
    if ([...query].some(([key, value]) => !keys.includes(key) || !value || query.getAll(key).length !== 1)) return false
    if (!query.has('from') || !query.has('to') || logTime(query.get('from')) >= logTime(query.get('to'))) return false
    if (query.has('actorId') && !actorID(query.get('actorId')!)) return false
    if (query.has('method') && !method(query.get('method'))) return false
    if (query.has('outcome') && !accessLogOutcomes.includes(query.get('outcome') as AccessLogOutcome)) return false
    if (query.has('requestReference') && !logUUID(query.get('requestReference'))) return false
    if (query.has('limit') && (!/^[1-9][0-9]{0,2}$/.test(query.get('limit')!) || Number(query.get('limit')) > 100)) return false
    if (query.has('cursor') && (query.get('cursor')!.length > 8192 || /[^\x21-\x7e]/.test(query.get('cursor')!))) return false
    return true
  } catch { return false }
}
export function accessLogsEndpoint(org: string, query: AccessLogQuery, cursor?: string): string {
  const params = new URLSearchParams(Object.entries(query).map(([key, value]) => [key, String(value)]))
  if (cursor) params.set('cursor', cursor)
  if (!logUUID(org) || !validAccessLogQuery(params)) throw Error('Check the actor ID, method, outcome, time range and request reference.')
  return `/api/v2/orgs/${org}/access-logs?` + params
}
export interface AccessLogItem { requestReference: string; observedAt: string; actorId: string; organizationId: string; method: string; outcome: AccessLogOutcome; httpStatus: number; rpcErrorCode: number | null; recordedStatus: number; trustedIP: string | null; policyDigest: string | null; configurationDigest: string; reason: 'not_recorded' }
export interface AccessLogSource { sourceId: string; generation: string; networkDigest: string; configurationDigest: string; headReference: string; sourceAsOf: string; retainedFrom: string; population: 'SEALED_REQUEST_COMPLETIONS_AS_OF_CHAIN_HEAD'; coverage: 'committed-sealed-prefix' }
export interface AccessLogPage { items: AccessLogItem[]; next: string | null; source: AccessLogSource }
export function sameLogSource(a: AccessLogSource, b: AccessLogSource): boolean {
  return ['sourceId', 'generation', 'networkDigest', 'configurationDigest', 'headReference', 'population', 'coverage'].every(key => a[key as keyof AccessLogSource] === b[key as keyof AccessLogSource])
}
export function accessLogPage(value: unknown, org: string, query: AccessLogQuery, pinned?: AccessLogSource): AccessLogPage {
  const page = exact(value, ['items', 'next', 'source']), source = exact(page.source, ['sourceId', 'generation', 'networkDigest', 'configurationDigest', 'headReference', 'sourceAsOf', 'retainedFrom', 'population', 'coverage'])
  if (
    !logUUID(source.sourceId) ||
    !logUUID(source.generation) ||
    !digest(source.networkDigest) ||
    !digest(source.configurationDigest) ||
    !digest(source.headReference) ||
    source.population !== 'SEALED_REQUEST_COMPLETIONS_AS_OF_CHAIN_HEAD' ||
    source.coverage !== 'committed-sealed-prefix' ||
    !Array.isArray(page.items) ||
    page.items.length > query.limit ||
    (page.next !== null && (
      typeof page.next !== 'string' ||
      page.next.length < 1 ||
      page.next.length > 8192 ||
      /[^\x21-\x7e]/.test(page.next)
    ))
  ) throw Error('Invalid access-log response')
  logTime(source.sourceAsOf); logTime(source.retainedFrom)
  if (!(source.sourceAsOf as string).endsWith('Z') || !(source.retainedFrom as string).endsWith('Z')) throw Error('Invalid access-log source time')
  if (pinned && !sameLogSource(pinned, source as unknown as AccessLogSource)) throw Error('The access-log source changed. Search again for a fresh snapshot.')
  const references = new Set<string>(), from = logTime(query.from), to = logTime(query.to)
  const items = page.items.map(value => {
    const row = exact(value, ['requestReference', 'observedAt', 'actorId', 'organizationId', 'method', 'outcome', 'httpStatus', 'rpcErrorCode', 'recordedStatus', 'trustedIP', 'policyDigest', 'configurationDigest', 'reason'])
    const time = logTime(row.observedAt), outcome = row.outcome as AccessLogOutcome
    if (!(row.observedAt as string).endsWith('Z')) throw Error('Invalid access-log observation time')
    const statuses = { success: 200, invalid: 400, unauthenticated: 401, denied: 403, 'evaluation-failed': 422, unavailable: 503, unconfirmed: 502 }
    if (
      !logUUID(row.requestReference) ||
      references.has(row.requestReference) ||
      typeof row.actorId !== 'string' ||
      (row.actorId !== '' && !actorID(row.actorId)) ||
      row.organizationId !== org ||
      !method(row.method) ||
      !accessLogOutcomes.includes(outcome) ||
      !Number.isInteger(row.httpStatus) ||
      Number(row.httpStatus) < 100 ||
      Number(row.httpStatus) > 599 ||
      (row.rpcErrorCode !== null && (
        !Number.isInteger(row.rpcErrorCode) ||
        Number(row.rpcErrorCode) < -2147483648 ||
        Number(row.rpcErrorCode) > 2147483647
      )) ||
      row.recordedStatus !== statuses[outcome] ||
      (outcome === 'success' && (
        row.rpcErrorCode !== null || Number(row.httpStatus) < 200 || Number(row.httpStatus) > 299
      )) ||
      (row.policyDigest !== null && !digest(row.policyDigest)) ||
      !digest(row.configurationDigest) ||
      row.reason !== 'not_recorded' ||
      (row.trustedIP !== null && (
        typeof row.trustedIP !== 'string' || row.trustedIP.length < 1 || row.trustedIP.length > 45
      )) ||
      time < from ||
      time >= to ||
      (query.actorId && row.actorId !== query.actorId) ||
      (query.method && row.method !== query.method) ||
      (query.outcome && row.outcome !== query.outcome) ||
      (query.requestReference && row.requestReference !== query.requestReference)
    ) throw Error('Access-log records do not match the requested scope')
    references.add(row.requestReference)
    return row as unknown as AccessLogItem
  })
  return { items, next: page.next as string | null, source: source as unknown as AccessLogSource }
}
export const accessLogErrorCodes = { invalid_request: 400, unauthenticated: 401, forbidden: 403, cursor_mismatch: 409, cursor_expired: 409, history_pruned: 410, source_unavailable: 503 } as const
export type AccessLogErrorCode = keyof typeof accessLogErrorCodes
export function accessLogError(value: unknown, status: number): { code: AccessLogErrorCode; retainedFrom?: string } | undefined {
  try {
    const detail = exact(exact(value, ['error']).error, ['code', 'message'], ['retainedFrom'])
    if (typeof detail.code !== 'string' || !(detail.code in accessLogErrorCodes) || accessLogErrorCodes[detail.code as AccessLogErrorCode] !== status || typeof detail.message !== 'string' || detail.message.length > 1024) return
    if ('retainedFrom' in detail) logTime(detail.retainedFrom)
    return { code: detail.code as AccessLogErrorCode, ...('retainedFrom' in detail ? { retainedFrom: detail.retainedFrom as string } : {}) }
  } catch { return }
}
