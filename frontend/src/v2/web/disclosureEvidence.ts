import { object, text } from '../auth/protocol'
import type { CaseScope, ObjectValue } from './operationsModels'

const digest = (v: unknown) => typeof v === 'string' && /^sha256:[0-9a-f]{64}$/.test(v)
const count = (v: unknown, max = 18446744073709551615n): v is string => typeof v === 'string' && /^(0|[1-9][0-9]{0,19})$/.test(v) && BigInt(v) <= max
const retainedCount = (v: unknown): v is string => count(v, 9223372036854775807n)
const uuid = (v: unknown) => typeof v === 'string' && /^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/.test(v)
const instant = (v: unknown): v is number => Number.isSafeInteger(v) && Number(v) >= 0 && Number(v) < 253402300800
const hash = (v: unknown) => typeof v === 'string' && /^0x[0-9a-f]{64}$/.test(v)
const optional = (v: ObjectValue, k: string, valid: (v: unknown) => boolean) => !(k in v) || valid(v[k])
function evidenceObject(raw: unknown, required: string[], optional: string[] = []): ObjectValue {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) throw Error('Invalid admission evidence')
  const value = raw as ObjectValue
  if (Object.keys(value).some(k => !required.includes(k) && !optional.includes(k)) || required.some(k => !(k in value))) throw Error('Invalid or private admission evidence fields')
  return value
}

// Go time.Time emits RFC3339Nano in UTC. Validate the calendar independently of
// the fractional part so nanoseconds survive browsers' millisecond Date precision.
function observedAt(value: unknown, preparedAt: number): boolean {
  if (typeof value !== 'string') return false
  const parts = /^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.([0-9]{1,9}))?Z$/.exec(value)
  if (!parts) return false
  const milliseconds = Date.parse(parts[1] + 'Z')
  return Number.isFinite(milliseconds) && milliseconds >= 0 &&
    new Date(milliseconds).toISOString().slice(0, 19) === parts[1] &&
    milliseconds / 1000 <= preparedAt
}

export function validateEvidencePage(result: ObjectValue, level: string, time: CaseScope['dataTime'], limit: number, preparedAt: number) {
  object(result, ['v', 'items', 'nextCursor', 'matchingRetainedCount', 'observedAt', 'pagination'])
  if (result.v !== 2 || result.pagination !== 'live-keyset' || !observedAt(result.observedAt, preparedAt) ||
    !Number.isSafeInteger(limit) || limit < 1 || limit > 100 ||
    !Array.isArray(result.items) || result.items.length > limit || !retainedCount(result.matchingRetainedCount) ||
    BigInt(result.matchingRetainedCount) < BigInt(result.items.length) ||
    result.nextCursor !== null && (typeof result.nextCursor !== 'string' || !/^[\x21-\x7e]{1,2048}$/.test(result.nextCursor)) ||
    result.items.length === 0 && result.nextCursor !== null) throw Error('Invalid admission evidence page')
  const ids = new Set<string>()
  let previousTime = Infinity
  for (const raw of result.items) {
    const base = ['id', 'population', 'time', 'kind', 'decision', 'monitored', 'coverage', 'policyDigest']
    const v = evidenceObject(raw, base, ['quoteDigest', ...(level === 'full' ? ['quote', 'transactionHash', 'recordId', 'reason'] : [])])
    if (!retainedCount(v.id) || v.id === '0' || ids.has(v.id) || v.population !== 'ADMISSION_DECISION' ||
      !instant(v.time) || v.time > previousTime || v.time < time.start || v.time > time.end || !['admission_only', 'root_native', 'root_erc20'].includes(String(v.kind)) ||
      !['allowed', 'denied'].includes(String(v.decision)) || typeof v.monitored !== 'boolean' ||
      !['not_detected', 'disabled', 'relay_request', 'root_transfer'].includes(String(v.coverage)) || !digest(v.policyDigest) ||
      !optional(v, 'quoteDigest', digest) || !optional(v, 'transactionHash', hash) ||
      !optional(v, 'recordId', uuid) || !optional(v, 'reason', x => text(x, 8192))) throw Error('Invalid or private admission evidence fields')
    if ('quote' in v) {
      const q = object(v.quote, ['id', 'currency', 'sourceId', 'value', 'providerAsOf', 'fetchedAt', 'digest'])
      if (!text(q.id, 128) || !text(q.currency, 3) || new TextEncoder().encode(q.currency).length !== 3 || !text(q.sourceId, 128) || !text(q.value, 512) ||
        !instant(q.providerAsOf) || !instant(q.fetchedAt) || !digest(q.digest) || q.digest !== v.quoteDigest) throw Error('Invalid quote evidence')
    }
    // Only whole seconds are exposed; the private keyset uses microseconds.
    // IDs therefore need not descend when two visible times are equal.
    previousTime = v.time
    ids.add(v.id)
  }
}

function afterUTF8(value: string, previous: string) {
  const left = new TextEncoder().encode(value), right = new TextEncoder().encode(previous)
  for (let i = 0; i < Math.min(left.length, right.length); i++) {
    if (left[i] !== right[i]) return left[i] > right[i]
  }
  return left.length > right.length
}

function validateSummary(raw: unknown) {
  const summary = object(raw, ['total', 'successful', 'failed', 'methodBreakdown'])
  const totals = (v: ObjectValue) => {
    if (!count(v.total) || !count(v.successful) || !count(v.failed) || BigInt(v.successful) + BigInt(v.failed) !== BigInt(v.total)) throw Error('Invalid activity summary')
    return [BigInt(v.total), BigInt(v.successful), BigInt(v.failed)]
  }
  const expected = totals(summary)
  if (!Array.isArray(summary.methodBreakdown) || summary.methodBreakdown.length > 512) throw Error('Invalid activity methods')
  let previous = ''
  const sum = [0n, 0n, 0n]
  for (const rawMethod of summary.methodBreakdown) {
    const method = object(rawMethod, ['method', 'total', 'successful', 'failed'])
    if (!text(method.method, 100) || !afterUTF8(method.method, previous)) throw Error('Invalid activity method')
    totals(method).forEach((v, i) => { sum[i] += v })
    previous = method.method
  }
  if (sum.some((value, i) => value !== expected[i])) throw Error('Invalid activity summary totals')
}

function validateSanctions(raw: unknown, scope: CaseScope) {
  const sanctions = object(raw, ['status', 'scopedAddressCount', 'sourceDigest', 'checkedAt', 'matches'])
  if (!Number.isSafeInteger(sanctions.scopedAddressCount) || Number(sanctions.scopedAddressCount) < 0 || Number(sanctions.scopedAddressCount) > 4096 ||
    !digest(sanctions.sourceDigest) || !instant(sanctions.checkedAt) || !Array.isArray(sanctions.matches) || sanctions.matches.length > 4096 ||
    sanctions.status !== (sanctions.scopedAddressCount === 0 ? 'not-applicable' : sanctions.matches.length ? 'hit' : 'clear')) throw Error('Invalid sanctions summary')
  const sources = new Set<string>(), addresses = new Set<string>()
  for (const rawMatch of sanctions.matches) {
    const match = evidenceObject(rawMatch, ['address', 'sourceId'], scope.level === 'full' ? ['reason'] : [])
    if (!uuid(match.sourceId) || sources.has(String(match.sourceId)) || !optional(match, 'reason', x => typeof x === 'string' && new TextEncoder().encode(x).length <= 1048576)) throw Error('Invalid or private sanctions fields')
    sources.add(String(match.sourceId))
    const address = evidenceObject(match.address, ['addressId', 'display'], scope.level === 'full' ? ['address', 'targetActorIds', 'ensName', 'isMine'] : scope.level === 'pseudonymous' ? ['isMine'] : [])
    if (typeof address.addressId !== 'string' || !/^da1\.[A-Za-z0-9_-]{1,64}\.[A-Za-z0-9_-]{22}$/.test(address.addressId) ||
      !text(address.display, 100) || !optional(address, 'isMine', x => typeof x === 'boolean')) throw Error('Invalid sanctions address')
    if (scope.level === 'redacted' && address.display !== '[PRIVATE]' ||
      scope.level === 'pseudonymous' && !/^Address-[A-Z2-7]{26}$/.test(String(address.display))) throw Error('Invalid private sanctions address')
    if (scope.level === 'full') {
      if (typeof address.address !== 'string' || !/^0x[0-9a-f]{40}$/.test(address.address) || address.display !== address.address ||
        !Array.isArray(address.targetActorIds) || !address.targetActorIds.length || address.targetActorIds.length > 256 ||
        address.targetActorIds.some(x => typeof x !== 'string' || !scope.targetActors.includes(x)) ||
        new Set(address.targetActorIds).size !== address.targetActorIds.length ||
        !optional(address, 'ensName', x => text(x, 255))) throw Error('Invalid full sanctions address')
    }
    addresses.add(address.addressId)
  }
  if (addresses.size > Number(sanctions.scopedAddressCount)) throw Error('Invalid sanctions address count')
}

export function validateComplianceSummary(result: ObjectValue, scope: CaseScope, preparedAt: number) {
  object(result, ['v', 'activity', 'sanctions', 'kyc', 'finance'])
  if (result.v !== 2 || result.kyc !== 'not_evaluated') throw Error('Invalid compliance summary')
  validateSummary(result.activity)
  validateSanctions(result.sanctions, scope)
  const finance = object(result.finance, ['matchingRetainedCount', 'observedAt', 'coverage', 'detailResource', 'detailView'])
  if (!retainedCount(finance.matchingRetainedCount) || !observedAt(finance.observedAt, preparedAt) || finance.coverage !== 'RETAINED_AT_READ' ||
    finance.detailResource !== 'compliance_report' || finance.detailView !== 'list') throw Error('Invalid retained finance summary')
}

export function readNarrowing(scope: CaseScope, actor: string, start: string, end: string) {
  if (actor && !scope.targetActors.includes(actor)) throw Error('Choose a target already included in this case.')
  const seconds = (raw: string, fallback: number) => {
    if (!raw) return fallback
    if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(?::\d{2}(?:\.0{1,3})?)?$/.test(raw)) throw Error('Enter UTC dates with whole-second precision.')
    const value = Date.parse(raw + 'Z') / 1000
    const normalized = raw.replace(/\.0+$/, '')
    if (!instant(value) || new Date(value * 1000).toISOString().slice(0, normalized.length) !== normalized) throw Error('Enter valid UTC dates.')
    return value
  }
  const dataTime = { start: seconds(start, scope.dataTime.start), end: seconds(end, scope.dataTime.end) }
  if (dataTime.start < scope.dataTime.start || dataTime.end > scope.dataTime.end || dataTime.start >= dataTime.end) throw Error('Keep the requested UTC interval within this case.')
  return { dataTime, body: { ...(actor ? { targetActorIds: [actor] } : {}), ...(start || end ? { dataTime } : {}) } }
}
