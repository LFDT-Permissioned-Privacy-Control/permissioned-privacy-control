import { object, text } from '../auth/protocol'
import type { CaseScope, ObjectValue } from './operationsModels'

const digest = (v: unknown) => typeof v === 'string' && /^sha256:[0-9a-f]{64}$/.test(v)
const count = (v: unknown) => typeof v === 'string' && /^(0|[1-9][0-9]{0,18})$/.test(v)
const instant = (v: unknown): v is number => Number.isSafeInteger(v) && Number(v) >= 0 && Number(v) < 253402300800
const hash = (v: unknown) => typeof v === 'string' && /^0x[0-9a-f]{64}$/.test(v)
const optional = (v: ObjectValue, k: string, valid: (v: unknown) => boolean) => !(k in v) || valid(v[k])
function evidenceObject(raw: unknown, required: string[], optional: string[]): ObjectValue {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) throw Error('Invalid admission evidence')
  const value = raw as ObjectValue
  if (Object.keys(value).some(k => !required.includes(k) && !optional.includes(k)) || required.some(k => !(k in value))) throw Error('Invalid or private admission evidence fields')
  return value
}

export function validateEvidencePage(result: ObjectValue, level: string, time: CaseScope['dataTime'], limit: number) {
  object(result, ['items', 'nextCursor', 'matchingRetainedCount'])
  if (!Array.isArray(result.items) || result.items.length > limit || !count(result.matchingRetainedCount) ||
    BigInt(result.matchingRetainedCount as string) > 16384n || BigInt(result.matchingRetainedCount as string) < BigInt(result.items.length) ||
    result.nextCursor !== null && (typeof result.nextCursor !== 'string' || !/^[\x21-\x7e]{1,2048}$/.test(result.nextCursor)) ||
    result.items.length === 0 && result.nextCursor !== null) throw Error('Invalid admission evidence page')
  let previous = 0n
  for (const raw of result.items) {
    const base = ['id', 'population', 'time', 'kind', 'decision', 'monitored', 'coverage', 'policyDigest']
    const v = evidenceObject(raw, base, ['quoteDigest', ...(level === 'full' ? ['quote', 'transactionHash', 'recordId', 'reason'] : [])])
    if (!count(v.id) || BigInt(v.id as string) <= previous || BigInt(v.id as string) > 9223372036854775807n || v.population !== 'ADMISSION_DECISION' ||
      !instant(v.time) || v.time < time.start || v.time > time.end || !['admission_only', 'root_native', 'root_erc20'].includes(String(v.kind)) ||
      !['allowed', 'denied'].includes(String(v.decision)) || typeof v.monitored !== 'boolean' ||
      !['not_detected', 'disabled', 'relay_request', 'root_transfer'].includes(String(v.coverage)) || !digest(v.policyDigest) ||
      !optional(v, 'quoteDigest', digest) || !optional(v, 'transactionHash', hash) ||
      !optional(v, 'recordId', x => typeof x === 'string' && /^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/.test(x)) ||
      !optional(v, 'reason', x => text(x, 8192))) throw Error('Invalid or private admission evidence fields')
    if ('quote' in v) {
      const q = object(v.quote, ['id', 'currency', 'sourceId', 'value', 'providerAsOf', 'fetchedAt', 'digest'])
      if (!text(q.id, 100) || !text(q.currency, 16) || !text(q.sourceId, 128) || !text(q.value, 1024) ||
        !instant(q.providerAsOf) || !instant(q.fetchedAt) || !digest(q.digest) || q.digest !== v.quoteDigest) throw Error('Invalid quote evidence')
    }
    previous = BigInt(v.id as string)
  }
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
