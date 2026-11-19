export type ObjectValue = Record<string, unknown>
export function record(value: unknown): ObjectValue {
  if (!value || typeof value !== 'object' || Array.isArray(value))
    throw Error('Invalid operational record')
  return value as ObjectValue
}
export function rows(value: unknown, max = 100): ObjectValue[] {
  if (!Array.isArray(value) || value.length > max) throw Error('Invalid operational list')
  return value.map(record)
}
export function text(value: unknown): string {
  if (typeof value !== 'string' || value.length > 16384) throw Error('Invalid operational text')
  return value
}
export function optionalText(value: unknown): string {
  return value === undefined || value === null ? '' : text(value)
}
export function quantity(value: unknown): string {
  if (typeof value !== 'string' || !/^(0|[1-9][0-9]{0,77})$/.test(value))
    throw Error('Invalid exact quantity')
  return value
}
export const actorID = (value: string) => /^ops:p1:[A-Za-z0-9_-]{43}$/.test(value)
export const address = (value: string) => /^0x[0-9a-f]{40}$/.test(value)
export function instant(value: unknown): string {
  if (
    typeof value === 'number' &&
    Number.isSafeInteger(value) &&
    value >= 0 &&
    value < 253402300800
  )
    return new Date(value * 1000).toLocaleString()
  if (typeof value === 'string' && Number.isFinite(Date.parse(value)))
    return new Date(value).toLocaleString()
  throw Error('Invalid record time')
}
export interface CaseScope {
  targetActors: string[]
  resources: string[]
  addresses: { mode: string; values: string[] }
  dataTime: { start: number; end: number }
  level: 'redacted' | 'pseudonymous' | 'full'
}
export interface NativeCase {
  caseId: string
  ruleId: string
  recipientActorId: string
  creatorActorId: string
  dataOrganizationId: string
  scope: CaseScope
  caseReference: string
  purpose: string
  legalBasis: string
  status: string
  version: number
  createdAt: number
  expiresAt: number
  originalRuleDigest: string
  originalBundleDigest: string
}
export function caseRecord(value: unknown): NativeCase {
  const v = record(value),
    scope = record(v.scope),
    at = record(scope.dataTime),
    addresses = record(scope.addresses)
  for (const key of [
    'caseId',
    'ruleId',
    'recipientActorId',
    'creatorActorId',
    'dataOrganizationId',
    'caseReference',
    'purpose',
    'legalBasis',
    'status',
    'originalRuleDigest',
    'originalBundleDigest',
  ])
    text(v[key])
  if (
    !actorID(String(v.recipientActorId)) ||
    !actorID(String(v.creatorActorId)) ||
    !Array.isArray(scope.targetActors) ||
    !scope.targetActors.length ||
    scope.targetActors.length > 256 ||
    scope.targetActors.some((a) => typeof a !== 'string' || !actorID(a)) ||
    !Array.isArray(scope.resources) ||
    scope.resources.some((r) => typeof r !== 'string') ||
    !['redacted', 'pseudonymous', 'full'].includes(String(scope.level)) ||
    !['list', 'all-target-addresses'].includes(String(addresses.mode)) ||
    !Array.isArray(addresses.values) ||
    addresses.values.some((a) => typeof a !== 'string' || !address(a)) ||
    !Number.isSafeInteger(at.start) ||
    !Number.isSafeInteger(at.end) ||
    Number(at.end) <= Number(at.start) ||
    !Number.isSafeInteger(v.version) ||
    Number(v.version) < 1
  )
    throw Error('Invalid case scope')
  instant(v.createdAt)
  instant(v.expiresAt)
  return v as unknown as NativeCase
}
export function casePage(value: unknown): {
  items: NativeCase[]
  nextCursor: string
  scanComplete: boolean
} {
  const v = record(value)
  if (typeof v.scanComplete !== 'boolean') throw Error('Invalid case continuation')
  return {
    items: rows(v.items).map(caseRecord),
    nextCursor: text(v.nextCursor),
    scanComplete: v.scanComplete,
  }
}
export interface ProtectedData {
  v: number
  readId: string
  caseId: string
  resource: string
  view: string
  level: string
  dataTime: { start: number; end: number }
  effectiveUntil: number
  coverage: ObjectValue
  result: ObjectValue
}
export function protectedData(
  value: unknown,
  selected: NativeCase,
  resource: string,
): ProtectedData {
  const v = record(value),
    coverage = record(v.coverage),
    result = record(v.result),
    time = record(v.dataTime)
  if (
    v.v !== 1 ||
    v.caseId !== selected.caseId ||
    v.resource !== resource ||
    v.level !== selected.scope.level ||
    time.start !== selected.scope.dataTime.start ||
    time.end !== selected.scope.dataTime.end ||
    !Number.isSafeInteger(v.effectiveUntil) ||
    Number(v.effectiveUntil) <= Date.now() / 1000 ||
    !['COMPLETE_AT_CUT', 'RETAINED_AT_READ'].includes(String(coverage.status)) ||
    !Array.isArray(coverage.populations)
  )
    throw Error('Disclosure response does not match this case')
  text(v.readId)
  if (resource === 'activity_logs')
    for (const row of rows(result.items)) {
      if (
        Object.keys(row).some(
          (k) =>
            ![
              'recordId',
              'method',
              'statusCode',
              'time',
              ...(v.level === 'full' ? ['actorId', 'ipAddress'] : []),
            ].includes(k),
        )
      )
        throw Error('Unexpected private log fields')
      text(row.recordId)
      text(row.method)
      instant(row.time)
      if (!Number.isSafeInteger(row.statusCode)) throw Error('Invalid activity status')
    }
  return v as unknown as ProtectedData
}
