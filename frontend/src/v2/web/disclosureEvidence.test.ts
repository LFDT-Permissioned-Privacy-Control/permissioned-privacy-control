import { expect, it, vi } from 'vitest'
import actualDTO from './testdata/finance-native-go-dto.json'
import oldHTTP from './testdata/finance-list-actual-http.json'
import oldLongCase from './testdata/finance-list-actual-long-case.json'
import { readNarrowing } from './disclosureEvidence'
import { protectedData, type NativeCase } from './operationsModels'

const now = Math.floor(Date.now() / 1000), digest = 'sha256:' + 'a'.repeat(64)
const actor = 'ops:p1:' + 'A'.repeat(43)
const selected = { caseId: '11111111-1111-4111-8111-111111111111', expiresAt: now + 300, scope: { targetActors: [actor], resources: ['compliance_report'], level: 'redacted', addresses: { mode: 'all-target-addresses', values: [] }, dataTime: { start: now - 10000, end: now } } } as NativeCase
const item = { id: '101', population: 'ADMISSION_DECISION', time: now - 1, kind: 'admission_only', decision: 'allowed', monitored: false, coverage: 'disabled', policyDigest: digest }
const observedAt = new Date(now * 1000).toISOString().replace('.000Z', '.123456789Z')
const response = () => ({ v: 1, readId: '22222222-2222-4222-8222-222222222222', caseId: selected.caseId, resource: 'compliance_report', view: 'list', level: 'redacted', dataTime: selected.scope.dataTime, effectiveUntil: now + 60, coverage: { status: 'RETAINED_AT_READ', populations: ['RETAINED_ADMISSION_DECISIONS_AS_OF_SNAPSHOT'], sourceBasisDigest: digest, preparedAt: now }, result: { v: 2, items: [item], nextCursor: 'opaque-next' as string | null, matchingRetainedCount: '20001', observedAt, pagination: 'live-keyset' } })
const decode = (v: unknown) => protectedData(v, selected, 'compliance_report', { view: 'list', limit: 25 })
const report = () => ({ ...response(), view: 'report', coverage: { ...response().coverage, populations: ['CURRENT_APPROVED_SANCTIONS', 'CURRENT_PROVED_ASSOCIATIONS', 'RETAINED_ADMISSION_DECISIONS_AS_OF_SNAPSHOT', 'RETAINED_AND_POSITIVELY_ATTRIBUTED_WALLET_HISTORY', 'SEALED_REQUEST_COMPLETIONS_AS_OF_CHAIN_HEAD'] }, result: { v: 2, activity: { total: '20001', successful: '20000', failed: '1', methodBreakdown: [{ method: 'eth_call', total: '20001', successful: '20000', failed: '1' }] }, sanctions: { status: 'not-applicable', scopedAddressCount: 0, sourceDigest: digest, checkedAt: now, matches: [] as unknown[] }, kyc: 'not_evaluated', finance: { matchingRetainedCount: '20001', observedAt, coverage: 'RETAINED_AT_READ', detailResource: 'compliance_report', detailView: 'list' } } })
const decodeReport = (v: unknown, c = selected) => protectedData(v, c, 'compliance_report', { view: 'report' })

it('accepts exact SQL counts above 16384 up to int64 without widening the page limit', () => {
  for (const count of ['20001', '9223372036854775807']) {
    const value = response(); value.result.matchingRetainedCount = count
    expect(decode(value).result.matchingRetainedCount).toBe(count)
  }
  const value = response(); value.result.items = Array.from({ length: 26 }, (_, i) => ({ ...item, id: String(i + 1) }))
  expect(() => decode(value)).toThrow()
})

it('decodes unchanged new Go RenderRetained serializer output for both report and list', () => {
  const clock = vi.spyOn(Date, 'now').mockReturnValue(actualDTO.report.coverage.preparedAt * 1000)
  try {
    for (const envelope of [actualDTO.report, actualDTO.list]) {
      const actualCase = { ...selected, caseId: envelope.caseId, expiresAt: envelope.effectiveUntil, scope: { ...selected.scope, level: envelope.level, dataTime: envelope.dataTime } } as NativeCase
      const value = protectedData(envelope, actualCase, 'compliance_report', { view: envelope.view, limit: 25 })
      expect(value).toEqual(envelope)
      if (envelope.view === 'report') expect(value.result).not.toHaveProperty('evidence')
      else expect(value.result.items).toHaveLength(2)
    }
  } finally { clock.mockRestore() }
})

it('preserves captured prototype HTTP fixtures as rejected old-contract controls', () => {
  for (const old of [oldHTTP, oldLongCase]) {
    const clock = vi.spyOn(Date, 'now').mockReturnValue(old.coverage.preparedAt * 1000)
    try {
      const oldCase = { ...selected, caseId: old.caseId, expiresAt: old.effectiveUntil, scope: { ...selected.scope, level: old.level, dataTime: old.dataTime } } as NativeCase
      expect(() => protectedData(old, oldCase, 'compliance_report', { view: 'list', limit: 25 })).toThrow()
    } finally { clock.mockRestore() }
  }
})

it('accepts only UTC RFC3339Nano observation dates without losing nanoseconds', () => {
  const base = new Date(now * 1000).toISOString().slice(0, 19)
  for (const date of [base + 'Z', base + '.1Z', base + '.123456Z', base + '.123456789Z']) {
    const value = response(); value.result.observedAt = date
    expect(decode(value).result.observedAt).toBe(date)
  }
  for (const date of ['2026-02-30T12:00:00Z', base + '.1234567890Z', base + '+00:00', 'not-a-date', new Date((now + 1) * 1000).toISOString()]) {
    const value = response(); value.result.observedAt = date
    expect(() => decode(value)).toThrow()
  }
})

it('validates newest-first visible seconds without inventing an ID order within one second', () => {
  const value = response()
  value.result.items = [{ ...item, id: '501' }, { ...item, id: '502' }, { ...item, id: '2', time: now - 2 }]
  expect(() => decode(value)).not.toThrow()
  value.result.items = [{ ...item, time: now - 2 }, { ...item, id: '502' }]
  expect(() => decode(value)).toThrow()
})

it('accepts an aggregate report with real activity, sanctions and a dated finance descriptor', () => {
  const got = decodeReport(report())
  expect(got.result.finance).toEqual(report().result.finance)
  expect(got.result).not.toHaveProperty('evidence')
  expect(got.result.activity).toEqual(report().result.activity)
  expect(got.result.sanctions).toEqual(report().result.sanctions)
})

it('accepts the existing Go UTF-8 method order including names outside the BMP', () => {
  const value = report()
  value.result.activity = { total: '2', successful: '2', failed: '0', methodBreakdown: ['\ue000', '\u{10000}'].map(method => ({ method, total: '1', successful: '1', failed: '0' })) }
  expect(() => decodeReport(value)).not.toThrow()
  value.result.activity.methodBreakdown.reverse()
  expect(() => decodeReport(value)).toThrow()
})

it('rejects private and unknown nested report fields, malformed counts, and substituted clearance', () => {
  const changes: ((value: any) => void)[] = [
    v => { v.result.evidence = [item] },
    v => { delete v.result.v },
    v => { v.result.kyc = 'clear' },
    v => { v.result.activity.actorId = actor },
    v => { v.result.activity.methodBreakdown[0].private = 'secret' },
    v => { v.result.activity.failed = '0' },
    v => { v.result.sanctions.status = 'clear' },
    v => { v.result.sanctions.privateMatches = [] },
    v => { v.result.finance.matchingRetainedCount = '9223372036854775808' },
    v => { v.result.finance.detailResource = 'transactions' },
    v => { v.result.finance.items = [item] },
    v => { v.coverage.sourceCutDigest = digest },
  ]
  for (const change of changes) { const value = report(); change(value); expect(() => decodeReport(value)).toThrow() }
})

it.each(['redacted', 'pseudonymous', 'full'] as const)('decodes sanctions privacy omissions for %s and rejects additional identity fields', level => {
  const address = { addressId: 'da1.render-test.' + 'A'.repeat(22), display: level === 'redacted' ? '[PRIVATE]' : level === 'pseudonymous' ? 'Address-' + 'A'.repeat(26) : '0x' + '1'.repeat(40), ...(level !== 'redacted' ? { isMine: false } : {}), ...(level === 'full' ? { address: '0x' + '1'.repeat(40), targetActorIds: [actor] } : {}) }
  const value = { ...report(), level }, c = { ...selected, scope: { ...selected.scope, level } }
  value.result.sanctions = { ...value.result.sanctions, status: 'hit', scopedAddressCount: 1, matches: [{ address, sourceId: '33333333-3333-4333-8333-333333333333', ...(level === 'full' ? { reason: 'Recorded reason' } : {}) }] }
  expect(() => decodeReport(value, c)).not.toThrow()
  ;(value.result.sanctions.matches[0] as any).actorId = actor
  expect(() => decodeReport(value, c)).toThrow()
  delete (value.result.sanctions.matches[0] as any).actorId
  if (level !== 'full') {
    ;(value.result.sanctions.matches[0] as any).reason = 'Private reason'
    expect(() => decodeReport(value, c)).toThrow()
    delete (value.result.sanctions.matches[0] as any).reason
    ;(value.result.sanctions.matches[0] as any).address.address = '0x' + '1'.repeat(40)
    expect(() => decodeReport(value, c)).toThrow()
  }
})

it('keeps the case cutoff separate from the original shorter session deadline', () => {
  const value = response(), c = { ...selected, expiresAt: now + 900 }
  value.effectiveUntil = now + 900; value.result.items = []; value.result.nextCursor = null; value.result.matchingRetainedCount = '0'
  expect(protectedData(value, c, 'compliance_report', { view: 'list', sessionExpiresAt: now + 300 }).effectiveUntil).toBe(now + 900)
  expect(() => protectedData(value, c, 'compliance_report', { view: 'list', sessionExpiresAt: now })).toThrow()
  expect(() => protectedData({ ...value, effectiveUntil: c.expiresAt + 1 }, c, 'compliance_report')).toThrow()
})

it('rejects private fields, wrong sources, bad keys and false pagination shapes', () => {
  const changes: ((value: any) => void)[] = [
    v => { v.result.items[0] = { ...item, reason: 'private' } },
    v => { v.result.items = [item, item] },
    v => { v.result.items = [{ ...item, id: '0' }] },
    v => { v.result.matchingRetainedCount = '0' },
    v => { v.result.matchingRetainedCount = '01' },
    v => { v.result.matchingRetainedCount = '9223372036854775808' },
    v => { v.result.items = [] },
    v => { v.result.activity = { total: '151' } },
    v => { v.result.pagination = 'snapshot' },
    v => { delete v.result.v },
    v => { v.coverage.populations = ['RECORDED_REQUEST_COMPLETIONS'] },
    v => { v.coverage.sourceCutDigest = digest },
    v => { v.privateSource = 'unexpected' },
  ]
  for (const change of changes) { const value = response(); change(value); expect(() => decode(value)).toThrow() }
})

it('binds the exact requested UTC narrowing, view and original session expiry', () => {
  const value = response(), time = { start: now - 50, end: now - 2 }
  value.dataTime = time; value.result.items = [{ ...item, time: now - 3 }]
  expect(() => decode(value)).toThrow()
  expect(protectedData(value, selected, 'compliance_report', { view: 'list', dataTime: time, sessionExpiresAt: now + 60 }).view).toBe('list')
  expect(() => protectedData(value, selected, 'compliance_report', { view: 'report', dataTime: time })).toThrow()
  expect(protectedData(value, selected, 'compliance_report', { view: 'list', dataTime: time, sessionExpiresAt: now + 30 }).effectiveUntil).toBe(now + 60)
  expect(() => protectedData(value, selected, 'compliance_report', { view: 'list', dataTime: time, sessionExpiresAt: now })).toThrow()
})

it('narrows only existing targets and exact inclusive UTC instants', () => {
  const start = new Date((now - 5000) * 1000).toISOString().slice(0, 19)
  expect(readNarrowing(selected.scope, actor, start, '').body).toEqual({ targetActorIds: [actor], dataTime: { start: now - 5000, end: now } })
  expect(readNarrowing(selected.scope, actor, start + '.000', '').body).toEqual({ targetActorIds: [actor], dataTime: { start: now - 5000, end: now } })
  expect(readNarrowing(selected.scope, '', '', '').body).toEqual({})
  expect(() => readNarrowing(selected.scope, 'ops:p1:' + 'B'.repeat(43), '', '')).toThrow()
  expect(() => readNarrowing(selected.scope, '', '2026-02-30T12:00:00', '')).toThrow()
  expect(() => readNarrowing(selected.scope, '', '', new Date((now + 1) * 1000).toISOString().slice(0, 19))).toThrow()
})
