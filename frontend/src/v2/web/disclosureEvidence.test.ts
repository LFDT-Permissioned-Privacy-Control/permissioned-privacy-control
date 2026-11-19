import { expect, it, vi } from 'vitest'
import actualHTTP from './testdata/finance-list-actual-http.json'
import { readNarrowing } from './disclosureEvidence'
import { protectedData, type NativeCase } from './operationsModels'

const now = Math.floor(Date.now() / 1000), digest = 'sha256:' + 'a'.repeat(64)
const actor = 'ops:p1:' + 'A'.repeat(43)
const selected = { caseId: '11111111-1111-4111-8111-111111111111', expiresAt: now + 300, scope: { targetActors: [actor], resources: ['compliance_report'], level: 'redacted', addresses: { mode: 'all-target-addresses', values: [] }, dataTime: { start: now - 10000, end: now } } } as NativeCase
const item = { id: '101', population: 'ADMISSION_DECISION', time: now - 1, kind: 'admission_only', decision: 'allowed', monitored: false, coverage: 'disabled', policyDigest: digest }
const response = () => ({ v: 1, readId: '22222222-2222-4222-8222-222222222222', caseId: selected.caseId, resource: 'compliance_report', view: 'list', level: 'redacted', dataTime: selected.scope.dataTime, effectiveUntil: now + 60, coverage: { status: 'RETAINED_AT_READ', populations: ['RETAINED_ADMISSION_DECISIONS_AS_OF_SNAPSHOT'], sourceBasisDigest: digest, preparedAt: now }, result: { items: [item], nextCursor: 'opaque-next', matchingRetainedCount: '151' } })
const decode = (v: unknown) => protectedData(v, selected, 'compliance_report', { view: 'list', limit: 25 })

it('accepts a separately counted finance page beyond the original complete-report limit', () => {
  const got = decode(response())
  expect(got.result.matchingRetainedCount).toBe('151')
  expect(got.result.nextCursor).toBe('opaque-next')
})

it('decodes the actual restricted-PG retained-source case HTTP envelope', () => {
  // Captured from TestActualRetainedFinanceEvidencePages; fixture identities and rows only.
  const clock = vi.spyOn(Date, 'now').mockReturnValue(actualHTTP.coverage.preparedAt * 1000)
  try {
    const actualCase = { ...selected, caseId: actualHTTP.caseId, expiresAt: actualHTTP.effectiveUntil, scope: { ...selected.scope, level: actualHTTP.level, dataTime: actualHTTP.dataTime } } as NativeCase
    const got = protectedData(actualHTTP, actualCase, 'compliance_report', { view: 'list', limit: 25 })
    expect(got.result.matchingRetainedCount).toBe('123')
    expect((got.result.items as unknown[])).toHaveLength(25)
  } finally { clock.mockRestore() }
})

it('rejects private fields, wrong sources, bad keys and false pagination shapes', () => {
  for (const change of [
    (v: any) => { v.result.items[0] = { ...item, reason: 'private' } },
    (v: any) => { v.result.items = [item, item] },
    (v: any) => { v.result.items = [{ ...item, id: '0' }] },
    (v: any) => { v.result.matchingRetainedCount = '0' },
    (v: any) => { v.result.matchingRetainedCount = '16385' },
    (v: any) => { v.result.items = [] },
    (v: any) => { v.result.activity = { total: '151' } },
    (v: any) => { v.coverage.populations = ['RECORDED_REQUEST_COMPLETIONS'] },
    (v: any) => { v.coverage.sourceCutDigest = digest },
    (v: any) => { v.privateSource = 'unexpected' },
  ]) {
    const v = response(); change(v)
    expect(() => decode(v)).toThrow()
  }
})

it('binds the exact requested UTC narrowing, view and original session expiry', () => {
  const v = response(), time = { start: now - 50, end: now - 2 }
  v.dataTime = time
  v.result.items = [{ ...item, time: now - 3 }]
  expect(() => decode(v)).toThrow()
  expect(protectedData(v, selected, 'compliance_report', { view: 'list', dataTime: time, until: now + 60 }).view).toBe('list')
  expect(() => protectedData(v, selected, 'compliance_report', { view: 'report', dataTime: time })).toThrow()
  expect(() => protectedData(v, selected, 'compliance_report', { view: 'list', dataTime: time, until: now + 30 })).toThrow()
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
