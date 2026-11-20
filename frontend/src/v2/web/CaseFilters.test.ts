import { expect, it } from 'vitest'
import { caseFilterQuery, emptyCaseFilters } from './CaseFilters'

it('converts UTC case-creation filters once without widening recipient scope', () => {
  expect(caseFilterQuery({ ...emptyCaseFilters, status: 'active', privacyLevel: 'redacted', createdFrom: '2026-11-20T00:00:00', createdTo: '2026-11-21T00:00:00' })).toEqual({ status: 'active', privacyLevel: 'redacted', createdFrom: String(Date.parse('2026-11-20T00:00:00Z') / 1000), createdTo: String(Date.parse('2026-11-21T00:00:00Z') / 1000) })
  expect(() => caseFilterQuery({ ...emptyCaseFilters, recipientActorId: 'admin' })).toThrow('OPS actor')
  expect(() => caseFilterQuery({ ...emptyCaseFilters, createdFrom: '2026-11-21T00:00:00', createdTo: '2026-11-20T00:00:00' })).toThrow('earlier')
})
