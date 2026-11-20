import '@testing-library/jest-dom/vitest'
import { act, cleanup, fireEvent, render, screen, within } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { afterEach, expect, it, vi } from 'vitest'
import actualDTO from './testdata/disclosure-events-go-dto.json'
import { NativeDisclosures } from './NativeDisclosures'
import { DisclosureEventCards } from './DisclosureEventCards'
import { protectedData, type NativeCase } from './operationsModels'
import type { OperationScope } from './controller'

const now = Math.floor(Date.now() / 1000), actor = 'ops:p1:' + 'A'.repeat(43), digest = 'sha256:' + 'a'.repeat(64)
const selected = (level: NativeCase['scope']['level'] = 'full'): NativeCase => ({ caseId: '11111111-1111-4111-8111-111111111111', ruleId: 'events', recipientActorId: actor, creatorActorId: actor, dataOrganizationId: '22222222-2222-4222-8222-222222222222', scope: { targetActors: [actor], resources: ['events'], addresses: { mode: 'all-target-addresses', values: [] }, dataTime: { start: now - 100, end: now }, level }, caseReference: 'Events audit', purpose: 'Audit', legalBasis: 'Mandate', status: 'open', version: 1, createdAt: now - 1, expiresAt: now + 900, originalRuleDigest: digest, originalBundleDigest: digest })
const event = (level: NativeCase['scope']['level'] = 'full') => ({ eventId: 'de1.data.' + 'A'.repeat(21) + 'Q', blockNumber: '9007199254740993', transactionIndex: 2, logIndex: 7, blockTime: now - 1, emitter: level === 'full' ? '0x' + '1'.repeat(40) : level === 'redacted' ? '[PRIVATE]' : 'Address-' + 'A'.repeat(26), payload: level === 'full' ? 'disclosed' : 'withheld', ...(level === 'full' ? { transactionHash: '0x' + 'a'.repeat(64), blockHash: '0x' + 'b'.repeat(64), topics: ['0x' + 'c'.repeat(64)], data: '0xdeadbeef' } : {}) })
const envelope = (level: NativeCase['scope']['level'] = 'full', empty = false) => ({ v: 1, readId: '33333333-3333-4333-8333-333333333333', caseId: selected().caseId, resource: 'events', view: 'list', level, dataTime: selected().scope.dataTime, effectiveUntil: now + 900, coverage: { status: 'RETAINED_AT_READ', populations: ['CURRENT_PROVED_ASSOCIATIONS', 'RETAINED_SAME_ORG_EVENTS_FROM_DISCLOSED_TRANSACTIONS'], sourceBasisDigest: digest, preparedAt: now }, result: { v: 1, population: 'EVENTS_FROM_DISCLOSED_TRANSACTIONS', items: empty ? [] : [event(level)], nextCursor: empty ? 'continue-opaque' : null } })
const decode = (value: unknown, level: NativeCase['scope']['level'] = 'full') => protectedData(value, selected(level), 'events', { view: 'list', limit: 25, sessionExpiresAt: now + 300 })
afterEach(() => { cleanup(); vi.restoreAllMocks(); vi.useRealTimers(); vi.unstubAllGlobals() })

it('decodes unchanged Go serializer fixtures for Full, both lower levels, and empty advancing Events', () => {
  const clock = vi.spyOn(Date, 'now').mockReturnValue(actualDTO.full.coverage.preparedAt * 1000)
  try {
    for (const raw of Object.values(actualDTO)) {
      const record = { ...selected(raw.level as NativeCase['scope']['level']), caseId: raw.caseId, expiresAt: raw.effectiveUntil, scope: { ...selected().scope, dataTime: raw.dataTime, level: raw.level as NativeCase['scope']['level'] } }
      expect(protectedData(raw, record, 'events', { view: 'list', limit: 25, sessionExpiresAt: raw.coverage.preparedAt + 30 })).toEqual(raw)
    }
  } finally { clock.mockRestore() }
})
it.each(['full', 'pseudonymous', 'redacted'] as const)('decodes the exact %s event branch and permits empty advancing pages', level => {
  expect(decode(envelope(level), level).result).toEqual(envelope(level).result)
  expect(decode(envelope(level, true), level).result.nextCursor).toBe('continue-opaque')
})
it('rejects lower payload and invented wallet-emitter authority even when fields are null', () => {
  for (const level of ['redacted', 'pseudonymous'] as const) for (const key of ['transactionHash', 'blockHash', 'topics', 'data', 'decoded', 'addressId', 'isMine', 'targetActorIds']) {
    const value = envelope(level); Object.assign(value.result.items[0], { [key]: null })
    expect(() => decode(value, level)).toThrow()
  }
})
it('requires exact Full hashes/topics/data, bounded coordinates, closed coverage and unique event IDs', () => {
  const changes: ((value: any) => void)[] = [
    value => { delete value.result.items[0].data }, value => { delete value.result.items[0].topics },
    value => { value.result.items[0].blockHash = '0x' + '0'.repeat(64) },
    value => { value.result.items[0].data = '0xabc' }, value => { value.result.items[0].topics = Array(5).fill('0x' + 'a'.repeat(64)) },
    value => { value.result.items[0].eventId = 'de1.data.' + 'A'.repeat(21) + 'B' },
    value => { value.result.items[0].logIndex = 4294967296 }, value => { value.result.items[0].blockNumber = '9223372036854775808' },
    value => { value.result.items[0].blockTime = now + 1 }, value => { value.result.items.push(value.result.items[0]) },
    value => { value.result.population = 'ALL_WALLET_EVENTS' }, value => { value.result.privateProgress = { hash: 'secret' } },
    value => { value.coverage.populations[1] = 'RETAINED_AND_POSITIVELY_ATTRIBUTED_WALLET_HISTORY' },
    value => { value.coverage.sourceCutDigest = digest }, value => { value.private = 'secret' },
  ]
  for (const change of changes) { const value = envelope(); change(value); expect(() => decode(value)).toThrow() }
  const emptyPayload = envelope(); Object.assign(emptyPayload.result.items[0], { topics: [], data: '0x' }); expect(() => decode(emptyPayload)).not.toThrow()
})
function fixture(level: NativeCase['scope']['level'] = 'full') {
  const bodies: any[] = [], request = vi.fn(async (path: string, init?: RequestInit) => {
    if (path.endsWith('/read')) { const body = JSON.parse(String(init?.body)); bodies.push(body); return envelope(level, !body.cursor) }
    return path.endsWith(selected().caseId) ? selected(level) : { items: [selected(level)], nextCursor: '', scanComplete: true }
  })
  const scope = { identity: { actor, expires: now + 300 }, signal: new AbortController().signal, check: vi.fn(), request, self: { organizations: [] } } as unknown as OperationScope
  return { scope, bodies, request }
}
async function open(scope: OperationScope) {
  render(<MemoryRouter><NativeDisclosures scope={scope} /></MemoryRouter>)
  fireEvent.click(await screen.findByRole('button', { name: 'Open case' }))
  fireEvent.click(await screen.findByRole('button', { name: 'Read permitted data' }))
}
it.each(['full', 'pseudonymous', 'redacted'] as const)('shows Events-only %s case, continues an empty page, and keeps Previous local', async level => {
  const fixtureValue = fixture(level); await open(fixtureValue.scope)
  fireEvent.click(await screen.findByRole('button', { name: 'Continue' }))
  await screen.findByRole('article', { name: 'Disclosed event 7' })
  expect(screen.getByText('9007199254740993')).toBeInTheDocument()
  expect(screen.getByText('Disclosed')).toBeInTheDocument()
  expect(within(screen.getByRole('article', { name: 'Disclosed event 7' })).getByText(level === 'full' ? 'Full' : level === 'redacted' ? 'Redacted' : 'Pseudonymous')).toBeInTheDocument()
  expect(fixtureValue.bodies).toEqual([{ v: 1, resource: 'events', view: 'list', limit: 25 }, { v: 1, resource: 'events', view: 'list', limit: 25, cursor: 'continue-opaque' }])
  expect(screen.queryByRole('link', { name: /Explorer|Details/ })).not.toBeInTheDocument()
  if (level === 'full') {
    expect(screen.getByText('0xdeadbeef')).toBeInTheDocument()
    expect(screen.getByText('0x' + 'c'.repeat(64))).toBeInTheDocument()
    expect(screen.getByText(/may include other parties/)).toBeInTheDocument()
  } else { expect(screen.getByText('Payload withheld')).toBeInTheDocument(); expect(screen.queryByText('Raw payload')).not.toBeInTheDocument(); expect(screen.queryByText('0xdeadbeef')).not.toBeInTheDocument() }
  fireEvent.click(screen.getByRole('button', { name: 'Previous page' }))
  expect(screen.getByText('No eligible events on this page.')).toBeInTheDocument()
  expect(fixtureValue.bodies).toHaveLength(2)
  expect(fixtureValue.request.mock.calls.every(([path]) => path.startsWith('/api/v1/disclosure/cases'))).toBe(true)
})
it('clears Events caches at original session expiry while the case remains open', async () => {
  vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] }); vi.spyOn(Date, 'now').mockReturnValue(now * 1000)
  const value = fixture('redacted')
  await act(async () => { render(<MemoryRouter><NativeDisclosures scope={value.scope} /></MemoryRouter>) })
  await act(async () => { fireEvent.click(screen.getByRole('button', { name: 'Open case' })) })
  await act(async () => { fireEvent.click(screen.getByRole('button', { name: 'Read permitted data' })) })
  await act(async () => { fireEvent.click(screen.getByRole('button', { name: 'Continue' })) })
  expect(screen.getByText('Payload withheld')).toBeInTheDocument()
  vi.mocked(Date.now).mockReturnValue((now + 300) * 1000)
  await act(async () => { await vi.advanceTimersByTimeAsync(300000) })
  expect(screen.queryByText('Payload withheld')).not.toBeInTheDocument()
  expect(screen.queryByRole('button', { name: 'Download this page' })).not.toBeInTheDocument()
})
it('rechecks the shorter case cutoff after download materialization', async () => {
  vi.spyOn(Date, 'now').mockReturnValue(now * 1000)
  const revoke = vi.fn(), click = vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => {})
  vi.stubGlobal('URL', class extends URL { static createObjectURL() { vi.mocked(Date.now).mockReturnValue((now + 60) * 1000); return 'blob:event-expired' } static revokeObjectURL = revoke })
  const value = fixture(), original = value.scope.request
  value.scope.request = vi.fn(async (path: string, init?: RequestInit) => {
    const raw = await original(path, init)
    return path.endsWith('/read') ? { ...raw as object, effectiveUntil: now + 60 } : raw
  }) as OperationScope['request']
  await open(value.scope)
  fireEvent.click(await screen.findByRole('button', { name: 'Continue' }))
  await screen.findByRole('article', { name: 'Disclosed event 7' })
  fireEvent.click(screen.getByRole('button', { name: 'Download this page' }))
  await screen.findByRole('alert')
  expect(click).not.toHaveBeenCalled(); expect(revoke).toHaveBeenCalledWith('blob:event-expired'); expect(value.bodies).toHaveLength(2)
  expect(screen.queryByRole('button', { name: 'Download this page' })).not.toBeInTheDocument()
})

it('renders genuine empty Full evidence in Admin cards without ordinary navigation or metadata reads', () => {
  const fetch = vi.fn(() => { throw Error('A case card must not fetch ordinary metadata') })
  vi.stubGlobal('fetch', fetch)
  const item = { ...event(), topics: [], data: '0x' }
  render(<DisclosureEventCards items={[item]} level="full" />)
  expect(screen.getByText('Disclosed')).toBeInTheDocument()
  expect(screen.getByText('Full')).toBeInTheDocument()
  expect(screen.getByText('No topics')).toBeInTheDocument()
  expect(screen.getByText('0x')).toBeInTheDocument()
  expect(screen.queryByText('Payload withheld')).not.toBeInTheDocument()
  expect(screen.queryByRole('link')).not.toBeInTheDocument()
  expect(fetch).not.toHaveBeenCalled()
})

it.each(['pseudonymous', 'redacted'] as const)('keeps the %s card payload and hashes absent with inert emitter text', level => {
  const fetch = vi.fn(() => { throw Error('A case card must not fetch ordinary metadata') })
  vi.stubGlobal('fetch', fetch)
  render(<DisclosureEventCards items={[event(level)]} level={level} />)
  expect(screen.getByText('Disclosed')).toBeInTheDocument()
  expect(screen.getByText('Payload withheld')).toBeInTheDocument()
  expect(screen.getByText(event(level).emitter)).toBeInTheDocument()
  expect(screen.queryByText('Topics')).not.toBeInTheDocument()
  expect(screen.queryByText('Data')).not.toBeInTheDocument()
  expect(screen.queryByText('Transaction hash')).not.toBeInTheDocument()
  expect(screen.queryByRole('link')).not.toBeInTheDocument()
  expect(fetch).not.toHaveBeenCalled()
})

it('does not apply the short administrative text-field limit to authorized raw event data', () => {
  const data = '0x' + 'ab'.repeat(20000)
  render(<DisclosureEventCards items={[{ ...event(), data }]} level="full" />)
  expect(screen.getByText(data)).toBeInTheDocument()
})
