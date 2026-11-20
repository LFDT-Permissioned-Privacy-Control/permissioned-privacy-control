import '@testing-library/jest-dom/vitest'
import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'
import { afterEach, expect, it, vi } from 'vitest'
import type { OperationScope } from './controller'
import { NativeDisclosures } from './NativeDisclosures'
import type { NativeCase } from './operationsModels'

afterEach(() => { cleanup(); vi.useRealTimers(); vi.restoreAllMocks(); vi.unstubAllGlobals() })
const now = Math.floor(Date.now() / 1000), actor = 'ops:p1:' + 'A'.repeat(43), digest = 'sha256:' + 'a'.repeat(64)
const selected: NativeCase = { caseId: '11111111-1111-4111-8111-111111111111', ruleId: 'audit', recipientActorId: actor, creatorActorId: actor, dataOrganizationId: '22222222-2222-4222-8222-222222222222', scope: { targetActors: [actor], resources: ['compliance_report'], addresses: { mode: 'all-target-addresses', values: [] }, dataTime: { start: now - 10000, end: now }, level: 'redacted' }, caseReference: 'CASE-151', purpose: 'Audit', legalBasis: 'Audit mandate', status: 'open', version: 1, createdAt: now - 1, expiresAt: now + 300, originalRuleDigest: digest, originalBundleDigest: digest }
const item = (id: number) => ({ id: String(id), population: 'ADMISSION_DECISION', time: now - 1, kind: 'admission_only', decision: 'allowed', monitored: false, coverage: 'disabled', policyDigest: digest })
const page = (number: number, time = selected.scope.dataTime) => ({ v: 1, readId: '33333333-3333-4333-8333-333333333333', caseId: selected.caseId, resource: 'compliance_report', view: 'list', level: 'redacted', dataTime: time, effectiveUntil: now + 60, coverage: { status: 'RETAINED_AT_READ', populations: ['RETAINED_ADMISSION_DECISIONS_AS_OF_SNAPSHOT'], sourceBasisDigest: digest, preparedAt: now }, result: { v: 2, observedAt: new Date(now * 1000).toISOString(), pagination: 'live-keyset', items: Array.from({ length: 25 }, (_, i) => item(101 + number * 25 + i)), nextCursor: 'cursor-' + (number + 1), matchingRetainedCount: '151' } })
const report = (time = selected.scope.dataTime) => ({ ...page(0, time), view: 'report', coverage: { ...page(0).coverage, populations: ['CURRENT_APPROVED_SANCTIONS', 'CURRENT_PROVED_ASSOCIATIONS', 'RETAINED_ADMISSION_DECISIONS_AS_OF_SNAPSHOT', 'RETAINED_AND_POSITIVELY_ATTRIBUTED_WALLET_HISTORY', 'SEALED_REQUEST_COMPLETIONS_AS_OF_CHAIN_HEAD'] }, result: { v: 2, activity: { total: '20100', successful: '20099', failed: '1', methodBreakdown: [{ method: 'eth_call', total: '20100', successful: '20099', failed: '1' }] }, sanctions: { status: 'not-applicable', scopedAddressCount: 0, sourceDigest: digest, checkedAt: now, matches: [] }, kyc: 'not_evaluated', finance: { matchingRetainedCount: '20001', observedAt: new Date(now * 1000).toISOString(), coverage: 'RETAINED_AT_READ', detailResource: 'compliance_report', detailView: 'list' } } })
function fixture(options: { effectiveUntil?: number; sessionExpiresAt?: number; empty?: boolean } = {}) {
  const bodies: Record<string, unknown>[] = []
  const caseValue = { ...selected, expiresAt: Math.max(selected.expiresAt, options.effectiveUntil ?? 0) }
  const request = vi.fn(async (path: string, options?: RequestInit): Promise<unknown> => {
    if (path.endsWith('/read')) {
      const body = JSON.parse(String(options?.body)); bodies.push(body)
      return response(body)
    }
    return path === '/api/v1/disclosure/cases/' + selected.caseId ? caseValue : { items: [caseValue], nextCursor: '', scanComplete: true }
  })
  function response(body: Record<string, unknown>) {
    if (body.view === 'report') return report(body.dataTime as typeof selected.scope.dataTime)
    const value = page(body.cursor ? Number(String(body.cursor).split('-')[1]) : 0, body.dataTime as typeof selected.scope.dataTime)
    return { ...value, effectiveUntil: options.effectiveUntil ?? value.effectiveUntil,
      result: options.empty ? { ...value.result, items: [], nextCursor: null, matchingRetainedCount: '0' } : value.result }
  }
  const scope = { identity: { actor, expires: options.sessionExpiresAt ?? now + 300 }, signal: new AbortController().signal, check: vi.fn(), dispose: vi.fn(), request, self: { organizations: [] } } as unknown as OperationScope
  return { scope, request, bodies }
}
async function open(scope: OperationScope) {
  render(<MemoryRouter><NativeDisclosures scope={scope} /></MemoryRouter>)
  await userEvent.click(await screen.findByRole('button', { name: 'Open case' }))
  await waitFor(() => expect(screen.getByRole('button', { name: 'Read permitted data' })).toBeEnabled())
}

it('reads a finance page, supports bounded Previous without a new request, and resets the cursor for target narrowing', async () => {
  const f = fixture(); await open(f.scope)
  await userEvent.click(screen.getByRole('button', { name: 'Read permitted data' }))
  await screen.findByRole('cell', { name: '101' })
  expect(screen.getByText('151')).toBeInTheDocument()
  expect(screen.getByRole('button', { name: 'Download this page' })).toBeInTheDocument()
  expect(screen.queryByRole('button', { name: 'Download verified report' })).not.toBeInTheDocument()
  await userEvent.click(screen.getByRole('button', { name: 'Next page' }))
  await screen.findByRole('cell', { name: '126' })
  await userEvent.click(screen.getByRole('button', { name: 'Previous page' }))
  expect(screen.getByRole('cell', { name: '101' })).toBeInTheDocument()
  expect(f.bodies).toHaveLength(2)
  await userEvent.click(screen.getByRole('button', { name: 'Next page' }))
  expect(screen.getByRole('cell', { name: '126' })).toBeInTheDocument()
  expect(f.bodies).toHaveLength(2)
  fireEvent.change(screen.getByLabelText('Target actor'), { target: { value: actor } })
  expect(screen.queryByRole('columnheader', { name: 'Decision ID' })).not.toBeInTheDocument()
  await userEvent.click(screen.getByRole('button', { name: 'Read permitted data' }))
  await screen.findByRole('cell', { name: '101' })
  expect(f.bodies.at(-1)).toEqual({ v: 1, resource: 'compliance_report', view: 'list', limit: 25, targetActorIds: [actor] })
}, 15000) // Multiple real DOM page transitions and filter reset.

it('clears prior evidence and does not retry or mix pages after a source conflict', async () => {
  const f = fixture(), original = f.request.getMockImplementation()!
  f.request.mockImplementation(async (path, options) => {
    if (path.endsWith('/read') && JSON.parse(String(options?.body)).cursor) throw Error('The source changed. Start a new read.')
    return original(path, options)
  })
  await open(f.scope)
  await userEvent.click(screen.getByRole('button', { name: 'Read permitted data' }))
  await screen.findByRole('cell', { name: '101' })
  await userEvent.click(screen.getByRole('button', { name: 'Next page' }))
  expect(await screen.findByRole('alert')).toHaveTextContent('Start a new read')
  expect(screen.queryByRole('columnheader', { name: 'Decision ID' })).not.toBeInTheDocument()
  expect(f.request.mock.calls.filter(([path]) => path.endsWith('/read'))).toHaveLength(2)
})

it('does not restore an expired cached page', async () => {
  const f = fixture(); await open(f.scope)
  await userEvent.click(screen.getByRole('button', { name: 'Read permitted data' }))
  await screen.findByRole('cell', { name: '101' })
  await userEvent.click(screen.getByRole('button', { name: 'Next page' }))
  await screen.findByRole('cell', { name: '126' })
  const clock = vi.spyOn(Date, 'now').mockReturnValue((now + 61) * 1000)
  try {
    await userEvent.click(screen.getByRole('button', { name: 'Previous page' }))
    expect(screen.queryByRole('columnheader', { name: 'Decision ID' })).not.toBeInTheDocument()
    expect(f.bodies).toHaveLength(2)
  } finally { clock.mockRestore() }
})

it('shows an empty long-lived case page with a separate original-session deadline', async () => {
  const f = fixture({ effectiveUntil: now + 900, sessionExpiresAt: now + 300, empty: true }); await open(f.scope)
  await userEvent.click(screen.getByRole('button', { name: 'Read permitted data' }))
  await screen.findByRole('button', { name: 'Download this page' })
  const coverage = screen.getByText(/Available in this session until/)
  expect(coverage).toHaveTextContent('Case/rule cutoff ' + new Date((now + 900) * 1000).toLocaleString())
  expect(coverage).toHaveTextContent('Available in this session until ' + new Date((now + 300) * 1000).toLocaleString())
  expect(within(screen.getByRole('dialog')).getByText('0')).toBeInTheDocument()
  expect(screen.queryByRole('alert')).not.toBeInTheDocument()
})

it.each(['Previous page', 'Next page', 'Download this page'])('blocks %s at original access expiry even while the case is live', async action => {
  const create = vi.fn(() => 'blob:disclosure-page')
  vi.stubGlobal('URL', class extends URL { static createObjectURL = create; static revokeObjectURL = vi.fn() })
  const f = fixture({ effectiveUntil: now + 900, sessionExpiresAt: now + 300 }); await open(f.scope)
  await userEvent.click(screen.getByRole('button', { name: 'Read permitted data' }))
  await screen.findByRole('cell', { name: '101' })
  await userEvent.click(screen.getByRole('button', { name: 'Next page' }))
  await screen.findByRole('cell', { name: '126' })
  if (action === 'Next page') {
    await userEvent.click(screen.getByRole('button', { name: 'Previous page' }))
    expect(screen.getByRole('cell', { name: '101' })).toBeInTheDocument()
  }
  vi.spyOn(Date, 'now').mockReturnValue((now + 300) * 1000)
  await act(async () => { fireEvent.click(screen.getByRole('button', { name: action })) })
  expect(screen.queryByRole('columnheader', { name: 'Decision ID' })).not.toBeInTheDocument()
  expect(screen.queryByRole('button', { name: 'Download this page' })).not.toBeInTheDocument()
  expect(f.bodies).toHaveLength(2)
  expect(create).not.toHaveBeenCalled()
})

it('clears long-lived case evidence at original access expiry without another click', async () => {
  vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] })
  vi.spyOn(Date, 'now').mockReturnValue(now * 1000)
  const f = fixture({ effectiveUntil: now + 900, sessionExpiresAt: now + 300 })
  await act(async () => { render(<MemoryRouter><NativeDisclosures scope={f.scope} /></MemoryRouter>) })
  await act(async () => { fireEvent.click(screen.getByRole('button', { name: 'Open case' })) })
  await act(async () => { fireEvent.click(screen.getByRole('button', { name: 'Read permitted data' })) })
  expect(screen.getByRole('cell', { name: '101' })).toBeInTheDocument()
  await act(async () => { fireEvent.click(screen.getByRole('button', { name: 'Next page' })) })
  expect(screen.getByRole('cell', { name: '126' })).toBeInTheDocument()
  vi.mocked(Date.now).mockReturnValue((now + 300) * 1000)
  await act(async () => { await vi.advanceTimersByTimeAsync(300000) })
  expect(screen.queryByRole('columnheader', { name: 'Decision ID' })).not.toBeInTheDocument()
  expect(screen.queryByRole('button', { name: 'Previous page' })).not.toBeInTheDocument()
  expect(screen.queryByRole('button', { name: 'Download this page' })).not.toBeInTheDocument()
  expect(f.bodies).toHaveLength(2)
})

it('sends inclusive UTC narrowing and ignores a superseded pending result', async () => {
  const f = fixture(); let finish!: (value: unknown) => void
  const original = f.request.getMockImplementation()!
  f.request.mockImplementation(async (path, options) => path.endsWith('/read') ? new Promise(resolve => { finish = resolve }) : original(path, options))
  await open(f.scope)
  const from = new Date((now - 5000) * 1000).toISOString().slice(0, 19)
  fireEvent.change(screen.getByLabelText('From (UTC, inclusive)'), { target: { value: from } })
  await userEvent.click(screen.getByRole('button', { name: 'Read permitted data' }))
  const body = JSON.parse(String(f.request.mock.calls.at(-1)![1]?.body))
  expect(body.dataTime).toEqual({ start: now - 5000, end: now })
  fireEvent.change(screen.getByLabelText('Target actor'), { target: { value: actor } })
  await act(async () => finish(page(0, body.dataTime)))
  expect(screen.queryByRole('columnheader', { name: 'Decision ID' })).not.toBeInTheDocument()
})


it('accepts live Next observations with changed count, basis, and as-of time; Refresh restarts newest', async () => {
  const f = fixture(), original = f.request.getMockImplementation()!
  f.request.mockImplementation(async (path, options) => {
    const value = await original(path, options)
    if (!path.endsWith('/read')) return value
    const body = JSON.parse(String(options?.body))
    if (!body.cursor) return value
    const next = page(1)
    return { ...next, coverage: { ...next.coverage, sourceBasisDigest: 'sha256:' + 'b'.repeat(64), preparedAt: now + 1 }, result: { ...next.result, items: Array.from({ length: 25 }, (_, i) => item(26 - i)), matchingRetainedCount: '20002', observedAt: new Date((now + 1) * 1000).toISOString() } }
  })
  await open(f.scope)
  await userEvent.click(screen.getByRole('button', { name: 'Read permitted data' }))
  await screen.findByRole('cell', { name: '101' })
  await userEvent.click(screen.getByRole('button', { name: 'Next page' }))
  await screen.findByRole('cell', { name: '26' })
  expect(screen.getByText('20002')).toBeInTheDocument()
  expect(screen.getByText(new Date((now + 1) * 1000).toISOString())).toBeInTheDocument()
  expect(screen.queryByRole('alert')).not.toBeInTheDocument()
  await userEvent.click(screen.getByRole('button', { name: 'Refresh admission decisions' }))
  await screen.findByRole('cell', { name: '101' })
  expect(f.bodies).toHaveLength(3)
  expect(f.bodies.at(-1)).not.toHaveProperty('cursor')
  expect(screen.getByRole('button', { name: 'Previous page' })).toBeDisabled()
})

it('opens admission decisions from the aggregate summary with the same case, actor and UTC interval', async () => {
  const f = fixture(); await open(f.scope)
  const start = new Date((now - 5000) * 1000).toISOString().slice(0, 19), end = new Date((now - 1) * 1000).toISOString().slice(0, 19)
  fireEvent.change(screen.getByLabelText('Target actor'), { target: { value: actor } })
  fireEvent.change(screen.getByLabelText('From (UTC, inclusive)'), { target: { value: start } })
  fireEvent.change(screen.getByLabelText('Through (UTC, inclusive)'), { target: { value: end } })
  fireEvent.change(screen.getByLabelText('Compliance view'), { target: { value: 'report' } })
  expect(screen.getByRole('option', { name: 'Summary report' })).toBeInTheDocument()
  await userEvent.click(screen.getByRole('button', { name: 'Read permitted data' }))
  await screen.findByRole('button', { name: 'View admission decisions' })
  expect(screen.getByText('20001')).toBeInTheDocument()
  expect(screen.getByText('KYC: not evaluated')).toBeInTheDocument()
  expect(screen.getByRole('cell', { name: 'eth_call' })).toBeInTheDocument()
  expect(screen.queryByRole('columnheader', { name: 'Decision ID' })).not.toBeInTheDocument()
  expect(f.bodies[0]).toEqual({ v: 1, resource: 'compliance_report', view: 'report', targetActorIds: [actor], dataTime: { start: now - 5000, end: now - 1 } })
  await userEvent.click(screen.getByRole('button', { name: 'View admission decisions' }))
  await screen.findByRole('cell', { name: '101' })
  expect(f.bodies[1]).toEqual({ ...f.bodies[0], view: 'list', limit: 25 })
  expect(f.request.mock.calls.filter(([path]) => path.endsWith('/read')).map(([path]) => path)).toEqual(Array(2).fill('/api/v1/disclosure/cases/' + selected.caseId + '/read'))
  expect(screen.getByLabelText('Compliance view')).toHaveValue('list')
  expect(screen.getByLabelText('Target actor')).toHaveValue(actor)
  expect((screen.getByLabelText('From (UTC, inclusive)') as HTMLInputElement).value.replace(/\.000$/, '')).toBe(start)
  expect((screen.getByLabelText('Through (UTC, inclusive)') as HTMLInputElement).value.replace(/\.000$/, '')).toBe(end)
})

it('downloads exactly the visible page and downloads a summary without inline evidence', async () => {
  const blobs: Blob[] = [], downloads: string[] = []
  vi.stubGlobal('URL', class extends URL { static createObjectURL(blob: Blob) { blobs.push(blob); return 'blob:disclosure' } static revokeObjectURL = vi.fn() })
  vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(function () { downloads.push(this.download) })
  const content = (blob: Blob) => new Promise<any>((resolve, reject) => { const reader = new FileReader(); reader.onload = () => resolve(JSON.parse(String(reader.result))); reader.onerror = reject; reader.readAsText(blob) })
  const f = fixture(); await open(f.scope)
  await userEvent.click(screen.getByRole('button', { name: 'Read permitted data' }))
  await screen.findByRole('cell', { name: '101' })
  await userEvent.click(screen.getByRole('button', { name: 'Next page' }))
  await screen.findByRole('cell', { name: '126' })
  await userEvent.click(screen.getByRole('button', { name: 'Download this page' }))
  const pageDownload = await content(blobs[0])
  expect(pageDownload.result.items).toHaveLength(25)
  expect(pageDownload.result.items[0].id).toBe('126')
  expect(pageDownload).toEqual(page(1))
  fireEvent.change(screen.getByLabelText('Compliance view'), { target: { value: 'report' } })
  await userEvent.click(screen.getByRole('button', { name: 'Read permitted data' }))
  await userEvent.click(await screen.findByRole('button', { name: 'Download summary report' }))
  const summaryDownload = await content(blobs[1])
  expect(summaryDownload).toEqual(report())
  expect(summaryDownload.result).not.toHaveProperty('evidence')
  expect(summaryDownload.result).not.toHaveProperty('items')
  expect(downloads).toEqual(['ops-disclosure-page.json', 'ops-disclosure-report.json'])
})

it('keeps only ten loaded pages and does not fetch when walking cached Previous pages', async () => {
  const f = fixture(); await open(f.scope)
  await userEvent.click(screen.getByRole('button', { name: 'Read permitted data' }))
  for (let i = 1; i <= 10; i++) {
    await userEvent.click(await screen.findByRole('button', { name: 'Next page' }))
    await screen.findByRole('cell', { name: String(101 + i * 25) })
  }
  expect(screen.getByText(/latest 10 pages are kept/)).toBeInTheDocument()
  for (let i = 0; i < 9; i++) await userEvent.click(screen.getByRole('button', { name: 'Previous page' }))
  expect(screen.getByRole('cell', { name: '126' })).toBeInTheDocument()
  expect(screen.getByRole('button', { name: 'Previous page' })).toBeDisabled()
  expect(f.bodies).toHaveLength(11)
}, 15000) // Twenty sequential DOM interactions; keep the ordinary per-test limit elsewhere.

it('clears cached evidence and supersedes pending Next when its original session expires', async () => {
  vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] })
  vi.spyOn(Date, 'now').mockReturnValue(now * 1000)
  const f = fixture({ effectiveUntil: now + 900, sessionExpiresAt: now + 300 }), original = f.request.getMockImplementation()!
  let finish!: (value: unknown) => void
  f.request.mockImplementation(async (path, options) => path.endsWith('/read') && JSON.parse(String(options?.body)).cursor ? new Promise(resolve => { finish = resolve }) : original(path, options))
  await act(async () => { render(<MemoryRouter><NativeDisclosures scope={f.scope} /></MemoryRouter>) })
  await act(async () => { fireEvent.click(screen.getByRole('button', { name: 'Open case' })) })
  await act(async () => { fireEvent.click(screen.getByRole('button', { name: 'Read permitted data' })) })
  expect(screen.getByRole('cell', { name: '101' })).toBeInTheDocument()
  await act(async () => { fireEvent.click(screen.getByRole('button', { name: 'Next page' })) })
  vi.mocked(Date.now).mockReturnValue((now + 300) * 1000)
  await act(async () => { await vi.advanceTimersByTimeAsync(300000) })
  await act(async () => { finish({ ...page(1), effectiveUntil: now + 900 }) })
  expect(screen.queryByRole('columnheader', { name: 'Decision ID' })).not.toBeInTheDocument()
  expect(screen.queryByRole('button', { name: 'Download this page' })).not.toBeInTheDocument()
  expect(screen.queryByRole('alert')).not.toBeInTheDocument()
})
