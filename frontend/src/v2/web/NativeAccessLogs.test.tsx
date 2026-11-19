import '@testing-library/jest-dom/vitest'
import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'
import { afterEach, beforeEach, expect, it, vi } from 'vitest'
import { NativeAccessLogs } from './NativeAccessLogs'
import { NativeOperationsPage } from './NativeOperationsPages'
import { OperationHTTPError } from './operationsTransport'
import type { Controller, OperationScope, State } from './controller'
import type { AccessLogItem, AccessLogPage } from './accessLogsModels'

const org = '11111111-1111-4111-8111-111111111111', otherOrg = '33333333-3333-4333-8333-333333333333', ref = '22222222-2222-4222-8222-222222222222', actor = 'ops:p1:' + 'A'.repeat(43)
const digest = 'sha256:' + 'a'.repeat(64), now = Date.parse('2026-11-20T12:00:00Z')
function row(changes: Partial<AccessLogItem> = {}): AccessLogItem {
  return { requestReference: ref, observedAt: '2026-11-20T11:00:00.123456Z', actorId: actor, organizationId: org, method: 'eth_call', outcome: 'denied', httpStatus: 200, rpcErrorCode: -32000, recordedStatus: 403, trustedIP: '127.0.0.1', policyDigest: digest, configurationDigest: digest, reason: 'not_recorded', ...changes }
}
function page(items = [row()], next: string | null = null): AccessLogPage {
  return { items, next, source: { sourceId: org, generation: '44444444-4444-4444-8444-444444444444', networkDigest: digest, configurationDigest: digest, headReference: digest, sourceAsOf: '2026-11-20T11:30:00Z', retainedFrom: '2026-01-01T00:00:00Z', population: 'SEALED_REQUEST_COMPLETIONS_AS_OF_CHAIN_HEAD', coverage: 'committed-sealed-prefix' } }
}
function scope(role: 'admin' | 'readonly' | 'member' = 'admin', extraOrg = false, owner: { actor?: string; digest?: string } = {}) {
  const abort = new AbortController(), request = vi.fn(async (_path: string): Promise<unknown> => page())
  let valid = true
  const value = { identity: { actor: owner.actor ?? actor, expires: now / 1000 + 300 }, signal: abort.signal, check: vi.fn(() => { if (!valid) throw Error('stale scope') }), dispose: vi.fn(), request,
    self: { actorId: owner.actor ?? actor, principalKind: 'human', sourceProfile: 'bank', sourceProfileDigest: owner.digest ?? digest, expiresAt: now / 1000 + 300, organizations: [{ id: org, slug: 'bank-a', name: 'Bank A', isOrgAdmin: role === 'admin', isOrgReadonlyAdmin: role === 'readonly' }, ...(extraOrg ? [{ id: otherOrg, slug: 'bank-b', name: 'Bank B', isOrgAdmin: true, isOrgReadonlyAdmin: false }] : [])] } } as unknown as OperationScope
  return { value, request, invalidate: () => { valid = false }, abort: () => { valid = false; abort.abort() } }
}
function show(value: OperationScope, path = '/admin/logs') { return render(<MemoryRouter initialEntries={[path]}><NativeAccessLogs scope={value} /></MemoryRouter>) }
function delayed() { let resolve!: (value: unknown) => void; return { promise: new Promise<unknown>(done => { resolve = done }), resolve: (value: unknown) => resolve(value) } }
beforeEach(() => vi.spyOn(Date, 'now').mockReturnValue(now))
afterEach(() => { cleanup(); vi.useRealTimers(); vi.restoreAllMocks() })

it.each(['admin', 'readonly'] as const)('%s can investigate own-org records without a disclosure case and sees distinct recorded statuses', async role => {
  const s = scope(role); show(s.value)
  const reference = await screen.findByText(ref), record = within(reference.closest('tr')!)
  expect(record.getByText('Denied')).toBeInTheDocument(); expect(record.getByText('200')).toBeInTheDocument(); expect(record.getByText('403')).toBeInTheDocument(); expect(record.getByText('-32000')).toBeInTheDocument(); expect(record.getByText('127.0.0.1')).toBeInTheDocument()
  expect(record.getByText('Not recorded')).toBeInTheDocument(); expect(screen.getByText(/not a complete live traffic history/)).toBeInTheDocument()
  expect(screen.getByText(/Newer requests may be missing/)).toBeInTheDocument()
  expect(screen.queryByRole('button', { name: 'Create case' })).not.toBeInTheDocument()
  expect(s.request).toHaveBeenCalledTimes(1); expect(s.request.mock.calls[0][0]).toContain(`/api/v2/orgs/${org}/access-logs?`)
  expect(s.request.mock.calls.every(([path]) => !path.includes('/disclosure/'))).toBe(true)
})
it('keeps long identifiers on one bounded line with the full values available to inspect and copy', async () => {
  const user = userEvent.setup(), copied = vi.spyOn(navigator.clipboard, 'writeText').mockResolvedValue()
  const s = scope(); show(s.value)
  const identity = await screen.findByText(actor), reference = screen.getByText(ref)
  for (const [element, value] of [[identity, actor], [reference, ref]] as const) {
    expect(element).toHaveAttribute('title', value)
    expect(element).toHaveClass('truncate', 'whitespace-nowrap', 'min-w-0')
    expect(element.parentElement).toHaveClass('w-56', 'min-w-56')
    expect(element.closest('table')?.parentElement).toHaveClass('overflow-auto')
    expect(element).not.toHaveClass('break-all')
  }
  expect(screen.getByText('eth_call')).toHaveClass('whitespace-nowrap')
  await user.click(screen.getByRole('button', { name: 'Copy actor ID' }))
  expect(copied).toHaveBeenLastCalledWith(actor)
  await user.click(screen.getByRole('button', { name: 'Copy request reference' }))
  expect(copied).toHaveBeenLastCalledWith(ref)
  expect(s.request).toHaveBeenCalledTimes(1)
})
it('a member cannot issue organization-admin reads or browse a local user directory', () => {
  const s = scope('member'); show(s.value)
  expect(screen.getByText(/no organization access-log administration role/)).toBeInTheDocument(); expect(s.request).not.toHaveBeenCalled()
  expect(screen.queryByLabelText('OPS actor ID')).not.toBeInTheDocument()
})
it('applies all filters on the server, reuses its continuation, and clears results/cursor when a filter changes', async () => {
  const s = scope(); s.request.mockResolvedValueOnce(page([row()], 'sealed-page-2')).mockResolvedValueOnce(page([row({ requestReference: otherOrg })], 'sealed-page-3'))
  show(s.value); await screen.findByText(ref)
  fireEvent.click(screen.getByRole('button', { name: 'Next page' })); await screen.findByText(otherOrg)
  expect(new URL(s.request.mock.calls[1][0], location.origin).searchParams.get('cursor')).toBe('sealed-page-2')
  for (const [label, value] of [['OPS actor ID', actor], ['Method', 'explorer.transactions'], ['Outcome', 'denied'], ['Request reference', ref], ['From (UTC)', '2026-11-20T10:00:00'], ['To (UTC, excluded)', '2026-11-20T12:00:00']]) fireEvent.change(screen.getByLabelText(label), { target: { value } })
  expect(screen.queryByText(otherOrg)).not.toBeInTheDocument(); expect(screen.queryByRole('button', { name: 'Next page' })).not.toBeInTheDocument(); expect(s.request).toHaveBeenCalledTimes(2)
  s.request.mockResolvedValueOnce(page([row({ method: 'explorer.transactions' })]))
  fireEvent.click(screen.getByRole('button', { name: 'Search', exact: true })); await screen.findByText(ref)
  const query = new URL(s.request.mock.calls[2][0], location.origin).searchParams
  expect(Object.fromEntries(query)).toEqual({ from: '2026-11-20T10:00:00Z', to: '2026-11-20T12:00:00Z', limit: '50', actorId: actor, method: 'explorer.transactions', outcome: 'denied', requestReference: ref })
  expect(query.has('cursor')).toBe(false); expect(screen.getByText(/Page 1 · 1 records/)).toBeInTheDocument()
  expect(screen.getByRole('button', { name: 'Previous page' })).toBeDisabled()
})
it('revisits page1 then page2 of the original cut without a blank-cursor requery or false repeat detection', async () => {
  const s = scope(), laterCut = page([row({ method: 'newer-source-record' })]); laterCut.source.headReference = 'sha256:' + 'b'.repeat(64)
  s.request.mockResolvedValueOnce(page([row()], 'sealed-page-2')).mockResolvedValueOnce(page([row({ requestReference: otherOrg })], 'sealed-page-3')).mockResolvedValueOnce(laterCut)
  show(s.value); await screen.findByText(ref)
  expect(screen.getByRole('button', { name: 'Previous page' })).toBeDisabled()
  fireEvent.click(screen.getByRole('button', { name: 'Next page' })); await screen.findByText(otherOrg)
  expect(screen.getByText(/Page 2 · 1 records/)).toBeInTheDocument()
  fireEvent.click(screen.getByRole('button', { name: 'Previous page' })); await screen.findByText(ref)
  expect(screen.getByText(/Page 1 · 1 records/)).toBeInTheDocument(); expect(s.request).toHaveBeenCalledTimes(2)
  expect(screen.queryByText('newer-source-record')).not.toBeInTheDocument()
  fireEvent.click(screen.getByRole('button', { name: 'Next page' })); await screen.findByText(otherOrg)
  expect(screen.getByText(/Page 2 · 1 records/)).toBeInTheDocument(); expect(s.request).toHaveBeenCalledTimes(2)
  expect(screen.queryByRole('alert')).not.toBeInTheDocument()
})
it('bounds cached pages while allowing Next beyond the history window and describes evictions honestly', async () => {
  const s = scope(), reference = (number: number) => '55555555-5555-4555-8555-' + String(number).padStart(12, '0')
  s.request.mockImplementation(async path => {
    const cursor = new URL(path, location.origin).searchParams.get('cursor'), number = cursor ? Number(cursor.slice(5)) : 1
    return page([row({ requestReference: reference(number) })], 'page-' + (number + 1))
  })
  show(s.value); await screen.findByText(reference(1))
  for (let number = 2; number <= 12; number++) { fireEvent.click(screen.getByRole('button', { name: 'Next page' })); await screen.findByText(reference(number)) }
  expect(s.request).toHaveBeenCalledTimes(12)
  expect(screen.getByText(/Up to 10 visited pages.*Pages before 3/)).toBeInTheDocument()
  for (let number = 11; number >= 3; number--) { fireEvent.click(screen.getByRole('button', { name: 'Previous page' })); await screen.findByText(reference(number)) }
  expect(screen.getByRole('button', { name: 'Previous page' })).toBeDisabled(); expect(screen.getByText(/Page 3 · 1 records/)).toBeInTheDocument()
  expect(s.request).toHaveBeenCalledTimes(12)
  for (let number = 4; number <= 13; number++) { fireEvent.click(screen.getByRole('button', { name: 'Next page' })); await screen.findByText(reference(number)) }
  expect(s.request).toHaveBeenCalledTimes(13); expect(screen.getByText(/Page 13 · 1 records/)).toBeInTheDocument()
  fireEvent.click(screen.getByRole('button', { name: 'Search', exact: true })); await screen.findByText(reference(1))
  expect(screen.getByRole('button', { name: 'Previous page' })).toBeDisabled(); expect(screen.queryByText(/Pages before 3/)).not.toBeInTheDocument()
  expect(new URL(s.request.mock.calls[13][0], location.origin).searchParams.has('cursor')).toBe(false)
})
it.each(['abort', 'expiry', 'invalidation'] as const)('never republishes previously authorized cached pages after scope %s', async reason => {
  const s = scope(); s.request.mockResolvedValueOnce(page([row()], 'page-two')).mockResolvedValueOnce(page([row({ requestReference: otherOrg })]))
  show(s.value); await screen.findByText(ref); fireEvent.click(screen.getByRole('button', { name: 'Next page' })); await screen.findByText(otherOrg)
  if (reason === 'abort') act(() => s.abort())
  else {
    if (reason === 'expiry') vi.mocked(Date.now).mockReturnValue(now + 300001)
    else s.invalidate()
    fireEvent.click(screen.getByRole('button', { name: 'Previous page' }))
  }
  expect(screen.queryByText(ref)).not.toBeInTheDocument(); expect(screen.queryByText(otherOrg)).not.toBeInTheDocument()
  expect(screen.queryByRole('button', { name: 'Previous page' })).not.toBeInTheDocument(); expect(screen.getByRole('alert')).toHaveTextContent('original session')
  expect(s.request).toHaveBeenCalledTimes(2)
})
it('clears visible and cached pages at the original scope expiry without another gesture', async () => {
  vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] })
  const s = scope(); s.request.mockResolvedValueOnce(page([row()], 'page-two')).mockResolvedValueOnce(page([row({ requestReference: otherOrg })]))
  await act(async () => { show(s.value) })
  expect(screen.getByText(ref)).toBeInTheDocument()
  await act(async () => { fireEvent.click(screen.getByRole('button', { name: 'Next page' })) })
  expect(screen.getByText(otherOrg)).toBeInTheDocument()
  vi.mocked(Date.now).mockReturnValue(now + 300001)
  await act(async () => { await vi.advanceTimersByTimeAsync(300001) })
  expect(screen.queryByText(otherOrg)).not.toBeInTheDocument(); expect(screen.queryByText(ref)).not.toBeInTheDocument()
  expect(screen.queryByRole('button', { name: 'Previous page' })).not.toBeInTheDocument(); expect(screen.getByRole('alert')).toHaveTextContent('original session')
})
it('does not publish a delayed old response after editing and searching new filters', async () => {
  const s = scope(), old = delayed(); s.request.mockImplementationOnce(() => old.promise)
  show(s.value); await waitFor(() => expect(s.request).toHaveBeenCalledTimes(1))
  fireEvent.change(screen.getByLabelText('Method'), { target: { value: 'eth_getLogs' } })
  s.request.mockResolvedValueOnce(page([row({ method: 'eth_getLogs', requestReference: otherOrg })]))
  fireEvent.click(screen.getByRole('button', { name: 'Search', exact: true })); await screen.findByText(otherOrg)
  await act(async () => old.resolve(page([row()], 'stale-cursor')))
  expect(screen.queryByText(ref)).not.toBeInTheDocument(); expect(screen.getByText(otherOrg)).toBeInTheDocument(); expect(screen.queryByRole('button', { name: 'Next page' })).not.toBeInTheDocument()
})
it('changes organization without adopting a delayed previous organization response', async () => {
  const s = scope('admin', true), old = delayed(); s.request.mockImplementationOnce(() => old.promise).mockResolvedValueOnce(page([row({ organizationId: otherOrg, requestReference: otherOrg })]))
  show(s.value, '/admin/logs?org=' + org); await waitFor(() => expect(s.request).toHaveBeenCalledTimes(1))
  fireEvent.change(screen.getByLabelText('Organization'), { target: { value: otherOrg } }); await screen.findByText(otherOrg)
  expect(s.request.mock.calls[1][0]).toContain(`/api/v2/orgs/${otherOrg}/access-logs?`)
  await act(async () => old.resolve(page([row()])))
  expect(screen.queryByText(ref)).not.toBeInTheDocument()
})
it('clears private records when the scope aborts and rejects a late response', async () => {
  const s = scope(); show(s.value); await screen.findByText(ref)
  act(() => s.abort()); expect(screen.queryByText(ref)).not.toBeInTheDocument(); expect(screen.getByRole('alert')).toHaveTextContent('original session')
})
it('does not publish a late in-flight page after the original account scope aborts', async () => {
  const s = scope(), held = delayed(); s.request.mockImplementationOnce(() => held.promise)
  show(s.value); await waitFor(() => expect(s.request).toHaveBeenCalledTimes(1))
  act(() => s.abort()); await act(async () => held.resolve(page([row()], 'stale-next')))
  expect(screen.queryByText(ref)).not.toBeInTheDocument(); expect(screen.queryByRole('button', { name: 'Next page' })).not.toBeInTheDocument()
  expect(screen.getByRole('alert')).toHaveTextContent('original session')
})
it.each(['account', 'profile activation'] as const)('resets results and cursor for a changed %s', async kind => {
  const s = scope(), next = scope('admin', false, kind === 'account' ? { actor: 'ops:p1:' + 'B'.repeat(43) } : { digest: 'sha256:' + 'b'.repeat(64) }); s.request.mockResolvedValueOnce(page([row()], 'old-cursor'))
  const view = show(s.value); await screen.findByText(ref)
  next.request.mockResolvedValueOnce(page([]))
  view.rerender(<MemoryRouter><NativeAccessLogs scope={next.value} /></MemoryRouter>)
  await screen.findByText('No sealed records match these filters in this organization.')
  expect(screen.queryByText(ref)).not.toBeInTheDocument(); expect(new URL(next.request.mock.calls[0][0], location.origin).searchParams.has('cursor')).toBe(false)
})
it.each(['history_pruned', 'source_unavailable', 'cursor_expired'] as const)('shows %s distinctly from an empty result and drops the old continuation', async code => {
  const s = scope(); s.request.mockResolvedValueOnce(page([row()], 'page-two')).mockRejectedValueOnce(new OperationHTTPError(code === 'history_pruned' ? 410 : code === 'source_unavailable' ? 503 : 409, false, { code, ...(code === 'history_pruned' ? { retainedFrom: '2026-11-20T10:30:00Z' } : {}) }))
  show(s.value); await screen.findByText(ref); fireEvent.click(screen.getByRole('button', { name: 'Next page' }))
  const alert = await screen.findByRole('alert'); expect(alert).toHaveTextContent(code === 'history_pruned' ? /pruned.*2026-11-20T10:30:00Z/ : code === 'source_unavailable' ? /source is unavailable/ : /Search again/)
  expect(screen.queryByText(ref)).not.toBeInTheDocument(); expect(screen.queryByText('No sealed records match these filters in this organization.')).not.toBeInTheDocument(); expect(screen.queryByRole('button', { name: 'Next page' })).not.toBeInTheDocument()
})
it('rejects a continuation whose source cut changed instead of mixing snapshots', async () => {
  const s = scope(), changed = page([row({ requestReference: otherOrg })]); changed.source.headReference = 'sha256:' + 'b'.repeat(64)
  s.request.mockResolvedValueOnce(page([row()], 'page-two')).mockResolvedValueOnce(changed)
  show(s.value); await screen.findByText(ref); fireEvent.click(screen.getByRole('button', { name: 'Next page' }))
  expect(await screen.findByRole('alert')).toHaveTextContent('source changed'); expect(screen.queryByText(otherOrg)).not.toBeInTheDocument()
})
it('the logs route uses the direct organization reader while disclosure remains a separate workflow', async () => {
  const s = scope(), controller = { scopeRevision: 1, captureOperations: vi.fn(async () => s.value) } as unknown as Controller
  const state = { self: s.value.self } as State
  render(<MemoryRouter><NativeOperationsPage controller={controller} state={state} section="logs" /></MemoryRouter>)
  await screen.findByText(ref); expect(screen.getByRole('heading', { name: 'Access Logs' })).toBeInTheDocument(); expect(s.request.mock.calls.every(([path]) => !path.includes('/disclosure/'))).toBe(true)
})

it('shows curated recorded reasons without inventing diagnostics for older records', async () => {
  const s = scope(); s.request.mockResolvedValueOnce(page([
    row({ reason: 'sender_not_linked' }),
    row({ requestReference: otherOrg, reason: 'method_not_allowed' }),
    row({ requestReference: '55555555-5555-4555-8555-555555555555' }),
  ]))
  show(s.value)
  expect(await screen.findByText('Wallet not linked')).toHaveAttribute('title', 'sender_not_linked')
  expect(screen.getByText('Method not allowed')).toHaveAttribute('title', 'method_not_allowed')
  expect(screen.getByText('Not recorded')).toHaveAttribute('title', 'not_recorded')
  expect(screen.getByText(/Older or unclassified/)).toBeInTheDocument()
})
