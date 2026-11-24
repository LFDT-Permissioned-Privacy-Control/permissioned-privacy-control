import '@testing-library/jest-dom/vitest'
import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'
import { afterEach, expect, it, vi } from 'vitest'
import { NativeCompliance } from './NativeCompliance'
import { ComplianceEventDetails, TravelRecordDetails } from './ComplianceDetails'
import { NativeDiagnostics } from './NativeDiagnostics'
import type { OperationScope } from './controller'
const org = '11111111-1111-4111-8111-111111111111', org2 = '22222222-2222-4222-8222-222222222222', actor = 'ops:p1:' + 'A'.repeat(43), one = '0x' + '1'.repeat(40), two = '0x' + '2'.repeat(40)
function scope() {
  const request = vi.fn(async (path: string, options?: RequestInit): Promise<unknown> => {
    if (path.includes('/health/')) return { ready: true }
    if (path.endsWith('/tokens')) return { data: [{ tokenAddress: 'native', symbol: 'ETH', decimals: 18 }, { tokenAddress: one, symbol: 'SAME', decimals: 6 }, { tokenAddress: two, symbol: 'SAME', decimals: 18 }] }
    if (path.endsWith('/config')) return { data: { spec: { settings: { enabled: true, thresholdFiat: 0, currency: 'usd', unknownPricePolicy: 'forbidden', enforcementMode: 'enforce' } }, recordMaxSeconds: 60, priceMaxAgeSeconds: 30 }, sourceDigest: '' }
    if (options?.method === 'POST') return { id: 'created' }
    if (path.includes('/travel-rule-records')) return { records: [], nextCursor: '' }
    if (path.includes('/events')) return { events: ['allowed', 'blocked', 'allowed'].map((decision, id) => ({ id, decision, monitored: id === 2, decisionAt: '2026-01-01T00:00:00Z', transactionHash: 'hash-' + id, actorId: actor, coverage: 'covered', reason: 'reason-' + id, kind: 'erc20', amountWei: '0', amountFiat: 0, thresholdFiat: 0, currency: 'usd', recordId: 'matched-' + id, policyDigest: 'sha256:' + 'a'.repeat(64) })), nextCursor: '' }
    throw Error('Unexpected request ' + path)
  })
  return { identity: { actor, expires: Date.now() / 1000 + 300 }, request, check: vi.fn(), signal: new AbortController().signal, self: { organizations: [org, org2].map((id, i) => ({ id, name: 'Bank ' + i, isOrgAdmin: true, isOrgReadonlyAdmin: false })) } } as unknown as OperationScope & { request: typeof request }
}
afterEach(cleanup)
it('reports a failed log fetch without presenting an empty history and retries successfully', async () => {
  const s = scope(), original = s.request.getMockImplementation()!
  let fail = true
  s.request.mockImplementation(async (path, options) => {
    if (path.includes('/events') && fail) throw new TypeError('Failed to fetch')
    return original(path, options)
  })
  render(<MemoryRouter initialEntries={['/?org=' + org]}><NativeCompliance scope={s} /></MemoryRouter>)
  await screen.findByText('0 usd')
  await userEvent.click(screen.getByRole('button', { name: 'Compliance logs' }))
  expect(await screen.findByRole('alert')).toHaveTextContent('Could not load compliance logs')
  expect(screen.queryByText('No records in this scope.')).not.toBeInTheDocument()
  expect(screen.queryByText(/End of the available records/)).not.toBeInTheDocument()
  fail = false
  await userEvent.click(screen.getByRole('button', { name: 'Refresh' }))
  expect(await screen.findAllByRole('button', { name: 'View details' })).toHaveLength(3)
  expect(screen.queryByRole('alert')).not.toBeInTheDocument()
})
it('retires open event details and history footer while a failed refresh is retried', async () => {
  const s = scope(), original = s.request.getMockImplementation()!
  let mode: 'ok' | 'fail' | 'held' = 'ok', resolve!: (value: unknown) => void
  s.request.mockImplementation(async (path, options) => {
    if (path.includes('/events') && mode === 'fail') throw new TypeError('Failed to fetch')
    if (path.includes('/events') && mode === 'held') return new Promise(done => { resolve = done })
    return original(path, options)
  })
  render(<MemoryRouter initialEntries={['/?org=' + org]}><NativeCompliance scope={s} /></MemoryRouter>)
  await screen.findByText('0 usd'); await userEvent.click(screen.getByRole('button', { name: 'Compliance logs' }))
  await userEvent.click((await screen.findAllByRole('button', { name: 'View details' }))[0])
  expect(screen.getByRole('dialog')).toHaveTextContent('matched-0')
  mode = 'fail'; fireEvent.click(screen.getByRole('button', { name: 'Refresh', hidden: true }))
  expect(await screen.findByRole('alert')).toHaveTextContent('Could not load compliance logs')
  expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
  mode = 'held'; await userEvent.click(screen.getByRole('button', { name: 'Refresh' }))
  await waitFor(() => expect(resolve).toBeTypeOf('function'))
  expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
  expect(screen.queryByText(/End of the available records/)).not.toBeInTheDocument()
  resolve(await original('/events'))
  expect(await screen.findAllByRole('button', { name: 'View details' })).toHaveLength(3)
  expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
})
it('opens allowed, blocked and monitored decision evidence without issuing extra reads; zero is evidence', async () => {
  const s = scope()
  render(<MemoryRouter initialEntries={['/?org=' + org]}><NativeCompliance scope={s} /></MemoryRouter>)
  await screen.findByText('0 usd')
  await userEvent.click(screen.getByRole('button', { name: 'Compliance logs' }))
  const details = await screen.findAllByRole('button', { name: 'View details' })
  for (let i = 0; i < details.length; i++) {
    const before = s.request.mock.calls.length
    await userEvent.click(details[i])
    const dialog = screen.getByRole('dialog')
    expect(within(dialog).getByText('matched-' + i)).toBeInTheDocument()
    expect(within(dialog).getAllByText('0 usd')).toHaveLength(2)
    expect(within(dialog).getByText(i === 2 ? 'Monitored' : 'Enforced')).toBeInTheDocument()
    expect(s.request.mock.calls.length).toBe(before)
    await userEvent.keyboard('{Escape}')
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument())
  }
  await userEvent.click(details[0])
  fireEvent.change(screen.getByLabelText('Organization'), { target: { value: org2 } })
  expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
})
it('renders absent evidence honestly and record dates/use/huge units from returned fields', () => {
  const { unmount } = render(<ComplianceEventDetails event={{ decision: 'blocked', amountFiat: 0, thresholdFiat: 0 }} />)
  expect(screen.getAllByText('Unavailable').length).toBeGreaterThan(5); expect(screen.getAllByText('0')).toHaveLength(2)
  unmount()
  render(<TravelRecordDetails tokens={[{ address: one, symbol: 'T', decimals: 6 }]} detail={{ id: 'record', organizationId: org, originatorActorId: actor, transferType: 'erc20', tokenAddress: one, beneficiaryAddress: two, amountWei: '9007199254740993123456789', amountFiat: 0, currency: 'usd', createdAt: '2026-01-01T00:00:00Z', expiresAt: '2099-01-01T00:00:00Z', usedAt: '2026-01-02T00:00:00Z', usedTxHash: 'used-hash', originatorData: { name: 'Alice' }, beneficiaryData: { name: 'Bob' } }} />)
  expect(screen.getByText('9007199254740993123.456789 T (9007199254740993123456789 base units)')).toBeInTheDocument()
  expect(screen.getByText('used-hash')).toBeInTheDocument(); expect(screen.getByText('Used')).toBeInTheDocument()
})
it('defaults approved units to human and clears same-symbol unit changes before native POST', async () => {
  const s = scope()
  render(<MemoryRouter initialEntries={['/?org=' + org]}><NativeCompliance scope={s} /></MemoryRouter>)
  await screen.findByText('0 usd'); await userEvent.click(screen.getByRole('button', { name: 'Travel rules' })); await userEvent.click(await screen.findByRole('button', { name: 'Create travel-rule record' }))
  const dialog = screen.getByRole('dialog')
  for (const [label, value] of [['Originator name', 'Alice'], ['Beneficiary name', 'Bob'], ['Beneficiary wallet', two], ['Transfer type', 'erc20']]) fireEvent.change(within(dialog).getByLabelText(label), { target: { value } })
  await waitFor(() => expect(within(dialog).getByLabelText('Approved token')).toHaveTextContent(one))
  fireEvent.change(within(dialog).getByLabelText('Approved token'), { target: { value: one } })
  expect(within(dialog).getByLabelText('Amount entry')).toHaveValue('human')
  fireEvent.change(within(dialog).getByLabelText('Amount (SAME)'), { target: { value: '0.1' } })
  expect(within(dialog).getByText('100000')).toBeInTheDocument()
  fireEvent.change(within(dialog).getByLabelText('Approved token'), { target: { value: two } })
  expect(within(dialog).queryByText('100000')).not.toBeInTheDocument()
  expect(within(dialog).getByLabelText('Amount (SAME)')).toHaveValue('')
  expect(within(dialog).getByText(/Amount cleared after changing units/)).toBeInTheDocument()
  fireEvent.change(within(dialog).getByLabelText('Amount (SAME)'), { target: { value: '0.1' } })
  expect(within(dialog).getByText('100000000000000000')).toBeInTheDocument()
  await userEvent.click(within(dialog).getByRole('button', { name: 'Create record' }))
  const body = JSON.parse(String(s.request.mock.calls.find(([, options]) => options?.method === 'POST')![1]!.body))
  expect(body).toEqual({ originatorActorId: actor, originatorData: { name: 'Alice', accountRef: '' }, beneficiaryData: { name: 'Bob', institution: '' }, transferType: 'erc20', tokenAddress: two, beneficiaryAddress: two, amountWei: '100000000000000000' })
})
it('binds diagnostic calldata to verified org and retires response on input/org edits', async () => {
  const s = scope(), base = s.request.getMockImplementation()!
  s.request.mockImplementation(async (path, options) => path.startsWith('/rpc/') ? { result: '0x' + '0'.repeat(63) + '7' } : base(path, options))
  render(<MemoryRouter><NativeDiagnostics scope={s} /></MemoryRouter>)
  fireEvent.change(screen.getByLabelText('Organization'), { target: { value: org } })
  await waitFor(() => expect(screen.getByRole('button', { name: 'Send test request' })).toBeEnabled())
  for (const [label, value] of [['Organization', org], ['Token address', one], ['Owner / account', two]]) fireEvent.change(screen.getByLabelText(label), { target: { value } })
  await userEvent.click(screen.getByRole('button', { name: 'Send test request' }))
  expect(await screen.findByText('balanceOf: 7')).toBeInTheDocument()
  const [path, options] = s.request.mock.calls.find(([path]) => path.startsWith('/rpc/'))!
  expect(path).toBe('/rpc/' + org); expect(JSON.parse(String(options?.body)).params[0].data).toBe('0x70a08231' + two.slice(2).padStart(64, '0'))
  fireEvent.change(screen.getByLabelText('Owner / account'), { target: { value: one } })
  expect(screen.queryByText('balanceOf: 7')).not.toBeInTheDocument()
})
it('does not render a late PII detail after changing organizations', async () => {
  const s = scope(), original = s.request.getMockImplementation()!, recordId = '33333333-3333-4333-8333-333333333333'
  let resolve!: (value: unknown) => void
  s.request.mockImplementation(async (path, options) => {
    if (path.endsWith('/' + recordId)) return new Promise(r => { resolve = r })
    if (path.includes('/travel-rule-records')) return { records: [{ id: recordId, originatorActorId: actor, beneficiaryAddress: two, amountWei: '1', amountFiat: 0, currency: 'usd', expiresAt: '2099-01-01T00:00:00Z' }], nextCursor: '' }
    return original(path, options)
  })
  render(<MemoryRouter initialEntries={['/?org=' + org]}><NativeCompliance scope={s} /></MemoryRouter>)
  await screen.findByText('0 usd'); await userEvent.click(screen.getByRole('button', { name: 'Travel rules' }))
  await userEvent.click(await screen.findByRole('button', { name: 'Details' }))
  await waitFor(() => expect(resolve).toBeTypeOf('function'))
  const signal = s.request.mock.calls.find(([path]) => path.endsWith('/' + recordId))![1]?.signal
  expect(signal?.aborted).toBe(false)
  fireEvent.change(screen.getByLabelText('Organization'), { target: { value: org2 } })
  expect(signal?.aborted).toBe(true)
  resolve({ id: recordId, originatorData: { name: 'private old org' }, beneficiaryData: { name: 'private recipient' } })
  await waitFor(() => expect(s.request.mock.calls.some(([path]) => path.includes(org2))).toBe(true))
  expect(screen.queryByText('private old org')).not.toBeInTheDocument(); expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
})

it('shows expired unused record dates and honest unavailable usage/base-unit metadata', () => {
  render(<TravelRecordDetails tokens={[]} detail={{ id: 'expired', transferType: 'erc20', tokenAddress: one, amountWei: '9007199254740993', expiresAt: '2000-01-01T00:00:00Z' }} />)
  expect(screen.getByText('Expired')).toBeInTheDocument()
  expect(screen.getByText('9007199254740993 base units (token decimals unavailable)')).toBeInTheDocument()
  expect(screen.getAllByText('Unavailable').length).toBeGreaterThan(4)
})
it('diagnostic estimates default approved units to human and clear token/mode/unknown changes', async () => {
  const s = scope()
  render(<MemoryRouter><NativeDiagnostics scope={s} /></MemoryRouter>)
  fireEvent.change(screen.getByLabelText('Organization'), { target: { value: org } })
  await waitFor(() => expect(screen.getByRole('button', { name: 'Send test request' })).toBeEnabled())
  await waitFor(() => expect(screen.getByLabelText('Approved token')).toHaveTextContent(one))
  expect(screen.getByLabelText('Approved token')).not.toHaveTextContent('ETH')
  fireEvent.change(screen.getByLabelText('ERC-20 template'), { target: { value: 'estimate approve' } })
  expect(screen.getByLabelText('Amount entry')).toHaveValue('base')
  fireEvent.change(screen.getByLabelText('Approved token'), { target: { value: one } })
  expect(screen.getByLabelText('Amount entry')).toHaveValue('human')
  fireEvent.change(screen.getByLabelText('Amount (SAME)'), { target: { value: '0.1' } })
  expect(screen.getByText('100000')).toBeInTheDocument()
  fireEvent.change(screen.getByLabelText('Approved token'), { target: { value: two } })
  expect(screen.getByLabelText('Amount (SAME)')).toHaveValue('')
  expect(screen.getByText(/Amount cleared/)).toBeInTheDocument()
  fireEvent.change(screen.getByLabelText('Amount (SAME)'), { target: { value: '0.1' } })
  expect(screen.getByText('100000000000000000')).toBeInTheDocument()
  fireEvent.change(screen.getByLabelText('Amount entry'), { target: { value: 'base' } })
  expect(screen.getByLabelText('Amount in base units')).toHaveValue('')
  fireEvent.change(screen.getByLabelText('Amount in base units'), { target: { value: '9007199254740993' } })
  fireEvent.change(screen.getByLabelText('Token address'), { target: { value: '0x' + '3'.repeat(40) } })
  expect(screen.getByLabelText('Amount entry')).toHaveValue('base')
  expect(screen.getByLabelText('Amount in base units')).toHaveValue('')
  expect(screen.queryByText('9007199254740993')).not.toBeInTheDocument()
})
