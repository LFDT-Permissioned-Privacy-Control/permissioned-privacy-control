import '@testing-library/jest-dom/vitest'
import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { Link, MemoryRouter } from 'react-router-dom'
import { StrictMode } from 'react'
import { afterEach, expect, it, vi } from 'vitest'
import type { OperationScope } from './controller'
import { NativeCompliance } from './NativeCompliance'
import { NativeDisclosures } from './NativeDisclosures'
import { NativeDiagnostics } from './NativeDiagnostics'
import { protectedData, type NativeCase } from './operationsModels'

const org = '11111111-1111-4111-8111-111111111111',
  id = '22222222-2222-4222-8222-222222222222',
  actor = 'ops:p1:' + 'A'.repeat(43)
const now = Math.floor(Date.now() / 1000)
const currentCase: NativeCase = {
  caseId: id,
  ruleId: 'auditor-access',
  recipientActorId: actor,
  creatorActorId: actor,
  dataOrganizationId: org,
  scope: {
    targetActors: [actor],
    resources: ['activity_logs'],
    addresses: { mode: 'all-target-addresses', values: [] },
    dataTime: { start: now - 86400, end: now },
    level: 'redacted',
  },
  caseReference: 'AUDIT-12',
  purpose: 'Internal audit',
  legalBasis: 'Approved audit mandate',
  status: 'open',
  version: 1,
  createdAt: now,
  expiresAt: now + 3600,
  originalRuleDigest: 'sha256:' + 'a'.repeat(64),
  originalBundleDigest: 'sha256:' + 'b'.repeat(64),
}
function scope(role: 'admin' | 'readonly' | 'member' = 'admin') {
  const request = vi.fn(async (path: string, _options?: RequestInit): Promise<unknown> => {
    if (path.endsWith('/config'))
      return {
        sourceDigest: 'sha256:' + 'a'.repeat(64),
        data: {
          spec: {
            settings: {
              enabled: true,
              thresholdFiat: 1000,
              currency: 'USD',
              unknownPricePolicy: 'deny',
              enforcementMode: 'enforce',
            },
          },
          recordMaxSeconds: 3600,
          priceMaxAgeSeconds: 300,
        },
      }
    if (path.includes('/travel-rule-records')) return { records: [], nextCursor: '' }
    if (path === `/api/v1/disclosure/cases/${id}`) return currentCase
    if (path.startsWith('/api/v1/disclosure/cases?'))
      return { items: [currentCase], nextCursor: '', scanComplete: true }
    throw Error('Unexpected native request ' + path)
  })
  return {
    identity: { actor, expires: now + 300 },
    signal: new AbortController().signal,
    check: vi.fn(),
    dispose: vi.fn(),
    request,
    self: {
      actorId: actor,
      principalKind: 'human',
      sourceProfile: 'bank',
      sourceProfileDigest: 'sha256:' + 'a'.repeat(64),
      expiresAt: now + 300,
      organizations: [
        {
          id: org,
          slug: 'bank',
          name: 'Bank A',
          isOrgAdmin: role === 'admin',
          isOrgReadonlyAdmin: role === 'readonly',
        },
      ],
    },
  } as unknown as OperationScope & { request: typeof request }
}
afterEach(() => cleanup())
it('readonly administration sees approved settings and cannot create travel-rule records', async () => {
  const s = scope('readonly')
  render(
    <MemoryRouter>
      <NativeCompliance scope={s} />
    </MemoryRouter>,
  )
  expect(await screen.findByText('1000 USD')).toBeInTheDocument()
  expect(screen.getByRole('link', { name: 'Edit a local source proposal' })).toHaveAttribute(
    'href',
    `/admin/compliance/policy?org=${org}`,
  )
  await userEvent.click(screen.getByRole('button', { name: 'Travel rules' }))
  await screen.findByText('No records in this scope.')
  expect(
    screen.queryByRole('button', { name: 'Create travel-rule record' }),
  ).not.toBeInTheDocument()
  expect(
    s.request.mock.calls.every(([, options]) => !options?.method || options.method === 'GET'),
  ).toBe(true)
})

it('keeps a live organization selection in the policy-draft destination', async () => {
  const s = scope('admin'), other = '33333333-3333-4333-8333-333333333333'
  s.self.organizations.push({ ...s.self.organizations[0], id: other, name: 'Bank B', slug: 'bank-b' })
  render(<MemoryRouter initialEntries={['/admin/compliance?org=' + org]}><NativeCompliance scope={s} /></MemoryRouter>)
  await screen.findByText('1000 USD')
  await userEvent.selectOptions(screen.getByLabelText('Organization'), other)
  await waitFor(() => expect(s.request.mock.calls.some(([path]) => path.startsWith(`/api/v2/orgs/${other}/compliance/`))).toBe(true))
  expect(screen.getByRole('link', { name: 'Edit a local source proposal' })).toHaveAttribute('href', `/admin/compliance/policy?org=${other}`)
})

it.each(['authorized', 'unauthorized'] as const)('retires a pending disclosure list on history navigation to an %s scope', async target => {
  const s = scope('admin'), other = '33333333-3333-4333-8333-333333333333', unknown = '44444444-4444-4444-8444-444444444444'
  s.self.organizations.push({ ...s.self.organizations[0], id: other, name: 'Bank B', slug: 'bank-b' })
  let finish!: (value: unknown) => void, oldSignal: AbortSignal | undefined
  const pending = new Promise<unknown>(resolve => { finish = resolve })
  s.request.mockImplementation(async (path, options) => {
    const query = new URL(path, 'https://ops.test').searchParams
    if (query.get('role') !== 'data-org-admin') return { items: [], nextCursor: '', scanComplete: true }
    if (query.get('organizationId') === org) { oldSignal = options?.signal ?? undefined; return pending }
    if (query.get('organizationId') === other) return { items: [{ ...currentCase, caseId: other, dataOrganizationId: other, caseReference: 'CURRENT-B' }], nextCursor: '', scanComplete: true }
    throw Error('Unauthorized organization request')
  })
  render(<MemoryRouter initialEntries={['/admin/disclosure?org=' + org]}><StrictMode>
    <Link to={'/admin/disclosure?org=' + (target === 'authorized' ? other : unknown)}>History navigation</Link>
    <NativeDisclosures scope={s} />
  </StrictMode></MemoryRouter>)
  await userEvent.selectOptions(await screen.findByLabelText('Case view'), 'data-org-admin')
  await waitFor(() => expect(oldSignal).toBeDefined())
  await userEvent.click(screen.getByRole('link', { name: 'History navigation' }))
  await waitFor(() => expect(oldSignal!.aborted).toBe(true))
  if (target === 'authorized') await screen.findByText('CURRENT-B')
  else {
    expect(await screen.findByLabelText('Data organization')).toHaveValue('')
    expect(s.request.mock.calls.some(([path]) => path.includes(unknown))).toBe(false)
  }
  await act(async () => { finish({ items: [{ ...currentCase, caseReference: 'STALE-A' }], nextCursor: '', scanComplete: true }); await pending })
  expect(screen.queryByText('STALE-A')).not.toBeInTheDocument()
  expect(screen.getByLabelText('Data organization')).toHaveValue(target === 'authorized' ? other : '')
})
it('members do not issue organization compliance administration reads', () => {
  const s = scope('member')
  render(
    <MemoryRouter>
      <NativeCompliance scope={s} />
    </MemoryRouter>,
  )
  expect(screen.getByText(/no organization compliance administration role/)).toBeInTheDocument()
  expect(s.request).not.toHaveBeenCalled()
})
it('an uncertain travel-record create is not repeated and requires a list check', async () => {
  const s = scope(),
    original = s.request.getMockImplementation()!
  s.request.mockImplementation(async (path, options) => {
    if (options?.method === 'POST') throw Error('connection lost')
    return original(path, options)
  })
  render(
    <MemoryRouter>
      <NativeCompliance scope={s} />
    </MemoryRouter>,
  )
  await screen.findByText('1000 USD')
  await userEvent.click(screen.getByRole('button', { name: 'Travel rules' }))
  await screen.findByText('No records in this scope.')
  await userEvent.click(screen.getByRole('button', { name: 'Create travel-rule record' }))
  const dialog = screen.getByRole('dialog')
  fireEvent.change(within(dialog).getByLabelText('Amount entry'), { target: { value: 'base' } })
  for (const [label, value] of [
    ['Originator name', 'Bank operator'],
    ['Beneficiary name', 'Recipient'],
    ['Beneficiary wallet', '0x' + '1'.repeat(40)],
    ['Amount in base units', '9007199254740993123456789'],
  ])
    fireEvent.change(within(dialog).getByLabelText(label), { target: { value } })
  await userEvent.click(within(dialog).getByRole('button', { name: 'Create record' }))
  await within(dialog).findByText('connection lost')
  expect(within(dialog).getByRole('button', { name: 'Create record' })).toBeDisabled()
  expect(s.request.mock.calls.filter(([, o]) => o?.method === 'POST')).toHaveLength(1)
})
it('a disclosure recheck reuses the original whole scope and idempotency key without customer approval', async () => {
  const s = scope('member'),
    created: string[] = []
  s.request.mockImplementation(async (path, options) => {
    if (options?.method === 'POST') {
      created.push(String(options.body))
      if (created.length === 1) throw Error('outcome uncertain')
      const body = JSON.parse(String(options.body))
      return { ...currentCase, scope: body.scope, caseReference: body.caseReference }
    }
    return path === baseID() ? currentCase : { items: [], nextCursor: '', scanComplete: true }
  })
  render(
    <MemoryRouter>
      <NativeDisclosures scope={s} />
    </MemoryRouter>,
  )
  await screen.findByText('No records in this scope.')
  await userEvent.click(screen.getByRole('button', { name: 'Create case' }))
  const dialog = screen.getByRole('dialog')
  for (const [label, value] of [
    ['Standing rule ID', 'auditor-access'],
    ['Case reference', 'AUDIT-NEW'],
    ['Purpose', 'Audit'],
    ['Legal basis', 'Approved mandate'],
    ['Target OPS actor IDs', actor],
  ])
    fireEvent.change(within(dialog).getByLabelText(label), { target: { value } })
  await userEvent.click(within(dialog).getByRole('button', { name: 'Create case' }))
  await within(dialog).findByText('outcome uncertain')
  await userEvent.keyboard('{Escape}')
  await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument())
  await userEvent.click(screen.getByRole('button', { name: 'Create case' }))
  const reopened = screen.getByRole('dialog')
  expect(within(reopened).getByText('AUDIT-NEW')).toBeInTheDocument()
  await userEvent.click(within(reopened).getByRole('button', { name: 'Check same submitted case' }))
  await screen.findByText('Case: AUDIT-NEW')
  expect(created).toHaveLength(2)
  expect(created[0]).toBe(created[1])
  expect(JSON.parse(created[0]).scope.addresses.mode).toBe('all-target-addresses')
  expect(screen.queryByRole('button', { name: /approve/i })).not.toBeInTheDocument()
  expect(screen.getByRole('dialog', { name: 'Disclosure case details' })).toBeInTheDocument()
  await waitFor(() => expect(screen.getByRole('heading', { name: 'Disclosure case details' })).toHaveFocus())
  await userEvent.click(within(screen.getByRole('dialog')).getByRole('button', { name: 'Close', exact: true }))
  await userEvent.click(screen.getByRole('button', { name: 'Create case' }))
  const next = screen.getByRole('dialog')
  expect(within(next).getByLabelText('Case reference')).toHaveValue('')
  expect(within(next).getByLabelText('Case reference')).toBeEnabled()
  expect(within(next).queryByRole('button', { name: 'Check same submitted case' })).not.toBeInTheDocument()
})
function baseID() {
  return '/api/v1/disclosure/cases/' + id
}
it('opens case details in the V1 dialog pattern and returns focus to the unchanged case list', async () => {
  const s = scope()
  render(<MemoryRouter><NativeDisclosures scope={s} /></MemoryRouter>)
  const opener = await screen.findByRole('button', { name: 'Open case' })
  await userEvent.click(opener)
  const dialog = await screen.findByRole('dialog', { name: 'Disclosure case details' })
  expect(within(dialog).getByRole('heading', { name: 'Case: AUDIT-12' })).toBeInTheDocument()
  await waitFor(() => expect(within(dialog).getByRole('heading', { name: 'Disclosure case details' })).toHaveFocus())
  expect(screen.queryByRole('heading', { name: 'Disclosure cases' })).not.toBeInTheDocument()
  await userEvent.click(within(dialog).getByRole('button', { name: 'Close', exact: true }))
  await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument())
  expect(screen.getByRole('heading', { name: 'Disclosure cases' })).toBeInTheDocument()
  await waitFor(() => expect(opener).toHaveFocus())
  expect(s.request.mock.calls.filter(([path]) => path.includes('/cases?'))).toHaveLength(1)
  await userEvent.click(opener)
  expect(await screen.findByRole('dialog', { name: 'Disclosure case details' })).toBeInTheDocument()
})
it('leaves a failed case open request visible in the list and allows retry', async () => {
  const s = scope(), original = s.request.getMockImplementation()!
  let fail = true
  s.request.mockImplementation(async (path, options) => {
    if (path === baseID() && fail) throw Error('Case could not be loaded. Try again.')
    return original(path, options)
  })
  render(<MemoryRouter><NativeDisclosures scope={s} /></MemoryRouter>)
  const opener = await screen.findByRole('button', { name: 'Open case' })
  await userEvent.click(opener)
  expect(await screen.findByRole('alert')).toHaveTextContent('Case could not be loaded. Try again.')
  await waitFor(() => expect(screen.getByRole('alert').parentElement).toHaveFocus())
  expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
  expect(opener).toBeEnabled()
  fail = false
  await userEvent.click(opener)
  expect(await screen.findByRole('dialog', { name: 'Disclosure case details' })).toBeInTheDocument()
  expect(screen.queryByRole('alert')).not.toBeInTheDocument()
})
it('shows expired stored-open cases honestly in both list and detail while retaining revoked status', async () => {
  const s = scope(), expired = { ...currentCase, caseReference: 'EXPIRED-1', createdAt: now - 600, expiresAt: now - 1 }
  const revoked = { ...expired, caseId: '33333333-3333-4333-8333-333333333333', caseReference: 'REVOKED-1', status: 'revoked' }
  s.request.mockImplementation(async path => path === baseID() ? expired : { items: [expired, revoked], nextCursor: '', scanComplete: true })
  render(<MemoryRouter><NativeDisclosures scope={s} /></MemoryRouter>)
  const expiredRow = within((await screen.findByText('EXPIRED-1')).closest('tr')!)
  expect(expiredRow.getByText('Expired')).toBeInTheDocument()
  expect(expiredRow.queryByText('Open')).not.toBeInTheDocument()
  expect(within(screen.getByText('REVOKED-1').closest('tr')!).getByText('Revoked')).toBeInTheDocument()
  await userEvent.click(expiredRow.getByRole('button', { name: 'Open case' }))
  await screen.findByRole('heading', { name: 'Case: EXPIRED-1' })
  expect(screen.getAllByText('Expired')).toHaveLength(2)
  expect(screen.getByRole('button', { name: 'Read permitted data' })).toBeDisabled()
  expect(expired.status).toBe('open')
})
it('shows the recorded resource and view in the case audit without inventing missing legacy fields', async () => {
  const s = scope(), original = s.request.getMockImplementation()!
  s.request.mockImplementation(async (path, options) => path === baseID() + '/audit?limit=25'
    ? { items: [
      { eventId: '33333333-3333-4333-8333-333333333333', time: now - 1, action: 'exposure_prepared', outcome: 'allowed', count: 2, resource: 'activity_logs', view: 'list', actor, ruleDigest: currentCase.originalRuleDigest, bundleDigest: currentCase.originalBundleDigest },
      { eventId: '44444444-4444-4444-8444-444444444444', time: now - 2, action: 'metadata_read', outcome: 'allowed', count: 1, ruleDigest: currentCase.originalRuleDigest, bundleDigest: currentCase.originalBundleDigest },
    ], nextCursor: '', scanComplete: true }
    : original(path, options))
  render(<MemoryRouter><NativeDisclosures scope={s} /></MemoryRouter>)
  await userEvent.click(await screen.findByRole('button', { name: 'Open case' }))
  await userEvent.click(await screen.findByRole('button', { name: 'Audit trail' }))
  const exposure = within((await screen.findByText('exposure_prepared')).closest('tr')!)
  expect(exposure.getByText('Access logs')).toBeInTheDocument()
  expect(exposure.getByText('List')).toBeInTheDocument()
  const legacy = within(screen.getByText('metadata_read').closest('tr')!)
  expect(legacy.getAllByText('Not recorded')).toHaveLength(2)
  expect(exposure.queryByText('Not recorded')).not.toBeInTheDocument()
  expect(screen.queryByText('queryDigest')).not.toBeInTheDocument()
  expect(s.request).toHaveBeenCalledWith(baseID() + '/audit?limit=25', expect.objectContaining({ signal: expect.any(AbortSignal) }))
})
it('case revocation collects its reason inside the actual confirmation dialog', async () => {
  const s = scope()
  s.request.mockImplementation(async (path, options) => {
    if (options?.method === 'POST') return { caseId: id, status: 'revoked', version: 2 }
    return path === baseID()
      ? currentCase
      : { items: [currentCase], nextCursor: '', scanComplete: true }
  })
  render(
    <MemoryRouter>
      <NativeDisclosures scope={s} />
    </MemoryRouter>,
  )
  await userEvent.click(await screen.findByRole('button', { name: 'Open case' }))
  await userEvent.click(await screen.findByRole('button', { name: 'Revoke case' }))
  const dialog = screen.getByRole('dialog')
  fireEvent.change(within(dialog).getByLabelText('Reason for revocation'), {
    target: { value: 'Audit completed' },
  })
  await userEvent.click(within(dialog).getByRole('button', { name: 'Revoke case' }))
  await waitFor(() =>
    expect(s.request).toHaveBeenCalledWith(baseID() + '/revoke', expect.objectContaining({
      method: 'POST',
      body: JSON.stringify({ reason: 'Audit completed' }),
      signal: expect.any(AbortSignal),
    })),
  )
})
it('closing a nested revocation dialog keeps its parent case open', async () => {
  const s = scope()
  render(<MemoryRouter><NativeDisclosures scope={s} /></MemoryRouter>)
  await userEvent.click(await screen.findByRole('button', { name: 'Open case' }))
  await userEvent.click(await screen.findByRole('button', { name: 'Revoke case' }))
  const confirmation = screen.getByRole('dialog', { name: 'Revoke this disclosure case?' })
  await userEvent.click(within(confirmation).getByRole('button', { name: 'Cancel', exact: true }))
  expect(screen.getByRole('dialog', { name: 'Disclosure case details' })).toBeInTheDocument()
  expect(screen.getByRole('heading', { name: 'Case: AUDIT-12' })).toBeInTheDocument()
  expect(s.request.mock.calls.some(([, options]) => options?.method === 'POST')).toBe(false)
})
it('retires a pending case revocation callback when its view is replaced', async () => {
  const s = scope(), original = s.request.getMockImplementation()!
  let finish!: () => void
  const pending = new Promise<void>(resolve => { finish = resolve })
  s.request.mockImplementation(async (path, options) => {
    if (path.endsWith('/revoke')) { await pending; return { caseId: id, status: 'revoked', version: 2 } }
    return original(path, options)
  })
  const view = render(<MemoryRouter><NativeDisclosures key="first" scope={s} /></MemoryRouter>)
  await userEvent.click(await screen.findByRole('button', { name: 'Open case' }))
  await userEvent.click(await screen.findByRole('button', { name: 'Revoke case' }))
  const confirmation = screen.getByRole('dialog', { name: 'Revoke this disclosure case?' })
  fireEvent.change(within(confirmation).getByLabelText('Reason for revocation'), { target: { value: 'Complete the old case' } })
  await userEvent.click(within(confirmation).getByRole('button', { name: 'Revoke case', exact: true }))
  await waitFor(() => expect(s.request.mock.calls.some(([path]) => path.endsWith('/revoke'))).toBe(true))
  view.rerender(<MemoryRouter><NativeDisclosures key="replacement" scope={s} /></MemoryRouter>)
  await userEvent.click(await screen.findByRole('button', { name: 'Open case' }))
  await screen.findByRole('dialog', { name: 'Disclosure case details' })
  await act(async () => { finish(); await pending })
  expect(screen.getByRole('dialog', { name: 'Disclosure case details' })).toBeInTheDocument()
  expect(s.request.mock.calls.filter(([path]) => path.includes('/cases?'))).toHaveLength(2)
})
it('redacted access-log responses reject unexpected identity fields', () => {
  const response = {
    v: 1,
    readId: id,
    caseId: id,
    resource: 'activity_logs',
    view: 'list',
    level: 'redacted',
    dataTime: currentCase.scope.dataTime,
    effectiveUntil: now + 60,
    coverage: { status: 'COMPLETE_AT_CUT', populations: ['RECORDED_REQUEST_COMPLETIONS'] },
    result: {
      items: [{ recordId: id, method: 'eth_call', statusCode: 200, time: now, actorId: actor }],
      nextCursor: null,
    },
  }
  expect(() => protectedData(response, currentCase, 'activity_logs')).toThrow('private log fields')
  delete (response.result.items[0] as { actorId?: string }).actorId
  expect(protectedData(response, currentCase, 'activity_logs').caseId).toBe(id)
})
it('diagnostic inputs are frozen while pending and changed parameters clear the previous result', async () => {
  const s = scope()
  let release!: (value: unknown) => void
  s.request.mockImplementation(async (path) =>
    path.startsWith('/health/')
      ? { ready: true, status: 204 }
      : new Promise((resolve) => (release = resolve)),
  )
  render(
    <MemoryRouter>
      <NativeDiagnostics scope={s} />
    </MemoryRouter>,
  )
  await waitFor(() =>
    expect(screen.getByRole('button', { name: 'Send test request' })).toBeEnabled(),
  )
  fireEvent.change(screen.getByLabelText('Request mode'), { target: { value: 'advanced' } })
  await userEvent.click(screen.getByRole('button', { name: 'Send test request' }))
  expect(screen.getByLabelText('Organization')).toBeDisabled()
  expect(screen.getByLabelText('RPC method')).toBeDisabled()
  expect(screen.getByLabelText('JSON parameters')).toBeDisabled()
  release({ jsonrpc: '2.0', id: 'test', result: 'old-result-marker' })
  await screen.findByText(/old-result-marker/)
  fireEvent.change(screen.getByLabelText('JSON parameters'), { target: { value: '["new-value"]' } })
  expect(screen.queryByText(/old-result-marker/)).not.toBeInTheDocument()
})
it('a disclosure dialog cannot close while its original create request is pending', async () => {
  const s = scope('member')
  let reject!: (error: Error) => void
  s.request.mockImplementation(async (_path, options) =>
    options?.method === 'POST'
      ? new Promise((_resolve, fail) => (reject = fail))
      : { items: [], nextCursor: '', scanComplete: true },
  )
  render(
    <MemoryRouter>
      <NativeDisclosures scope={s} />
    </MemoryRouter>,
  )
  await screen.findByText('No records in this scope.')
  await userEvent.click(screen.getByRole('button', { name: 'Create case' }))
  const dialog = screen.getByRole('dialog')
  for (const [label, value] of [
    ['Standing rule ID', 'auditor-access'],
    ['Case reference', 'AUDIT-PENDING'],
    ['Purpose', 'Audit'],
    ['Legal basis', 'Approved mandate'],
    ['Target OPS actor IDs', actor],
  ])
    fireEvent.change(within(dialog).getByLabelText(label), { target: { value } })
  await userEvent.click(within(dialog).getByRole('button', { name: 'Create case' }))
  await userEvent.keyboard('{Escape}')
  expect(screen.getByRole('dialog')).toBeInTheDocument()
  reject(Error('outcome uncertain'))
  await within(dialog).findByText('outcome uncertain')
})
