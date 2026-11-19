import '@testing-library/jest-dom/vitest'
import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'
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
    `/admin/rbac/compliance-source?org=${org}`,
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
  await userEvent.click(screen.getByRole('button', { name: 'Create case' }))
  const next = screen.getByRole('dialog')
  expect(within(next).getByLabelText('Case reference')).toHaveValue('')
  expect(within(next).getByLabelText('Case reference')).toBeEnabled()
  expect(within(next).queryByRole('button', { name: 'Check same submitted case' })).not.toBeInTheDocument()
})
function baseID() {
  return '/api/v1/disclosure/cases/' + id
}
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
    expect(s.request).toHaveBeenCalledWith(baseID() + '/revoke', {
      method: 'POST',
      body: JSON.stringify({ reason: 'Audit completed' }),
    }),
  )
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
