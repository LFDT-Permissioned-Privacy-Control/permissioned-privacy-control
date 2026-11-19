import '@testing-library/jest-dom/vitest'
import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { MemoryRouter } from 'react-router-dom'
import { NativeAdminApp } from './AdminApp'
import { Controller, State } from './controller'
import { WalletController } from './wallet'
vi.mock('./NativeOperationsPages', () => ({ NativeOperationsPage: () => <p>Operational page fixture</p> }))

const org = '11111111-1111-1111-1111-111111111111', group = '22222222-2222-2222-2222-222222222222'
const selected: State = { phase: 'selected', busy: false, flow: null, pending: null, candidate: null, error: null,
  profiles: [{ id: 'bank', provider: 'privado', principalKind: 'human' }],
  self: { actorId: 'ops:p1:' + 'A'.repeat(43), principalKind: 'human', sourceProfile: 'bank', sourceProfileDigest: 'sha256:' + 'a'.repeat(64),
    expiresAt: Math.floor(Date.now() / 1000) + 300, organizations: [] } }
function harness(path = '/admin/rbac/organizations') {
  let state = { ...selected }, revision = 0
  const subscribers = new Set<() => void>()
  const notify = () => subscribers.forEach(fn => fn())
  const mock = {
    snapshot: () => state,
    subscribe: (fn: () => void) => { subscribers.add(fn); return () => { subscribers.delete(fn) } },
    get scopeRevision() { return revision },
    ownsScope: (scope: number, actor: string) => scope === revision && state.phase === 'selected' && state.self?.actorId === actor,
    logout: vi.fn(async () => { revision++; state = { ...state, phase: 'anonymous', self: null }; notify() }),
    refresh: vi.fn(), forgetAppChoices: vi.fn(), downloadOwnWalletToken: vi.fn(),
    wallet: new WalletController(async () => { throw Error('no operation requested') }),
  }
  render(<MemoryRouter initialEntries={[path]}><NativeAdminApp controller={mock as unknown as Controller} /></MemoryRouter>)
  return { mock, replace: (next: State) => act(() => { revision++; state = next; notify() }) }
}
function jsonFile(name: string, value: unknown, read?: () => Promise<string>) {
  const raw = JSON.stringify(value), file = new File([raw], name.split('/').pop()!, { type: 'application/json' })
  Object.defineProperty(file, 'webkitRelativePath', { value: 'source/' + name })
  Object.defineProperty(file, 'text', { configurable: true, value: read ?? (() => Promise.resolve(raw)) })
  return { file, raw }
}
function packageFiles(hold?: (raw: string) => Promise<string>) {
  const draft = jsonFile('draft.json', { apiVersion: 'ops.policy-draft/v1alpha1', kind: 'PolicyDraft', environment: 'local', chainId: '31337',
    evaluatorVersion: 'policycore/native-v1alpha4', profile: 'catalog-runtime-creation-observed/v1', sourceRevision: 'worktree-revision',
    organizations: [{ id: org, slug: 'draft-bank', name: 'Imported Bank' }], documents: [{ kind: 'groups', organizationId: org, path: 'groups.json' }] })
  if (hold) Object.defineProperty(draft.file, 'text', { value: () => hold(draft.raw) })
  const groups = jsonFile('groups.json', { apiVersion: 'ops.policy-document/v1alpha1', kind: 'groups', organizationId: org,
    spec: { groups: [{ id: group, slug: 'payments', name: 'Payments team', description: 'Configured payments operators',
      isOrgAdmin: false, isOrgReadonlyAdmin: false, allowedMethods: ['eth_sendRawTransaction'], claims: ['bank-payments'], verboseErrors: false }] } })
  return [draft.file, groups.file]
}
async function importFiles(files = packageFiles()) {
  fireEvent.change(screen.getByLabelText('Policy source folder'), { target: { files } })
  await screen.findByTestId('workspace-source')
}
afterEach(() => { cleanup(); vi.unstubAllGlobals() })

describe('native account with the established Admin presentation', () => {
  it('shows real imported organization/group permissions using the original shell, separate from live roles', async () => {
    const request = vi.fn(); vi.stubGlobal('fetch', request)
    harness()
    expect(screen.getByTestId('admin-header')).toHaveTextContent('Open Privacy Suite')
    expect(screen.getByTestId('nav-rbac')).toBeEnabled()
    expect(screen.getByRole('tab', { name: 'Disclosure' })).toBeEnabled()
    expect(screen.queryByText(/UI preview:/)).not.toBeInTheDocument()
    await importFiles()
    expect(screen.getByTestId('workspace-source')).toHaveTextContent('worktree-revision')
    expect(within(screen.getByRole('table')).getByText('Imported Bank')).toBeInTheDocument()
    expect(screen.getByText('No organizations are assigned to this identity by the current approved rules.')).toBeInTheDocument()
    expect(screen.getByText(/Imported source files are a local proposal/)).toBeInTheDocument()
    await userEvent.click(within(screen.getByRole('table')).getByText('Imported Bank'))
    expect(await screen.findByTestId('group-card')).toHaveTextContent('Payments team')
    await userEvent.click(screen.getByTitle('View declared permissions'))
    expect(await screen.findByRole('dialog')).toHaveTextContent('eth_sendRawTransaction')
    expect(screen.getByRole('dialog')).toHaveTextContent('bank-payments')
    expect(request).not.toHaveBeenCalled()
    expect(localStorage.length).toBe(0); expect(sessionStorage.length).toBe(0)
  })
  it('authors a general local organization using the original form and requires export or explicit discard before closing it', async () => {
    const request = vi.fn(); vi.stubGlobal('fetch', request)
    harness(); await importFiles(); await userEvent.click(screen.getByRole('button', { name: 'Edit local proposal' }))
    await userEvent.click(screen.getByRole('button', { name: 'New organization' }))
    const form = screen.getByRole('dialog')
    await userEvent.type(within(form).getByLabelText('Name'), 'New payment bank')
    await userEvent.click(within(form).getByRole('button', { name: 'Save organization draft' }))
    expect(within(screen.getByRole('table')).getByText('New payment bank')).toBeInTheDocument()
    expect(screen.getByText('Changed local draft')).toBeInTheDocument()
    expect(request).not.toHaveBeenCalled()
    await userEvent.click(screen.getByRole('button', { name: 'Close source' }))
    expect(screen.getByRole('dialog')).toHaveTextContent('Keep your changed source')
    await userEvent.click(screen.getByRole('button', { name: 'Cancel' }))
    expect(screen.getByTestId('workspace-source')).toBeInTheDocument()
    await userEvent.click(screen.getByRole('button', { name: 'Close source' })); await userEvent.click(screen.getByRole('button', { name: 'Discard and continue' }))
    expect(screen.queryByTestId('workspace-source')).not.toBeInTheDocument()
  })
  it('clears confidential source on context replacement and requires an explicit fresh import', async () => {
    const page = harness(); await importFiles()
    page.replace({ ...selected, phase: 'context-changed', self: null })
    expect(screen.queryByTestId('workspace-source')).not.toBeInTheDocument()
    page.replace({ ...selected, self: { ...selected.self!, actorId: 'ops:p1:' + 'B'.repeat(43) } })
    expect(screen.queryByTestId('workspace-source')).not.toBeInTheDocument()
    expect(screen.getByText('Open your policy source to view organizations and groups')).toBeInTheDocument()
  })
  it('does not publish a delayed file read after account replacement', async () => {
    const page = harness()
    let release!: () => void
    const waiting = new Promise<void>(resolve => { release = resolve })
    fireEvent.change(screen.getByLabelText('Policy source folder'), { target: { files: packageFiles(async raw => { await waiting; return raw }) } })
    page.replace({ ...selected, self: { ...selected.self!, actorId: 'ops:p1:' + 'B'.repeat(43) } })
    await act(async () => { release(); await waiting })
    await waitFor(() => expect(screen.getByText('Open your policy source to view organizations and groups')).toBeInTheDocument())
    expect(screen.queryByText('Imported Bank')).not.toBeInTheDocument()
  })
  it('keeps the ordinary own-account/wallet page available without organization admin roles', () => {
    harness('/admin/account')
    expect(screen.getByTestId('account-identity')).toHaveTextContent(selected.self!.actorId)
    expect(screen.getByRole('button', { name: 'Refresh session' })).toBeEnabled()
    expect(screen.getByRole('heading', { name: 'Linked Addresses' })).toBeInTheDocument()
    expect(screen.getByTestId('account-organizations')).toHaveTextContent('No organizations')
    expect(screen.queryByText('KYC Status')).not.toBeInTheDocument()
    expect(screen.queryByText('Token Issued')).not.toBeInTheDocument()
    expect(screen.queryByText('Forget remembered app choices')).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /Cancel/ })).not.toBeInTheDocument()
    expect(screen.getByTestId('account-session').querySelector('time')).toHaveAttribute('datetime', new Date(selected.self!.expiresAt * 1000).toISOString())
  })
  it('does not render a source workspace at unsupported routes', () => {
    harness('/admin/users')
    expect(screen.queryByTestId('rbac-manager')).not.toBeInTheDocument()
  })
  it.each(['/admin/rbac/compliance-source', '/admin/rbac/disclosure-source'])('keeps %s in the local authoring workspace', path => {
    harness(path)
    expect(screen.getByTestId('rbac-manager')).toBeInTheDocument()
    expect(screen.queryByText('Operational page fixture')).not.toBeInTheDocument()
  })
  it('keeps an unsupported document version available as raw source and disables semantic forms', async () => {
    harness()
    const files = packageFiles(), groups = await files[1].text()
    Object.defineProperty(files[1], 'text', { value: async () => groups.replace('ops.policy-document/v1alpha1', 'ops.policy-document/v999') })
    // v999 and v1alpha1 differ in length; supply a file whose exact byte size
    // agrees with its content, as a real selected source file does.
    files[1] = jsonFile('groups.json', JSON.parse(groups.replace('ops.policy-document/v1alpha1', 'ops.policy-document/v999'))).file
    await importFiles(files)
    expect(screen.getByText(/Browser forms are disabled/)).toBeInTheDocument()
    await userEvent.click(screen.getByRole('button', { name: 'Edit local proposal' }))
    expect(screen.queryByRole('button', { name: 'New organization' })).not.toBeInTheDocument()
    await userEvent.click(screen.getByRole('button', { name: 'Open source for repair' }))
    expect(screen.getByLabelText('Proposed source')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Export complete source package' })).toBeEnabled()
  })
  it('retains typed raw text through file switches and includes it in export and unsaved-close handling', async () => {
    let blob: Blob | undefined
    vi.stubGlobal('URL', class extends URL { static createObjectURL(value: Blob) { blob = value; return 'blob:source-package' }; static revokeObjectURL() {} })
    const click = vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => {})
    try {
      harness(); await importFiles(); await userEvent.click(screen.getByRole('button', { name: 'Edit local proposal' })); await userEvent.click(screen.getByRole('tab', { name: 'Configuration' }))
      const raw = String((screen.getByLabelText('Proposed source') as HTMLTextAreaElement).value).slice(0, -1) + '\n unfinished proposal'
      fireEvent.change(screen.getByLabelText('Proposed source'), { target: { value: raw } })
      expect(screen.getByText('Changed local draft')).toBeInTheDocument()
      await userEvent.click(screen.getByRole('button', { name: /^groups\.json/ })); await userEvent.click(screen.getByRole('button', { name: /^draft\.json/ }))
      expect(screen.getByLabelText('Proposed source')).toHaveValue(raw)
      await userEvent.click(screen.getByRole('button', { name: 'Export complete source package' }))
      const saved = await new Promise<string>((resolve, reject) => { const reader = new FileReader(); reader.onload = () => resolve(String(reader.result)); reader.onerror = reject; reader.readAsText(blob!) })
      expect(atob(JSON.parse(saved).roots[0].files.find((f: { path: string }) => f.path === 'draft.json').dataBase64)).toBe(raw)
      await userEvent.click(screen.getByRole('button', { name: 'Close source' }))
      expect(screen.getByRole('dialog')).toHaveTextContent('Keep your changed source')
    } finally { click.mockRestore() }
  })
  it('opens execution candidate source in the same tracked raw editor', async () => {
    const files = packageFiles(), draft = JSON.parse(await files[0].text())
    draft.documents.push({ kind: 'contract-registry', organizationId: org, path: 'registry.json' }, { kind: 'execution-rules', organizationId: org, path: 'execution.json' })
    files[0] = jsonFile('draft.json', draft).file
    files.push(jsonFile('registry.json', { apiVersion: 'ops.policy-document/v1alpha1', kind: 'contract-registry', organizationId: org, spec: { contracts: [] } }).file)
    files.push(jsonFile('execution.json', { apiVersion: 'ops.policy-document/v1alpha1', kind: 'execution-rules', organizationId: org, spec: { policy: { apiVersion: 'privacy.gateway.fm/v1alpha4', kind: 'ContractExecutionPolicy', org, nestedCalls: 'requireOwnRule', bindings: [] } } }).file)
    harness(); await importFiles(files); await userEvent.click(screen.getByRole('button', { name: 'Edit local proposal' }))
    await userEvent.click(within(screen.getByRole('table')).getByText('Imported Bank'))
    await userEvent.click(screen.getByRole('tab', { name: 'Execution Policy' })); await userEvent.click(screen.getByRole('button', { name: 'Candidate source' }))
    const editor = screen.getByLabelText('Proposed source') as HTMLTextAreaElement
    expect(editor.value).toContain('"kind":"execution-rules"')
    const raw = editor.value + '\n incomplete candidate'
    fireEvent.change(editor, { target: { value: raw } })
    await userEvent.click(screen.getByRole('tab', { name: 'Organizations' })); await userEvent.click(screen.getByRole('button', { name: 'Open source for repair' }))
    expect(screen.getByLabelText('Proposed source')).toHaveValue(raw)
  })
  it.each(['Sign Out', 'Switch account', 'Refresh session', 'Download wallet token'])('guards Account-page %s after a typed source edit', async action => {
    const page = harness(); await importFiles(); await userEvent.click(screen.getByRole('button', { name: 'Edit local proposal' })); await userEvent.click(screen.getByRole('tab', { name: 'Configuration' }))
    const editor = screen.getByLabelText('Proposed source') as HTMLTextAreaElement
    fireEvent.change(editor, { target: { value: editor.value + '\n ' } })
    await userEvent.click(screen.getByTestId('account-dropdown-trigger')); await userEvent.click(screen.getByRole('menuitem', { name: 'Account' }))
    const departure = new Event('beforeunload', { cancelable: true }); window.dispatchEvent(departure)
    expect(departure.defaultPrevented).toBe(true)
    await userEvent.click(screen.getByRole('button', { name: action }))
    expect(screen.getByRole('dialog')).toHaveTextContent('Keep your changed source')
    expect(page.mock.logout).not.toHaveBeenCalled()
    expect(page.mock.refresh).not.toHaveBeenCalled(); expect(page.mock.downloadOwnWalletToken).not.toHaveBeenCalled()
    await userEvent.click(screen.getByRole('button', { name: 'Cancel' }))
    await userEvent.click(screen.getByTestId('account-dropdown-trigger')); await userEvent.click(screen.getByRole('menuitem', { name: 'Configuration workspace' }))
    expect(screen.getByText('Changed local draft')).toBeInTheDocument()
  })
})
