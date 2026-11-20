import '@testing-library/jest-dom/vitest'
import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { MemoryRouter, useNavigate } from 'react-router-dom'
import { NativeAdminApp } from './AdminApp'
import { Controller, State } from './controller'
import { WalletController } from './wallet'
import { CONTEXT_KEY } from '../auth/context'
import { activeMulti, deniedMulti, writeMultiMarker, type MultiMarker } from '../auth/multiContext'
const protectedRenders = vi.hoisted(() => [] as boolean[])
vi.mock('./NativeOperationsPages', () => ({ NativeOperationsPage: ({ state }: { state: State }) => {
  protectedRenders.push(state.self!.organizations.some(org => org.isOrgAdmin === true || org.isOrgReadonlyAdmin === true))
  return <p>Operational page fixture</p>
} }))

const org = '11111111-1111-1111-1111-111111111111', group = '22222222-2222-2222-2222-222222222222'
const family = '33333333-3333-4333-8333-333333333333', requestID = '44444444-4444-4444-8444-444444444444'
const selected: State = { phase: 'selected', busy: false, flow: null, pending: null, candidate: null, error: null,
  profiles: [{ id: 'bank', provider: 'privado', principalKind: 'human' }],
  self: { actorId: 'ops:p1:' + 'A'.repeat(43), principalKind: 'human', sourceProfile: 'bank', sourceProfileDigest: 'sha256:' + 'a'.repeat(64),
    expiresAt: Math.floor(Date.now() / 1000) + 300, organizations: [{ id: org, slug: 'live-bank', name: 'Serving Bank', isOrgAdmin: true, isOrgReadonlyAdmin: false }] } }
const member: State = { ...selected, self: { ...selected.self!, organizations: [{ ...selected.self!.organizations[0], isOrgAdmin: false, isOrgReadonlyAdmin: false }] } }
function harness(path = '/admin/rbac/organizations', initial = selected) {
  let state = { ...initial }, revision = 0
  let navigate: ReturnType<typeof useNavigate>
  function NavigationProbe() { navigate = useNavigate(); return null }
  localStorage.clear(); sessionStorage.clear()
  function markerFor(next: State): MultiMarker {
    if (next.pending?.status === 'proof_required') {
      const proof = next.pending
      return {...deniedMulti(proof), pendingFlow: {kind: 'privado', mode: 'renew', requestId: proof.requestId, sourceProfile: proof.sourceProfile, expectedActorId: proof.actorId, expectedSessionId: proof.browserSessionId, expiresAt: proof.expiresAt}}
    }
    return next.self ? activeMulti({actorId: next.self.actorId, sourceProfile: next.self.sourceProfile, browserSessionId: family, provider: 'privado'}) : deniedMulti()
  }
  writeMultiMarker(markerFor(state))
  const subscribers = new Set<() => void>()
  const notify = () => subscribers.forEach(fn => fn())
  const mock = {
    snapshot: () => state,
    subscribe: (fn: () => void) => { subscribers.add(fn); return () => { subscribers.delete(fn) } },
    get scopeRevision() { return revision },
    ownsScope: vi.fn((scope: number, actor: string) => scope === revision && state.phase === 'selected' && !state.pending && !state.flow && state.self?.actorId === actor && state.self.expiresAt * 1000 > Date.now()),
    logout: vi.fn(async () => { revision++; state = { ...state, phase: 'anonymous', self: null }; notify() }),
    refresh: vi.fn(), forgetAppChoices: vi.fn(), downloadOwnWalletToken: vi.fn(), copyOwnRPCCredential: vi.fn(async () => true),
    wallet: new WalletController(async () => { throw Error('no operation requested') }),
  }
  render(<MemoryRouter initialEntries={[path]}><NavigationProbe /><NativeAdminApp controller={mock as unknown as Controller} /></MemoryRouter>)
  return { mock,
    navigate: (path: string) => act(() => navigate(path)),
    replace: (next: State, marker?: MultiMarker) => act(() => { revision++; state = next; writeMultiMarker(marker ?? markerFor(next)); notify() }),
    transition: (next: State, marker?: MultiMarker) => act(() => { state = next; writeMultiMarker(marker ?? markerFor(next)); notify() }),
  }
}
function proofRequired(): State {
  return {...selected, phase: 'proof-pending', self: null, pending: {status: 'proof_required', provider: 'privado', sourceProfile: 'bank', actorId: selected.self!.actorId, browserSessionId: family, principalKind: 'human', mode: 'renew', requestId: requestID, requestUri: location.origin + '/api/v2/auth/privado/requests/' + requestID, expiresAt: Math.floor(Date.now() / 1000) + 120}}
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
async function fullPackageFiles() {
  const files = packageFiles(), draft = JSON.parse(await files[0].text())
  draft.documents.push({ kind: 'contract-registry', organizationId: org, path: 'registry.json' }, { kind: 'execution-rules', organizationId: org, path: 'execution.json' })
  files[0] = jsonFile('draft.json', draft).file
  files.push(jsonFile('registry.json', { apiVersion: 'ops.policy-document/v1alpha1', kind: 'contract-registry', organizationId: org, spec: { contracts: [{ id: '55555555-5555-4555-8555-555555555555', name: 'Payments', address: '0x' + '1'.repeat(40), abi: [{ type: 'event', name: 'Transfer', inputs: [{ name: 'from', type: 'address', indexed: true }] }], allowVisibleToUnlock: false, eventsAllowDynamicPayload: false, readGrants: [{ id: '66666666-6666-4666-8666-666666666666', groupId: group, eventRules: { mode: 'none', rules: [] } }] }] } }).file)
  files.push(jsonFile('execution.json', { apiVersion: 'ops.policy-document/v1alpha1', kind: 'execution-rules', organizationId: org, spec: { policy: { apiVersion: 'privacy.gateway.fm/v1alpha4', kind: 'ContractExecutionPolicy', org, nestedCalls: 'requireOwnRule', bindings: [{ group, allow: [] }] } } }).file)
  return files
}
async function importFiles(files = packageFiles()) {
  fireEvent.change(screen.getByLabelText('Policy source folder'), { target: { files } })
  await screen.findByTestId('workspace-source')
}
async function expectEmptySource() {
  await waitFor(() => expect(screen.queryByTestId('workspace-source')).not.toBeInTheDocument())
  expect(screen.queryByLabelText('Proposed source')).not.toBeInTheDocument()
  expect(screen.getByRole('button', { name: 'Import source folder' })).toBeEnabled()
}
async function selectRBACPage(name: string) {
  if (!screen.queryByTestId('rbac-tabs')) await userEvent.click(screen.getByRole('tab', { name: 'RBAC', exact: true }))
  await userEvent.click(within(screen.getByTestId('rbac-tabs')).getByRole('tab', { name, exact: true }))
}
async function editSource() {
  await importFiles()
  await userEvent.click(screen.getByRole('button', {name: 'Edit local proposal'}))
  await userEvent.click(screen.getByRole('button', {name: 'Review & export'}))
  const editor = screen.getByLabelText('Proposed source') as HTMLTextAreaElement
  const raw = editor.value + '\n{"unfinished":' // preserve even invalid work-in-progress bytes
  fireEvent.change(editor, {target: {value: raw}})
  return raw
}
afterEach(() => { cleanup(); vi.unstubAllGlobals(); vi.restoreAllMocks(); localStorage.clear(); sessionStorage.clear(); protectedRenders.length = 0 })

describe('native account with the established Admin presentation', () => {
  it.each([false, true])('retains newer %s-saved proposal work when a slow import finishes', async saved => {
    harness(); await importFiles()
    await userEvent.click(screen.getByRole('button', { name: 'Edit local proposal' }))
    await userEvent.click(screen.getByRole('button', { name: 'New organization' }))
    let finish!: () => void
    const replacement = packageFiles(raw => new Promise(resolve => { finish = () => resolve(raw) }))
    fireEvent.change(screen.getByLabelText('Policy source folder'), { target: { files: replacement } })
    await waitFor(() => expect(finish).toBeTypeOf('function'))
    fireEvent.change(screen.getByLabelText('Name'), { target: { value: 'Newer work during import' } })
    if (saved) await userEvent.click(screen.getByRole('button', { name: 'Save organization draft' }))
    await act(async () => finish())
    expect(await screen.findByText(/The configuration draft changed/)).toBeInTheDocument()
    if (saved) expect(within(screen.getByRole('table')).getByText('Newer work during import')).toBeInTheDocument()
    else expect(screen.getByLabelText('Name')).toHaveValue('Newer work during import')
  })
  it('groups four RBAC pages and two Identity pages without making utilities into policy tabs', async () => {
    harness()
    expect(within(screen.getByTestId('rbac-tabs')).getAllByRole('tab').map(tab => tab.textContent)).toEqual(['Organizations', 'Groups', 'Contracts', 'Execution Policy'])
    expect(within(screen.getByTestId('admin-nav')).getAllByRole('tab').map(tab => tab.textContent)).toEqual(['RBAC', 'Identity', 'Compliance', 'Disclosure'])
    expect(screen.getByRole('link', { name: 'Settings' })).toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'Access Logs' })).toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'Diagnostics' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Review & export' })).toBeInTheDocument()
    expect(screen.queryByRole('tab', { name: 'Configuration' })).not.toBeInTheDocument()
    await userEvent.click(screen.getByRole('tab', { name: 'Identity' }))
    expect(within(screen.getByTestId('identity-tabs')).getAllByRole('tab').map(tab => tab.textContent)).toEqual(['Profiles', 'Claim mappings'])
    expect(screen.queryByTestId('rbac-tabs')).not.toBeInTheDocument()
    expect(screen.queryByRole('tab', { name: 'Azure Tenants' })).not.toBeInTheDocument()
  })
  it('keeps import and saved-draft restore on the selected Identity page', async () => {
    harness('/admin/identity/claim-mappings')
    await importFiles()
    expect(screen.getByRole('tab', { name: 'Claim mappings' })).toHaveAttribute('aria-selected', 'true')
    const { loadSourceProject, sourcePackage } = await import('./sourceProject')
    const project = await loadSourceProject(packageFiles().map(file => ({ path: file.name, size: file.size, read: () => file.text() })))
    const file = jsonFile('saved.json', sourcePackage(project)).file
    fireEvent.change(screen.getByLabelText('Saved configuration draft'), { target: { files: [file] } })
    await waitFor(() => expect(screen.getByRole('tab', { name: 'Claim mappings' })).toHaveAttribute('aria-selected', 'true'))
    expect(screen.queryByTestId('rbac-tabs')).not.toBeInTheDocument()
  })
  it('keeps unfinished fields across all business sections, operational pages and review', async () => {
    const page = harness(); await importFiles()
    await userEvent.click(screen.getByRole('button', { name: 'Edit local proposal' }))
    await userEvent.click(screen.getByRole('button', { name: 'New organization' }))
    fireEvent.change(screen.getByLabelText('Name'), { target: { value: 'Unfinished bank' } })
    // Model leaving an open dialog using browser navigation, without canceling it.
    fireEvent.mouseDown(screen.getByTestId('nav-identity'), { button: 0, ctrlKey: false })
    expect(screen.getByTestId('identity-tabs')).toBeInTheDocument()
    await userEvent.click(screen.getByRole('tab', { name: 'Compliance', exact: true }))
    expect(screen.getByText('Operational page fixture')).toBeInTheDocument()
    await userEvent.click(screen.getByRole('tab', { name: 'Policy draft' }))
    expect(screen.queryByText('Operational page fixture')).not.toBeInTheDocument()
    await userEvent.click(screen.getByRole('tab', { name: 'Disclosure', exact: true }))
    await userEvent.click(screen.getByRole('tab', { name: 'Rules draft' }))
    expect(screen.queryByText('Operational page fixture')).not.toBeInTheDocument()
    await userEvent.click(screen.getByRole('link', { name: 'Settings' }))
    await userEvent.click(screen.getByRole('button', { name: 'Review & export' }))
    expect(screen.getByRole('button', { name: 'Export configuration draft' })).toBeDisabled()
    page.navigate('/admin/configuration?org=' + org)
    await userEvent.click(screen.getByRole('tab', { name: 'RBAC' }))
    expect(screen.getByLabelText('Name')).toHaveValue('Unfinished bank')
    await userEvent.click(screen.getByRole('button', { name: 'Save organization draft' }))
    expect(within(screen.getByRole('table')).getByText('Unfinished bank')).toBeInTheDocument()
    await userEvent.click(screen.getByRole('button', { name: 'Review & export' }))
    expect(screen.getByRole('button', { name: 'Export configuration draft' })).toBeEnabled()
  })
  it('recovers a global Settings draft after the organization context changes elsewhere', async () => {
    const page = harness(`/admin/settings?org=${org}`), files = await fullPackageFiles()
    const draft = JSON.parse(await files[0].text()); draft.runtimeCatalog = { path: 'runtime.json' }
    files[0] = jsonFile('draft.json', draft).file
    files.push(jsonFile('runtime.json', { apiVersion: 'ops.runtime-policy/v1alpha7', kind: 'RuntimePolicy', readProfile: 'original-profile', nodeEvidenceProfile: '', intraOrgGrantTracing: false, rawSubmissionMode: 'guard-v1', sharedInfrastructure: [], addressScopes: [] }).file)
    await importFiles(files)
    await userEvent.click(screen.getByRole('button', { name: 'Edit local proposal' }))
    await userEvent.click(screen.getByRole('button', { name: 'Edit runtime policy draft' }))
    fireEvent.change(screen.getByLabelText('Read profile'), { target: { value: 'Unfinished global value' } })
    page.navigate('/admin/rbac/organizations?org=77777777-7777-4777-8777-777777777777')
    await userEvent.click(screen.getByRole('link', { name: 'Settings' }))
    expect(screen.getByLabelText('Read profile')).toHaveValue('Unfinished global value')
    await userEvent.click(within(screen.getByRole('dialog')).getByRole('button', { name: 'Cancel' }))
    await userEvent.click(screen.getByRole('button', { name: 'Review & export' }))
    expect(screen.getByRole('button', { name: 'Export configuration draft' })).toBeEnabled()
  })
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
    expect(screen.getByText('Serving Bank')).toBeInTheDocument()
    expect(screen.getByText('Organization admin')).toBeInTheDocument()
    expect(screen.getByText(/Imported source files are a local proposal/)).toBeInTheDocument()
    await userEvent.click(within(screen.getByRole('table')).getByText('Imported Bank'))
    expect(await screen.findByTestId('group-card')).toHaveTextContent('Payments team')
    await userEvent.click(screen.getByTitle('View declared permissions'))
    expect(await screen.findByRole('dialog')).toHaveTextContent('eth_sendRawTransaction')
    expect(screen.getByRole('dialog')).toHaveTextContent('bank-payments')
    expect(request).not.toHaveBeenCalled()
    expect(localStorage.length).toBe(1); expect(localStorage.key(0)).toBe(CONTEXT_KEY); expect(localStorage.getItem(CONTEXT_KEY)).not.toContain('Imported Bank'); expect(sessionStorage.length).toBe(0)
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
    page.replace({ ...selected, self: { ...selected.self!, actorId: 'ops:p1:' + 'B'.repeat(42) + 'A' } })
    expect(screen.queryByTestId('workspace-source')).not.toBeInTheDocument()
    expect(screen.queryByTestId('workspace-source')).not.toBeInTheDocument()
  })
  it('does not publish a delayed file read after account replacement', async () => {
    const page = harness()
    let release!: () => void
    const waiting = new Promise<void>(resolve => { release = resolve })
    fireEvent.change(screen.getByLabelText('Policy source folder'), { target: { files: packageFiles(async raw => { await waiting; return raw }) } })
    page.replace({ ...selected, self: { ...selected.self!, actorId: 'ops:p1:' + 'B'.repeat(42) + 'A' } })
    await act(async () => { release(); await waiting })
    await expectEmptySource()
    expect(screen.queryByText('Imported Bank')).not.toBeInTheDocument()
  })
  it('keeps edited source hidden through a fresh proof and restores it only to the same verified family', async () => {
    const page = harness(), raw = await editSource()
    page.transition(proofRequired())
    expect(screen.queryByTestId('workspace-source')).not.toBeInTheDocument()
    expect(screen.queryByLabelText('Proposed source')).not.toBeInTheDocument()
    expect(screen.getByText(/Your draft is kept here while you verify this account/)).toBeInTheDocument()
    const departure = new Event('beforeunload', {cancelable: true}); window.dispatchEvent(departure)
    expect(departure.defaultPrevented).toBe(true)
    page.transition({...selected, self: {...selected.self!, expiresAt: Math.floor(Date.now() / 1000) + 300}})
    expect(await screen.findByLabelText('Proposed source')).toHaveValue(raw)
    expect(screen.getByText('Changed local draft')).toBeInTheDocument()
    expect(localStorage.length).toBe(1); expect(localStorage.getItem(CONTEXT_KEY)).not.toContain(raw)
    expect(sessionStorage.length).toBe(0)
  })
  it('survives the controller expiry revision before same-family proof renewal', async () => {
    let now = Date.now(); vi.spyOn(Date, 'now').mockImplementation(() => now)
    const page = harness(), raw = await editSource()
    now = selected.self!.expiresAt * 1000 + 1
    const same = activeMulti({actorId: selected.self!.actorId, sourceProfile: 'bank', provider: 'privado', browserSessionId: family})
    page.replace({...selected, self: null, busy: true}, same)
    expect(screen.queryByLabelText('Proposed source')).not.toBeInTheDocument()
    page.transition(proofRequired())
    page.transition({...selected, self: {...selected.self!, expiresAt: Math.floor(now / 1000) + 300}})
    expect(await screen.findByLabelText('Proposed source')).toHaveValue(raw)
  })
  it.each(['actor', 'profile', 'digest', 'family'] as const)('discards the locked draft when verified %s ownership changes', async change => {
    const page = harness(); await editSource(); page.transition(proofRequired())
    const self = {...selected.self!}
    if (change === 'actor') self.actorId = 'ops:p1:' + 'B'.repeat(42) + 'A'
    if (change === 'profile') self.sourceProfile = 'other-bank'
    if (change === 'digest') self.sourceProfileDigest = 'sha256:' + 'b'.repeat(64)
    const marker = activeMulti({actorId: self.actorId, sourceProfile: self.sourceProfile, provider: 'privado', browserSessionId: change === 'family' ? '55555555-5555-4555-8555-555555555555' : family})
    page.transition({...selected, self}, marker)
    await expectEmptySource()
    expect(screen.queryByTestId('workspace-source')).not.toBeInTheDocument()
  })
  it('discards a locked draft if the fresh account no longer owns the current scope', async () => {
    const page = harness(); await editSource(); page.transition(proofRequired())
    page.mock.ownsScope.mockReturnValueOnce(false)
    page.transition(selected)
    await expectEmptySource()
  })
  it.each(['failed', 'anonymous'] as const)('does not recover a draft after verification becomes %s', async phase => {
    const page = harness(); await editSource(); page.transition(proofRequired())
    page.transition({...selected, phase, self: null, error: phase === 'failed' ? 'authentication_unavailable' : null})
    page.transition(selected)
    const open = screen.queryByRole('link', {name: 'Open configuration workspace'})
    if (open) await userEvent.click(open)
    await expectEmptySource()
  })
  it('retires a delayed import before checking authority during an ordinary proof renewal', async () => {
    const page = harness(); await importFiles()
    let release!: () => void
    const waiting = new Promise<void>(r => {release = r})
    fireEvent.change(screen.getByLabelText('Policy source folder'), {target: {files: packageFiles(async raw => {await waiting; return raw})}})
    page.transition(proofRequired())
    const checks = page.mock.ownsScope.mock.calls.length
    await act(async () => {release(); await waiting})
    expect(page.mock.ownsScope).toHaveBeenCalledTimes(checks)
    page.transition(selected)
    expect(await screen.findByTestId('workspace-source')).toHaveTextContent('worktree-revision')
  })
  it.each(['family', 'logout'] as const)('clears memory on a foreign-tab %s marker and does not revive it later', async change => {
    const page = harness(); await editSource()
    const pair = {actorId: selected.self!.actorId, sourceProfile: 'bank', provider: 'privado' as const, browserSessionId: change === 'family' ? '55555555-5555-4555-8555-555555555555' : family}
    act(() => {
      writeMultiMarker(change === 'family' ? activeMulti(pair) : deniedMulti(pair))
      window.dispatchEvent(new StorageEvent('storage', {key: CONTEXT_KEY}))
    })
    expect(screen.queryByTestId('workspace-source')).not.toBeInTheDocument()
    page.transition(selected)
    await expectEmptySource()
  })
  it('clears the memory buffer when the document leaves instead of saving it in browser storage', async () => {
    const page = harness(); await editSource()
    act(() => window.dispatchEvent(new PageTransitionEvent('pagehide', {persisted: true})))
    page.transition(selected)
    await expectEmptySource()
    expect(localStorage.length).toBe(1); expect(localStorage.key(0)).toBe(CONTEXT_KEY); expect(sessionStorage.length).toBe(0)
  })
  it('restores unfinished organization input and edit mode, then removes canceled fields from the buffer', async () => {
    const page = harness(); await importFiles(); await userEvent.click(screen.getByRole('button', {name: 'Edit local proposal'}))
    await userEvent.click(screen.getByRole('button', {name: 'New organization'}))
    fireEvent.change(screen.getByLabelText('Name'), {target: {value: 'Unsubmitted bank'}})
    fireEvent.change(screen.getByLabelText('Slug'), {target: {value: 'unfinished slug !'}})
    const departure = new Event('beforeunload', {cancelable: true}); window.dispatchEvent(departure)
    expect(departure.defaultPrevented).toBe(true)
    page.transition(proofRequired())
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument(); expect(screen.queryByDisplayValue('Unsubmitted bank')).not.toBeInTheDocument()
    page.transition(selected)
    expect(await screen.findByLabelText('Name')).toHaveValue('Unsubmitted bank')
    expect(screen.getByLabelText('Slug')).toHaveValue('unfinished slug !')
    expect(screen.getByText('Inspect proposal')).toBeInTheDocument()
    expect(localStorage.getItem(CONTEXT_KEY)).not.toContain('Unsubmitted bank'); expect(sessionStorage.length).toBe(0)
    await userEvent.click(within(screen.getByRole('dialog')).getByRole('button', {name: 'Cancel'}))
    const canceled = new Event('beforeunload', {cancelable: true}); window.dispatchEvent(canceled)
    expect(canceled.defaultPrevented).toBe(false)
    await userEvent.click(screen.getByRole('button', {name: 'New organization'}))
    expect(screen.getByLabelText('Name')).toHaveValue(''); expect(screen.getByLabelText('Slug')).toHaveValue('')
  })
  it('restores unfinished group strings, flags and method selection without converting them into source', async () => {
    const page = harness(); await importFiles(); await userEvent.click(screen.getByRole('button', {name: 'Edit local proposal'}))
    await userEvent.click(within(screen.getByRole('table')).getByText('Imported Bank'))
    await userEvent.click(screen.getByTitle('Edit access settings'))
    fireEvent.change(screen.getByLabelText('Additional method names'), {target: {value: 'method_one,  method_two '}})
    fireEvent.change(screen.getByLabelText(/^RPC credential environment reference/), {target: {value: 'unfinished reference!'}})
    await userEvent.click(screen.getByLabelText('Verbose error policy'))
    page.transition(proofRequired()); page.transition(selected)
    expect(await screen.findByLabelText('Additional method names')).toHaveValue('method_one,  method_two ')
    expect(screen.getByLabelText('Additional method names')).toHaveValue('method_one,  method_two ')
    expect(screen.getByLabelText(/^RPC credential environment reference/)).toHaveValue('unfinished reference!')
    expect(screen.getByLabelText('Verbose error policy')).toBeChecked()
    expect(screen.getByLabelText('eth_sendRawTransaction')).toBeChecked()
    await userEvent.click(within(screen.getByRole('dialog')).getByRole('button', {name: 'Cancel'}))
    expect(screen.getByText('Local draft')).toBeInTheDocument()
  })
  it('recovers invalid unsaved ABI replacement JSON and permits source export only after those fields are saved or canceled', async () => {
    const page = harness(); await importFiles(await fullPackageFiles()); await userEvent.click(screen.getByRole('button', {name: 'Edit local proposal'}))
    await userEvent.click(within(screen.getByRole('table')).getByText('Imported Bank'))
    await selectRBACPage('Contracts'); await userEvent.click(screen.getByRole('button', {name: /ABI ·/}))
    await userEvent.click(screen.getByText('Paste or inspect ABI JSON'))
    fireEvent.change(screen.getByLabelText('Public ABI JSON'), {target: {value: '[ unfinished JSON '}})
    page.transition(proofRequired()); page.transition(selected)
    expect(await screen.findByLabelText('Public ABI JSON')).toHaveValue('[ unfinished JSON ')
    // Browser history can leave a modal's route; unfinished fields stay owned,
    // but they cannot be silently omitted from an apparent complete export.
    fireEvent.click(screen.getByTestId('review-export-action'))
    expect(await screen.findByRole('button', {name: 'Export configuration draft'})).toBeDisabled()
    expect(screen.getByText(/Save or cancel unfinished form fields before exporting source/)).toBeInTheDocument()
    await userEvent.click(screen.getByTestId('account-dropdown-trigger')); await userEvent.click(screen.getByRole('menuitem', {name: 'Sign Out'}))
    expect(screen.getByRole('dialog')).toHaveTextContent('Unfinished form fields are not part of a source export')
    expect(within(screen.getByRole('dialog')).getByRole('button', {name: 'Export source'})).toBeDisabled()
    expect(page.mock.logout).not.toHaveBeenCalled()
    await userEvent.click(within(screen.getByRole('dialog')).getByRole('button', {name: 'Cancel'}))
    await selectRBACPage('Contracts')
    expect(await screen.findByLabelText('Public ABI JSON')).toHaveValue('[ unfinished JSON ')
    await userEvent.click(within(screen.getByRole('dialog')).getByRole('button', {name: 'Cancel'}))
    await userEvent.click(screen.getByRole('button', {name: 'Review & export'}))
    expect(screen.getByRole('button', {name: 'Export configuration draft'})).toBeEnabled()
  })
  it('recovers a nested execution-rule form with exact unfinished decimal and JSON strings', async () => {
    const page = harness(); await importFiles(await fullPackageFiles()); await userEvent.click(screen.getByRole('button', {name: 'Edit local proposal'}))
    await userEvent.click(within(screen.getByRole('table')).getByText('Imported Bank'))
    await selectRBACPage('Execution Policy')
    await userEvent.click(screen.getByRole('button', {name: 'Add frame rule'}))
    fireEvent.change(screen.getByLabelText('Maximum native value (wei)'), {target: {value: '90071992547409931234567890'}})
    page.transition(proofRequired()); page.transition(selected)
    expect(await screen.findByLabelText('Maximum native value (wei)')).toHaveValue('90071992547409931234567890')
    await userEvent.click(screen.getByRole('button', {name: 'Advanced native JSON'}))
    fireEvent.change(screen.getByLabelText('Advanced frame rule JSON'), {target: {value: '[unfinished'}})
    page.transition(proofRequired()); page.transition(selected)
    expect(await screen.findByLabelText('Advanced frame rule JSON')).toHaveValue('[unfinished')
    expect(screen.queryByLabelText('Maximum native value (wei)')).not.toBeInTheDocument()
    const dialogs = screen.getAllByRole('dialog')
    await userEvent.click(within(dialogs.at(-1)!).getByRole('button', {name: 'Cancel'}))
    expect(screen.queryByLabelText('Advanced frame rule JSON')).not.toBeInTheDocument()
    expect(screen.getByText('Local draft')).toBeInTheDocument()
  })
  it('recovers guided read-grant choices and an invalid custom constraint through proof renewal', async () => {
    const page = harness(); await importFiles(await fullPackageFiles()); await userEvent.click(screen.getByRole('button', {name: 'Edit local proposal'}))
    await userEvent.click(within(screen.getByRole('table')).getByText('Imported Bank'))
    await selectRBACPage('Contracts'); await userEvent.click(screen.getByRole('button', {name: 'Read grants'}))
    await userEvent.click(screen.getByRole('button', {name: 'Edit read grant for Payments team'}))
    await userEvent.click(screen.getByLabelText('Specific events only'))
    await userEvent.click(screen.getByRole('button', {name: 'Transfer(address)'}))
    fireEvent.change(screen.getByLabelText('from constraint'), {target: {value: 'custom'}})
    fireEvent.change(screen.getByLabelText('from custom value'), {target: {value: '0xunfinished'}})
    page.transition(proofRequired()); page.transition(selected)
    expect(await screen.findByLabelText('from custom value')).toHaveValue('0xunfinished')
    expect(screen.getByLabelText('Specific events only')).toBeChecked()
    expect(screen.getByLabelText('Group')).toHaveValue(group)
  })
  it('restores hypothetical scenario input and mode without retaining old imported results', async () => {
    const page = harness(); await importFiles(await fullPackageFiles())
    await userEvent.click(within(screen.getByRole('table')).getByText('Imported Bank'))
    await selectRBACPage('Execution Policy'); await userEvent.click(screen.getByRole('button', {name: 'Policy scenario'}))
    fireEvent.change(screen.getByLabelText('Hypothetical signer'), {target: {value: '0x' + '8'.repeat(40)}})
    fireEvent.change(screen.getByLabelText('Hypothetical context facts'), {target: {value: '{unfinished scenario'}})
    fireEvent.change(screen.getByLabelText('Hypothetical frames'), {target: {value: '[unfinished frames'}})
    await userEvent.click(screen.getByLabelText('Payments team'))
    page.transition(proofRequired()); page.transition(selected)
    expect(await screen.findByLabelText('Hypothetical signer')).toHaveValue('0x' + '8'.repeat(40))
    expect(screen.getByLabelText('Hypothetical context facts')).toHaveValue('{unfinished scenario')
    expect(screen.getByLabelText('Hypothetical frames')).toHaveValue('[unfinished frames')
    expect(screen.getByLabelText('Payments team')).toBeChecked()
    expect(screen.queryByText('Imported local result')).not.toBeInTheDocument()
  })
  it('keeps selected root, source document and edit mode across same-account renewal', async () => {
    const files = (await Promise.all(['core', 'broker'].map(async root => Promise.all(packageFiles().map(async file => {
      const value = JSON.parse(await file.text()); if (file.name === 'draft.json') value.sourceRevision = root + '-revision'
      return jsonFile(root + '/' + file.name, value).file
    }))))).flat()
    const page = harness(); await importFiles(files)
    expect(screen.getByLabelText('Source root')).toHaveValue('core')
    fireEvent.change(screen.getByLabelText('Source root'), {target: {value: 'broker'}})
    await userEvent.click(screen.getByRole('button', {name: 'Edit local proposal'}))
    await userEvent.click(screen.getByRole('button', {name: 'Review & export'}))
    await userEvent.click(within(screen.getByRole('navigation', {name: 'Source files'})).getByRole('button', {name: 'groups.json'}))
    page.transition(proofRequired()); page.transition(selected)
    expect(await screen.findByLabelText('Source root')).toHaveValue('broker')
    expect(screen.getByTestId('workspace-source')).toHaveTextContent('broker-revision')
    expect(screen.getByRole('button', {name: 'Inspect proposal'})).toBeInTheDocument()
    expect((screen.getByLabelText('Proposed source') as HTMLTextAreaElement).value).toContain('Configured payments operators')
  })
  it.each(['contract', 'organization', 'group', 'settings', 'frame', 'grant'] as const)('suspends the pending %s editor in Inspect mode and restores its exact input only after explicit Edit', async kind => {
    const files = await fullPackageFiles()
    if (kind === 'settings') {
      const draft = JSON.parse(await files[0].text()); draft.runtimeCatalog = {path: 'runtime.json'}; files[0] = jsonFile('draft.json', draft).file
      files.push(jsonFile('runtime.json', {apiVersion: 'ops.runtime-policy/v1alpha7', kind: 'RuntimePolicy', readProfile: 'original-read-profile', nodeEvidenceProfile: '', intraOrgGrantTracing: false, rawSubmissionMode: 'guard-v1', sharedInfrastructure: [], addressScopes: []}).file)
    }
    const page = harness(); await importFiles(files); await userEvent.click(screen.getByRole('button', {name: 'Edit local proposal'}))
    let tab = 'Organizations', field = 'Name', pending = 'Pending organization'
    if (kind === 'organization') await userEvent.click(screen.getByRole('button', {name: 'New organization'}))
    else {
      await userEvent.click(within(screen.getByRole('table')).getByText('Imported Bank'))
      if (kind === 'group') { tab = 'Groups'; field = 'Description'; pending = 'Unsubmitted group description'; await userEvent.click(screen.getByTitle('Edit group draft')) }
      if (kind === 'settings') { tab = 'Settings'; field = 'Read profile'; pending = 'unfinished profile !'; await userEvent.click(screen.getByRole('link', {name: tab})); await userEvent.click(screen.getByRole('button', {name: 'Edit runtime policy draft'})) }
      if (kind === 'contract' || kind === 'grant') {
        tab = 'Contracts'; await userEvent.click(screen.getByRole('tab', {name: tab}))
        if (kind === 'contract') { pending = 'Pending contract'; await userEvent.click(screen.getByRole('button', {name: 'Add contract'})) }
        else {
          field = 'from custom value'; pending = '0xunfinished'
          await userEvent.click(screen.getByRole('button', {name: 'Read grants'})); await userEvent.click(screen.getByRole('button', {name: 'Edit read grant for Payments team'}))
          await userEvent.click(screen.getByLabelText('Specific events only')); await userEvent.click(screen.getByRole('button', {name: 'Transfer(address)'}))
          fireEvent.change(screen.getByLabelText('from constraint'), {target: {value: 'custom'}})
        }
      }
      if (kind === 'frame') {
        tab = 'Execution Policy'; field = 'Maximum native value (wei)'; pending = '90071992547409931234567890'
        await userEvent.click(screen.getByRole('tab', {name: tab})); await userEvent.click(screen.getByRole('button', {name: 'Add frame rule'}))
      }
    }
    fireEvent.change(screen.getByLabelText(field), {target: {value: pending}})
    // Browser history can leave an unfinished editor without discarding it.
    fireEvent.click(screen.getByTestId('review-export-action'))
    await userEvent.click(screen.getByRole('button', {name: 'Inspect proposal'})); if (kind === 'settings') await userEvent.click(screen.getByRole('link', {name: tab})); else await selectRBACPage(tab)
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
    expect(screen.queryByLabelText(field)).not.toBeInTheDocument()
    expect(screen.queryByRole('button', {name: /Save.*draft/})).not.toBeInTheDocument()
    // Renewal must not turn inspection back into authoring.
    page.transition(proofRequired()); page.transition(selected)
    expect(await screen.findByRole('button', {name: 'Edit local proposal'})).toBeInTheDocument()
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
    if (kind === 'contract') {
      await userEvent.click(within(screen.getByRole('table')).getByRole('button', {name: 'Payments'}))
      expect(screen.getByRole('dialog')).toHaveTextContent('Payments')
      expect(screen.queryByRole('button', {name: 'Save draft'})).not.toBeInTheDocument()
      await userEvent.click(within(screen.getByRole('dialog')).getAllByRole('button', {name: 'Close'})[0])
    }
    if (kind === 'group') {
      await userEvent.click(screen.getByTitle('View declared permissions'))
      expect(screen.getByRole('dialog')).toHaveTextContent('Configured payments operators')
      expect(screen.queryByLabelText('Description')).not.toBeInTheDocument()
      await userEvent.click(within(screen.getByRole('dialog')).getAllByRole('button', {name: 'Close'})[0])
    }
    if (kind === 'frame') {
      await userEvent.click(screen.getByRole('button', {name: 'Inspect binding'}))
      expect(screen.getByRole('dialog')).toHaveTextContent('Native execution inspection')
      expect(screen.queryByRole('button', {name: 'Add frame rule'})).not.toBeInTheDocument()
      await userEvent.click(within(screen.getByRole('dialog')).getByRole('button', {name: 'Close'}))
    }
    if (kind === 'grant') {
      await userEvent.click(screen.getByRole('button', {name: 'Read grants'})); await userEvent.click(screen.getByRole('button', {name: 'Payments team'}))
      expect(screen.getByLabelText('No events visible')).toBeChecked()
      expect(screen.getByLabelText('Group')).toBeDisabled()
      expect(screen.queryByLabelText('from custom value')).not.toBeInTheDocument()
      const inspector = screen.getAllByRole('dialog').at(-1)!
      await userEvent.click(within(inspector).getAllByRole('button', {name: 'Close'})[0])
      await userEvent.click(within(screen.getByRole('dialog')).getByRole('button', {name: 'Close'}))
    }
    await userEvent.click(screen.getByRole('button', {name: 'Edit local proposal'}))
    expect(await screen.findByLabelText(field)).toHaveValue(pending)
    expect(screen.getByLabelText(field)).toBeEnabled()
  })
  it('does not accept a delayed referenced-document import or raw-text input after switching to Inspect', async () => {
    harness(); await importFiles(); await userEvent.click(screen.getByRole('button', {name: 'Edit local proposal'})); await userEvent.click(screen.getByRole('button', {name: 'Review & export'}))
    const editor = screen.getByLabelText('Proposed source') as HTMLTextAreaElement, draft = JSON.parse(editor.value)
    draft.documents.push({kind: 'execution-rules', organizationId: org, path: 'extra.json'})
    const proposed = JSON.stringify(draft)
    fireEvent.change(editor, {target: {value: proposed}})
    let release!: () => void
    const waiting = new Promise<void>(resolve => {release = resolve})
    const extra = jsonFile('extra.json', {apiVersion: 'ops.policy-document/v1alpha1', kind: 'execution-rules', organizationId: org, spec: {policy: {apiVersion: 'privacy.gateway.fm/v1alpha4', kind: 'ContractExecutionPolicy', org, nestedCalls: 'requireOwnRule', bindings: []}}})
    Object.defineProperty(extra.file, 'text', {value: async () => {await waiting; return extra.raw}})
    fireEvent.change(screen.getByLabelText('Missing referenced source document'), {target: {files: [extra.file]}})
    await userEvent.click(screen.getByRole('button', {name: 'Inspect proposal'}))
    expect(screen.getByLabelText('Proposed source')).toHaveAttribute('readonly')
    fireEvent.change(screen.getByLabelText('Proposed source'), {target: {value: 'must not become source'}})
    expect(screen.getByLabelText('Proposed source')).toHaveValue(proposed)
    await act(async () => {release(); await waiting})
    expect(within(screen.getByRole('navigation', {name: 'Source files'})).queryByRole('button', {name: 'extra.json'})).not.toBeInTheDocument()
    expect(screen.getByText('Choose Edit local proposal before changing source.')).toBeInTheDocument()
  })
  it('retires a read-only inspector when a replacement source import completes', async () => {
    harness(); await importFiles()
    await userEvent.click(within(screen.getByRole('table')).getByText('Imported Bank')); await userEvent.click(screen.getByTitle('View declared permissions'))
    expect(screen.getByRole('dialog')).toHaveTextContent('Payments team')
    const files = packageFiles(), draft = JSON.parse(await files[0].text()); draft.sourceRevision = 'replacement-revision'; files[0] = jsonFile('draft.json', draft).file
    fireEvent.change(screen.getByLabelText('Policy source folder'), {target: {files}})
    await waitFor(() => expect(screen.getByTestId('workspace-source')).toHaveTextContent('replacement-revision'))
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
  })
  it('clears unfinished forms when the verified owner changes and does not revive them after a fresh import', async () => {
    const page = harness(); await importFiles(); await userEvent.click(screen.getByRole('button', {name: 'Edit local proposal'}))
    await userEvent.click(screen.getByRole('button', {name: 'New organization'}))
    fireEvent.change(screen.getByLabelText('Name'), {target: {value: 'Old private draft'}})
    page.transition(proofRequired()); page.transition({...selected, self: {...selected.self!, actorId: 'ops:p1:' + 'B'.repeat(42) + 'A'}})
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument(); expect(screen.queryByDisplayValue('Old private draft')).not.toBeInTheDocument()
    page.transition(selected); await importFiles()
    expect(screen.getByRole('button', {name: 'Edit local proposal'})).toBeInTheDocument()
    await userEvent.click(screen.getByRole('button', {name: 'Edit local proposal'})); await userEvent.click(screen.getByRole('button', {name: 'New organization'}))
    expect(screen.getByLabelText('Name')).toHaveValue('')
  })
  it('keeps the ordinary own-account/wallet page available without organization admin roles', () => {
    harness('/admin/account', { ...member, self: { ...member.self!, organizations: [] } })
    expect(screen.getByTestId('account-identity')).toHaveTextContent(selected.self!.actorId)
    expect(screen.getByRole('button', { name: 'Refresh session' })).toBeEnabled()
    expect(screen.getByRole('heading', { name: 'Linked Addresses' })).toBeInTheDocument()
    expect(screen.getByTestId('account-organizations')).toHaveTextContent('No organizations')
    expect(screen.queryByText('KYC Status')).not.toBeInTheDocument()
    expect(screen.queryByText('Token Issued')).not.toBeInTheDocument()
    expect(screen.queryByText('Forget remembered app choices')).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /Cancel/ })).not.toBeInTheDocument()
    expect(screen.getByTestId('account-session').querySelector('time')).toHaveAttribute('datetime', new Date(selected.self!.expiresAt * 1000).toISOString())
    expect(screen.queryByTestId('admin-nav')).not.toBeInTheDocument()
  })
  it.each(['/admin', '/admin/rbac', '/admin/rbac/organizations', '/admin/rbac/configuration', '/admin/configuration', '/admin/identity/profiles', '/admin/identity/claim-mappings', '/admin/settings', '/admin/disclosure/rules', '/admin/compliance/policy', '/admin/compliance', '/admin/disclosure', '/disclosures', '/admin/logs', '/admin/diagnostics'])('denies a member direct console entry at %s without mounting protected content', async path => {
    const request = vi.fn(); vi.stubGlobal('fetch', request)
    harness(path, member)
    expect(screen.getByRole('heading', { name: 'Access Denied' })).toBeInTheDocument()
    expect(screen.queryByTestId('admin-nav')).not.toBeInTheDocument()
    expect(screen.queryByTestId('rbac-manager')).not.toBeInTheDocument()
    expect(screen.queryByText('Operational page fixture')).not.toBeInTheDocument()
    await userEvent.click(screen.getByTestId('account-dropdown-trigger'))
    expect(screen.queryByTestId('back-to-app-link')).not.toBeInTheDocument()
    await userEvent.keyboard('{Escape}')
    await userEvent.click(screen.getByRole('button', { name: 'Go to your account' }))
    expect(screen.getByTestId('account-identity')).toBeInTheDocument()
    expect(request).not.toHaveBeenCalled()
  })
  it('allows verified read-only organization admins into the console', () => {
    harness('/admin/rbac/organizations', { ...selected, self: { ...selected.self!, organizations: [{ ...selected.self!.organizations[0], isOrgAdmin: false, isOrgReadonlyAdmin: true }] } })
    expect(screen.getByTestId('admin-nav')).toBeInTheDocument()
    expect(screen.getByTestId('rbac-manager')).toBeInTheDocument()
    expect(screen.getByText('Read-only organization admin')).toBeInTheDocument()
  })
  it('lets a readonly admin inspect/export source without offering local edits', async () => {
    harness('/admin/rbac/organizations', { ...selected, self: { ...selected.self!, organizations: [{ ...selected.self!.organizations[0], isOrgAdmin: false, isOrgReadonlyAdmin: true }] } })
    await importFiles()
    expect(screen.getByText(/Read-only access: you can import/)).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Edit local proposal' })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'New organization' })).not.toBeInTheDocument()
    await userEvent.click(screen.getByRole('button', { name: 'Review & export' }))
    expect(screen.getByLabelText('Proposed source')).toHaveAttribute('readonly')
    expect(screen.getByRole('button', { name: 'Export configuration draft' })).toBeEnabled()
  })
  it('clears pending forms but preserves source on same-identity renewal to readonly, then requires explicit Edit after a regrant', async () => {
    const page = harness(); await importFiles()
    await userEvent.click(screen.getByRole('button', { name: 'Edit local proposal' }))
    await userEvent.click(screen.getByRole('button', { name: 'New organization' }))
    fireEvent.change(screen.getByLabelText('Name'), { target: { value: 'Pending privileged edit' } })
    page.transition(proofRequired())
    page.transition({ ...selected, self: { ...selected.self!, organizations: [{ ...selected.self!.organizations[0], isOrgAdmin: false, isOrgReadonlyAdmin: true }] } })
    expect(screen.getByTestId('workspace-source')).toBeInTheDocument()
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Edit local proposal' })).not.toBeInTheDocument()
    await userEvent.click(screen.getByRole('button', { name: 'Review & export' }))
    expect(screen.getByRole('button', { name: 'Export configuration draft' })).toBeEnabled()
    page.transition(selected)
    expect(screen.getByRole('button', { name: 'Edit local proposal' })).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'New organization' })).not.toBeInTheDocument()
    expect(screen.queryByDisplayValue('Pending privileged edit')).not.toBeInTheDocument()
  })
  it.each(['same-session', 'proof-renewal', 'switch-account'])('immediately removes console content and retires drafts on %s downgrade', async kind => {
    const page = harness(); await editSource()
    if (kind === 'proof-renewal') page.transition(proofRequired())
    const next = kind === 'switch-account' ? { ...member, self: { ...member.self!, actorId: 'ops:p1:' + 'B'.repeat(42) + 'A' } } : member
    page.transition(next)
    expect(screen.getByRole('heading', { name: 'Access Denied' })).toBeInTheDocument()
    expect(screen.queryByTestId('admin-nav')).not.toBeInTheDocument()
    expect(screen.queryByLabelText('Proposed source')).not.toBeInTheDocument()
    expect(screen.queryByTestId('workspace-source')).not.toBeInTheDocument()
    page.transition(selected)
    expect(screen.queryByTestId('workspace-source')).not.toBeInTheDocument()
    expect(screen.queryByTestId('workspace-source')).not.toBeInTheDocument()
  })
  it('offers no console link to a signed-in member at login', () => {
    harness('/login', member)
    expect(screen.getByRole('link', { name: 'Open account' })).toBeInTheDocument()
    expect(screen.queryByRole('link', { name: 'Open configuration workspace' })).not.toBeInTheDocument()
  })
  it('never renders a protected operational subtree under a downgraded same-session identity', () => {
    const page = harness('/admin/logs')
    expect(protectedRenders.length).toBeGreaterThan(0)
    const before = protectedRenders.length
    page.transition(member)
    expect(protectedRenders).toHaveLength(before)
    expect(protectedRenders.every(Boolean)).toBe(true)
    expect(screen.getByRole('heading', { name: 'Access Denied' })).toBeInTheDocument()
  })
  it('explains saved drafts without presenting them as deployed configuration', () => {
    harness()
    expect(screen.getByRole('button', { name: 'Open saved draft' })).toHaveAttribute('title', 'Restore a configuration draft you exported earlier. This does not change the running configuration.')
    expect(screen.getByLabelText('Saved configuration draft')).toHaveAttribute('accept', '.json')
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
    expect(screen.getByRole('button', { name: 'Export configuration draft' })).toBeEnabled()
  })
  it('retains typed raw text through file switches and includes it in export and unsaved-close handling', async () => {
    let blob: Blob | undefined
    vi.stubGlobal('URL', class extends URL { static createObjectURL(value: Blob) { blob = value; return 'blob:source-package' }; static revokeObjectURL() {} })
    const click = vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => {})
    try {
      harness(); await importFiles(); await userEvent.click(screen.getByRole('button', { name: 'Edit local proposal' })); await userEvent.click(screen.getByRole('button', { name: 'Review & export' }))
      const raw = String((screen.getByLabelText('Proposed source') as HTMLTextAreaElement).value).slice(0, -1) + '\n unfinished proposal'
      fireEvent.change(screen.getByLabelText('Proposed source'), { target: { value: raw } })
      expect(screen.getByText('Changed local draft')).toBeInTheDocument()
      await userEvent.click(screen.getByRole('button', { name: /^groups\.json/ })); await userEvent.click(screen.getByRole('button', { name: /^draft\.json/ }))
      expect(screen.getByLabelText('Proposed source')).toHaveValue(raw)
      await userEvent.click(screen.getByRole('button', { name: 'Export configuration draft' }))
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
    await selectRBACPage('Execution Policy'); await userEvent.click(screen.getByRole('button', { name: 'Candidate source' }))
    const editor = screen.getByLabelText('Proposed source') as HTMLTextAreaElement
    expect(editor.value).toContain('"kind":"execution-rules"')
    const raw = editor.value + '\n incomplete candidate'
    fireEvent.change(editor, { target: { value: raw } })
    await selectRBACPage('Organizations'); await userEvent.click(screen.getByRole('button', { name: 'Open source for repair' }))
    expect(screen.getByLabelText('Proposed source')).toHaveValue(raw)
  })
  it.each(['Sign Out', 'Switch account', 'Refresh session', 'Download wallet token', 'Copy access token', 'Copy Authorization header', 'Copy for Foundry'])('guards Account-page %s after a typed source edit', async action => {
    const page = harness(); await importFiles(); await userEvent.click(screen.getByRole('button', { name: 'Edit local proposal' })); await userEvent.click(screen.getByRole('button', { name: 'Review & export' }))
    const editor = screen.getByLabelText('Proposed source') as HTMLTextAreaElement
    fireEvent.change(editor, { target: { value: editor.value + '\n ' } })
    await userEvent.click(screen.getByTestId('account-dropdown-trigger')); await userEvent.click(screen.getByRole('menuitem', { name: 'Account' }))
    const departure = new Event('beforeunload', { cancelable: true }); window.dispatchEvent(departure)
    expect(departure.defaultPrevented).toBe(true)
    await userEvent.click(screen.getByRole('button', { name: action }))
    expect(screen.getByRole('dialog')).toHaveTextContent('Keep your changed source')
    expect(page.mock.logout).not.toHaveBeenCalled()
    expect(page.mock.refresh).not.toHaveBeenCalled(); expect(page.mock.downloadOwnWalletToken).not.toHaveBeenCalled()
    expect(page.mock.copyOwnRPCCredential).not.toHaveBeenCalled()
    await userEvent.click(screen.getByRole('button', { name: 'Cancel' }))
    await userEvent.click(screen.getByTestId('account-dropdown-trigger')); await userEvent.click(screen.getByRole('menuitem', { name: 'Configuration workspace' }))
    expect(screen.getByText('Changed local draft')).toBeInTheDocument()
  })
  it.each([['Copy access token', 'token'], ['Copy Authorization header', 'header'], ['Copy for Foundry', 'foundry']] as const)('uses the explicit credential action for %s without a changed draft', async (label, format) => {
    const page = harness('/admin/account')
    expect(screen.getByTestId('rpc-onboarding')).toHaveTextContent('https://ops.test/rpc/' + org)
    await userEvent.click(screen.getByRole('button', { name: label }))
    expect(page.mock.copyOwnRPCCredential).toHaveBeenCalledWith(format)
    expect(screen.getByRole('button', { name: 'Copied' })).toBeInTheDocument()
  })
})
