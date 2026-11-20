import '@testing-library/jest-dom/vitest'
import { useState } from 'react'
import { cleanup, fireEvent, render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, beforeEach, expect, it, vi } from 'vitest'
import { SourceContracts } from './SourceContracts'
import { SourceAuthoringProvider } from './SourceAuthoringScope'
import type { AuthoringState } from './sourceAuthoring'
import { documentValue, loadSavedSourcePackage, loadSourceProject, object, sourcePackage, updateDocument, type JSONObject, type SourceProject } from './sourceProject'
const org = '11111111-1111-4111-8111-111111111111', reader = '22222222-2222-4222-8222-222222222222', other = '33333333-3333-4333-8333-333333333333'
const address = '0x' + '1'.repeat(40), secondAddress = '0x' + '2'.repeat(40)
const abi = [{ type: 'function', name: 'balanceOf', inputs: [{ name: 'owner', type: 'address' }], outputs: [{ type: 'uint256' }], stateMutability: 'view' }, { type: 'event', name: 'Transfer', inputs: [{ name: 'from', type: 'address', indexed: true }, { name: 'to', type: 'address', indexed: true }], anonymous: false }]
const contract: JSONObject = { id: '44444444-4444-4444-8444-444444444444', name: 'Treasury Vault', address, abi, allowVisibleToUnlock: false, eventsAllowDynamicPayload: false, readGrants: [{ id: '55555555-5555-4555-8555-555555555555', groupId: reader, futureGrant: true, eventRules: { mode: 'all', rules: [], futureVisibility: 'retain' } }], futureContract: { keep: [false, 0, 'value'] } }
async function fixture(rows: JSONObject[] = [contract]) {
  const draft = { apiVersion: 'ops.policy-draft/v1alpha1', kind: 'PolicyDraft', sourceRevision: 'contracts-parity', environment: 'local', chainId: '31337', evaluatorVersion: 'policycore/native-v1alpha4', profile: 'catalog-runtime-creation-observed/v1', organizations: [{ id: org, name: 'Bank', slug: 'bank' }], documents: [{ kind: 'groups', organizationId: org, path: 'groups.json' }, { kind: 'contract-registry', organizationId: org, path: 'registry.json' }, { kind: 'execution-rules', organizationId: org, path: 'execution.json' }] }
  const groups = { apiVersion: 'ops.policy-document/v1alpha1', kind: 'groups', organizationId: org, spec: { groups: [reader, other].map((id, i) => ({ id, slug: i ? 'operators' : 'readers', name: i ? 'Operators' : 'Readers', description: '', isOrgAdmin: false, isOrgReadonlyAdmin: false, allowedMethods: ['eth_call'], claims: [], verboseErrors: false })) } }
  const registry = { apiVersion: 'ops.policy-document/v1alpha1', kind: 'contract-registry', organizationId: org, futureEnvelope: 'keep', spec: { futureSpec: ['keep'], contracts: rows } }
  const execution = { apiVersion: 'ops.policy-document/v1alpha1', kind: 'execution-rules', organizationId: org, spec: { policy: { apiVersion: 'privacy.gateway.fm/v1alpha4', kind: 'ContractExecutionPolicy', org, nestedCalls: 'requireOwnRule', bindings: [{ group: reader, allow: [{ storageAddress: address, selector: '*', abiDigest: '', maxValue: '0', futureRule: true }] }] } } }
  return loadSourceProject([['draft.json', draft], ['groups.json', groups], ['registry.json', registry], ['execution.json', execution]].map(([path, value]) => { const text = JSON.stringify(value); return { path: String(path), size: text.length, read: async () => text } }))
}
function mount(initial: SourceProject, editing = true) {
  let latest = initial
  function App() { const [project, setProject] = useState(initial); return <SourceContracts project={project} root="source" organization={org} editing={editing} onChange={next => { latest = next; setProject(next) }} /> }
  const view = render(<App />); return { ...view, project: () => latest }
}
const rows = (project: SourceProject) => object(documentValue(project, 'source', 'registry.json').spec).contracts as JSONObject[]
beforeEach(() => { vi.stubGlobal('ResizeObserver', class { observe() {} unobserve() {} disconnect() {} }) })
afterEach(() => { cleanup(); vi.unstubAllGlobals() })
it('restores dedicated readonly columns, address copy and structured ABI inspection with collapsed raw source', async () => {
  const initial = await fixture(); mount(initial, false)
  for (const name of ['Address', 'Name', 'ABI', 'Read groups', 'Execution rules', 'Actions']) expect(screen.getByRole('columnheader', { name })).toBeInTheDocument()
  expect(screen.queryByRole('button', { name: 'Add contract' })).not.toBeInTheDocument(); expect(screen.queryByRole('checkbox')).not.toBeInTheDocument()
  expect(screen.getByTitle('Readers')).toHaveTextContent('1'); expect(screen.getByRole('link', { name: '1 source rules' })).toHaveAttribute('href', '/admin/rbac/execution-policy?org=' + org)
  const clipboard = userEvent.setup(); await clipboard.click(screen.getByRole('button', { name: 'Copy address ' + address })); expect(await navigator.clipboard.readText()).toBe(address)
  await userEvent.click(screen.getByRole('button', { name: 'ABI · 1 functions · 1 events' })); const dialog = screen.getByRole('dialog')
  expect(within(dialog).getByText('balanceOf(address)')).toBeInTheDocument(); expect(within(dialog).getByText('view')).toBeInTheDocument(); expect(within(dialog).getByText('Transfer(address,address)')).toBeInTheDocument(); expect(within(dialog).getByText(/from · address · indexed/)).toBeInTheDocument()
  expect(within(dialog).getByText('Advanced public ABI JSON').closest('details')).not.toHaveAttribute('open'); expect(within(dialog).queryByRole('button', { name: 'Save ABI draft' })).not.toBeInTheDocument()
})
it('renames a contract with immutable identity, exact unknown/value retention and unchanged other exported files', async () => {
  const initial = await fixture(); const app = mount(initial)
  await userEvent.click(screen.getByRole('button', { name: 'Edit contract Treasury Vault' })); const dialog = screen.getByRole('dialog')
  expect(within(dialog).getByLabelText('Contract address')).toBeDisabled(); expect(within(dialog).queryByLabelText('Contract ID')).not.toBeInTheDocument()
  fireEvent.change(within(dialog).getByLabelText('Name'), { target: { value: 'Renamed Vault' } }); await userEvent.click(within(dialog).getByRole('button', { name: 'Save draft' }))
  expect(rows(app.project())).toEqual([{ ...contract, name: 'Renamed Vault' }]); const restored = await loadSavedSourcePackage(JSON.stringify(sourcePackage(app.project())))
  expect(rows(restored)).toEqual(rows(app.project())); const doc = documentValue(restored, 'source', 'registry.json'); expect(doc.futureEnvelope).toBe('keep'); expect(object(doc.spec).futureSpec).toEqual(['keep'])
  for (const path of ['draft.json', 'groups.json', 'execution.json']) expect(sourcePackage(restored).roots[0].files.find(f => f.path === path)).toEqual(sourcePackage(initial).roots[0].files.find(f => f.path === path))
})
it('validates registration, keeps last good source and requires visibleTo confirmation before local save', async () => {
  const app = mount(await fixture()); await userEvent.click(screen.getByRole('button', { name: 'Add contract' })); let dialog = screen.getByRole('dialog')
  fireEvent.change(within(dialog).getByLabelText('Name'), { target: { value: 'Duplicate' } }); fireEvent.change(within(dialog).getByLabelText('Contract address'), { target: { value: 'bad' } }); await userEvent.click(within(dialog).getByRole('button', { name: 'Save draft' })); expect(within(dialog).getByRole('alert')).toHaveTextContent('40 hexadecimal')
  fireEvent.change(within(dialog).getByLabelText('Contract address'), { target: { value: address } }); await userEvent.click(within(dialog).getByRole('button', { name: 'Save draft' })); expect(within(dialog).getByRole('alert')).toHaveTextContent('already registered'); expect(rows(app.project())).toEqual([contract])
  await userEvent.click(within(dialog).getByRole('button', { name: 'Cancel' })); await userEvent.click(screen.getByRole('button', { name: 'Edit contract Treasury Vault' })); dialog = screen.getByRole('dialog')
  await userEvent.click(within(dialog).getByLabelText('Visible to unlock')); let confirm = screen.getAllByRole('dialog').at(-1)!
  expect(within(confirm).getByRole('heading', { name: 'Enable visibleTo unlock?' })).toBeInTheDocument(); await userEvent.click(within(confirm).getByRole('button', { name: 'Cancel' })); expect(within(dialog).getByLabelText('Visible to unlock')).not.toBeChecked()
  await userEvent.click(within(dialog).getByLabelText('Visible to unlock')); confirm = screen.getAllByRole('dialog').at(-1)!; await userEvent.click(within(confirm).getByRole('button', { name: 'Enable in draft' })); expect(within(dialog).getByLabelText('Visible to unlock')).toBeChecked(); expect(rows(app.project())[0].allowVisibleToUnlock).toBe(false)
  await userEvent.click(within(dialog).getByRole('button', { name: 'Save draft' })); expect(rows(app.project())[0]).toEqual({ ...contract, allowVisibleToUnlock: true })
})
it('filters only names/addresses, explains no results, pages local rows and styles selection without changing payload', async () => {
  const list = Array.from({ length: 26 }, (_, i) => ({ ...contract, id: `contract-${i}`, address: '0x' + i.toString(16).padStart(40, '0'), name: `Vault ${i}` })); const app = mount(await fixture(list))
  expect(screen.getByText('Showing 1–25 of 26')).toBeInTheDocument(); await userEvent.click(screen.getByRole('button', { name: 'Next' })); expect(screen.getByText('Showing 26–26 of 26')).toBeInTheDocument()
  fireEvent.change(screen.getByLabelText('Search contracts'), { target: { value: 'balanceOf' } }); expect(screen.getByText('No matching contracts')).toBeInTheDocument(); await userEvent.click(screen.getByRole('button', { name: 'Clear search' }))
  await userEvent.click(screen.getByRole('checkbox', { name: 'Select Vault 0' })); expect(screen.getByText('1 selected')).toBeInTheDocument(); expect(screen.getByRole('checkbox', { name: 'Select all contracts on this page' })).toHaveAttribute('data-state', 'indeterminate'); expect(rows(app.project())).toEqual(list)
})
it('previews and adds only missing bulk read grants, preserving existing grants and execution rules', async () => {
  const second = { ...contract, id: '66666666-6666-4666-8666-666666666666', name: 'Second vault', address: secondAddress, readGrants: [], futureContract: { keep: 'second' } }, initial = await fixture([contract, second]), app = mount(initial)
  await userEvent.click(screen.getByRole('checkbox', { name: 'Select all contracts on this page' })); await userEvent.click(screen.getByRole('button', { name: 'Add read grants' })); const dialog = screen.getByRole('dialog')
  fireEvent.change(within(dialog).getByLabelText('Target group'), { target: { value: reader } }); expect(within(dialog).getByText('1 new grants · 1 existing grants unchanged')).toBeInTheDocument(); await userEvent.click(within(dialog).getByLabelText('All events visible')); await userEvent.click(within(dialog).getByRole('button', { name: 'Add missing read grants' }))
  expect(rows(app.project())[0]).toEqual(contract); expect(rows(app.project())[1]).toEqual({ ...second, readGrants: [{ id: expect.any(String), groupId: reader, eventRules: { mode: 'all', rules: [] } }] }); expect(sourcePackage(app.project()).roots[0].files.find(f => f.path === 'execution.json')).toEqual(sourcePackage(initial).roots[0].files.find(f => f.path === 'execution.json'))
})
it('retains unfinished contract fields across unmounts, then retires them when their source file changes', async () => {
  const initial = await fixture(); let replace!: (project: SourceProject) => void, show!: (open: boolean) => void
  function App() { const [project, setProject] = useState(initial), [state, setState] = useState<AuthoringState>({}), [visible, setVisible] = useState(true); replace = setProject; show = setVisible; return <SourceAuthoringProvider project={project} state={state} update={(key, entry) => setState(old => ({ ...old, [key]: entry }))} clear={prefix => setState(old => Object.fromEntries(Object.entries(old).filter(([key]) => !key.startsWith(prefix))))}>{visible && <SourceContracts project={project} root="source" organization={org} editing onChange={setProject} />}</SourceAuthoringProvider> }
  const view = render(<App />); await userEvent.click(screen.getByRole('button', { name: 'Edit contract Treasury Vault' })); fireEvent.change(screen.getByLabelText('Name'), { target: { value: 'unfinished local name' } })
  const { act } = await import('@testing-library/react'); act(() => show(false)); act(() => show(true)); expect(screen.getByLabelText('Name')).toHaveValue('unfinished local name')
  const doc = documentValue(initial, 'source', 'registry.json'); act(() => replace(updateDocument(initial, 'source', 'registry.json', { ...doc, spec: { ...object(doc.spec), contracts: [{ ...contract, name: 'Externally changed' }] } }))); expect(screen.queryByRole('dialog')).not.toBeInTheDocument(); expect(screen.queryByDisplayValue('unfinished local name')).not.toBeInTheDocument(); view.unmount()
})

it('stages ABI upload inside the contract form without submitting its parent or losing pending fields', async () => {
  const app = mount(await fixture()); await userEvent.click(screen.getByRole('button', { name: 'Edit contract Treasury Vault' })); let dialog = screen.getByRole('dialog')
  fireEvent.change(within(dialog).getByLabelText('Name'), { target: { value: 'Pending ABI rename' } }); await userEvent.click(within(dialog).getByRole('button', { name: 'ABI · 1 functions · 1 events' })); const nested = screen.getAllByRole('dialog').at(-1)!
  const nextABI = [{ type: 'function', name: 'owner', stateMutability: 'view', inputs: [], outputs: [{ type: 'address' }] }], raw = JSON.stringify({ abi: nextABI }), file = new File([raw], 'vault-artifact.json'); Object.defineProperty(file, 'text', { value: async () => raw }); fireEvent.change(within(nested).getByLabelText('Upload or replace ABI file'), { target: { files: [file] } })
  await screen.findByText(/Loaded file: vault-artifact.json/); await userEvent.click(within(nested).getByRole('button', { name: 'Save ABI draft' })); dialog = screen.getByRole('dialog')
  expect(within(dialog).getByLabelText('Name')).toHaveValue('Pending ABI rename'); expect(rows(app.project())).toEqual([contract]); await userEvent.click(within(dialog).getByRole('button', { name: 'Save draft' })); expect(rows(app.project())).toEqual([{ ...contract, name: 'Pending ABI rename', abi: nextABI }])
})
it('creates a named bulk target by its exact generated ID, with source groups and grants changed together', async () => {
  const app = mount(await fixture()); await userEvent.click(screen.getByRole('checkbox', { name: 'Select Treasury Vault' })); await userEvent.click(screen.getByRole('button', { name: 'Add read grants' })); const dialog = screen.getByRole('dialog')
  await userEvent.click(within(dialog).getByLabelText('Create a new source group')); fireEvent.change(within(dialog).getByLabelText('Group name'), { target: { value: 'New source readers' } }); fireEvent.change(within(dialog).getByLabelText('Group slug'), { target: { value: 'new-readers' } }); await userEvent.click(within(dialog).getByRole('button', { name: 'Add missing read grants' }))
  const group = (object(documentValue(app.project(), 'source', 'groups.json').spec).groups as JSONObject[]).at(-1)!
  expect(group).toMatchObject({ id: expect.any(String), name: 'New source readers', slug: 'new-readers', claims: [], allowedMethods: [] }); expect((rows(app.project())[0].readGrants as JSONObject[]).at(-1)).toEqual({ id: expect.any(String), groupId: group.id, eventRules: { mode: 'none', rules: [] } }); expect((rows(app.project())[0].readGrants as JSONObject[])[0]).toEqual((contract.readGrants as JSONObject[])[0])
})
