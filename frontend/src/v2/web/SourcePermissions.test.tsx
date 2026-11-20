import '@testing-library/jest-dom/vitest'
import { useState } from 'react'
import { cleanup, fireEvent, render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, expect, it, vi } from 'vitest'
import { SourcePermissionChoices, matchingNativePreset, NATIVE_METHODS, NATIVE_PRESETS } from './SourcePermissions'
import { SourceOrganizations } from './SourceOrganizations'
import { SourceAuthoringProvider, SourceAuthoringScope } from './SourceAuthoringScope'
import type { AuthoringState } from './sourceAuthoring'
import { documentValue, loadSourceProject, object, type JSONObject } from './sourceProject'

afterEach(() => { cleanup(); vi.unstubAllGlobals() })
const networkReader = ['eth_chainId', 'eth_blockNumber', 'net_version', 'net_listening', 'eth_gasPrice', 'eth_feeHistory']
function Choices({ initialMethods = [], initialClaims = [], onMethods = vi.fn(), onClaims = vi.fn() }: { initialMethods?: string[]; initialClaims?: string[]; onMethods?(methods: string[]): void; onClaims?(claims: string[]): void }) {
  const [methods, setMethods] = useState(initialMethods), [claims, setClaims] = useState(initialClaims)
  return <SourcePermissionChoices methods={methods} claims={claims} isAdmin={false} onMethods={value => { setMethods(value); onMethods(value) }} onClaims={value => { setClaims(value); onClaims(value) }} />
}
it('derives the selected preset from the exact guided choices and retires it after manual or bulk changes without removing imported names', async () => {
  const onMethods = vi.fn()
  render(<Choices initialMethods={[...networkReader, 'custom_rpc', 'eth_newFilter', 'private_*']} onMethods={onMethods} />)
  const preset = screen.getByRole('button', { name: 'Network reader' })
  expect(preset).toHaveAttribute('aria-pressed', 'true'); expect(preset).toHaveClass('border-primary', 'bg-primary-50')
  expect(screen.getByRole('checkbox', { name: 'eth_chainId' })).toBeChecked()
  expect(screen.getByRole('checkbox', { name: 'eth_accounts' })).not.toBeChecked()
  expect(screen.getByLabelText('Network and fees: 6 of 12 selected')).toHaveTextContent('6 / 12')
  await userEvent.click(screen.getByRole('checkbox', { name: 'eth_chainId' }))
  expect(preset).toHaveAttribute('aria-pressed', 'false'); expect(screen.getByRole('checkbox', { name: 'eth_chainId' })).not.toBeChecked()
  expect(screen.getByLabelText('Network and fees: 5 of 12 selected')).toHaveTextContent('5 / 12')
  expect(screen.queryAllByRole('button', { pressed: true })).toHaveLength(0)
  await userEvent.click(preset)
  expect(onMethods).toHaveBeenLastCalledWith([...networkReader, 'custom_rpc', 'eth_newFilter', 'private_*'].sort())
  expect(preset).toHaveAttribute('aria-pressed', 'true')
  await userEvent.click(screen.getByRole('button', { name: 'Select all account state' }))
  expect(preset).toHaveAttribute('aria-pressed', 'false'); expect(screen.getByLabelText('Account state: 5 of 5 selected')).toHaveTextContent('5 / 5')
  await userEvent.click(screen.getByRole('button', { name: 'Clear account state' }))
  expect(preset).toHaveAttribute('aria-pressed', 'true')
  expect(onMethods).toHaveBeenLastCalledWith(expect.arrayContaining(['custom_rpc', 'eth_newFilter', 'private_*']))
  expect(onMethods.mock.calls.every(([methods]) => methods.includes('custom_rpc') && methods.includes('eth_newFilter') && methods.includes('private_*'))).toBe(true)
  expect(matchingNativePreset([...networkReader, networkReader[0], 'future_method'])).toBe('Network reader')
  for (const p of NATIVE_PRESETS) expect(matchingNativePreset(p.methods)).toBe(p.name)
  expect(matchingNativePreset(['custom_rpc'])).toBeNull()
})
it('keeps native keyboard behavior and displays admin implication without adding deploy or upgrade to declared source flags', async () => {
  const onClaims = vi.fn()
  render(<Choices initialClaims={['deploy', 'custom-claim']} onClaims={onClaims} />)
  const admin = screen.getByRole('checkbox', { name: 'Execution administrator' }), deploy = screen.getByRole('checkbox', { name: 'Deploy contracts' }), upgrade = screen.getByRole('checkbox', { name: 'Upgrade contracts' })
  admin.focus(); expect(admin).toHaveFocus(); await userEvent.keyboard('[Space]')
  expect(admin).toBeChecked(); expect(onClaims).toHaveBeenLastCalledWith(['deploy', 'custom-claim', 'admin'])
  expect(deploy).toBeChecked(); expect(deploy).toBeDisabled(); expect(upgrade).toBeChecked(); expect(upgrade).toBeDisabled()
  expect(within(deploy.closest('label')!).getByText('Declared · also implied by admin')).toBeInTheDocument()
  expect(within(upgrade.closest('label')!).getByText('Implied by admin')).toBeInTheDocument()
  expect(admin.closest('label')).toHaveClass('border-primary', 'focus-within:ring-2')
  expect(deploy.closest('label')?.querySelector('[data-state="checked"]')).toHaveClass('bg-primary', 'border-primary')
  await userEvent.click(upgrade); expect(onClaims).toHaveBeenCalledTimes(1)
  admin.focus(); await userEvent.keyboard('[Space]')
  expect(onClaims).toHaveBeenLastCalledWith(['deploy', 'custom-claim']); expect(deploy).toBeChecked(); expect(deploy).toBeEnabled(); expect(upgrade).not.toBeChecked(); expect(upgrade).toBeEnabled()
  expect(screen.getByRole('button', { name: 'Remove claim custom-claim' })).toBeInTheDocument()
})
it('renders selected, unselected and implied checks plus a matching preset in read-only inspection with no editing controls', async () => {
  render(<SourcePermissionChoices methods={[...networkReader, 'custom_rpc']} claims={['admin', 'future-claim']} isAdmin={false} />)
  const preset = screen.getByRole('button', { name: 'Network reader' })
  expect(preset).toHaveAttribute('aria-pressed', 'true'); expect(preset).toBeDisabled(); expect(preset).toHaveClass('border-primary', 'bg-primary-50')
  expect(screen.getAllByRole('checkbox')).toHaveLength(NATIVE_METHODS.length + 3)
  expect(screen.getAllByRole('checkbox').every(input => input.hasAttribute('disabled'))).toBe(true)
  expect(screen.getByRole('checkbox', { name: 'eth_chainId' })).toBeChecked(); expect(screen.getByRole('checkbox', { name: 'eth_accounts' })).not.toBeChecked()
  expect(screen.getByRole('checkbox', { name: 'Deploy contracts' })).toBeChecked(); expect(screen.getByRole('checkbox', { name: 'Upgrade contracts' })).toBeChecked()
  expect(screen.getAllByText('Implied by admin')).toHaveLength(2)
  expect(screen.getByLabelText('Network and fees: 6 of 12 selected')).toHaveClass('bg-primary-50', 'text-primary')
  expect(screen.getByText('custom_rpc')).toBeInTheDocument(); expect(screen.getByText('future-claim')).toBeInTheDocument()
  expect(screen.queryByRole('button', { name: 'Select all network and fees' })).not.toBeInTheDocument(); expect(screen.queryByRole('button', { name: 'Remove method custom_rpc' })).not.toBeInTheDocument()
  await userEvent.click(preset); expect(screen.getByRole('checkbox', { name: 'eth_accounts' })).not.toBeChecked()
})
it('keeps organization administration separate from execution admin implication in inspection', () => {
  render(<SourcePermissionChoices methods={networkReader} claims={[]} isAdmin />)
  expect(screen.getByText('Execution claims · 0 declared')).toBeInTheDocument()
  expect(screen.getByText(/Organization admin groups save an empty claims list/)).toBeInTheDocument()
  expect(screen.queryByRole('checkbox', { name: 'Execution administrator' })).not.toBeInTheDocument()
  expect(screen.queryByText('Implied by admin')).not.toBeInTheDocument()
  expect(screen.getByRole('checkbox', { name: 'eth_chainId' })).toBeChecked()
})
const org = '11111111-1111-1111-1111-111111111111', groupID = '33333333-3333-3333-3333-333333333333'
async function sourceProject(patch: JSONObject = {}) {
  const group = { id: groupID, slug: 'readers', name: 'Readers', description: 'Native proposal', isOrgAdmin: false, isOrgReadonlyAdmin: false, verboseErrors: false, allowedMethods: ['eth_call', 'custom_rpc', 'eth_newFilter'], claims: ['deploy', 'future-claim'], rpcCredential: { fromEnv: 'BANK_RPC', futureReference: { preserved: true } }, futureGroup: true, ...patch }
  const draft = { apiVersion: 'ops.policy-draft/v1alpha1', kind: 'PolicyDraft', sourceRevision: 'proposal', environment: 'local', chainId: '31337', evaluatorVersion: 'policycore/native-v1alpha4', profile: 'catalog-runtime-creation-observed/v1', organizations: [{ id: org, slug: 'bank', name: 'Bank' }], documents: [{ kind: 'groups', organizationId: org, path: 'groups.json' }] }
  const groups = { apiVersion: 'ops.policy-document/v1alpha1', kind: 'groups', organizationId: org, spec: { groups: [group] } }
  return loadSourceProject([['draft.json', draft], ['groups.json', groups]].map(([path, value]) => { const raw = JSON.stringify(value); return { path: String(path), size: raw.length, read: async () => raw } }))
}
it('retains the selected source preset and declared flags through pane suspension, saving native fields and imported entries unchanged', async () => {
  const project = await sourceProject(), change = vi.fn(), fetch = vi.fn(); vi.stubGlobal('fetch', fetch)
  function Retained({ visible }: { visible: boolean }) {
    const [state, setState] = useState<AuthoringState>({})
    return <SourceAuthoringProvider project={project} state={state} update={(key, entry) => setState(s => ({ ...s, [key]: entry }))} clear={prefix => setState(s => Object.fromEntries(Object.entries(s).filter(([key]) => !key.startsWith(prefix))))}><SourceAuthoringScope id="groups" root="source" path="groups.json">{visible && <SourceOrganizations project={project} root="source" organization={org} groupsPage editing onChange={change} onOrganization={() => {}} />}</SourceAuthoringScope></SourceAuthoringProvider>
  }
  const pane = render(<Retained visible />)
  await userEvent.click(screen.getByTitle('Edit access settings')); await userEvent.click(screen.getByRole('button', { name: 'Network reader' })); await userEvent.click(screen.getByRole('checkbox', { name: 'Execution administrator' })); await userEvent.click(screen.getByRole('checkbox', { name: 'Verbose error policy' }))
  pane.rerender(<Retained visible={false} />); pane.rerender(<Retained visible />)
  expect(screen.getByRole('button', { name: 'Network reader' })).toHaveAttribute('aria-pressed', 'true'); expect(screen.getByRole('checkbox', { name: 'eth_chainId' })).toBeChecked(); expect(screen.getByRole('checkbox', { name: 'Upgrade contracts' })).toBeDisabled(); expect(screen.getByRole('checkbox', { name: 'Verbose error policy' })).toBeChecked()
  fireEvent.change(screen.getByLabelText('Additional method names'), { target: { value: 'custom_pending' } })
  expect(screen.getByRole('button', { name: 'Network reader' })).toHaveAttribute('aria-pressed', 'false')
  expect(screen.getByText(/Additional method names are pending/)).toBeInTheDocument()
  pane.rerender(<Retained visible={false} />); pane.rerender(<Retained visible />)
  expect(screen.getByLabelText('Additional method names')).toHaveValue('custom_pending'); expect(screen.getByRole('button', { name: 'Network reader' })).toHaveAttribute('aria-pressed', 'false')
  await userEvent.click(screen.getByRole('button', { name: 'Save access draft' }))
  expect(change).toHaveBeenCalledTimes(1)
  const saved = (object(documentValue(change.mock.calls[0][0], 'source', 'groups.json').spec).groups as JSONObject[])[0]
  expect(saved.allowedMethods).toEqual([...networkReader, 'custom_rpc', 'eth_newFilter', 'custom_pending'].sort())
  expect(saved.claims).toEqual(['deploy', 'future-claim', 'admin']); expect(saved.claims).not.toContain('upgrade')
  expect(saved.rpcCredential).toEqual({ fromEnv: 'BANK_RPC', futureReference: { preserved: true } }); expect(saved.futureGroup).toBe(true); expect(saved.verboseErrors).toBe(true); expect(saved.isOrgAdmin).toBe(false)
  expect(fetch).not.toHaveBeenCalled()
})
it('uses the same selection states from the real source inspection dialog while keeping the imported proposal unchanged', async () => {
  const project = await sourceProject({ allowedMethods: [...networkReader, 'custom_rpc'], claims: ['admin'] }), change = vi.fn()
  const before = documentValue(project, 'source', 'groups.json')
  render(<SourceOrganizations project={project} root="source" organization={org} groupsPage editing={false} onChange={change} onOrganization={() => {}} />)
  await userEvent.click(screen.getByTitle('View declared permissions'))
  const dialog = screen.getByRole('dialog')
  expect(within(dialog).getByRole('button', { name: 'Network reader' })).toHaveAttribute('aria-pressed', 'true')
  expect(within(dialog).getByRole('checkbox', { name: 'eth_chainId' })).toBeChecked(); expect(within(dialog).getByRole('checkbox', { name: 'eth_accounts' })).not.toBeChecked()
  expect(within(dialog).getByRole('checkbox', { name: 'Deploy contracts' })).toBeDisabled(); expect(within(dialog).getAllByText('Implied by admin')).toHaveLength(2)
  expect(within(dialog).queryByRole('button', { name: 'Save group draft' })).not.toBeInTheDocument()
  expect(documentValue(project, 'source', 'groups.json')).toEqual(before); expect(change).not.toHaveBeenCalled()
})
