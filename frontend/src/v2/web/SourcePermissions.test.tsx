import '@testing-library/jest-dom/vitest'
import { cleanup, render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, expect, it } from 'vitest'
import { SourcePermissionChoices, matchingNativePreset, NATIVE_METHODS } from './SourcePermissions'
import { SourceOrganizations } from './SourceOrganizations'
import { documentValue, loadSourceProject, type JSONObject } from './sourceProject'
const testCatalog = { status: 'ready' as const, catalog: { version: 'test/v1', methods: NATIVE_METHODS.map(name => ({ name, canonical: name })) } }
afterEach(cleanup)
const networkReader = ['eth_chainId', 'eth_blockNumber', 'net_version', 'net_listening', 'eth_gasPrice', 'eth_feeHistory']
it('renders selected, unselected and implied checks plus a matching preset in read-only inspection with no editing controls', async () => {
  render(<SourcePermissionChoices catalog={testCatalog} methods={[...networkReader, 'custom_rpc']} claims={['admin', 'future-claim']} isAdmin={false} />)
  const preset = screen.getByRole('group', { name: 'Network reader' })
  expect(preset).toHaveAttribute('data-state', 'unselected')
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
  render(<SourcePermissionChoices catalog={testCatalog} methods={networkReader} claims={[]} isAdmin />)
  expect(screen.getByText('Execution claims · 0 declared')).toBeInTheDocument()
  expect(screen.getByText(/Organization admin groups declare an empty claims list/)).toBeInTheDocument()
  expect(screen.queryByRole('checkbox', { name: 'Execution administrator' })).not.toBeInTheDocument()
  expect(screen.queryByText('Implied by admin')).not.toBeInTheDocument()
  expect(screen.getByRole('checkbox', { name: 'eth_chainId' })).toBeChecked()
})
it('shows trace and transaction capabilities as recognized methods without hiding unknown names', () => {
  render(<SourcePermissionChoices catalog={testCatalog} methods={['debug_traceTransaction', 'eth_sendTransaction', 'custom_rpc']} claims={[]} isAdmin={false} />)
  expect(screen.getByRole('checkbox', { name: 'debug_traceTransaction' })).toBeChecked()
  expect(screen.getByRole('checkbox', { name: 'eth_sendTransaction' })).toBeChecked()
  expect(screen.getByText('Other configured methods · 1')).toBeInTheDocument()
  expect(screen.getByText('custom_rpc')).toBeInTheDocument()
  expect(screen.getByText(/permission is also used for signed raw submission/)).toBeInTheDocument()
})
const org = '11111111-1111-1111-1111-111111111111', groupID = '33333333-3333-3333-3333-333333333333'
async function sourceProject(patch: JSONObject = {}) {
  const group = { id: groupID, slug: 'readers', name: 'Readers', description: 'Native proposal', isOrgAdmin: false, isOrgReadonlyAdmin: false, verboseErrors: false, allowedMethods: ['eth_call', 'custom_rpc', 'eth_newFilter'], claims: ['deploy', 'future-claim'], rpcCredential: { fromEnv: 'BANK_RPC', futureReference: { preserved: true } }, futureGroup: true, ...patch }
  const draft = { apiVersion: 'ops.policy-draft/v1alpha1', kind: 'PolicyDraft', sourceRevision: 'proposal', environment: 'local', chainId: '31337', evaluatorVersion: 'policycore/native-v1alpha4', profile: 'catalog-runtime-creation-observed/v1', organizations: [{ id: org, slug: 'bank', name: 'Bank' }], documents: [{ kind: 'groups', organizationId: org, path: 'groups.json' }] }
  const groups = { apiVersion: 'ops.policy-document/v1alpha1', kind: 'groups', organizationId: org, spec: { groups: [group] } }
  return loadSourceProject([['draft.json', draft], ['groups.json', groups]].map(([path, value]) => { const raw = JSON.stringify(value); return { path: String(path), size: raw.length, read: async () => raw } }))
}
it('uses the same selection states from the real source inspection dialog while keeping the imported proposal unchanged', async () => {
  const project = await sourceProject({ allowedMethods: [...networkReader, 'custom_rpc'], claims: ['admin'] })
  const before = documentValue(project, 'source', 'groups.json')
  render(<SourceOrganizations catalog={testCatalog} project={project} root="source" organization={org} groupsPage onOrganization={() => {}} />)
  await userEvent.click(screen.getByTitle('View declared permissions'))
  const dialog = screen.getByRole('dialog')
  expect(within(dialog).getByRole('group', { name: 'Network reader' })).toHaveAttribute('data-state', 'unselected')
  expect(within(dialog).getByRole('checkbox', { name: 'eth_chainId' })).toBeChecked(); expect(within(dialog).getByRole('checkbox', { name: 'eth_accounts' })).not.toBeChecked()
  expect(within(dialog).getByRole('checkbox', { name: 'Deploy contracts' })).toBeDisabled(); expect(within(dialog).getAllByText('Implied by admin')).toHaveLength(2)
  expect(within(dialog).queryByRole('button', { name: 'Save group draft' })).not.toBeInTheDocument()
  expect(documentValue(project, 'source', 'groups.json')).toEqual(before)
})

it('matches a preset from known methods while retaining additional names', () => { expect(matchingNativePreset([...networkReader, 'private_*'])).toBeNull(); expect(matchingNativePreset(['eth_accounts'])).toBeNull() })


it('uses all names supplied by the running catalog and preserves preview-only names', () => {
  const catalog = { status: 'ready' as const, catalog: { version: 'test/v2', methods: [
    { name: 'eth_call', canonical: 'eth_call' }, { name: 'bank_call', canonical: 'eth_call' },
    { name: 'chain_newFeature', canonical: 'chain_newFeature' },
  ] } }
  render(<SourcePermissionChoices catalog={catalog} methods={['bank_call', 'chain_newFeature', 'preview_only']} claims={[]} isAdmin={false} />)
  expect(screen.getByRole('checkbox', { name: 'bank_call' })).toBeChecked()
  expect(screen.getByText('alias of eth_call')).toBeInTheDocument()
  expect(screen.getByRole('checkbox', { name: 'chain_newFeature' })).toBeChecked()
  expect(screen.getByText('Other catalog methods')).toBeInTheDocument()
  expect(screen.getByText('preview_only')).toBeInTheDocument()
  expect(screen.getByText(/viewed configuration may target another instance/)).toBeInTheDocument()
})
it('shows every configured name when the running catalog is unavailable or empty', () => {
  const { rerender } = render(<SourcePermissionChoices catalog={{ status: 'unavailable' }} methods={['eth_call', 'private_rpc']} claims={[]} isAdmin={false} />)
  expect(screen.getByText(/method catalog is unavailable/)).toBeInTheDocument()
  expect(screen.getByText('eth_call')).toBeInTheDocument(); expect(screen.getByText('private_rpc')).toBeInTheDocument()
  rerender(<SourcePermissionChoices catalog={{ status: 'ready', catalog: { version: 'test', methods: [] } }} methods={['eth_call', 'private_rpc']} claims={[]} isAdmin={false} />)
  expect(screen.queryByText(/method catalog is unavailable/)).not.toBeInTheDocument()
  expect(screen.getByText('Other configured methods · 2')).toBeInTheDocument()
})
