import '@testing-library/jest-dom/vitest'
import { useState } from 'react'
import { cleanup, fireEvent, render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, expect, it, vi } from 'vitest'
import { OrganizationTable } from '../../components/rbac/OrganizationTable'
import { SourceOrganizations } from './SourceOrganizations'
import { SourceRecords, type SourceField } from './SourceRecords'
import { SourceClaimMappings } from './SourceClaimMappings'
import { documentValue, groupsOf, loadSavedSourcePackage, loadSourceProject, object, sourcePackage, updateDocument, type JSONObject, type SourceProject } from './sourceProject'

const uuid = (n: number) => n.toString(16).padStart(8, '0') + '-1111-4111-8111-111111111111'
const orgID = uuid(1)
const groupID = (index: number) => uuid(1000 + index)
const groupPath = 'groups-0.json'
const profile = { id: 'staff', kind: 'azure-human/v1', tenantId: uuid(8000), issuer: 'https://login.example.test', apiAudience: uuid(8001), clientId: uuid(8002), delegatedScope: 'access', factSource: 'appRoles', futureProfile: { retained: true } }
const mapping = { id: 'staff-readers', profileId: 'staff', principalKind: 'human', organizationId: orgID, fact: { kind: 'azure.role', value: 'Readers.Exact', futureFact: 0 }, groupIds: [groupID(0)], futureMapping: { keep: [false, 'value'] } }
const secondMapping = { ...mapping, id: 'staff-auditors', fact: { kind: 'azure.role', value: 'Auditors.Exact' }, groupIds: [groupID(1)], futureMapping: { keep: ['second'] } }

async function fixture({ groupCount = 2, orgCount = 1, profileRows = [profile] }: { groupCount?: number; orgCount?: number; profileRows?: JSONObject[] } = {}) {
  const organizations = Array.from({ length: orgCount }, (_, i) => ({ id: uuid(i + 1), name: `Organization ${String(i).padStart(2, '0')}`, slug: `org-${i}`, futureOrg: { retain: i } }))
  const docs: Record<string, JSONObject> = {}
  const references: { kind: string; organizationId: string; path: string }[] = []
  for (const [index, org] of organizations.entries()) {
    const groups = Array.from({ length: index ? 1 : groupCount }, (_, i) => ({
      id: uuid(1000 + index * 100 + i), name: `Group ${String(i).padStart(2, '0')}`, slug: `group-${i}`, description: 'Original description',
      isOrgAdmin: false, isOrgReadonlyAdmin: false, allowedMethods: ['eth_call', 'custom_rpc'], claims: ['deploy', 'future-claim'], verboseErrors: false,
      rpcCredential: { fromEnv: 'BANK_RPC_TOKEN', futureReference: { keep: true } }, futureGroup: { preserve: [i, false] },
    }))
    const path = `groups-${index}.json`
    references.push({ kind: 'groups', organizationId: org.id, path })
    docs[path] = { apiVersion: 'ops.policy-document/v1alpha1', kind: 'groups', organizationId: org.id, futureEnvelope: 'retain', spec: { groups, futureSpec: { keep: true } } }
  }
  references.push({ kind: 'contract-registry', organizationId: orgID, path: 'registry.json' }, { kind: 'execution-rules', organizationId: orgID, path: 'execution.json' })
  docs['registry.json'] = { apiVersion: 'ops.policy-document/v1alpha1', kind: 'contract-registry', organizationId: orgID, spec: { contracts: [{ id: uuid(6000), name: 'Treasury', address: '0x' + '1'.repeat(40), abi: [], allowVisibleToUnlock: false, eventsAllowDynamicPayload: false, readGrants: [0, 50].filter(i => i < groupCount).map(i => ({ id: uuid(6100 + i), groupId: groupID(i), eventRules: { mode: 'none', rules: [] }, futureGrant: 'retain' })) }] } }
  docs['execution.json'] = { apiVersion: 'ops.policy-document/v1alpha1', kind: 'execution-rules', organizationId: orgID, spec: { policy: { apiVersion: 'privacy.gateway.fm/v1alpha4', kind: 'ContractExecutionPolicy', org: orgID, nestedCalls: 'requireOwnRule', bindings: [0, 50].filter(i => i < groupCount).map(i => ({ group: groupID(i), allow: [], futureBinding: i })) } } }
  docs['identity.json'] = { apiVersion: 'ops.identity-catalog/v1alpha1', kind: 'IdentityCatalog', issuers: [], profiles: profileRows, mappings: [mapping, secondMapping], futureCatalog: ['keep'] }
  docs['draft.json'] = { apiVersion: 'ops.policy-draft/v1alpha1', kind: 'PolicyDraft', sourceRevision: 'shell-parity', environment: 'local', chainId: '31337', profile: 'catalog-runtime-creation-observed/v1', evaluatorVersion: 'policycore/native-v1alpha4', organizations, documents: references, identityCatalog: { path: 'identity.json' }, futureDraft: { keep: true } }
  return loadSourceProject(Object.entries(docs).map(([path, value]) => { const raw = JSON.stringify(value); return { path, size: raw.length, read: async () => raw } }))
}

function mountOrganizations(initial: SourceProject, groupsPage: boolean, editing = true) {
  let current = initial
  const changes = vi.fn(), onOrganization = vi.fn()
  function App() {
    const [project, setProject] = useState(initial)
    return <SourceOrganizations project={project} root="source" organization={orgID} groupsPage={groupsPage} editing={editing} onChange={next => { current = next; changes(next); setProject(next) }} onOrganization={onOrganization} />
  }
  return { ...render(<App />), current: () => current, changes, onOrganization }
}
function groupCard(name: string) { return screen.getByText(name, { exact: true }).closest('[data-testid="group-card"]') as HTMLElement }
function unchangedFiles(before: SourceProject, after: SourceProject, edited: string[]) {
  const previous = sourcePackage(before).roots[0].files
  for (const file of previous.filter(file => !edited.includes(file.path))) expect(sourcePackage(after).roots[0].files.find(candidate => candidate.path === file.path)).toEqual(file)
}
afterEach(cleanup)

it('pages more than 50 source groups and resets a filtered empty view to the first page without mutation', async () => {
  const app = mountOrganizations(await fixture({ groupCount: 53 }), true)
  expect(screen.getAllByTestId('group-card')).toHaveLength(50)
  expect(screen.getByText('Showing 1–50 of 53')).toBeInTheDocument()
  await userEvent.click(screen.getByRole('button', { name: 'Next' }))
  expect(screen.getAllByTestId('group-card')).toHaveLength(3)
  expect(screen.getByText('Group 50')).toBeInTheDocument()
  expect(screen.queryByText('Group 00')).not.toBeInTheDocument()
  fireEvent.change(screen.getByLabelText('Search groups'), { target: { value: 'GROUP-51' } })
  expect(screen.getAllByTestId('group-card')).toHaveLength(1)
  expect(screen.getByText('Group 51')).toBeInTheDocument()
  fireEvent.change(screen.getByLabelText('Search groups'), { target: { value: 'missing group' } })
  expect(screen.getByText('No groups match this source selection.')).toBeInTheDocument()
  await userEvent.click(screen.getByRole('button', { name: 'Clear search' }))
  expect(screen.getByText('Showing 1–50 of 53')).toBeInTheDocument()
  expect(screen.getByText('Group 00')).toBeInTheDocument()
  expect(app.changes).not.toHaveBeenCalled()
})

it('preserves page selections by stable group ID and confirms batch removal while retaining dependent source references', async () => {
  const initial = await fixture({ groupCount: 53 }), originals = groupsOf(initial, 'source', orgID), app = mountOrganizations(initial, true)
  await userEvent.click(within(groupCard('Group 00')).getByRole('checkbox'))
  expect(screen.getByRole('checkbox', { name: 'Select all groups on this page' })).toHaveAttribute('data-state', 'indeterminate')
  await userEvent.click(screen.getByRole('button', { name: 'Next' }))
  await userEvent.click(within(groupCard('Group 50')).getByRole('checkbox'))
  expect(screen.getByText('2 selected')).toBeInTheDocument()
  expect(screen.getByRole('checkbox', { name: 'Select all groups on this page' })).toHaveAttribute('data-state', 'indeterminate')
  await userEvent.click(screen.getByRole('button', { name: 'Prev' }))
  expect(within(groupCard('Group 00')).getByRole('checkbox')).toBeChecked()
  await userEvent.click(screen.getByRole('checkbox', { name: 'Select all groups on this page' }))
  expect(screen.getByText('51 selected')).toBeInTheDocument()
  await userEvent.click(screen.getByRole('checkbox', { name: 'Select all groups on this page' }))
  expect(screen.getByText('1 selected')).toBeInTheDocument()
  await userEvent.click(within(groupCard('Group 00')).getByRole('checkbox'))
  await userEvent.click(screen.getByRole('button', { name: 'Remove selected from draft' }))
  let dialog = screen.getByRole('dialog')
  for (const path of ['registry.json', 'execution.json', 'identity.json']) expect(within(dialog).getByText(path)).toBeInTheDocument()
  expect(within(dialog).getByText(/Other policy references are preserved for review/)).toBeInTheDocument()
  await userEvent.click(within(dialog).getByRole('button', { name: 'Cancel' }))
  expect(app.changes).not.toHaveBeenCalled()
  expect(groupsOf(app.current(), 'source', orgID)).toEqual(originals)
  await userEvent.click(screen.getByRole('button', { name: 'Remove selected from draft' }))
  dialog = screen.getByRole('dialog')
  await userEvent.click(within(dialog).getByRole('button', { name: 'Remove from draft' }))
  expect(app.changes).toHaveBeenCalledTimes(1)
  const remaining = groupsOf(app.current(), 'source', orgID)
  expect(remaining).toEqual(originals.filter(group => ![groupID(0), groupID(50)].includes(group.id)))
  expect(remaining.find(group => group.id === groupID(51))).toEqual(originals[51])
  const envelope = documentValue(app.current(), 'source', groupPath)
  expect(envelope.futureEnvelope).toBe('retain'); expect(object(envelope.spec).futureSpec).toEqual({ keep: true })
  unchangedFiles(initial, app.current(), [groupPath])
  const restored = await loadSavedSourcePackage(JSON.stringify(sourcePackage(app.current())))
  expect(groupsOf(restored, 'source', orgID)).toEqual(remaining)
  expect(documentValue(restored, 'source', 'execution.json')).toEqual(documentValue(initial, 'source', 'execution.json'))
  expect(documentValue(restored, 'source', 'identity.json')).toEqual(documentValue(initial, 'source', 'identity.json'))
  expect(screen.queryByTestId('selection-toolbar')).not.toBeInTheDocument()
})

it('keeps metadata pencil and access gear saves separate while retaining unknown group and credential fields', async () => {
  const initial = await fixture(), original = groupsOf(initial, 'source', orgID)[0], app = mountOrganizations(initial, true)
  await userEvent.click(within(groupCard('Group 00')).getByTitle('Edit group draft'))
  let dialog = screen.getByRole('dialog')
  expect(within(dialog).queryByLabelText('Additional method names')).not.toBeInTheDocument()
  expect(within(dialog).queryByRole('button', { name: 'Save access draft' })).not.toBeInTheDocument()
  fireEvent.change(within(dialog).getByLabelText('Name'), { target: { value: 'Renamed metadata group' } })
  fireEvent.change(within(dialog).getByLabelText('Description'), { target: { value: 'Metadata only' } })
  await userEvent.click(within(dialog).getByRole('button', { name: 'Save group draft' }))
  const renamed = groupsOf(app.current(), 'source', orgID)[0]
  expect(renamed).toEqual({ ...original, name: 'Renamed metadata group', description: 'Metadata only' })
  await userEvent.click(within(groupCard('Renamed metadata group')).getByTitle('Edit access settings'))
  dialog = screen.getByRole('dialog')
  expect(within(dialog).queryByLabelText('Name')).not.toBeInTheDocument()
  expect(within(dialog).queryByLabelText('Description')).not.toBeInTheDocument()
  expect(within(dialog).queryByRole('button', { name: 'Save group draft' })).not.toBeInTheDocument()
  await userEvent.click(within(dialog).getByLabelText('Verbose error policy'))
  fireEvent.change(within(dialog).getByLabelText(/RPC credential environment reference/), { target: { value: 'NEXT_BANK_RPC_TOKEN' } })
  await userEvent.click(within(dialog).getByRole('button', { name: 'Save access draft' }))
  expect(groupsOf(app.current(), 'source', orgID)[0]).toEqual({ ...renamed, allowedMethods: [...renamed.allowedMethods].sort(), verboseErrors: true, rpcCredential: { ...original.rpcCredential, fromEnv: 'NEXT_BANK_RPC_TOKEN' } })
  expect(groupsOf(app.current(), 'source', orgID)[1]).toEqual(groupsOf(initial, 'source', orgID)[1])
  unchangedFiles(initial, app.current(), [groupPath])
  expect(app.changes).toHaveBeenCalledTimes(2)
})

it('pages more than 25 organizations, hides unsupported Created in native source and preserves the shared V1 default', async () => {
  const initial = await fixture({ orgCount: 27 }), app = mountOrganizations(initial, false, false)
  expect(screen.getAllByRole('row')).toHaveLength(26)
  expect(screen.queryByRole('columnheader', { name: 'Created' })).not.toBeInTheDocument()
  expect(screen.getByText('Showing 1–25 of 27')).toBeInTheDocument()
  await userEvent.click(screen.getByRole('button', { name: 'Next' }))
  expect(screen.getAllByRole('row')).toHaveLength(3)
  await userEvent.click(screen.getByText('Organization 26'))
  expect(app.onOrganization).toHaveBeenCalledWith(uuid(27), true)
  expect(app.changes).not.toHaveBeenCalled()
  app.unmount()
  render(<OrganizationTable organizations={[{ id: 'v1', name: 'Existing V1 organization', slug: 'v1', createdAt: '2026-11-20T12:00:00Z' }]} onSelect={() => {}} />)
  expect(screen.getByRole('columnheader', { name: 'Created' })).toBeInTheDocument()
  expect(screen.getByText('Nov 20, 2026')).toBeInTheDocument()
})

const recordFields: SourceField[] = [
  { key: 'id', label: 'Entry ID' }, { key: 'name', label: 'Name' }, { key: 'enabled', label: 'Enabled policy', kind: 'boolean' },
  { key: 'fallbackEnabled', label: 'Fallback policy', kind: 'boolean' }, { key: 'allowedMethods', label: 'Declared methods', kind: 'list' },
  { key: 'minimumDepth', label: 'Minimum depth', kind: 'number' }, { key: 'maximumWei', label: 'Maximum wei' }, { key: 'facts', label: 'Fact bindings', kind: 'json' },
]
// Imported extension metadata exercises SourceRecords' public rendering contract;
// the real source model still owns preservation, export and validation boundaries.
const profileRecords = () => Array.from({ length: 53 }, (_, i) => ({ ...profile, id: `issuer-${String(i).padStart(2, '0')}`, name: `Issuer ${String(i).padStart(2, '0')}`, enabled: true, fallbackEnabled: false, allowedMethods: ['eth_call', 'custom_rpc'], minimumDepth: 0, maximumWei: '90071992547409931234567890', facts: { source: 'operator assertion', futureFact: i }, futureProfile: { preserve: [i, false] } }))
function mountRecords(initial: SourceProject, editing = false) {
  let current = initial
  const changes = vi.fn()
  function App() {
    const [project, setProject] = useState(initial), catalog = documentValue(project, 'source', 'identity.json')
    return <SourceRecords title="Verification profiles" records={catalog.profiles} fields={recordFields} defaults={() => ({})} editing={editing} onChange={profiles => { const next = updateDocument(project, 'source', 'identity.json', { ...catalog, profiles }); current = next; changes(next); setProject(next) }} />
  }
  return { ...render(<App />), current: () => current, changes }
}

it('pages a source catalog beyond 50 records and clears search-empty results back to its first page', async () => {
  const initial = await fixture({ profileRows: profileRecords() }), app = mountRecords(initial)
  expect(screen.getByText('Showing 1–50 of 53')).toBeInTheDocument()
  expect(screen.getAllByRole('row')).toHaveLength(51)
  await userEvent.click(screen.getByRole('button', { name: 'Next' }))
  expect(screen.getAllByRole('row')).toHaveLength(4)
  expect(screen.getByRole('button', { name: 'Issuer 52' })).toBeInTheDocument()
  fireEvent.change(screen.getByLabelText('Search verification profiles'), { target: { value: 'no matching issuer' } })
  expect(screen.getByText('No verification profiles match this search.')).toBeInTheDocument()
  await userEvent.click(screen.getByRole('button', { name: 'Clear search' }))
  expect(screen.getByText('Showing 1–50 of 53')).toBeInTheDocument()
  expect(screen.getByRole('button', { name: 'Issuer 00' })).toBeInTheDocument()
  expect(app.current()).toBe(initial); expect(app.changes).not.toHaveBeenCalled()
})

it('inspects readable booleans, lists, zero/exact scalars and collapsed nested/unknown JSON without editing source', async () => {
  const initial = await fixture({ profileRows: profileRecords() }), app = mountRecords(initial)
  await userEvent.click(screen.getByRole('button', { name: 'Issuer 00' }))
  const dialog = screen.getByRole('dialog')
  function field(label: string) { return within(dialog).getByText(label, { selector: 'dt' }).parentElement! }
  expect(within(field('Enabled policy')).getByText('Enabled')).toBeInTheDocument()
  expect(within(field('Fallback policy')).getByText('Disabled')).toBeInTheDocument()
  expect(within(field('Declared methods')).getByText('eth_call')).toBeInTheDocument()
  expect(within(field('Declared methods')).getByText('custom_rpc')).toBeInTheDocument()
  expect(within(field('Minimum depth')).getByText('0')).toBeInTheDocument()
  expect(within(field('Maximum wei')).getByText('90071992547409931234567890')).toBeInTheDocument()
  const nested = within(dialog).getByText('Show fact bindings').closest('details')!
  expect(nested).not.toHaveAttribute('open')
  const advanced = within(dialog).getByText('Raw JSON (advanced)').closest('details')!
  expect(advanced).not.toHaveAttribute('open')
  expect(advanced.querySelector('pre')).toHaveTextContent('"futureProfile"')
  expect(advanced.querySelector('pre')).not.toBeVisible()
  expect(within(dialog).queryByRole('button', { name: 'Save draft' })).not.toBeInTheDocument()
  await userEvent.click(within(dialog).getAllByRole('button', { name: 'Close', exact: true })[0])
  expect(sourcePackage(app.current())).toEqual(sourcePackage(initial)); expect(app.changes).not.toHaveBeenCalled()
})

it('edits the intended catalog record after paging while preserving unknown fields, sibling rows and other source files', async () => {
  const records = profileRecords(), initial = await fixture({ profileRows: records }), app = mountRecords(initial, true)
  await userEvent.click(screen.getByRole('button', { name: 'Next' }))
  const row = screen.getByRole('button', { name: 'Issuer 51' }).closest('tr')!
  await userEvent.click(within(row).getByTitle('Edit verification profiles draft'))
  const dialog = screen.getByRole('dialog')
  fireEvent.change(within(dialog).getByLabelText('Name'), { target: { value: 'Renamed second-page issuer' } })
  await userEvent.click(within(dialog).getByRole('button', { name: 'Save draft' }))
  const after = documentValue(app.current(), 'source', 'identity.json')
  expect(after.profiles).toEqual(records.map((record, i) => i === 51 ? { ...record, name: 'Renamed second-page issuer' } : record))
  expect(after.mappings).toEqual([mapping, secondMapping]); expect(after.futureCatalog).toEqual(['keep'])
  unchangedFiles(initial, app.current(), ['identity.json'])
  const restored = await loadSavedSourcePackage(JSON.stringify(sourcePackage(app.current())))
  expect(documentValue(restored, 'source', 'identity.json')).toEqual(after)
})

function mountMappings(initial: SourceProject) {
  let current = initial
  const changes = vi.fn()
  function App() {
    const [project, setProject] = useState(initial), catalog = documentValue(project, 'source', 'identity.json')
    return <SourceClaimMappings project={project} root="source" organization={orgID} profiles={catalog.profiles as JSONObject[]} records={catalog.mappings as JSONObject[]} editing onChange={mappings => { const next = updateDocument(project, 'source', 'identity.json', { ...catalog, mappings }); current = next; changes(next); setProject(next) }} />
  }
  return { ...render(<App />), current: () => current, changes }
}

it('requires mapping-removal confirmation and explains its post-deployment effect while preserving sibling catalog data', async () => {
  const initial = await fixture(), app = mountMappings(initial)
  const row = screen.getByText('staff-auditors', { selector: 'h4' }).closest('article')!
  await userEvent.click(within(row).getByRole('button', { name: 'Remove mapping' }))
  let dialog = screen.getByRole('dialog')
  expect(within(dialog).getByText(/After approval and deployment, this verified fact will no longer grant these groups through this mapping/)).toBeInTheDocument()
  expect(app.changes).not.toHaveBeenCalled()
  await userEvent.click(within(dialog).getByRole('button', { name: 'Cancel' }))
  expect(sourcePackage(app.current())).toEqual(sourcePackage(initial))
  await userEvent.click(within(row).getByRole('button', { name: 'Remove mapping' }))
  dialog = screen.getByRole('dialog')
  await userEvent.click(within(dialog).getByRole('button', { name: 'Remove from draft' }))
  expect(app.changes).toHaveBeenCalledTimes(1)
  const catalog = documentValue(app.current(), 'source', 'identity.json'), before = documentValue(initial, 'source', 'identity.json')
  expect(catalog).toEqual({ ...before, mappings: [mapping] })
  unchangedFiles(initial, app.current(), ['identity.json'])
})

it('uses V1 selected group styling in a mapping and saves explicit group choices with unknown mapping/fact fields retained', async () => {
  const initial = await fixture(), app = mountMappings(initial)
  const row = screen.getByText('staff-readers', { selector: 'h4' }).closest('article')!
  await userEvent.click(within(row).getByRole('button', { name: 'Edit mapping' }))
  const dialog = screen.getByRole('dialog'), selected = within(dialog).getByRole('checkbox', { name: /Group 00/ }), unselected = within(dialog).getByRole('checkbox', { name: /Group 01/ })
  expect(selected).toBeChecked(); expect(selected.closest('label')).toHaveClass('bg-primary-50', 'border-primary-200')
  expect(selected.closest('label')?.querySelector('[data-state="checked"]')).toHaveClass('bg-primary')
  expect(unselected).not.toBeChecked(); expect(unselected.closest('label')).toHaveClass('border-neutral-200')
  await userEvent.click(unselected)
  expect(unselected.closest('label')).toHaveClass('bg-primary-50', 'border-primary-200')
  expect(within(dialog).getByText('Organization groups · 2 selected')).toBeInTheDocument()
  await userEvent.click(within(dialog).getByRole('button', { name: 'Save mapping draft' }))
  const after = documentValue(app.current(), 'source', 'identity.json')
  expect(after.mappings).toEqual([{ ...mapping, groupIds: [groupID(0), groupID(1)].sort() }, secondMapping])
  expect(after.profiles).toEqual([profile]); expect(after.futureCatalog).toEqual(['keep'])
  unchangedFiles(initial, app.current(), ['identity.json'])
})
