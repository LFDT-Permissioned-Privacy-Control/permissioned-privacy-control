import '@testing-library/jest-dom/vitest'
import { useState } from 'react'
import { SourceAuthoringProvider, SourceAuthoringScope } from './SourceAuthoringScope'
import type { AuthoringState } from './sourceAuthoring'
import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, expect, it, vi } from 'vitest'
import { SourceOrganizations } from './SourceOrganizations'
import { SourceCatalogs } from './SourceCatalogs'
import { ABIForm, parseAuthoringABI } from './SourceContractABI'
import { complianceDecimal, complianceInteger, defaultComplianceOrganization, validateComplianceRow } from './SourceComplianceSettings'
import { NATIVE_METHODS, NATIVE_PRESETS } from './SourcePermissions'
import { profileCompatibility } from './SourceClaimMappings'
import { documentValue, loadSourceProject, object, type JSONObject } from './sourceProject'
const org = '11111111-1111-1111-1111-111111111111', org2 = '22222222-2222-2222-2222-222222222222', groupID = '33333333-3333-3333-3333-333333333333', secondGroup = '44444444-4444-4444-4444-444444444444', address = '0x' + '1'.repeat(40)
const group = { id: groupID, slug: 'readers', name: 'Readers', description: '', isOrgAdmin: false, isOrgReadonlyAdmin: false, verboseErrors: false, allowedMethods: ['eth_call', 'custom_rpc', 'eth_newFilter'], claims: ['deploy', 'future-claim'], rpcCredential: { fromEnv: 'BANK_RPC', futureReference: { preserve: true } }, preservedGroup: { nested: true } }
async function projectWith(catalogs: Record<string, JSONObject> = {}) {
  const draft: JSONObject = { apiVersion: 'ops.policy-draft/v1alpha1', kind: 'PolicyDraft', sourceRevision: 'proposal', environment: 'local', chainId: '31337', evaluatorVersion: 'policycore/native-v1alpha4', profile: 'catalog-runtime-creation-observed/v1', organizations: [{ id: org, slug: 'bank', name: 'Bank' }, { id: org2, slug: 'other', name: 'Other Bank' }], documents: [{ kind: 'groups', organizationId: org, path: 'groups.json' }, { kind: 'groups', organizationId: org2, path: 'other-groups.json' }] }
  const values: Record<string, JSONObject> = { 'draft.json': draft, 'groups.json': { apiVersion: 'ops.policy-document/v1alpha1', kind: 'groups', organizationId: org, spec: { groups: [group] } }, 'other-groups.json': { apiVersion: 'ops.policy-document/v1alpha1', kind: 'groups', organizationId: org2, spec: { groups: [{ ...group, id: secondGroup, name: 'Other Readers', allowedMethods: [], claims: [] }] } } }
  for (const [key, value] of Object.entries(catalogs)) { draft[key] = { path: key.toLowerCase() + '.json' }; values[key.toLowerCase() + '.json'] = value }
  return loadSourceProject(Object.entries(values).map(([path, value]) => { const raw = JSON.stringify(value); return { path, size: raw.length, read: async () => raw } }))
}
afterEach(() => { cleanup(); vi.unstubAllGlobals() })
it('uses native presets, section controls and rich inspection while preserving custom methods, claims and source fields without network writes', async () => {
  const project = await projectWith(), onChange = vi.fn(), fetch = vi.fn(); vi.stubGlobal('fetch', fetch)
  expect(NATIVE_PRESETS.every(p => p.methods.every(m => NATIVE_METHODS.includes(m)))).toBe(true)
  expect(NATIVE_METHODS).toContain('eth_accounts'); expect(NATIVE_METHODS).toContain('net_listening'); expect(NATIVE_METHODS).not.toContain('eth_sendTransaction'); expect(NATIVE_METHODS).not.toContain('eth_newFilter')
  const { rerender } = render(<SourceOrganizations project={project} root="source" organization={org} groupsPage editing onChange={onChange} onOrganization={() => {}} />)
  await userEvent.click(screen.getByTitle('Edit access settings')); const dialog = screen.getByRole('dialog')
  await userEvent.click(within(dialog).getByRole('button', { name: /Network reader/ }))
  await userEvent.click(within(dialog).getByRole('button', { name: 'Select all account state' }))
  await userEvent.click(within(dialog).getByRole('button', { name: 'Clear network and fees' }))
  expect(within(dialog).getByLabelText('Account state: 5 of 5 selected')).toHaveTextContent('5 / 5')
  await userEvent.click(within(dialog).getByRole('button', { name: 'Save access draft' }))
  // Access through native model, retaining imported/unknown rows and flags.
  const actual = (object(documentValue(onChange.mock.calls[0][0], 'source', 'groups.json').spec).groups as JSONObject[])[0]
  expect(actual.allowedMethods).toEqual(expect.arrayContaining(['custom_rpc', 'eth_newFilter', 'eth_getBalance']))
  expect(actual.allowedMethods).not.toContain('eth_chainId'); expect(actual.claims).toEqual(['deploy', 'future-claim']); expect(actual.preservedGroup).toEqual({ nested: true }); expect(actual.rpcCredential).toEqual(group.rpcCredential); expect(fetch).not.toHaveBeenCalled()
  rerender(<SourceOrganizations project={onChange.mock.calls[0][0]} root="source" organization={org} groupsPage editing={false} onChange={onChange} onOrganization={() => {}} />)
  await userEvent.click(screen.getByTitle('View declared permissions'))
  expect(screen.getByText('Execution administrator')).toBeInTheDocument(); expect(screen.getByText(/Expands to admin, deploy and upgrade/)).toBeInTheDocument(); expect(screen.getByText('Imported additional methods · 2')).toBeInTheDocument()
})
it.each(['admin', 'readonly', 'member'])('serializes %s organization role using native claims rules', async role => {
  const project = await projectWith(), onChange = vi.fn()
  render(<SourceOrganizations project={project} root="source" organization={org} groupsPage editing onChange={onChange} onOrganization={() => {}} />)
  await userEvent.click(screen.getByTitle('Edit group draft')); await userEvent.click(screen.getByRole('radio', { name: role === 'admin' ? 'Organization admin' : role === 'readonly' ? 'Read-only organization admin' : 'Member' })); await userEvent.click(screen.getByRole('button', { name: 'Save group draft' }))
  const actual = (object(documentValue(onChange.mock.calls[0][0], 'source', 'groups.json').spec).groups as JSONObject[])[0]
  expect(actual.isOrgAdmin).toBe(role === 'admin'); expect(actual.isOrgReadonlyAdmin).toBe(role === 'readonly'); expect(actual.claims).toEqual(role === 'admin' ? [] : group.claims)
})
const price = { id: '55555555-5555-5555-5555-555555555555', tokenAddress: 'native', symbol: 'ETH', decimals: 18, pricesByCurrency: { usd: 1.23 }, coingeckoId: 'ethereum', customPrice: { preserve: true } }
const override = { id: '66666666-6666-6666-6666-666666666666', address, thresholdFiat: 25, note: 'Existing', customThreshold: ['preserve'] }
async function complianceProject() {
  const policy = defaultComplianceOrganization(org); policy.customOrg = 'preserve'; policy.spec = { ...object(policy.spec), customSpec: true, settings: { ...object(object(policy.spec).settings), customSetting: true }, tokenPrices: [price], addressThresholds: [override] }
  return projectWith({ complianceCatalog: { apiVersion: 'ops.compliance-policy/v1alpha1', kind: 'CompliancePolicy', catalogField: true, organizations: [policy, defaultComplianceOrganization(org2)], sanctions: [{ id: 'sanction' }] } })
}
it('edits only compliance threshold while retaining prices, overrides, sibling organizations and unknown fields', async () => {
  const project = await complianceProject(), onChange = vi.fn(), before = documentValue(project, 'source', 'compliancecatalog.json')
  render(<SourceCatalogs project={project} root="source" organization={org} page="compliance-source" editing onChange={onChange} />)
  await userEvent.click(screen.getByRole('button', { name: 'Edit compliance settings' })); const dialog = screen.getByRole('dialog')
  fireEvent.change(within(dialog).getByLabelText('Default fiat threshold'), { target: { value: '0.29' } }); await userEvent.click(within(dialog).getByRole('button', { name: 'Save draft' }))
  const result = documentValue(onChange.mock.calls[0][0], 'source', 'compliancecatalog.json'), rows = result.organizations as JSONObject[], old = before.organizations as JSONObject[]
  expect(result.sanctions).toEqual(before.sanctions); expect(result.catalogField).toBe(true); expect(rows[1]).toEqual(old[1]); expect(rows[0]).toEqual({ ...old[0], spec: { ...object(old[0].spec), settings: { ...object(object(old[0].spec).settings), thresholdFiat: 0.29 } } })
})
it('adds configured token currency prices, updates retained IDs and removes rows through dedicated controls', async () => {
  const project = await complianceProject(), onChange = vi.fn(); const { rerender } = render(<SourceCatalogs project={project} root="source" organization={org} page="compliance-source" editing onChange={onChange} />)
  await userEvent.click(screen.getByRole('button', { name: 'Edit ETH price' })); let dialog = screen.getByRole('dialog')
  await userEvent.click(within(dialog).getByRole('button', { name: 'Add currency price' })); fireEvent.change(within(dialog).getByLabelText('Configured price 2'), { target: { value: '0.125' } }); await userEvent.click(within(dialog).getByRole('button', { name: 'Save draft' }))
  let next = onChange.mock.calls.at(-1)![0]; let row = (object((documentValue(next, 'source', 'compliancecatalog.json').organizations as JSONObject[])[0].spec).tokenPrices as JSONObject[])[0]
  expect(row).toEqual({ ...price, pricesByCurrency: { usd: 1.23, eur: 0.125 } })
  rerender(<SourceCatalogs project={next} root="source" organization={org} page="compliance-source" editing onChange={onChange} />)
  await userEvent.click(screen.getByRole('button', { name: 'Add token price' })); dialog = screen.getByRole('dialog')
  fireEvent.change(within(dialog).getByLabelText('Token address or native'), { target: { value: '0x' + '9'.repeat(40) } }); fireEvent.change(within(dialog).getByLabelText('Symbol'), { target: { value: 'USD' } }); fireEvent.change(within(dialog).getByLabelText('Token decimals'), { target: { value: '6' } }); await userEvent.click(within(dialog).getByRole('button', { name: 'Save draft' }))
  next = onChange.mock.calls.at(-1)![0]; expect((object((documentValue(next, 'source', 'compliancecatalog.json').organizations as JSONObject[])[0].spec).tokenPrices as JSONObject[])).toHaveLength(2)
  rerender(<SourceCatalogs project={next} root="source" organization={org} page="compliance-source" editing onChange={onChange} />)
  await userEvent.click(screen.getByRole('button', { name: 'Remove USD price' })); expect((object((documentValue(onChange.mock.calls.at(-1)![0], 'source', 'compliancecatalog.json').organizations as JSONObject[])[0].spec).tokenPrices as JSONObject[])).toHaveLength(1)
  await userEvent.click(screen.getByRole('button', { name: 'Edit address threshold 1' })); dialog = screen.getByRole('dialog'); fireEvent.change(within(dialog).getByLabelText('Override fiat threshold'), { target: { value: '0' } }); await userEvent.click(within(dialog).getByRole('button', { name: 'Save draft' }))
  row = (object((documentValue(onChange.mock.calls.at(-1)![0], 'source', 'compliancecatalog.json').organizations as JSONObject[])[0].spec).addressThresholds as JSONObject[])[0]; expect(row).toEqual({ ...override, thresholdFiat: 0 })
  await userEvent.click(screen.getByRole('button', { name: 'Remove address threshold 1' })); expect((object((documentValue(onChange.mock.calls.at(-1)![0], 'source', 'compliancecatalog.json').organizations as JSONObject[])[0].spec).addressThresholds as JSONObject[])).toHaveLength(0)
})
it('rejects non-roundtripping fiat precision, invalid thresholds, TTLs and duplicate addresses; readonly shows readable settings', async () => {
  expect(complianceDecimal('0.29', 'Threshold', true)).toBe(0.29); expect(complianceDecimal('0.00000001', 'Price')).toBe(1e-8)
  for (const value of ['0.123456789012345678901', '-1', '1e3', 'Infinity']) expect(() => complianceDecimal(value, 'Price')).toThrow()
  expect(() => complianceDecimal('0.291', 'Threshold', true)).toThrow(/two decimal/); expect(() => complianceInteger('86401', 'Age', 1, 86400)).toThrow(); expect(() => validateComplianceRow({ ...override, id: '77777777-7777-7777-7777-777777777777' }, [override], [price], 1, false)).toThrow(/already configured/)
  const project = await complianceProject(); render(<SourceCatalogs project={project} root="source" organization={org} page="compliance-source" editing={false} onChange={vi.fn()} />)
  expect(screen.getByText('1000 USD')).toBeInTheDocument(); expect(screen.getByText('USD: 1.23 (configured)')).toBeInTheDocument(); expect(screen.queryByRole('button', { name: 'Edit compliance settings' })).not.toBeInTheDocument()
})
it('uses named compatible profile/org/group pickers and clears old groups on organization changes', async () => {
  const profile = { id: 'staff-profile', name: 'Staff login', kind: 'azure-service/v1', factSource: 'appRoles' }, mapping = { id: 'mapping', profileId: profile.id, organizationId: org, principalKind: 'service', fact: { kind: 'azure.role', value: 'Exact.Role' }, groupIds: [groupID], unknown: true }, project = await projectWith({ identityCatalog: { apiVersion: 'ops.identity-catalog/v1alpha1', kind: 'IdentityCatalog', profiles: [profile, { id: 'identity-only', kind: 'privado-identity/v1' }], issuers: [], mappings: [mapping] } }), onChange = vi.fn()
  render(<SourceCatalogs project={project} root="source" organization={org} page="claim-mappings" editing onChange={onChange} />)
  await userEvent.click(screen.getByRole('button', { name: 'Edit mapping' })); const dialog = screen.getByRole('dialog')
  expect(within(dialog).getByRole('option', { name: /Staff login.*staff-profile.*azure-service/ })).toBeInTheDocument(); expect(within(dialog).getByLabelText(/Readers/)).toBeChecked()
  fireEvent.change(within(dialog).getByLabelText('Mapping organization'), { target: { value: org2 } }); expect(within(dialog).queryByLabelText(/^Readers/)).not.toBeInTheDocument(); expect(within(dialog).getByLabelText(/Other Readers/)).not.toBeChecked(); await userEvent.click(within(dialog).getByLabelText(/Other Readers/)); await userEvent.click(within(dialog).getByRole('button', { name: 'Save mapping draft' }))
  const result = documentValue(onChange.mock.calls[0][0], 'source', 'identitycatalog.json'); expect(result.mappings).toEqual([{ ...mapping, organizationId: org2, groupIds: [secondGroup] }]); expect(result.profiles).toEqual([profile, { id: 'identity-only', kind: 'privado-identity/v1' }]); expect(profileCompatibility({ kind: 'privado-identity/v1' }).factKind).toBe(''); expect(profileCompatibility({ kind: 'privado-role-query/v1', predicates: [{ id: 'banker' }] })).toEqual({ principalKind: 'human', factKind: 'privado.predicate', predicates: ['banker'] })
})
const abi = [{ type: 'function', name: 'transfer', inputs: [{ name: 'to', type: 'address' }], outputs: [], stateMutability: 'nonpayable' }, { type: 'event', name: 'Transfer', inputs: [] }]
function localFile(raw: string, name = 'contract.json') { const file = new File([raw], name); Object.defineProperty(file, 'text', { configurable: true, value: async () => raw }); return file }
it('uploads artifact ABI with counts, retains prior valid ABI on malformed/duplicate/oversized input and fences a slow file after source generation changes', async () => {
  const onSave = vi.fn(), { rerender } = render(<ABIForm value={[]} identity="source:contract" generation={0} onClose={() => {}} onSave={onSave} />)
  fireEvent.change(screen.getByLabelText('Upload or replace ABI file'), { target: { files: [localFile(JSON.stringify({ abi, compiler: 'solc' }), 'artifact.json')] } }); await screen.findByText(/Loaded file: artifact.json.*2 entries · 1 functions · 1 events/)
  fireEvent.change(screen.getByLabelText('Upload or replace ABI file'), { target: { files: [localFile('{"abi":[],"abi":[]}')] } }); expect(await screen.findByRole('alert')).toHaveTextContent('previous saved ABI remains unchanged'); expect(screen.getByRole('status')).toHaveTextContent('2 entries')
  const oversized = localFile('[]'); Object.defineProperty(oversized, 'size', { value: (1 << 20) + 1 }); fireEvent.change(screen.getByLabelText('Upload or replace ABI file'), { target: { files: [oversized] } }); expect(await screen.findByRole('alert')).toHaveTextContent('at most 1 MiB')
  let finish!: (raw: string) => void; const slow = localFile('[]', 'old.json'); Object.defineProperty(slow, 'text', { configurable: true, value: () => new Promise<string>(resolve => { finish = resolve }) });
  fireEvent.change(screen.getByLabelText('Upload or replace ABI file'), { target: { files: [slow] } }); rerender(<ABIForm value={[]} identity="source:contract" generation={1} onClose={() => {}} onSave={onSave} />); await act(async () => { finish('[]') }); expect(screen.getByRole('status')).toHaveTextContent('artifact.json'); await userEvent.click(screen.getByRole('button', { name: 'Save ABI draft' })); expect(onSave).toHaveBeenCalledWith(abi)
  expect(() => parseAuthoringABI('[{"type":"function","type":"event","name":"x"}]')).toThrow(); expect(() => parseAuthoringABI('{"abi":{}}')).toThrow(); expect(() => parseAuthoringABI('[{"type":"nonsense"}]')).toThrow()
})
it('replaces only a contract ABI through the catalog action, preserving flags, grants and unknown fields', async () => {
  let project = await projectWith(); const doc: JSONObject = { apiVersion: 'ops.policy-document/v1alpha1', kind: 'contract-registry', organizationId: org, spec: { contracts: [{ id: groupID, name: 'Vault', address, abi: [], allowVisibleToUnlock: true, eventsAllowDynamicPayload: true, readGrants: [{ groupId: groupID }], futureContract: { preserve: true } }] } }
  const draft = project.roots[0].draft; draft.documents.push({ kind: 'contract-registry', organizationId: org, path: 'registry.json' }); const raw = JSON.stringify(doc); project = { ...project, roots: [{ ...project.roots[0], files: [...project.roots[0].files, { path: 'registry.json', originalText: raw, originalBytes: new TextEncoder().encode(raw), editedText: null }] }] }
  const onChange = vi.fn(); render(<SourceCatalogs project={project} root="source" organization={org} page="contracts" editing onChange={onChange} />)
  await userEvent.click(screen.getByRole('button', { name: 'ABI · 0 functions · 0 events' })); fireEvent.change(screen.getByLabelText('Upload or replace ABI file'), { target: { files: [localFile(JSON.stringify(abi))] } }); await waitFor(() => expect(screen.getByRole('status')).toHaveTextContent('2 entries')); await userEvent.click(screen.getByRole('button', { name: 'Save ABI draft' })); expect(object(documentValue(onChange.mock.calls[0][0], 'source', 'registry.json').spec).contracts).toEqual([{ ...(object(doc.spec).contracts as JSONObject[])[0], abi }])
})
it('retains unresolved imported mapping references on unrelated edits and exposes explicit remove controls', async () => {
  const mapping = { id: 'unresolved', profileId: 'removed-profile', organizationId: org, principalKind: 'human', fact: { kind: 'azure.role', value: 'Exact.Role' }, groupIds: ['removed-group'], preserve: { future: true } }, project = await projectWith({ identityCatalog: { apiVersion: 'ops.identity-catalog/v1alpha1', kind: 'IdentityCatalog', profiles: [], issuers: [], mappings: [mapping] } }), onChange = vi.fn()
  render(<SourceCatalogs project={project} root="source" organization={org} page="claim-mappings" editing onChange={onChange} />)
  expect(screen.getByText('Unresolved imported profile')).toBeInTheDocument(); await userEvent.click(screen.getByRole('button', { name: 'Edit mapping' })); const dialog = screen.getByRole('dialog'); expect(within(dialog).getByText(/Unresolved imported group/)).toBeInTheDocument(); fireEvent.change(within(dialog).getByLabelText('Mapping ID'), { target: { value: 'retained-reference' } }); await userEvent.click(within(dialog).getByRole('button', { name: 'Save mapping draft' })); expect(documentValue(onChange.mock.calls[0][0], 'source', 'identitycatalog.json').mappings).toEqual([{ ...mapping, id: 'retained-reference' }])
})

it('retains unfinished dedicated compliance controls across pane suspension and clears canceled fields', async () => {
  const project = await complianceProject()
  function Retained({ visible }: { visible: boolean }) {
    const [state, setState] = useState<AuthoringState>({})
    return <SourceAuthoringProvider project={project} state={state} update={(key, entry) => setState(s => ({ ...s, [key]: entry }))} clear={prefix => setState(s => Object.fromEntries(Object.entries(s).filter(([key]) => !key.startsWith(prefix))))}><SourceAuthoringScope id="compliance-source" root="source" path="compliancecatalog.json">{visible && <SourceCatalogs project={project} root="source" organization={org} page="compliance-source" editing onChange={vi.fn()} />}</SourceAuthoringScope></SourceAuthoringProvider>
  }
  const page = render(<Retained visible />); await userEvent.click(screen.getByRole('button', { name: 'Edit compliance settings' })); fireEvent.change(screen.getByLabelText('Default fiat threshold'), { target: { value: 'unfinished 0.29' } }); page.rerender(<Retained visible={false} />); page.rerender(<Retained visible />); expect(screen.getByLabelText('Default fiat threshold')).toHaveValue('unfinished 0.29'); await userEvent.click(screen.getByRole('button', { name: 'Cancel' })); await userEvent.click(screen.getByRole('button', { name: 'Edit compliance settings' })); expect(screen.getByLabelText('Default fiat threshold')).toHaveValue('1000'); await userEvent.click(screen.getByRole('button', { name: 'Cancel' }));
  await userEvent.click(screen.getByRole('button', { name: 'Add token price' })); fireEvent.change(screen.getByLabelText('Symbol'), { target: { value: 'Unfinished' } }); fireEvent.change(screen.getByLabelText('Token decimals'), { target: { value: 'invalid 6' } }); page.rerender(<Retained visible={false} />); page.rerender(<Retained visible />); expect(screen.getByLabelText('Symbol')).toHaveValue('Unfinished'); expect(screen.getByLabelText('Token decimals')).toHaveValue('invalid 6')
})
