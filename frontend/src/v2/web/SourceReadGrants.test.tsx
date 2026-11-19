import '@testing-library/jest-dom/vitest'
import { useState } from 'react'
import { cleanup, fireEvent, render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, expect, it, vi } from 'vitest'
import { SourceCatalogs } from './SourceCatalogs'
import { SourceReadGrants } from './SourceReadGrants'
import { documentValue, loadSavedSourcePackage, loadSourceProject, sourcePackage, type JSONObject, type SourceProject } from './sourceProject'
const org = '11111111-1111-4111-8111-111111111111', reader = '22222222-2222-4222-8222-222222222222', operator = '33333333-3333-4333-8333-333333333333'
const transferTopic = '0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef'
const abi = [
  { type: 'event', name: 'Transfer', anonymous: false, inputs: [{ name: 'from', type: 'address', indexed: true }, { name: 'to', type: 'address', indexed: true }, { name: 'value', type: 'uint256', indexed: false }] },
  { type: 'event', name: 'Flagged', anonymous: false, inputs: [{ name: 'accepted', type: 'bool', indexed: false }, { name: 'tag', type: 'bytes4', indexed: false }] },
  { type: 'event', name: 'PrivateAnonymous', anonymous: true, inputs: [] },
]
const choices = [{ id: reader, slug: 'reader', name: 'Bank Readers' }, { id: operator, slug: 'operators', name: 'Bank Operators' }]
const contract = (readGrants: unknown[] = []): JSONObject => ({ id: '44444444-4444-4444-8444-444444444444', name: 'Bank token', address: '0x' + '1'.repeat(40), abi, allowVisibleToUnlock: false, eventsAllowDynamicPayload: false, readGrants })
function component(value = contract(), editing = true) { const onChange = vi.fn(); render(<SourceReadGrants contract={value} groups={choices} editing={editing} onChange={onChange} />); return onChange }
async function add() {
  await userEvent.click(screen.getByRole('button', { name: 'Add read grant' }))
  const dialog = screen.getAllByRole('dialog').at(-1)!
  fireEvent.change(within(dialog).getByLabelText('Group'), { target: { value: reader } })
  await userEvent.click(within(dialog).getByLabelText('Specific events only'))
  return dialog
}
afterEach(cleanup)
it('offers named groups and ABI events, retaining OR/self and exact large scalar constraints', async () => {
  const onChange = component(), dialog = await add()
  expect(within(dialog).getByRole('option', { name: 'Bank Readers (reader)' })).toHaveValue(reader)
  expect(within(dialog).queryByRole('button', { name: /PrivateAnonymous/ })).not.toBeInTheDocument()
  await userEvent.click(within(dialog).getByRole('button', { name: 'Transfer(address,address,uint256)' }))
  expect(within(dialog).getByText(/any one of its parameter constraints matches \(OR\)/)).toBeInTheDocument()
  expect(within(dialog).getByLabelText('from constraint')).toHaveValue('self')
  fireEvent.change(within(dialog).getByLabelText('to constraint'), { target: { value: 'any' } })
  fireEvent.change(within(dialog).getByLabelText('value constraint'), { target: { value: 'custom' } })
  const literal = '0x' + 'f'.repeat(64)
  fireEvent.change(within(dialog).getByLabelText('value custom value'), { target: { value: literal } })
  await userEvent.click(within(dialog).getByRole('button', { name: 'Save grant draft' }))
  expect(onChange).toHaveBeenCalledTimes(1)
  expect(onChange.mock.calls[0][0]).toEqual([{ id: expect.any(String), groupId: reader, eventRules: { mode: 'allowlist', rules: [{ topic0: transferTopic, name: 'Transfer', paramRules: [{ index: 0, must_be: 'self' }, { index: 2, must_be: literal }] }] } }])
})
it('writes booleans and fixed bytes in the native Go schema widths', async () => {
  const onChange = component(), dialog = await add()
  await userEvent.click(within(dialog).getByRole('button', { name: 'Flagged(bool,bytes4)' }))
  fireEvent.change(within(dialog).getByLabelText('accepted constraint'), { target: { value: 'true' } })
  fireEvent.change(within(dialog).getByLabelText('tag constraint'), { target: { value: 'custom' } })
  fireEvent.change(within(dialog).getByLabelText('tag custom value'), { target: { value: '0xaabb' } })
  await userEvent.click(within(dialog).getByRole('button', { name: 'Save grant draft' }))
  expect(onChange.mock.calls[0][0][0].eventRules.rules[0].paramRules).toEqual([{ index: 0, must_be: '0x' + '0'.repeat(63) + '1' }, { index: 1, must_be: '0xaabb0000' }])
})
it('checks integer ranges without reinterpreting a short unsigned value as signed negative', async () => {
  const onChange = component({ ...contract(), abi: [{ type: 'event', name: 'Small', inputs: [{ name: 'count', type: 'uint8', indexed: true }, { name: 'delta', type: 'int8', indexed: false }] }] }), dialog = await add()
  await userEvent.click(within(dialog).getByRole('button', { name: 'Small(uint8,int8)' }))
  for (const name of ['count', 'delta']) fireEvent.change(within(dialog).getByLabelText(`${name} constraint`), { target: { value: 'custom' } })
  fireEvent.change(within(dialog).getByLabelText('count custom value'), { target: { value: '0x0100' } })
  fireEvent.change(within(dialog).getByLabelText('delta custom value'), { target: { value: '0x7f' } })
  await userEvent.click(within(dialog).getByRole('button', { name: 'Save grant draft' }))
  expect(within(dialog).getByRole('alert')).toHaveTextContent('outside the uint8 range')
  fireEvent.change(within(dialog).getByLabelText('count custom value'), { target: { value: '0xff' } })
  fireEvent.change(within(dialog).getByLabelText('delta custom value'), { target: { value: '0xff' } })
  await userEvent.click(within(dialog).getByRole('button', { name: 'Save grant draft' }))
  expect(within(dialog).getByRole('alert')).toHaveTextContent('outside the int8 range')
  expect(onChange).not.toHaveBeenCalled()
  const negative = '0x' + 'f'.repeat(64)
  fireEvent.change(within(dialog).getByLabelText('delta custom value'), { target: { value: negative } })
  await userEvent.click(within(dialog).getByRole('button', { name: 'Save grant draft' }))
  expect(onChange.mock.calls[0][0][0].eventRules.rules[0].paramRules).toEqual([{ index: 0, must_be: '0x' + '0'.repeat(62) + 'ff' }, { index: 1, must_be: negative }])
})
it('refuses oversized or incomplete custom values instead of truncating or dropping them', async () => {
  const onChange = component(), dialog = await add()
  await userEvent.click(within(dialog).getByRole('button', { name: 'Transfer(address,address,uint256)' }))
  fireEvent.change(within(dialog).getByLabelText('from constraint'), { target: { value: 'custom' } })
  await userEvent.click(within(dialog).getByRole('button', { name: 'Save grant draft' }))
  expect(within(dialog).getByRole('alert')).toHaveTextContent('0x-prefixed hex value')
  fireEvent.change(within(dialog).getByLabelText('from custom value'), { target: { value: '0x' + '1'.repeat(42) } })
  await userEvent.click(within(dialog).getByRole('button', { name: 'Save grant draft' }))
  expect(within(dialog).getByRole('alert')).toHaveTextContent('will not be truncated')
  fireEvent.change(within(dialog).getByLabelText('from custom value'), { target: { value: '0x12' } })
  await userEvent.click(within(dialog).getByRole('button', { name: 'Save grant draft' }))
  expect(within(dialog).getByRole('alert')).toHaveTextContent('exactly 40 hex characters')
  expect(onChange).not.toHaveBeenCalled()
})
it('preserves extra grant/event/parameter fields when changing only the selected group', async () => {
  const grant = { id: 'existing', groupId: reader, futureGrant: { preserved: true }, eventRules: { mode: 'allowlist', futureRules: 7, rules: [{ topic0: transferTopic, name: 'Transfer', futureEvent: 'keep', paramRules: [{ index: 0, must_be: 'self', futureParam: ['keep'] }] }] } }
  const onChange = component(contract([grant]))
  await userEvent.click(screen.getByRole('button', { name: 'Edit read grant for Bank Readers' }))
  fireEvent.change(screen.getByLabelText('Group'), { target: { value: operator } })
  await userEvent.click(screen.getByRole('button', { name: 'Save grant draft' }))
  expect(onChange.mock.calls[0][0]).toEqual([{ ...grant, groupId: operator }])
})
it('preserves unresolved events and keeps advanced JSON available', async () => {
  const grant = { id: 'existing', groupId: reader, eventRules: { mode: 'allowlist', rules: [{ topic0: '0x' + 'a'.repeat(64), name: 'LegacyUnknown', paramRules: [] }] } }
  const onChange = component(contract([grant]))
  await userEvent.click(screen.getByRole('button', { name: 'Edit read grant for Bank Readers' }))
  expect(screen.getByText(/does not match an event in the current ABI/)).toBeInTheDocument()
  await userEvent.click(screen.getByRole('button', { name: 'Advanced grant JSON' }))
  expect(screen.getByLabelText('Custom event rules')).toHaveValue(JSON.stringify(grant.eventRules.rules, null, 2))
  fireEvent.change(screen.getByLabelText('Group ID'), { target: { value: operator } })
  await userEvent.click(screen.getByRole('button', { name: 'Save draft' }))
  expect(onChange.mock.calls[0][0]).toEqual([{ ...grant, groupId: operator }])
})
it('allows read-only inspection without mutation controls or writes', async () => {
  const onChange = component(contract([{ id: 'existing', groupId: reader, eventRules: { mode: 'all', rules: [] } }]), false)
  expect(screen.queryByRole('button', { name: 'Add read grant' })).not.toBeInTheDocument()
  expect(screen.queryByRole('button', { name: /Remove read grant/ })).not.toBeInTheDocument()
  await userEvent.click(screen.getByRole('button', { name: 'Bank Readers' }))
  expect(screen.getByLabelText('Group')).toBeDisabled()
  expect(screen.queryByRole('button', { name: 'Save grant draft' })).not.toBeInTheDocument()
  await userEvent.click(within(screen.getByRole('dialog')).getAllByRole('button', { name: 'Close', exact: true })[0])
  expect(onChange).not.toHaveBeenCalled()
})
it('exports and recovers a guided SourceCatalogs edit without changing other files', async () => {
  const draft = { apiVersion: 'ops.policy-draft/v1alpha1', kind: 'PolicyDraft', sourceRevision: 'guided-grant', environment: 'local', chainId: '31337', evaluatorVersion: 'policycore/native-v1alpha1', profile: 'catalog-foundation/v1', organizations: [{ id: org, name: 'Bank', slug: 'bank' }], documents: [{ kind: 'groups', organizationId: org, path: 'groups.json' }, { kind: 'contract-registry', organizationId: org, path: 'registry.json' }, { kind: 'execution-rules', organizationId: org, path: 'execution.json' }] }
  const groups = { apiVersion: 'ops.policy-document/v1alpha1', kind: 'groups', organizationId: org, spec: { groups: choices.map(group => ({ ...group, description: '', isOrgAdmin: false, isOrgReadonlyAdmin: false, allowedMethods: ['eth_call'], claims: [], verboseErrors: false })) } }
  const registry = { apiVersion: 'ops.policy-document/v1alpha1', kind: 'contract-registry', organizationId: org, spec: { contracts: [contract()] } }
  const execution = { apiVersion: 'ops.policy-document/v1alpha1', kind: 'execution-rules', organizationId: org, spec: { policy: { apiVersion: 'privacy.gateway.fm/v1alpha1', kind: 'ContractExecutionPolicy', org, nestedCalls: 'requireOwnRule', bindings: [] } } }
  const initial = await loadSourceProject([['draft.json', draft], ['groups.json', groups], ['registry.json', registry], ['execution.json', execution]].map(([path, value]) => { const raw = JSON.stringify(value); return { path: String(path), size: raw.length, read: async () => raw } }))
  let latest = initial
  function App() { const [project, setProject] = useState<SourceProject>(initial); return <SourceCatalogs project={project} root="source" organization={org} page="contracts" editing onChange={next => { latest = next; setProject(next) }} /> }
  render(<App />)
  await userEvent.click(screen.getByRole('button', { name: 'Read grants' }))
  const dialog = await add()
  await userEvent.click(within(dialog).getByRole('button', { name: 'Transfer(address,address,uint256)' }))
  await userEvent.click(within(dialog).getByRole('button', { name: 'Save grant draft' }))
  const restored = await loadSavedSourcePackage(JSON.stringify(sourcePackage(latest))), result = documentValue(restored, 'source', 'registry.json')
  expect((result.spec as JSONObject).contracts).toEqual([{ ...contract(), readGrants: [{ id: expect.any(String), groupId: reader, eventRules: { mode: 'allowlist', rules: [{ name: 'Transfer', topic0: transferTopic, paramRules: [{ index: 0, must_be: 'self' }, { index: 1, must_be: 'self' }] }] } }] }])
  for (const path of ['draft.json', 'groups.json', 'execution.json']) expect(sourcePackage(restored).roots[0].files.find(file => file.path === path)).toEqual(sourcePackage(initial).roots[0].files.find(file => file.path === path))
})

it('offers only unassigned groups and refuses a duplicate group even through advanced editing', async () => {
  const onChange = component(contract([{ id: 'existing', groupId: reader, eventRules: { mode: 'none', rules: [] } }]))
  await userEvent.click(screen.getByRole('button', { name: 'Add read grant' }))
  const dialog = screen.getByRole('dialog')
  expect(within(dialog).queryByRole('option', { name: 'Bank Readers (reader)' })).not.toBeInTheDocument()
  expect(within(dialog).getByRole('option', { name: 'Bank Operators (operators)' })).toHaveValue(operator)
  await userEvent.click(within(dialog).getByRole('button', { name: 'Advanced grant JSON' }))
  fireEvent.change(within(dialog).getByLabelText('Group ID'), { target: { value: reader } })
  await userEvent.click(within(dialog).getByRole('button', { name: 'Save draft' }))
  expect(within(dialog).getByRole('alert')).toHaveTextContent('already has a read grant')
  expect(onChange).not.toHaveBeenCalled()
})
