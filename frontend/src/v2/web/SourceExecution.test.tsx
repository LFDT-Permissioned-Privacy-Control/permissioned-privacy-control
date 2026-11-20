import '@testing-library/jest-dom/vitest'
import { cleanup, fireEvent, render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, expect, it, vi } from 'vitest'
import { SourceExecution } from './SourceExecution'
import { createGroup, documentValue, loadSourceProject, object, sourcePackage, updateDocument, type JSONObject } from './sourceProject'
const org = '11111111-1111-4111-8111-111111111111', first = '22222222-2222-4222-8222-222222222222', second = '33333333-3333-4333-8333-333333333333', address = '0x' + '1'.repeat(40)
async function fixture() {
  const draft = { apiVersion: 'ops.policy-draft/v1alpha1', kind: 'PolicyDraft', sourceRevision: 'execution-parity', environment: 'local', chainId: '31337', evaluatorVersion: 'policycore/native-v1alpha4', profile: 'catalog-runtime-creation-observed/v1', organizations: [{ id: org, name: 'Bank', slug: 'bank' }], documents: [{ kind: 'groups', organizationId: org, path: 'groups.json' }, { kind: 'contract-registry', organizationId: org, path: 'registry.json' }, { kind: 'execution-rules', organizationId: org, path: 'execution.json' }] }
  const groups = { apiVersion: 'ops.policy-document/v1alpha1', kind: 'groups', organizationId: org, spec: { groups: [first, second].map((id, i) => ({ id, name: i ? 'Operators' : 'Readers', slug: i ? 'operators' : 'readers', description: '', isOrgAdmin: false, isOrgReadonlyAdmin: false, allowedMethods: [], claims: [], verboseErrors: false })) } }
  const registry = { apiVersion: 'ops.policy-document/v1alpha1', kind: 'contract-registry', organizationId: org, spec: { contracts: [{ id: '44444444-4444-4444-8444-444444444444', name: 'Vault', address, abi: [], allowVisibleToUnlock: false, eventsAllowDynamicPayload: false, readGrants: [] }] } }
  const execution = { apiVersion: 'ops.policy-document/v1alpha1', kind: 'execution-rules', organizationId: org, futureEnvelope: true, spec: { futureSpec: 7, policy: { apiVersion: 'privacy.gateway.fm/v1alpha4', kind: 'ContractExecutionPolicy', org, nestedCalls: 'requireOwnRule', futurePolicy: ['retain'], bindings: [{ group: first, futureBinding: { keep: true }, allow: [{ storageAddress: address, selector: '*', abiDigest: '', maxValue: '0', minDepth: 0, maxDepth: 0, futureRule: true }] }, { group: second, allow: [] }] } } }
  return loadSourceProject([['draft.json', draft], ['groups.json', groups], ['registry.json', registry], ['execution.json', execution]].map(([path, value]) => { const text = JSON.stringify(value); return { path: String(path), size: text.length, read: async () => text } }))
}
afterEach(cleanup)
it('shows structured readonly frame inspection and exact source-only context without mutation controls', async () => {
  const project = await fixture(), onChange = vi.fn(); render(<SourceExecution project={project} root="source" organization={org} editing={false} onChange={onChange} check={() => {}} onOpenSource={() => {}} />)
  expect(screen.getByText('≤ 0 wei')).toBeInTheDocument(); expect(screen.getByText('Depth 0–0')).toBeInTheDocument(); expect(screen.queryByRole('button', { name: 'Remove rule' })).not.toBeInTheDocument(); await userEvent.click(screen.getByRole('button', { name: 'Inspect rule' })); const dialog = screen.getByRole('dialog')
  expect(within(dialog).getByText('0 wei')).toBeInTheDocument(); expect(within(dialog).getByText('Advanced native rule JSON').closest('details')).not.toHaveAttribute('open'); expect(onChange).not.toHaveBeenCalled()
})
it('confirms local removal and preserves sibling native data and exact other files', async () => {
  const project = await fixture(), onChange = vi.fn(), check = vi.fn(); render(<SourceExecution project={project} root="source" organization={org} editing onChange={onChange} check={check} onOpenSource={() => {}} />)
  await userEvent.click(screen.getByRole('button', { name: 'Remove rule' })); expect(onChange).not.toHaveBeenCalled(); await userEvent.click(within(screen.getByRole('dialog')).getByRole('button', { name: 'Cancel' })); expect(onChange).not.toHaveBeenCalled()
  await userEvent.click(screen.getByRole('button', { name: 'Remove rule' })); await userEvent.click(within(screen.getByRole('dialog')).getByRole('button', { name: 'Remove from draft' })); expect(check).toHaveBeenCalledTimes(1)
  const next = onChange.mock.calls[0][0], doc = documentValue(next, 'source', 'execution.json'), policy = object(object(doc.spec).policy)
  expect(doc.futureEnvelope).toBe(true); expect(object(doc.spec).futureSpec).toBe(7); expect(policy.futurePolicy).toEqual(['retain']); expect(policy.bindings).toEqual([{ group: first, futureBinding: { keep: true }, allow: [] }, { group: second, allow: [] }])
  for (const path of ['draft.json', 'groups.json', 'registry.json']) expect(sourcePackage(next).roots[0].files.find(f => f.path === path)).toEqual(sourcePackage(project).roots[0].files.find(f => f.path === path))
})
it('excludes duplicate binding targets and retires an open rule editor when its file changes', async () => {
  const project = await fixture(), p = { project, root: 'source', organization: org, editing: true, onChange: vi.fn(), check: vi.fn(), onOpenSource: vi.fn() }, view = render(<SourceExecution {...p} />)
  expect(within(screen.getByLabelText('Group binding 1')).queryByRole('option', { name: /Operators/ })).not.toBeInTheDocument(); expect(screen.getByRole('button', { name: 'Add group binding' })).toBeDisabled()
  await userEvent.click(screen.getByRole('button', { name: 'Edit rule' })); fireEvent.change(screen.getByLabelText('Maximum native value (wei)'), { target: { value: '99' } })
  const doc = documentValue(project, 'source', 'execution.json'), policy = object(object(doc.spec).policy); const next = updateDocument(project, 'source', 'execution.json', { ...doc, spec: { ...object(doc.spec), policy: { ...policy, bindings: [...(policy.bindings as JSONObject[])].reverse() } } })
  view.rerender(<SourceExecution {...p} project={next} />); expect(screen.queryByRole('dialog')).not.toBeInTheDocument(); expect(p.onChange).not.toHaveBeenCalled()
})

it('requires an explicit preview/confirmation before reassigning a binding to another unbound group', async () => {
  const third = '77777777-7777-4777-8777-777777777777', project = createGroup(await fixture(), 'source', org, { id: third, name: 'Auditors', slug: 'auditors' }), onChange = vi.fn()
  render(<SourceExecution project={project} root="source" organization={org} editing onChange={onChange} check={() => {}} onOpenSource={() => {}} />)
  expect(screen.getByRole('button', { name: 'Execution rules' })).toHaveAttribute('aria-pressed', 'true'); fireEvent.change(screen.getByLabelText('Group binding 1'), { target: { value: third } }); expect(onChange).not.toHaveBeenCalled(); expect(screen.getByRole('dialog')).toHaveTextContent('Assign 1 frame rules from Readers to Auditors'); await userEvent.click(within(screen.getByRole('dialog')).getByRole('button', { name: 'Cancel' })); expect(onChange).not.toHaveBeenCalled()
  fireEvent.change(screen.getByLabelText('Group binding 1'), { target: { value: third } }); await userEvent.click(within(screen.getByRole('dialog')).getByRole('button', { name: 'Reassign in draft' })); const policy = object(object(documentValue(onChange.mock.calls[0][0], 'source', 'execution.json').spec).policy), old = object(object(documentValue(project, 'source', 'execution.json').spec).policy)
  expect((policy.bindings as JSONObject[])[0]).toEqual({ ...(old.bindings as JSONObject[])[0], group: third })
})
