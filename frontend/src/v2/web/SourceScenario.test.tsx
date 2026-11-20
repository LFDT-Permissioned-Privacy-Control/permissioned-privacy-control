import '@testing-library/jest-dom/vitest'
import { webcrypto } from 'node:crypto'
import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, expect, it, vi } from 'vitest'
import { SourceScenario, scenarioDigest } from './SourceScenario'
import { loadSourceProject } from './sourceProject'
const mocks = vi.hoisted(() => ({ download: vi.fn() }))
vi.mock('./SourceReview', () => ({ download: mocks.download }))
afterEach(() => { cleanup(); vi.unstubAllGlobals(); mocks.download.mockReset() })
it('binds an imported hypothetical Go result to exact exported bytes and retires the visible decision after editing', async () => {
  vi.stubGlobal('crypto', webcrypto)
  const org = '11111111-1111-1111-1111-111111111111', draft = { apiVersion: 'ops.policy-draft/v1alpha1', kind: 'PolicyDraft', sourceRevision: 'proposal', environment: 'local', chainId: '31337', evaluatorVersion: 'policycore/native-v1alpha1', profile: 'catalog-foundation/v1', organizations: [{ id: org, slug: 'bank', name: 'Bank' }], documents: [{ kind: 'groups', organizationId: org, path: 'groups.json' }] }, groups = { kind: 'groups', organizationId: org, spec: { groups: [] } }
  const project = await loadSourceProject([['draft.json', draft], ['groups.json', groups]].map(([path, v]) => { const raw = JSON.stringify(v); return { path: String(path), size: raw.length, read: async () => raw } }))
  render(<SourceScenario project={project} root="source" organization={org} check={() => {}} />)
  await userEvent.type(screen.getByLabelText('Hypothetical signer'), '0x' + '1'.repeat(40))
  await userEvent.click(screen.getByRole('button', { name: 'Export policy scenario' })); await waitFor(() => expect(mocks.download).toHaveBeenCalledTimes(1))
  const raw = mocks.download.mock.calls[0][1], digest = await scenarioDigest(raw), manifest = 'sha256:' + 'a'.repeat(64)
  fireEvent.change(screen.getByLabelText('Selected prepared manifest digest'), { target: { value: manifest } })
  const report = JSON.stringify({ action: 'simulate', approved: false, hypothetical: true, deploymentVerified: false, manifestDigest: manifest, scenarioDigest: digest, profile: draft.profile, evaluatorVersion: draft.evaluatorVersion, decision: { Allowed: true, Code: '', Reason: '' } })
  const file = new File([report], 'scenario-report.json'); Object.defineProperty(file, 'text', { value: async () => report })
  fireEvent.change(screen.getByLabelText('Go scenario result'), { target: { files: [file] } })
  expect(await screen.findByText('Conditional allow')).toBeInTheDocument(); expect(screen.getByText(/Its provenance and the running deployment are not established/)).toBeInTheDocument()
  fireEvent.change(screen.getByLabelText('Hypothetical frames'), { target: { value: '[]' } })
  expect(screen.queryByText('Conditional allow')).not.toBeInTheDocument(); expect(screen.getByText(/Scenario or source changed; export again/)).toBeInTheDocument()
})

it('authors two native frame cards, linked addresses and hypothetical claims without JSON, then removes a frame', async () => {
  vi.stubGlobal('crypto', webcrypto)
  const org = '11111111-1111-1111-1111-111111111111', group = '22222222-2222-2222-2222-222222222222'
  const draft = { apiVersion: 'ops.policy-draft/v1alpha1', kind: 'PolicyDraft', sourceRevision: 'proposal', environment: 'local', chainId: '31337', evaluatorVersion: 'policycore/native-v1alpha4', profile: 'catalog-runtime-creation-observed/v1', organizations: [{ id: org, slug: 'bank', name: 'Bank' }], documents: [{ kind: 'groups', organizationId: org, path: 'groups.json' }] }, groups = { kind: 'groups', organizationId: org, spec: { groups: [{ id: group, slug: 'readers', name: 'Readers', description: '', isOrgAdmin: false, isOrgReadonlyAdmin: false, verboseErrors: false, allowedMethods: [], claims: [] }] } }
  const project = await loadSourceProject([['draft.json', draft], ['groups.json', groups]].map(([path, v]) => { const raw = JSON.stringify(v); return { path: String(path), size: raw.length, read: async () => raw } }))
  render(<SourceScenario project={project} root="source" organization={org} check={() => {}} />)
  fireEvent.change(screen.getByLabelText('Hypothetical signer'), { target: { value: '0x' + '1'.repeat(40) } }); await userEvent.click(screen.getByLabelText('Readers'))
  await userEvent.click(screen.getByRole('button', { name: 'Add linked address' })); fireEvent.change(screen.getByLabelText('Linked address 1'), { target: { value: '0x' + '2'.repeat(40) } }); await userEvent.click(screen.getByLabelText('Deploy contracts'))
  fireEvent.change(screen.getByLabelText('Frame 1 storage address'), { target: { value: '0x' + '3'.repeat(40) } }); fireEvent.change(screen.getByLabelText('Frame 1 native value (exact wei)'), { target: { value: '90071992547409931234567890' } }); fireEvent.change(screen.getByLabelText('Frame 1 code kind'), { target: { value: '2' } }); fireEvent.change(screen.getByLabelText('Frame 1 storage organization assumption'), { target: { value: org } }); fireEvent.change(screen.getByLabelText('Frame 1 code organization assumption'), { target: { value: org } }); fireEvent.change(screen.getByLabelText('Frame 1 caller address assumption'), { target: { value: '0x' + '4'.repeat(40) } })
  await userEvent.click(screen.getByRole('button', { name: 'Add frame' })); fireEvent.change(screen.getByLabelText('Frame 2 call type'), { target: { value: 'delegatecall' } }); fireEvent.change(screen.getByLabelText('Frame 2 storage address'), { target: { value: '0x' + '3'.repeat(40) } }); fireEvent.change(screen.getByLabelText('Frame 2 code address (optional)'), { target: { value: '0x' + '5'.repeat(40) } }); fireEvent.change(screen.getByLabelText('Frame 2 depth'), { target: { value: '1' } }); fireEvent.change(screen.getByLabelText('Frame 2 calldata'), { target: { value: '0x12345678' } })
  await userEvent.click(screen.getByRole('button', { name: 'Export policy scenario' })); await waitFor(() => expect(mocks.download).toHaveBeenCalledTimes(1))
  const value = JSON.parse(mocks.download.mock.calls[0][1]); expect(value.context).toEqual({ Org: org, Groups: [group], Signer: '0x' + '1'.repeat(40), LinkedAddresses: ['0x' + '2'.repeat(40)], Claims: 2, GroupSourceClaims: {} }); expect(value.frames[0]).toMatchObject({ callType: 'call', storageAddress: '0x' + '3'.repeat(40), codeAddress: '0x' + '3'.repeat(40), value: '90071992547409931234567890', depth: 0, facts: { CodeKind: 2, StorageOrg: org, CodeOrg: org, CallerAddress: '0x' + '4'.repeat(40) } }); expect(value.frames[1]).toMatchObject({ callType: 'delegatecall', storageAddress: '0x' + '3'.repeat(40), codeAddress: '0x' + '5'.repeat(40), calldata: '0x12345678', value: '0', depth: 1 })
  await userEvent.click(screen.getByRole('button', { name: 'Remove frame 2' })); await userEvent.click(screen.getByRole('button', { name: 'Export policy scenario' })); await waitFor(() => expect(mocks.download).toHaveBeenCalledTimes(2)); expect(JSON.parse(mocks.download.mock.calls[1][1]).frames).toHaveLength(1); expect(screen.getByRole('button', { name: 'Remove frame 1' })).toBeDisabled()
})

it('rejects mismatched reports and invalidates decisions on manifest/source edits; ignores slow stale scenario imports', async () => {
  vi.stubGlobal('crypto', webcrypto)
  const org = '11111111-1111-1111-1111-111111111111', draft = { apiVersion: 'ops.policy-draft/v1alpha1', kind: 'PolicyDraft', sourceRevision: 'proposal', environment: 'local', chainId: '31337', evaluatorVersion: 'policycore/native-v1alpha1', profile: 'catalog-foundation/v1', organizations: [{ id: org, slug: 'bank', name: 'Bank' }], documents: [{ kind: 'groups', organizationId: org, path: 'groups.json' }] }, groups = { kind: 'groups', organizationId: org, spec: { groups: [] } }
  const project = await loadSourceProject([['draft.json', draft], ['groups.json', groups]].map(([path, v]) => { const raw = JSON.stringify(v); return { path: String(path), size: raw.length, read: async () => raw } }))
  const { rerender } = render(<SourceScenario project={project} root="source" organization={org} check={() => {}} />)
  fireEvent.change(screen.getByLabelText('Hypothetical signer'), { target: { value: '0x' + '1'.repeat(40) } }); await userEvent.click(screen.getByRole('button', { name: 'Export policy scenario' })); await waitFor(() => expect(mocks.download).toHaveBeenCalledTimes(1))
  const raw = mocks.download.mock.calls[0][1], digest = await scenarioDigest(raw), manifest = 'sha256:' + 'a'.repeat(64)
  fireEvent.change(screen.getByLabelText('Selected prepared manifest digest'), { target: { value: manifest } })
  const report = { action: 'simulate', approved: false, hypothetical: true, deploymentVerified: false, manifestDigest: manifest, scenarioDigest: digest, profile: draft.profile, evaluatorVersion: draft.evaluatorVersion, decision: { Allowed: false, Code: 'no_matching_rule', Reason: 'No rule' } }
  function result(value: unknown) { const text = JSON.stringify(value), file = new File([text], 'report.json'); Object.defineProperty(file, 'text', { value: async () => text }); return file }
  fireEvent.change(screen.getByLabelText('Go scenario result'), { target: { files: [result({ ...report, scenarioDigest: 'sha256:' + 'b'.repeat(64) })] } }); expect(await screen.findByRole('alert')).toHaveTextContent('does not match')
  fireEvent.change(screen.getByLabelText('Go scenario result'), { target: { files: [result(report)] } }); expect(await screen.findByText('Conditional deny: no_matching_rule')).toBeInTheDocument()
  fireEvent.change(screen.getByLabelText('Selected prepared manifest digest'), { target: { value: 'sha256:' + 'c'.repeat(64) } }); expect(screen.queryByText('Conditional deny: no_matching_rule')).not.toBeInTheDocument()
  fireEvent.change(screen.getByLabelText('Selected prepared manifest digest'), { target: { value: manifest } }); rerender(<SourceScenario project={{ ...project, generation: 1 }} root="source" organization={org} check={() => {}} />); expect(screen.queryByText('Conditional deny: no_matching_rule')).not.toBeInTheDocument()
  let finish!: (raw: string) => void; const slow = new File([raw], 'old-scenario.json'); Object.defineProperty(slow, 'text', { value: () => new Promise<string>(resolve => { finish = resolve }) }); fireEvent.change(screen.getByLabelText('Import hypothetical scenario'), { target: { files: [slow] } }); fireEvent.change(screen.getByLabelText('Frame 1 native value (exact wei)'), { target: { value: '1' } }); await act(async () => { finish(raw) }); expect(screen.getByLabelText('Frame 1 native value (exact wei)')).toHaveValue('1')
})
