import '@testing-library/jest-dom/vitest'
import { webcrypto } from 'node:crypto'
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
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
  expect(screen.queryByText('Conditional allow')).not.toBeInTheDocument(); expect(screen.getByText('Scenario, source or selected artifact changed')).toBeInTheDocument()
})
