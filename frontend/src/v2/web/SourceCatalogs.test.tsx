import '@testing-library/jest-dom/vitest'
import { cleanup, fireEvent, render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, expect, it, vi } from 'vitest'
import { SourceCatalogs } from './SourceCatalogs'
import { loadSourceProject, documentValue } from './sourceProject'

afterEach(cleanup)
it('switches a local verification profile using only its native variant fields', async () => {
  const draft = { apiVersion: 'ops.policy-draft/v1alpha1', kind: 'PolicyDraft', sourceRevision: 'proposal', environment: 'local', chainId: '31337', evaluatorVersion: 'policycore/native-v1alpha4', profile: 'catalog-runtime-creation-observed/v1', organizations: [], documents: [], identityCatalog: { path: 'identity.json' } }
  const identity = { apiVersion: 'ops.identity-catalog/v1alpha1', kind: 'IdentityCatalog', issuers: [], mappings: [], profiles: [{ id: 'bank', kind: 'azure-human/v1', tenantId: 'old-tenant', issuer: 'https://old-issuer', apiAudience: 'old-audience', clientId: 'old-client', delegatedScope: 'old-scope', factSource: 'appRoles' }] }
  const files = [['draft.json', draft], ['identity.json', identity]].map(([path, value]) => { const raw = JSON.stringify(value); return { path: String(path), size: raw.length, read: async () => raw } })
  const project = await loadSourceProject(files), onChange = vi.fn()
  render(<SourceCatalogs project={project} root="source" organization="" page="identity-profiles" editing onChange={onChange} />)
  await userEvent.click(screen.getByTitle('Edit identity profiles draft'))
  const dialog = screen.getByRole('dialog')
  fireEvent.change(within(dialog).getByLabelText('Verification kind'), { target: { value: 'privado-identity/v1' } })
  expect(within(dialog).queryByLabelText('Client ID')).not.toBeInTheDocument()
  await userEvent.type(within(dialog).getByLabelText('Privado verifier ID'), 'did:iden3:verifier')
  await userEvent.type(within(dialog).getByLabelText('Privado network'), 'polygon:test')
  await userEvent.type(within(dialog).getByLabelText('Identity state contract'), '0x' + '1'.repeat(40))
  await userEvent.click(within(dialog).getByRole('button', { name: 'Save draft' }))
  expect(onChange).toHaveBeenCalledTimes(1)
  expect(documentValue(onChange.mock.calls[0][0], 'source', 'identity.json').profiles).toEqual([{ id: 'bank', kind: 'privado-identity/v1', verifierId: 'did:iden3:verifier', network: 'polygon:test', identityStateContract: '0x' + '1'.repeat(40) }])
})
