import '@testing-library/jest-dom/vitest'
import { act, cleanup, render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, expect, it, vi } from 'vitest'
import type { Controller } from './controller'
import { ServingSelection } from './ServingSelection'
import type { SourceDraft } from './sourceProject'

afterEach(cleanup)
const selected = { manifestDigest: 'sha256:' + 'a'.repeat(64), sourceRevision: 'reviewed-123', environment: 'demo', chainId: '31337', profile: 'catalog-runtime-creation-observed/v1', evaluatorVersion: 'policycore/native-v1alpha4' }
const draft = { ...selected, apiVersion: 'ops.policy-draft/v1alpha1', kind: 'PolicyDraft', organizations: [], documents: [] } as SourceDraft
function fixture(request = vi.fn(async () => selected), check = vi.fn()) {
  const dispose = vi.fn()
  const controller = { snapshot: () => ({ self: { organizations: [{ isOrgAdmin: true, isOrgReadonlyAdmin: false }] } }), captureOperations: vi.fn(async () => ({ request, check, dispose })) } as unknown as Controller
  return { controller, dispose, request }
}

it('checks the instance explicitly and never calls matching draft labels deployed file contents', async () => {
  const f = fixture()
  const view = render(<ServingSelection controller={f.controller} draft={draft} />)
  expect(f.request).not.toHaveBeenCalled()
  await userEvent.click(screen.getByRole('button', { name: 'Check this OPS instance' }))
  expect(f.request).toHaveBeenCalledWith('/api/v2/self/selection')
  expect(screen.getByText(/File contents have not been compared/)).toBeInTheDocument()
  expect(screen.getByText(/does not check other OPS instances/)).toBeInTheDocument()
  expect(f.dispose).toHaveBeenCalledOnce()
  view.rerender(<ServingSelection controller={f.controller} draft={{ ...draft, sourceRevision: 'another' }} />)
  expect(screen.getByText(/differ from the imported draft/)).toBeInTheDocument()
})

it('does not publish an old response after scope retirement', async () => {
  let finish!: (value: typeof selected) => void
  const request = vi.fn(() => new Promise<typeof selected>(resolve => { finish = resolve }))
  const f = fixture(request, vi.fn(() => { throw Error('retired account') }))
  render(<ServingSelection controller={f.controller} draft={draft} />)
  await userEvent.click(screen.getByRole('button', { name: 'Check this OPS instance' }))
  await act(async () => finish(selected))
  expect(screen.queryByText(/Selected revision/)).not.toBeInTheDocument()
  expect(screen.getByRole('alert')).toHaveTextContent('Could not verify')
  expect(f.dispose).toHaveBeenCalledOnce()
})

it('rejects extra source contents and does not offer metadata to a normal member', async () => {
  const f = fixture(vi.fn(async () => ({ ...selected, documents: ['private'] })))
  const view = render(<ServingSelection controller={f.controller} />)
  await userEvent.click(screen.getByRole('button', { name: 'Check this OPS instance' }))
  expect(screen.getByRole('alert')).toBeInTheDocument()
  expect(screen.queryByText(/private/)).not.toBeInTheDocument()
  const member = { snapshot: () => ({ self: { organizations: [{ isOrgAdmin: false, isOrgReadonlyAdmin: false }] } }) } as unknown as Controller
  view.rerender(<ServingSelection controller={member} />)
  expect(screen.queryByRole('button')).not.toBeInTheDocument()
})

it('aborts and disposes a pending selection on unmount', async () => {
  let finish!: (value: typeof selected) => void
  const f = fixture(vi.fn(() => new Promise<typeof selected>(resolve => { finish = resolve })))
  const view = render(<ServingSelection controller={f.controller} />)
  await userEvent.click(screen.getByRole('button', { name: 'Check this OPS instance' }))
  const signal = vi.mocked(f.controller.captureOperations).mock.calls[0][0]
  view.unmount()
  expect(signal.aborted).toBe(true)
  await act(async () => finish(selected))
  expect(f.dispose).toHaveBeenCalledOnce()
})
