import '@testing-library/jest-dom/vitest'
import { cleanup, fireEvent, render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { AuthenticationPage } from './AuthenticationPage'
import { Controller, State } from './controller'
import type { ReactNode } from 'react'

const profile = { id: 'configured-connection', provider: 'privado' as const, principalKind: 'human' as const }
const anonymous: State = { phase: 'anonymous', profiles: [profile], self: null, flow: null, pending: null, candidate: null, busy: false, error: null }
function page(state = anonymous, demoSlot?: ReactNode, demoBusy = false) {
  const controller = { snapshot: () => state, subscribe: () => () => {}, login: vi.fn(), prepareLogin: vi.fn(), confirm: vi.fn(), cancel: vi.fn(), logout: vi.fn(), continue: vi.fn() }
  render(<MemoryRouter><AuthenticationPage controller={controller as unknown as Controller} demoSlot={demoSlot} demoBusy={demoBusy} /></MemoryRouter>)
  return controller
}
afterEach(cleanup)
describe('native sign-in with the V1 presentation', () => {
  it('shows one Sign In heading and a clean provider action for a normal signed-out visit', () => {
    const controller = page()
    expect(screen.getByTestId('login-header')).toHaveTextContent('Open Privacy Suite')
    expect(screen.getAllByRole('heading', { name: 'Sign In', exact: true })).toHaveLength(1)
    expect(screen.queryByRole('alert')).not.toBeInTheDocument()
    expect(screen.queryByText(profile.id)).not.toBeInTheDocument()
    const action = screen.getByRole('button', { name: 'Continue with Privado ID' })
    expect(action).toHaveAttribute('data-profile-id', profile.id)
    expect(action).not.toHaveAttribute('aria-describedby')
    fireEvent.click(action); expect(controller.login).toHaveBeenCalledWith(profile.id, 'privado')
  })
  it('uses profile IDs only as secondary disambiguation when a provider has several connections', () => {
    page({ ...anonymous, profiles: [profile, { ...profile, id: 'another-approved-connection' }] })
    expect(screen.getAllByRole('button', { name: 'Continue with Privado ID' })).toHaveLength(2)
    expect(screen.getByText('Connection: ' + profile.id)).toBeInTheDocument()
    expect(screen.getByText('Connection: another-approved-connection')).toBeInTheDocument()
    const actions = screen.getAllByRole('button', { name: 'Continue with Privado ID' })
    expect(actions[0]).toHaveAccessibleDescription('Connection: ' + profile.id)
    expect(actions[1]).toHaveAccessibleDescription('Connection: another-approved-connection')
  })
  it('prepares ordinary signed-out entry without presenting an old restore denial as a warning', () => {
    const controller = page({ ...anonymous, ordinaryEntry: true, error: 'login_required' })
    expect(controller.prepareLogin).toHaveBeenCalledTimes(1)
    expect(screen.queryByText('Sign in to continue')).not.toBeInTheDocument()
    expect(screen.queryByRole('alert')).not.toBeInTheDocument()
    expect(controller.confirm).not.toHaveBeenCalled()
    cleanup(); page({ ...anonymous, error: 'login_required' })
    expect(screen.getByText('Sign in to continue')).toBeInTheDocument()
  })
  it('shows the common wallet QR and demo identities together without a collapsed manual-login section', () => {
    const id = '44444444-4444-4444-4444-444444444444'
    page({ ...anonymous, phase: 'proof-pending', pending: { status: 'login_in_progress', provider: 'privado', sourceProfile: profile.id,
      requestId: id, requestUri: location.origin + '/api/v2/auth/privado/requests/' + id, expiresAt: Math.floor(Date.now() / 1000) + 300 } }, <button>Demo Admin</button>)
    expect(screen.getByTestId('qr-code')).toBeVisible()
    expect(screen.getByRole('button', { name: 'Demo Admin' })).toBeVisible()
    expect(screen.queryByTestId('manual-wallet-login')).not.toBeInTheDocument()
  })
  it('keeps Microsoft reachable by explicitly canceling the unsigned QR, without starting Microsoft automatically', async () => {
    const id = '44444444-4444-4444-4444-444444444444'
    let state: State = { ...anonymous, profiles: [profile, { ...profile, id: 'azure-bank', provider: 'azure' }], phase: 'proof-pending',
      pending: { status: 'login_in_progress', provider: 'privado', sourceProfile: profile.id, requestId: id,
        requestUri: location.origin + '/api/v2/auth/privado/requests/' + id, expiresAt: Math.floor(Date.now() / 1000) + 300 } }
    let notify = () => {}
    const controller = { snapshot: () => state, subscribe: (fn: () => void) => { notify = fn; return () => {} }, login: vi.fn(), prepareLogin: vi.fn(),
      cancel: vi.fn(async () => { state = { ...state, pending: null, phase: 'anonymous' }; notify() }) }
    render(<MemoryRouter><AuthenticationPage controller={controller as unknown as Controller} /></MemoryRouter>)
    expect(screen.getByTestId('qr-code')).toBeVisible(); expect(controller.login).not.toHaveBeenCalled()
    fireEvent.click(screen.getByRole('button', { name: 'Sign in with Microsoft instead' }))
    const microsoft = await screen.findByRole('button', { name: 'Continue with Microsoft' })
    expect(controller.cancel).toHaveBeenCalledTimes(1); expect(controller.login).not.toHaveBeenCalled()
    fireEvent.click(microsoft); expect(controller.login).toHaveBeenCalledWith('azure-bank', 'azure')
  })
  it('preserves real provider failures and explains actual expiry without an interrupted-app alarm on ordinary entry', () => {
    page({ ...anonymous, phase: 'failed', error: 'authentication_unavailable' })
    expect(screen.getByRole('alert')).toHaveTextContent('Sign-in is unavailable')
    cleanup(); page({ ...anonymous, phase: 'failed', error: 'flow_expired' })
    expect(screen.getByText('Application sign-in expired')).toBeInTheDocument()
    expect(screen.getByText('Return to the application and start sign-in again.')).toBeInTheDocument()
  })
  it('hides console entry and signed-in confirmation for an expired retained account', () => {
    page({ ...anonymous, phase: 'selected', self: { actorId: 'ops:p1:' + 'A'.repeat(43), principalKind: 'human', sourceProfile: profile.id,
      sourceProfileDigest: 'sha256:' + 'b'.repeat(64), expiresAt: Math.floor(Date.now() / 1000) - 1,
      organizations: [{ id: '11111111-1111-1111-1111-111111111111', slug: 'bank', name: 'Bank', isOrgAdmin: true, isOrgReadonlyAdmin: false }] } })
    expect(screen.queryByRole('link', { name: 'Open configuration viewer' })).not.toBeInTheDocument()
    expect(screen.queryByText('Authentication successful!')).not.toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Continue with Privado ID' })).toBeInTheDocument()
  })
  it.each(['azure', 'privado'] as const)('keeps %s application confirmation focused on the selected account and application', provider => {
    const expiresAt = Math.floor(Date.now() / 1000) + 300
    const controller = page({ ...anonymous, phase: 'selected', profiles: [{ ...profile, provider }],
      self: { actorId: 'ops:p1:' + 'A'.repeat(43), principalKind: 'human', sourceProfile: profile.id,
        sourceProfileDigest: 'sha256:' + 'b'.repeat(64), expiresAt, organizations: [] },
      flow: { id: '44444444-4444-4444-4444-444444444444', clientId: 'explorer', displayName: 'Explorer', expiresAt } })
    expect(screen.getByTestId('auth-card')).toHaveTextContent('Explorer')
    expect(screen.queryByRole('button', { name: /Forget/ })).not.toBeInTheDocument()
    expect(controller.continue).not.toHaveBeenCalled()
    fireEvent.click(screen.getByRole('button', { name: 'Continue to application', exact: true }))
    expect(controller.continue).toHaveBeenCalledTimes(1)
  })
  it('keeps real proof renewal and explicit candidate confirmation in the styled wallet flow', () => {
    const id = '44444444-4444-4444-4444-444444444444', actor = 'ops:p1:' + 'A'.repeat(43)
    const state: State = { ...anonymous, phase: 'proof-pending', pending: { status: 'proof_required', provider: 'privado', sourceProfile: profile.id,
      actorId: actor, browserSessionId: '11111111-1111-1111-1111-111111111111', principalKind: 'human', mode: 'renew', requestId: id,
      requestUri: location.origin + '/api/v2/auth/privado/requests/' + id, expiresAt: Math.floor(Date.now() / 1000) + 300 } }
    page(state)
    expect(screen.getByRole('heading', { name: 'Verify Your Identity' })).toBeInTheDocument()
    expect(screen.getByTestId('qr-code')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Use this identity' })).not.toBeInTheDocument()
    expect(screen.queryByTestId('account-page')).not.toBeInTheDocument()
    cleanup()
    const controller = page({ ...state, candidate: { status: 'candidate', requestId: id, holderDid: 'did:iden3:polygon:amoy:verified-holder', network: 'polygon:amoy',
      actorId: actor, sourceProfile: profile.id, proofDigest: 'sha256:' + 'a'.repeat(64), verifiedAt: Math.floor(Date.now() / 1000), expiresAt: Math.floor(Date.now() / 1000) + 300 } })
    expect(screen.getByLabelText('Choose account')).toHaveTextContent('did:iden3:polygon:amoy:verified-holder')
    expect(screen.getByLabelText('Choose account')).toHaveTextContent('polygon:amoy')
    expect(screen.getByLabelText('Choose account')).toHaveTextContent(profile.id)
    expect(controller.confirm).not.toHaveBeenCalled()
    fireEvent.click(screen.getByRole('button', { name: 'Use this identity' })); expect(controller.confirm).toHaveBeenCalledTimes(1)
  })
  it('keeps renewal QR visible alongside the demo helper and explicit whole-flow cancellation', () => {
    const id = '44444444-4444-4444-4444-444444444444'
    const controller = page({ ...anonymous, phase: 'proof-pending', pending: { status: 'proof_required', provider: 'privado', sourceProfile: profile.id,
      actorId: 'ops:p1:' + 'A'.repeat(43), browserSessionId: '11111111-1111-1111-1111-111111111111', principalKind: 'human', mode: 'renew', requestId: id,
      requestUri: location.origin + '/api/v2/auth/privado/requests/' + id, expiresAt: Math.floor(Date.now() / 1000) + 300 } }, <button>Demo Admin</button>)
    expect(screen.getByRole('button', { name: 'Demo Admin' })).toBeVisible()
    expect(screen.queryByTestId('manual-wallet-login')).not.toBeInTheDocument()
    expect(screen.getByTestId('qr-code')).toBeVisible()
    expect(screen.queryByRole('button', { name: 'Continue with Privado ID' })).not.toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Cancel sign in', exact: true }))
    expect(controller.cancel).toHaveBeenCalledTimes(1)
  })
  it('keeps manual confirmation available for a candidate the demo helper does not own', () => {
    const id = '44444444-4444-4444-4444-444444444444', actorId = 'ops:p1:' + 'A'.repeat(43), expiresAt = Math.floor(Date.now() / 1000) + 300
    const state: State = { ...anonymous, phase: 'proof-pending', pending: { status: 'proof_required', provider: 'privado', sourceProfile: profile.id, actorId,
      browserSessionId: '11111111-1111-1111-1111-111111111111', principalKind: 'human', mode: 'renew', requestId: id,
      requestUri: location.origin + '/api/v2/auth/privado/requests/' + id, expiresAt }, candidate: { status: 'candidate', requestId: id, holderDid: 'did:iden3:polygon:mumbai:x11111', network: 'polygon:mumbai', actorId, sourceProfile: profile.id, proofDigest: 'sha256:' + 'a'.repeat(64), verifiedAt: expiresAt - 300, expiresAt } }
    const controller = page(state, <p>Demo helper</p>)
    expect(controller.confirm).not.toHaveBeenCalled()
    fireEvent.click(screen.getByRole('button', { name: 'Use this identity' }))
    expect(controller.confirm).toHaveBeenCalledTimes(1)
    cleanup(); page(state, <p>Demo helper progress</p>, true)
    expect(screen.queryByRole('button', { name: 'Use this identity' })).not.toBeInTheDocument()
    expect(screen.getByText('Demo helper progress')).toBeVisible()
    expect(screen.getByRole('button', { name: 'Cancel sign in', exact: true })).toBeVisible()
  })
})
