import '@testing-library/jest-dom/vitest'
import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { useSyncExternalStore } from 'react'
import { MemoryRouter, useLocation } from 'react-router-dom'
import { afterEach, expect, it, vi } from 'vitest'
import LocalDemoHost from './LocalDemoHost'
import { AuthenticationPage } from './AuthenticationPage'
import type { Controller, State } from './controller'
const wallet = 'https://localhost:9444', now = () => Math.floor(Date.now() / 1000)
const rows = ['admin', 'deployer', 'reader', 'outsider'].map((id, n) => ({ id, profileId: 'demo-' + id, holderDid: 'did:iden3:polygon:mumbai:x' + String(n + 3).repeat(10) }))
afterEach(() => { cleanup(); vi.unstubAllEnvs(); vi.unstubAllGlobals() })
it('keeps one demo owner across pending/candidate/selected branches and uses the V1 picker', async () => {
  vi.stubEnv('VITE_OPS_DEMO_WALLET_ORIGIN', wallet)
  let state: State = { phase: 'anonymous', profiles: rows.map(p => ({ id: p.profileId, provider: 'privado', principalKind: 'human' })), self: null, flow: null, pending: null, candidate: null, error: null, busy: false }, revision = 0
  const listeners = new Set<() => void>(), set = (next: Partial<State>) => { state = { ...state, ...next }; listeners.forEach(f => f()) }
  const id = '11111111-2222-4333-8444-555555555555', actor = 'ops:p1:' + 'A'.repeat(43)
  const controller = { snapshot: () => state, subscribe: (f: () => void) => { listeners.add(f); return () => listeners.delete(f) }, get scopeRevision() { return revision },
    login: vi.fn(async () => { revision++; set({ phase: 'proof-pending', pending: { status: 'login_in_progress', provider: 'privado', sourceProfile: 'demo-admin', requestId: id, requestUri: location.origin + '/api/v2/auth/privado/requests/' + id, expiresAt: now() + 300 } }) }),
    confirm: vi.fn(async () => set({ phase: 'selected', pending: null, candidate: null, self: { actorId: actor, sourceProfile: 'demo-admin', principalKind: 'human', sourceProfileDigest: 'sha256:' + 'a'.repeat(64), expiresAt: now() + 300, organizations: [] } })),
    cancel: vi.fn(async () => set({ phase: 'anonymous', pending: null, candidate: null })),
  } as unknown as Controller
  const popup = { closed: false, close: vi.fn(), postMessage: vi.fn() }
  const open = vi.spyOn(window, 'open').mockReturnValue(popup as unknown as Window)
  function App() {
    const current = useSyncExternalStore(controller.subscribe, controller.snapshot), path = useLocation()
    return <LocalDemoHost controller={controller}>{(slot, active) => <><output data-testid="path">{path.pathname}</output>{current.phase === 'selected' && path.pathname === '/admin/account' ? <p>Verified account</p> : <AuthenticationPage controller={controller} demoSlot={slot} demoBusy={active} />}</>}</LocalDemoHost>
  }
  render(<MemoryRouter initialEntries={['/login']}><App /></MemoryRouter>)
  expect(await screen.findByText('Development Only')).toBeInTheDocument()
  expect(screen.getAllByTestId(/^demo-persona-/)).toHaveLength(4)
  fireEvent.click(screen.getByRole('button', { name: 'Demo Admin', exact: true }))
  const uri = open.mock.calls[0][0] as string, nonce = new URL(uri).hash.slice(1)
  expect(nonce).toMatch(/^[0-9a-f]{64}$/)
  const event = new MessageEvent('message', { origin: wallet, data: { v: 1, type: 'ready', nonce, config: { v: 1, testOnly: true, opsOrigin: location.origin, network: 'polygon:mumbai', issuerDid: 'did:iden3:polygon:mumbai:x1111', verifierDid: 'did:iden3:polygon:mumbai:x2222', personas: rows } } })
  Object.defineProperty(event, 'source', { value: popup })
  act(() => { window.dispatchEvent(event) })
  await waitFor(() => expect(popup.postMessage).toHaveBeenCalledTimes(1))
  expect(screen.queryByTestId('qr-code')).not.toBeInTheDocument()
  expect(screen.getByRole('button', { name: 'Cancel demo sign in' })).toBeInTheDocument()
  act(() => set({ candidate: { status: 'candidate', requestId: id, sourceProfile: 'demo-admin', holderDid: rows[0].holderDid, network: 'polygon:mumbai', actorId: actor, proofDigest: 'sha256:' + 'a'.repeat(64), verifiedAt: now(), expiresAt: now() + 300 } }))
  await waitFor(() => expect(screen.getByTestId('path')).toHaveTextContent('/admin/account'))
  expect(controller.confirm).toHaveBeenCalledTimes(1); expect(popup.close).toHaveBeenCalledTimes(1)
  expect(controller.cancel).not.toHaveBeenCalled(); expect(open).toHaveBeenCalledTimes(1)
})

it.each([undefined, 'http://localhost:9444', 'https://evil.test'])('shows a disabled demo picker for invalid compiled wallet address %s without side effects', async address => {
  vi.stubEnv('VITE_OPS_DEMO_WALLET_ORIGIN', address)
  const state: State = { phase: 'anonymous', profiles: [{ id: 'demo-admin', provider: 'privado', principalKind: 'human' }], self: null, flow: null, pending: null, candidate: null, error: null, busy: false }
  const login = vi.fn(), controller = { snapshot: () => state, subscribe: () => () => {}, login } as unknown as Controller
  const open = vi.spyOn(window, 'open').mockReturnValue(null), fetcher = vi.fn()
  vi.stubGlobal('fetch', fetcher)
  render(<MemoryRouter><LocalDemoHost controller={controller}>{(slot, active) => <AuthenticationPage controller={controller} demoSlot={slot} demoBusy={active} />}</LocalDemoHost></MemoryRouter>)
  expect(screen.getByText('Development Only')).toBeInTheDocument()
  expect(screen.getByText('Demo sign-in is unavailable')).toBeInTheDocument()
  const buttons = screen.getAllByTestId(/^demo-persona-/)
  expect(buttons).toHaveLength(4)
  for (const button of buttons) { expect(button).toBeDisabled(); fireEvent.click(button) }
  expect(login).not.toHaveBeenCalled(); expect(open).not.toHaveBeenCalled(); expect(fetcher).not.toHaveBeenCalled()
})
