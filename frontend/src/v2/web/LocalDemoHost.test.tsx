import '@testing-library/jest-dom/vitest'
import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { useSyncExternalStore } from 'react'
import { MemoryRouter, useLocation } from 'react-router-dom'
import { afterEach, expect, it, vi } from 'vitest'
import LocalDemoHost from './LocalDemoHost'
import { AuthenticationPage } from './AuthenticationPage'
import type { Controller, State } from './controller'
import { writeMultiMarker } from '../auth/multiContext'
const wallet = 'https://localhost:9444', now = () => Math.floor(Date.now() / 1000)
const rows = ['admin', 'deployer', 'reader', 'outsider'].map((id, n) => ({ id, profileId: 'demo-privado', holderDid: 'did:iden3:polygon:mumbai:x' + String(n + 3).repeat(10) }))
afterEach(() => { cleanup(); localStorage.clear(); vi.unstubAllEnvs(); vi.unstubAllGlobals() })
it('keeps one demo owner across pending/candidate/selected branches and uses the V1 picker', async () => {
  vi.stubEnv('VITE_OPS_DEMO_WALLET_ORIGIN', wallet)
  let state: State = { phase: 'anonymous', profiles: [{ id: 'demo-privado', provider: 'privado', principalKind: 'human' }], self: null, flow: null, pending: null, candidate: null, error: null, busy: false }, revision = 0
  const listeners = new Set<() => void>(), set = (next: Partial<State>) => { state = { ...state, ...next }; listeners.forEach(f => f()) }
  const id = '11111111-2222-4333-8444-555555555555', actor = 'ops:p1:' + 'A'.repeat(43)
  const controller = { snapshot: () => state, subscribe: (f: () => void) => { listeners.add(f); return () => listeners.delete(f) }, get scopeRevision() { return revision },
    login: vi.fn(async () => { revision++; set({ phase: 'proof-pending', pending: { status: 'login_in_progress', provider: 'privado', sourceProfile: 'demo-privado', requestId: id, requestUri: location.origin + '/api/v2/auth/privado/requests/' + id, expiresAt: now() + 300 } }) }),
    confirm: vi.fn(async () => set({ phase: 'selected', pending: null, candidate: null, self: { actorId: actor, sourceProfile: 'demo-privado', principalKind: 'human', sourceProfileDigest: 'sha256:' + 'a'.repeat(64), expiresAt: now() + 300, organizations: [] } })),
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
  expect(screen.queryByTestId('manual-wallet-login')).not.toBeInTheDocument()
  for (const manual of screen.getAllByTestId('privado-signin-btn')) expect(manual).toBeVisible()
  for (const demo of screen.getAllByTestId(/^demo-persona-/)) expect(demo).toBeVisible()
  fireEvent.click(screen.getByRole('button', { name: 'Demo Admin', exact: true }))
  const uri = open.mock.calls[0][0] as string, nonce = new URL(uri).hash.slice(1)
  expect(nonce).toMatch(/^[0-9a-f]{64}$/)
  const event = new MessageEvent('message', { origin: wallet, data: { v: 1, type: 'ready', nonce, config: { v: 1, testOnly: true, opsOrigin: location.origin, network: 'polygon:mumbai', issuerDid: 'did:iden3:polygon:mumbai:x1111', verifierDid: 'did:iden3:polygon:mumbai:x2222', personas: rows } } })
  Object.defineProperty(event, 'source', { value: popup })
  act(() => { window.dispatchEvent(event) })
  await waitFor(() => expect(popup.postMessage).toHaveBeenCalledTimes(1))
  expect(screen.queryByTestId('qr-code')).not.toBeInTheDocument()
  expect(screen.getByRole('button', { name: 'Cancel demo sign in' })).toBeInTheDocument()
  act(() => set({ candidate: { status: 'candidate', requestId: id, sourceProfile: 'demo-privado', holderDid: rows[0].holderDid, network: 'polygon:mumbai', actorId: actor, proofDigest: 'sha256:' + 'a'.repeat(64), verifiedAt: now(), expiresAt: state.pending!.expiresAt } }))
  await waitFor(() => expect(screen.getByTestId('path')).toHaveTextContent('/admin/account'))
  expect(controller.confirm).toHaveBeenCalledTimes(1); expect(popup.close).toHaveBeenCalledTimes(1)
  expect(controller.cancel).not.toHaveBeenCalled(); expect(open).toHaveBeenCalledTimes(1)
})

it('keeps demo choices alongside an existing QR and binds only the explicitly chosen holder', async () => {
  vi.stubEnv('VITE_OPS_DEMO_WALLET_ORIGIN', wallet)
  const requestId = '11111111-2222-4333-8444-555555555555', replacement = '22222222-2222-4222-8222-222222222222'
  const pending = { status: 'login_in_progress', provider: 'privado', sourceProfile: 'demo-privado', requestId, requestUri: location.origin + '/api/v2/auth/privado/requests/' + requestId, expiresAt: now() + 300 } as const
  let state: State = { phase: 'proof-pending', profiles: [{ id: 'demo-privado', provider: 'privado', principalKind: 'human' }], self: null, flow: null, pending, candidate: null, error: null, busy: false }, revision = 0
  const listeners = new Set<() => void>(), controller = { snapshot: () => state, subscribe: (fn: () => void) => { listeners.add(fn); return () => listeners.delete(fn) }, get scopeRevision() { return revision },
    login: vi.fn(async () => { revision++; state = { ...state, pending: { ...pending, requestId: replacement, requestUri: location.origin + '/api/v2/auth/privado/requests/' + replacement } }; listeners.forEach(fn => fn()) }),
    cancel: vi.fn(), confirm: vi.fn() } as unknown as Controller
  writeMultiMarker({ version: 2, phase: 'require-login', actorId: null, browserSessionId: null, provider: null, sourceProfile: null,
    pendingFlow: { kind: 'privado', mode: 'login', requestId, sourceProfile: pending.sourceProfile, expiresAt: pending.expiresAt, expectedActorId: null, expectedSessionId: null } })
  const raw = localStorage.getItem('ops-v2.browser-context'), popup = { closed: false, close: vi.fn(), postMessage: vi.fn() }
  const open = vi.spyOn(window, 'open').mockReturnValue(popup as unknown as Window)
  render(<MemoryRouter><LocalDemoHost controller={controller}>{(slot, active) => <AuthenticationPage controller={controller} demoSlot={slot} demoBusy={active} />}</LocalDemoHost></MemoryRouter>)
  expect(screen.getByTestId('qr-code')).toBeVisible()
  for (const button of await screen.findAllByTestId(/^demo-persona-/)) { expect(button).toBeVisible(); expect(button).toBeEnabled() }
  expect(controller.login).not.toHaveBeenCalled(); expect(controller.cancel).not.toHaveBeenCalled(); expect(open).not.toHaveBeenCalled()
  fireEvent.click(screen.getByRole('button', { name: 'Demo Reader', exact: true }))
  expect(controller.login).not.toHaveBeenCalled(); expect(state.pending).toBe(pending)
  const nonce = new URL(open.mock.calls[0][0] as string).hash.slice(1)
  const event = new MessageEvent('message', { origin: wallet, data: { v: 1, type: 'ready', nonce, config: { v: 1, testOnly: true, opsOrigin: location.origin, network: 'polygon:mumbai', issuerDid: 'did:iden3:polygon:mumbai:x1111', verifierDid: 'did:iden3:polygon:mumbai:x2222', personas: rows } } })
  Object.defineProperty(event, 'source', { value: popup }); act(() => window.dispatchEvent(event))
  await waitFor(() => expect(popup.postMessage).toHaveBeenCalledTimes(1))
  expect(controller.login).toHaveBeenCalledWith('demo-privado', 'privado', rows[2].holderDid, raw)
  expect(popup.postMessage).toHaveBeenCalledWith({ v: 1, type: 'prove', nonce, persona: 'reader', requestUri: state.pending!.requestUri, keepAlive: true }, wallet)
  expect(controller.confirm).not.toHaveBeenCalled()
})

it.each([undefined, 'http://localhost:9444', 'https://evil.test'])('shows a disabled demo picker for invalid compiled wallet address %s without side effects', async address => {
  vi.stubEnv('VITE_OPS_DEMO_WALLET_ORIGIN', address)
  const state: State = { phase: 'anonymous', profiles: [{ id: 'demo-privado', provider: 'privado', principalKind: 'human' }], self: null, flow: null, pending: null, candidate: null, error: null, busy: false }
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

it('lets a demo renew its owned request and cancel only the helper, preserving the original pending and draft notice', async () => {
  vi.stubEnv('VITE_OPS_DEMO_WALLET_ORIGIN', wallet)
  const requestId = '11111111-2222-4333-8444-555555555555', actorId = 'ops:p1:' + 'A'.repeat(43), browserSessionId = '22222222-2222-4222-8222-222222222222'
  const pending = { status: 'proof_required', provider: 'privado', sourceProfile: 'demo-privado', actorId, browserSessionId, principalKind: 'human', mode: 'renew', requestId, requestUri: location.origin + '/api/v2/auth/privado/requests/' + requestId, expiresAt: now() + 300 } as const
  let state: State = { phase: 'proof-pending', profiles: [{ id: 'demo-privado', provider: 'privado', principalKind: 'human' }], self: null, flow: null, pending, candidate: null, error: null, busy: false }
  const listeners = new Set<() => void>(), controller = { snapshot: () => state, subscribe: (fn: () => void) => { listeners.add(fn); return () => listeners.delete(fn) }, scopeRevision: 5,
    login: vi.fn(), confirm: vi.fn(), cancel: vi.fn(async () => { state = { ...state, phase: 'anonymous', pending: null }; listeners.forEach(fn => fn()) }) } as unknown as Controller
  writeMultiMarker({ version: 2, phase: 'require-login', actorId, browserSessionId, provider: 'privado', sourceProfile: 'demo-privado', pendingFlow: { kind: 'privado', mode: 'renew', requestId, sourceProfile: 'demo-privado', expiresAt: pending.expiresAt, expectedActorId: actorId, expectedSessionId: browserSessionId } })
  const raw = localStorage.getItem('ops-v2.browser-context'), popup = { closed: false, close: vi.fn(), postMessage: vi.fn() }
  const open = vi.spyOn(window, 'open').mockReturnValue(popup as unknown as Window)
  render(<MemoryRouter><LocalDemoHost controller={controller}>{(slot, active) => <AuthenticationPage controller={controller} demoSlot={slot} demoBusy={active} notice={<p>Your draft is kept here while you verify this account.</p>} />}</LocalDemoHost></MemoryRouter>)
  expect(await screen.findByRole('button', { name: 'Demo Admin', exact: true })).toBeVisible()
  expect(screen.getByTestId('qr-code')).toBeVisible()
  fireEvent.click(screen.getByRole('button', { name: 'Demo Admin', exact: true }))
  const nonce = new URL(open.mock.calls[0][0] as string).hash.slice(1), event = new MessageEvent('message', { origin: wallet, data: { v: 1, type: 'ready', nonce, config: { v: 1, testOnly: true, opsOrigin: location.origin, network: 'polygon:mumbai', issuerDid: 'did:iden3:polygon:mumbai:x1111', verifierDid: 'did:iden3:polygon:mumbai:x2222', personas: rows } } })
  Object.defineProperty(event, 'source', { value: popup }); act(() => window.dispatchEvent(event))
  await waitFor(() => expect(popup.postMessage).toHaveBeenCalledTimes(1))
  expect(controller.login).not.toHaveBeenCalled(); expect(controller.confirm).not.toHaveBeenCalled()
  expect(screen.getByRole('button', { name: 'Cancel sign in', exact: true })).toBeVisible()
  fireEvent.click(screen.getByRole('button', { name: 'Cancel demo verification', exact: true }))
  expect(controller.cancel).not.toHaveBeenCalled(); expect(state.pending).toBe(pending); expect(localStorage.getItem('ops-v2.browser-context')).toBe(raw)
  expect(screen.getByText('Your draft is kept here while you verify this account.')).toBeVisible()
  expect(screen.getByRole('button', { name: 'Demo Admin', exact: true })).toBeEnabled()
  fireEvent.click(screen.getByRole('button', { name: 'Cancel sign in', exact: true }))
  await waitFor(() => expect(controller.cancel).toHaveBeenCalledTimes(1))
})
