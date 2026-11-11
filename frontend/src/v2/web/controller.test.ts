import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { MultiAccess } from '../auth/multiProtocol'
import { MultiBrowserAuthClient } from '../auth/multiClient'
import { activeMulti, writeMultiMarker } from '../auth/multiContext'
import { Controller } from './controller'
import { FLOW_KEY } from './protocol'

const mocks = vi.hoisted(() => ({ next: null as unknown, own: vi.fn(), inspect: vi.fn(), complete: vi.fn() }))
vi.mock('../auth/multiClient', () => ({ NewMultiClient: () => mocks.next }))
vi.mock('./protocol', async original => ({ ...await original<typeof import('./protocol')>(), ownSelf: mocks.own, inspectFlow: mocks.inspect, completeFlow: mocks.complete }))
const a: MultiAccess = { accessToken: 'never-persist-this-token', tokenType: 'Bearer', actorId: 'ops:p1:' + 'A'.repeat(43),
  principalKind: 'human', provider: 'privado', sourceProfile: 'bank', browserSessionId: '11111111-1111-1111-1111-111111111111', expiresAt: 0 }
const b = { ...a, actorId: 'ops:p1:' + 'B'.repeat(42) + 'A', browserSessionId: '22222222-2222-2222-2222-222222222222' }
const self = (v: MultiAccess) => ({ actorId: v.actorId, principalKind: 'human', sourceProfile: v.sourceProfile, sourceProfileDigest: 'sha256:' + 'a'.repeat(64), expiresAt: v.expiresAt, organizations: [] })
function deferred<T>() { let resolve!: (v: T) => void; const promise = new Promise<T>(r => { resolve = r }); return { promise, resolve } }
function fake(v = a) {
  return { providers: vi.fn(async () => ({ profiles: [{ id: 'bank', provider: 'privado', principalKind: 'human' }], completionPath: '/auth/complete' })),
    restore: vi.fn(async () => { writeMultiMarker(activeMulti(v)); return { status: 'access', access: v } }),
    needAccess: vi.fn(async () => ({ status: 'access', access: v })),
    withAccess: vi.fn(async (_pair, fn) => ({ status: 'completed', value: await fn(v.accessToken) })),
    cancelPrivado: vi.fn(async () => undefined), previewPrivado: vi.fn(), startPrivadoLogin: vi.fn(), confirmPrivado: vi.fn(), logout: vi.fn() }
}
let controller: Controller
const flush = async () => { for (let i = 0; i < 12; i++) await Promise.resolve() }
beforeEach(() => {
  vi.useFakeTimers(); vi.setSystemTime(new Date('2026-11-11T12:00:00Z'))
  // jsdom23 lacks the modern Chromium signal combinator. Keep the same abort
  // propagation in these ownership controls; the shipped API runs in Chrome.
  if (!AbortSignal.any) Object.defineProperty(AbortSignal, 'any', { configurable: true, value: (signals: AbortSignal[]) => {
    const c = new AbortController()
    for (const s of signals) { if (s.aborted) c.abort(); else s.addEventListener('abort', () => c.abort(), { once: true }) }
    return c.signal
  } })
  a.expiresAt = b.expiresAt = Math.floor(Date.now() / 1000) + 300
  localStorage.clear(); sessionStorage.clear(); history.replaceState(null, '', '/login')
  mocks.own.mockReset().mockImplementation(async v => self(v)); mocks.inspect.mockReset(); mocks.complete.mockReset()
})
afterEach(() => { controller?.stop(); vi.useRealTimers(); vi.unstubAllGlobals() })
describe('document context and flow ownership', () => {
  it('restores once and requires explicit acceptance of an external account change', async () => {
    const first = fake(); mocks.next = first; controller = new Controller(first as unknown as MultiBrowserAuthClient)
    await controller.start(); await controller.start(); expect(first.restore).toHaveBeenCalledTimes(1)
    expect(controller.snapshot().self?.actorId).toBe(a.actorId)
    writeMultiMarker(activeMulti(b)); window.dispatchEvent(new StorageEvent('storage', { key: 'ops-v2.browser-context' }))
    expect(controller.snapshot().phase).toBe('context-changed'); expect(controller.snapshot().self).toBeNull()
    await vi.advanceTimersByTimeAsync(4000); expect(first.restore).toHaveBeenCalledTimes(1)
    mocks.next = fake(b); await controller.useCurrent()
    expect(controller.snapshot().self?.actorId).toBe(b.actorId)
    expect(JSON.stringify([...Object.values(localStorage), ...Object.values(sessionStorage)])).not.toContain(a.accessToken)
  })
  it('cannot publish old own-self when another account wins during its HTTP request', async () => {
    const waiting = deferred<ReturnType<typeof self>>(); mocks.own.mockReturnValueOnce(waiting.promise)
    const client = fake(); controller = new Controller(client as unknown as MultiBrowserAuthClient)
    const started = controller.start(); await flush(); expect(mocks.own).toHaveBeenCalledTimes(1)
    writeMultiMarker(activeMulti(b)); waiting.resolve(self(a)); await started
    expect(controller.snapshot().phase).toBe('context-changed'); expect(controller.snapshot().self).toBeNull()
  })
  it('fences the actual complete POST after an awaited helper renewal and never replays an uncertain completion', async () => {
    history.replaceState(null, '', '/auth/sso?flow=33333333-3333-3333-3333-333333333333')
    const flow = { id: '33333333-3333-3333-3333-333333333333', expiresAt: a.expiresAt, displayName: 'Explorer' }
    mocks.inspect.mockResolvedValue(flow)
    const client = fake(); const held = deferred<void>()
    client.withAccess.mockImplementation(async (_pair, fn) => { await held.promise; return { status: 'completed', value: await fn(a.accessToken) } })
    controller = new Controller(client as unknown as MultiBrowserAuthClient); await controller.start()
    const finishing = controller.continue(); await flush()
    writeMultiMarker(activeMulti(b)); window.dispatchEvent(new StorageEvent('storage', { key: 'ops-v2.browser-context' }))
    held.resolve(); await finishing; expect(mocks.complete).not.toHaveBeenCalled(); expect(controller.snapshot().phase).toBe('context-changed')
    mocks.next = fake(a); writeMultiMarker(activeMulti(a)); await controller.useCurrent()
    mocks.complete.mockRejectedValue(new Error('unknown response'))
    await controller.continue(); await controller.continue()
    expect(mocks.complete).toHaveBeenCalledTimes(1); expect(controller.snapshot().flow).toBeNull(); expect(sessionStorage.getItem(FLOW_KEY)).toBeNull()
  })
  it('discards an old inspect after navigation and cannot extend saved original expiry', async () => {
    const id = '33333333-3333-3333-3333-333333333333'
    history.replaceState(null, '', '/auth/sso?flow=' + id)
    const waiting = deferred<unknown>(); mocks.inspect.mockReturnValueOnce(waiting.promise)
    const client = fake(); controller = new Controller(client as unknown as MultiBrowserAuthClient)
    const started = controller.start(); await flush(); window.dispatchEvent(new PopStateEvent('popstate'))
    waiting.resolve({ id, displayName: 'Late app', expiresAt: a.expiresAt }); await started
    expect(controller.snapshot().flow).toBeNull(); expect(client.restore).not.toHaveBeenCalled()
    controller.stop()
    sessionStorage.setItem(FLOW_KEY, JSON.stringify({ version: 1, phase: 'pending', id, expiresAt: a.expiresAt - 100 }))
    mocks.inspect.mockResolvedValue({ id, displayName: 'App', expiresAt: a.expiresAt })
    controller = new Controller(client as unknown as MultiBrowserAuthClient); await controller.start()
    expect(controller.snapshot().phase).toBe('failed'); expect(controller.snapshot().flow).toBeNull()
  })
  it('clears expired display facts and uses genuine proof renewal instead of extending them', async () => {
    const client = fake(); controller = new Controller(client as unknown as MultiBrowserAuthClient); await controller.start()
    client.needAccess.mockResolvedValue({ status: 'proof_required', ...a, mode: 'renew', requestId: '44444444-4444-4444-4444-444444444444', requestUri: location.origin + '/api/v2/auth/privado/requests/44444444-4444-4444-4444-444444444444' } as never)
    await vi.advanceTimersByTimeAsync(295000)
    expect(client.needAccess).toHaveBeenCalledTimes(1); expect(controller.snapshot().self).toBeNull(); expect(controller.snapshot().phase).toBe('proof-pending')
  })
  it('stops an expired proof and discards its delayed candidate after explicit cancellation', async () => {
    const client = fake(); mocks.next = client
    client.startPrivadoLogin.mockResolvedValue({ requestId: '44444444-4444-4444-4444-444444444444',
      requestUri: location.origin + '/api/v2/auth/privado/requests/44444444-4444-4444-4444-444444444444', expiresAt: Math.floor(Date.now() / 1000) + 3 })
    const pending = deferred<unknown>(); client.previewPrivado.mockReturnValue(pending.promise)
    controller = new Controller(client as unknown as MultiBrowserAuthClient); await controller.start(); await controller.login('bank', 'privado')
    await vi.advanceTimersByTimeAsync(1000); expect(client.previewPrivado).toHaveBeenCalledTimes(1)
    await controller.cancel(); pending.resolve({ status: 'candidate', requestId: '44444444-4444-4444-4444-444444444444', holderDid: 'late' }); await flush()
    expect(controller.snapshot().candidate).toBeNull(); expect(controller.snapshot().phase).toBe('anonymous')
    await controller.login('bank', 'privado'); await vi.advanceTimersByTimeAsync(3000)
    expect(controller.snapshot().pending).toBeNull(); expect(controller.snapshot().candidate).toBeNull(); expect(controller.snapshot().phase).toBe('anonymous')
  })
  it('retires only the original completion while a new account completion is pending', async () => {
    history.replaceState(null, '', '/auth/sso?flow=33333333-3333-3333-3333-333333333333')
    const flow = { id: '33333333-3333-3333-3333-333333333333', expiresAt: a.expiresAt, displayName: 'Explorer' }
    mocks.inspect.mockResolvedValue(flow)
    const oldClient = fake(), oldHeld = deferred<void>(), newHeld = deferred<void>()
    oldClient.withAccess.mockImplementation(async (_pair, fn) => { await oldHeld.promise; return { status: 'completed', value: await fn(a.accessToken) } })
    controller = new Controller(oldClient as unknown as MultiBrowserAuthClient); await controller.start()
    const oldCompletion = controller.continue(); await flush()
    writeMultiMarker(activeMulti(b)); window.dispatchEvent(new StorageEvent('storage', { key: 'ops-v2.browser-context' }))
    const newClient = fake(b)
    newClient.withAccess.mockImplementation(async (_pair, fn) => { await newHeld.promise; return { status: 'completed', value: await fn(b.accessToken) } })
    mocks.next = newClient; await controller.useCurrent()
    const newCompletion = controller.continue(); await flush()
    try {
      oldHeld.resolve(); await oldCompletion
      expect(controller.snapshot().flow?.id).toBe(flow.id); expect(controller.snapshot().busy).toBe(true)
      expect(sessionStorage.getItem(FLOW_KEY)).not.toBeNull(); expect(mocks.complete).not.toHaveBeenCalled()
    } finally { controller.stop(); newHeld.resolve(); await newCompletion }
  })
  it('clears private facts on pagehide and reloads a persisted return instead of reviving stopped state', async () => {
    const client = fake(); controller = new Controller(client as unknown as MultiBrowserAuthClient); await controller.start()
    expect(controller.snapshot().self?.actorId).toBe(a.actorId)
    const reload = vi.fn(); vi.stubGlobal('location', { reload })
    window.dispatchEvent(new PageTransitionEvent('pagehide', { persisted: true }))
    expect(controller.snapshot().self).toBeNull(); expect(controller.snapshot().candidate).toBeNull()
    await vi.advanceTimersByTimeAsync(301000)
    window.dispatchEvent(new PageTransitionEvent('pageshow', { persisted: true })); await flush()
    expect(controller.snapshot().self).toBeNull(); expect(reload).toHaveBeenCalledTimes(1)
    await controller.useCurrent(); expect(controller.snapshot().self).toBeNull()
  })
})
