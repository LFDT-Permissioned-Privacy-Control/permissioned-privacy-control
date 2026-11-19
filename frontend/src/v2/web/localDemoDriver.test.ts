import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { LocalDemoDriver, type DemoEnvironment, type DemoPopup } from './localDemoDriver'
import { demoPersonas, demoReady, type DemoConfig, type DemoPersona } from './localDemoProtocol'
import type { Controller, State } from './controller'
import type { Candidate } from '../auth/multiProtocol'
import type { Flow, Self } from './protocol'
const origin = 'https://localhost:8443', wallet = 'https://localhost:9444'
const config: DemoConfig = { v: 1, testOnly: true, opsOrigin: origin, network: 'polygon:mumbai', issuerDid: 'did:iden3:polygon:mumbai:x11111', verifierDid: 'did:iden3:polygon:mumbai:x22222', personas: demoPersonas.map((id, n) => ({ id, profileId: 'demo-' + id, holderDid: 'did:iden3:polygon:mumbai:x' + String(n + 3).repeat(10) })) }
const future = () => Date.now() / 1000 + 300
function deferred() { let resolve!: () => void; const promise = new Promise<void>(r => { resolve = r }); return { promise, resolve } }
const flush = async () => { for (let n = 0; n < 20; n++) await Promise.resolve() }
interface Controls { flow?: Flow; holdLogin?: Promise<void>; holdConfirm?: Promise<void>; holdContinue?: Promise<void>; admin?: boolean; automatic?: boolean }
function fixture(options: Controls = {}) {
  let state: State = { phase: 'anonymous', profiles: demoPersonas.map(id => ({ id: 'demo-' + id, provider: 'privado', principalKind: 'human' })), self: null, flow: options.flow ?? null, pending: null, candidate: null, busy: false, error: null }
  let revision = 0, serial = 0, message: ((e: MessageEvent) => void) | null = null
  const listeners = new Set<() => void>(), events: string[] = [], popups: (DemoPopup & { sent: unknown[] })[] = []
  const set = (next: Partial<State>) => { state = { ...state, ...next }; listeners.forEach(f => f()) }
  const native = {
    snapshot: () => state, subscribe: (f: () => void) => { listeners.add(f); return () => listeners.delete(f) }, get scopeRevision() { return revision },
    login: vi.fn(async (profile: string, _provider: string, _holder?: string) => {
      const mine = ++revision, hold = options.holdLogin; options.holdLogin = undefined
      set({ phase: 'booting', busy: true, self: null, pending: null, candidate: null }); if (hold) await hold
      if (mine !== revision) return
      const id = '11111111-2222-4333-8444-' + String(++serial).padStart(12, '0')
      set({ phase: 'proof-pending', busy: false, pending: { status: 'login_in_progress', provider: 'privado', sourceProfile: profile, requestId: id, requestUri: origin + '/api/v2/auth/privado/requests/' + id, expiresAt: future() } })
    }),
    confirm: vi.fn(async () => {
      const mine = revision, candidate = state.candidate!; set({ busy: true }); if (options.holdConfirm) await options.holdConfirm
      if (mine !== revision) return
      const self: Self = { actorId: candidate.actorId, sourceProfile: candidate.sourceProfile, sourceProfileDigest: 'sha256:' + 'a'.repeat(64), principalKind: 'human', expiresAt: future(), organizations: options.admin ? [{ id: '11111111-1111-1111-1111-111111111111', slug: 'bank', name: 'Bank', isOrgAdmin: true, isOrgReadonlyAdmin: false }] : [] }
      set({ phase: 'selected', busy: !!options.automatic, self, candidate: null, pending: null })
    }),
    continue: vi.fn(async () => { set({ busy: true }); if (options.holdContinue) await options.holdContinue; set({ flow: null, busy: false }) }),
    cancel: vi.fn(async () => { revision++; set({ phase: 'anonymous', self: null, pending: null, candidate: null, busy: false }) }),
  }
  const navigate = vi.fn()
  const env: DemoEnvironment = { origin, walletOrigin: wallet, nonce: () => String(popups.length + 1).repeat(64), navigate,
    listen: fn => { events.push('listen'); message = fn; return () => { if (message === fn) message = null } },
    open: () => { events.push('open'); const popup = { closed: false, sent: [] as unknown[], close: vi.fn(function (this: DemoPopup) { this.closed = true }), postMessage(value: unknown, target: string) { expect(target).toBe(wallet); this.sent.push(value) } }; popups.push(popup); return popup },
  }
  const driver = new LocalDemoDriver(native as unknown as Controller, env)
  const receive = (data: unknown, source: unknown = popups.at(-1), eventOrigin = wallet) => message?.({ data, source, origin: eventOrigin } as MessageEvent)
  const ready = async () => { receive({ v: 1, type: 'ready', nonce: String(popups.length).repeat(64), config }); await flush() }
  const candidate = (persona: DemoPersona, changes: Partial<Candidate> = {}) => {
    const identity = config.personas.find(p => p.id === persona)!, pending = state.pending!
    const value: Candidate = { status: 'candidate', requestId: pending.requestId!, sourceProfile: identity.profileId, holderDid: identity.holderDid, network: config.network, actorId: 'ops:p1:' + persona[0].toUpperCase().repeat(43), proofDigest: 'sha256:' + 'a'.repeat(64), verifiedAt: Date.now() / 1000, expiresAt: pending.expiresAt, ...changes }
    set({ candidate: value }); return value
  }
  return { driver, env, native, navigate, popups, events, receive, ready, candidate, state: () => state, set, replace: (next: Partial<State>) => { revision++; set(next) } }
}
let f: ReturnType<typeof fixture>
beforeEach(() => { vi.useFakeTimers(); vi.setSystemTime(new Date('2026-11-19T12:00:00Z')) })
afterEach(() => { f?.driver.dispose(); vi.useRealTimers() })

describe('one explicit public demo identity owns the normal native login', () => {
  it.each(demoPersonas)('completes %s from verified candidate and current roles, not its label', async persona => {
    f = fixture({ admin: persona === 'reader' }); f.driver.start(persona)
    expect(f.events).toEqual(['listen', 'open']); expect(f.native.login).not.toHaveBeenCalled(); await f.ready()
    const p = config.personas.find(p => p.id === persona)!
    expect(f.native.login).toHaveBeenCalledWith(p.profileId, 'privado', p.holderDid)
    expect(f.popups[0].sent).toEqual([{ v: 1, type: 'prove', nonce: '1'.repeat(64), persona, requestUri: f.state().pending!.requestUri }])
    f.receive({ v: 1, type: 'status', nonce: '1'.repeat(64), status: 'submitted' }); await flush(); expect(f.native.confirm).not.toHaveBeenCalled()
    f.candidate(persona); await flush()
    expect(f.native.confirm).toHaveBeenCalledTimes(1); expect(f.native.continue).not.toHaveBeenCalled()
    expect(f.navigate).toHaveBeenCalledWith(persona === 'reader' ? '/admin/rbac/organizations' : '/admin/account')
    expect(f.popups[0].closed).toBe(true); expect(f.driver.snapshot().active).toBe(false)
  })
  it('ignores a foreign window/origin and rejects substituted metadata before native start', async () => {
    f = fixture(); f.driver.start('admin'); const ready = { v: 1, type: 'ready', nonce: '1'.repeat(64), config }
    f.receive(ready, {}, wallet); f.receive(ready, f.popups[0], 'https://evil.test'); await flush()
    expect(f.native.login).not.toHaveBeenCalled(); expect(f.driver.snapshot().active).toBe(true)
    f.receive({ ...ready, config: { ...config, network: 'polygon:amoy' } }); await flush()
    expect(f.native.login).not.toHaveBeenCalled(); expect(f.popups[0].closed).toBe(true)
  })
  it('rejects wrong expected holder and does not adopt a matching-looking replacement pending object', async () => {
    f = fixture(); f.driver.start('admin'); await f.ready(); f.candidate('reader'); await flush()
    expect(f.native.confirm).not.toHaveBeenCalled(); expect(f.native.cancel).toHaveBeenCalledTimes(1)
    f.driver.start('deployer'); await f.ready(); f.set({ pending: { ...f.state().pending! } }); await flush()
    expect(f.native.confirm).not.toHaveBeenCalled(); expect(f.native.cancel).toHaveBeenCalledTimes(1)
  })
  it('cancels its in-flight start locally, then ignores late work after a different persona click', async () => {
    const held = deferred(); f = fixture({ holdLogin: held.promise }); f.driver.start('admin'); await f.ready(); expect(f.state().phase).toBe('booting')
    const old = f.popups[0]; f.driver.cancel(); await flush(); expect(f.native.cancel).toHaveBeenCalledTimes(1)
    f.driver.start('reader'); await f.ready(); held.resolve(); await flush()
    f.receive({ v: 1, type: 'status', nonce: '1'.repeat(64), status: 'submitted' }, old); f.candidate('reader'); await flush()
    expect(f.native.confirm).toHaveBeenCalledTimes(1); expect(f.state().self?.sourceProfile).toBe('demo-reader'); expect(f.popups.every(p => p.closed)).toBe(true)
  })
  it('cancels only its original pending, never a newer account or request', async () => {
    f = fixture(); f.driver.start('admin'); await f.ready(); f.replace({ pending: { ...f.state().pending!, requestId: '22222222-2222-4222-8222-222222222222' } }); await flush()
    expect(f.native.cancel).not.toHaveBeenCalled(); expect(f.native.confirm).not.toHaveBeenCalled()
  })
  it('keeps an original SSO handoff and sends Continue once', async () => {
    const flow = { id: '33333333-3333-4333-8333-333333333333', clientId: 'explorer', displayName: 'Explorer', expiresAt: future() }
    f = fixture({ flow }); f.driver.start('deployer'); await f.ready(); f.candidate('deployer'); await flush()
    expect(f.native.confirm).toHaveBeenCalledTimes(1); expect(f.native.continue).toHaveBeenCalledTimes(1); expect(f.navigate).not.toHaveBeenCalled()
  })
  it('leaves remembered normal Continue alone and never sends a duplicate', async () => {
    const flow = { id: '33333333-3333-4333-8333-333333333333', clientId: 'explorer', displayName: 'Explorer', expiresAt: future() }
    f = fixture({ flow, automatic: true }); f.driver.start('admin'); await f.ready(); f.candidate('admin'); await flush()
    expect(f.native.continue).not.toHaveBeenCalled(); expect(f.driver.snapshot().cancellable).toBe(false)
    f.set({ flow: null, busy: false }); await flush(); expect(f.driver.snapshot().active).toBe(false); expect(f.navigate).not.toHaveBeenCalled()
  })
  it('a removed original SSO flow never becomes direct account navigation', async () => {
    const flow = { id: '33333333-3333-4333-8333-333333333333', clientId: 'explorer', displayName: 'Explorer', expiresAt: future() }
    const held = deferred(); f = fixture({ flow, holdConfirm: held.promise }); f.driver.start('admin'); await f.ready(); f.candidate('admin'); await flush()
    f.set({ flow: null }); held.resolve(); await flush()
    expect(f.native.continue).not.toHaveBeenCalled(); expect(f.navigate).not.toHaveBeenCalled(); expect(f.native.cancel).not.toHaveBeenCalled()
  })
  it('rejects replacement ready metadata and never confirms a late old candidate', async () => {
    f = fixture(); f.driver.start('admin'); await f.ready()
    const oldPending = f.state().pending!
    f.receive({ v: 1, type: 'ready', nonce: '1'.repeat(64), config }); await flush()
    expect(f.native.cancel).toHaveBeenCalledTimes(1); expect(f.native.login).toHaveBeenCalledTimes(1)
    f.set({ pending: oldPending }); f.candidate('admin'); await flush()
    expect(f.native.confirm).not.toHaveBeenCalled()
  })
  it('does not offer undo or retry after confirmation was dispatched', async () => {
    const held = deferred(); f = fixture({ holdConfirm: held.promise })
    f.driver.start('admin'); await f.ready(); f.candidate('admin'); await flush()
    expect(f.driver.snapshot().cancellable).toBe(false)
    f.driver.cancel(); expect(f.native.cancel).not.toHaveBeenCalled()
    f.popups[0].closed = true; await vi.advanceTimersByTimeAsync(201)
    expect(f.driver.snapshot().error).toMatch(/after confirmation started/)
    held.resolve(); await flush()
    expect(f.native.confirm).toHaveBeenCalledTimes(1); expect(f.native.continue).not.toHaveBeenCalled(); expect(f.navigate).not.toHaveBeenCalled()
  })
  it('popup failure and original expiry never retry or extend ownership', async () => {
    f = fixture(); f.env.open = () => null; f.driver.start('admin'); await flush()
    expect(f.native.login).not.toHaveBeenCalled(); expect(f.driver.snapshot().error).toMatch(/could not open/)
    f.driver.dispose(); f = fixture(); f.driver.start('admin'); await f.ready(); await vi.advanceTimersByTimeAsync(150001)
    expect(f.native.confirm).not.toHaveBeenCalled(); expect(f.native.cancel).toHaveBeenCalledTimes(1); expect(f.popups[0].closed).toBe(true)
  })
})

describe('closed public fixture metadata', () => {
  it('copies the snapshot and rejects unknown, duplicate and wrong-nonce data', () => {
    const raw = structuredClone(config), ready = { v: 1, type: 'ready', nonce: 'a'.repeat(64), config: raw }
    const parsed = demoReady(ready, ready.nonce, origin)!
    expect(parsed).not.toBeNull(); expect(Object.isFrozen(parsed.config.personas[0])).toBe(true)
    ;(raw.personas as { holderDid: string }[])[0].holderDid = config.personas[1].holderDid
    expect(parsed.config.personas[0].holderDid).toBe(config.personas[0].holderDid); expect(demoReady(ready, ready.nonce, origin)).toBeNull()
    expect(demoReady({ ...ready, config: { ...config, token: 'not-accepted' } }, ready.nonce, origin)).toBeNull()
    expect(demoReady({ ...ready, nonce: 'b'.repeat(64) }, ready.nonce, origin)).toBeNull()
  })
})
