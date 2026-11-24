import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { canAssistDemoLogin, LocalDemoDriver, type DemoEnvironment, type DemoPopup } from './localDemoDriver'
import { demoPersonas, demoReady, type DemoConfig, type DemoPersona } from './localDemoProtocol'
import type { Controller, State } from './controller'
import type { Candidate } from '../auth/multiProtocol'
import type { Flow, Self } from './protocol'
import { activeMulti, writeMultiMarker } from '../auth/multiContext'
import type { LoginPending, ProofRequired } from '../auth/multiProtocol'
const origin = 'https://localhost:8443', wallet = 'https://localhost:9444'
const config: DemoConfig = { v: 1, testOnly: true, opsOrigin: origin, network: 'polygon:mumbai', issuerDid: 'did:iden3:polygon:mumbai:x11111', verifierDid: 'did:iden3:polygon:mumbai:x22222', personas: demoPersonas.map((id, n) => ({ id, profileId: 'demo-privado', holderDid: 'did:iden3:polygon:mumbai:x' + String(n + 3).repeat(10) })) }
const future = () => Date.now() / 1000 + 300
function deferred() { let resolve!: () => void; const promise = new Promise<void>(r => { resolve = r }); return { promise, resolve } }
const flush = async () => { for (let n = 0; n < 20; n++) await Promise.resolve() }
interface Controls { flow?: Flow; holdLogin?: Promise<void>; holdConfirm?: Promise<void>; holdContinue?: Promise<void>; admin?: boolean; automatic?: boolean; autoRenew?: boolean }
function fixture(options: Controls = {}) {
  let state: State = { phase: 'anonymous', profiles: [{ id: 'demo-privado', provider: 'privado', principalKind: 'human' }], self: null, flow: options.flow ?? null, pending: null, candidate: null, busy: false, error: null }
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
      if (options.autoRenew) writeMultiMarker(activeMulti({ actorId: self.actorId, browserSessionId: '22222222-2222-4222-8222-222222222222', provider: 'privado', sourceProfile: self.sourceProfile }))
      set({ phase: 'selected', busy: !!options.automatic, self, candidate: null, pending: null })
    }),
    continue: vi.fn(async () => { set({ busy: true }); if (options.holdContinue) await options.holdContinue; set({ flow: null, busy: false }) }),
    cancel: vi.fn(async () => { revision++; set({ phase: 'anonymous', self: null, pending: null, candidate: null, busy: false }) }),
  }
  const navigate = vi.fn()
  const env: DemoEnvironment = { origin, walletOrigin: wallet, autoRenew: options.autoRenew, nonce: () => String(popups.length + 1).repeat(64), navigate,
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
beforeEach(() => { localStorage.clear(); vi.useFakeTimers(); vi.setSystemTime(new Date('2026-11-19T12:00:00Z')) })
afterEach(() => { f?.driver.dispose(); vi.useRealTimers() })

function renewing(persona: DemoPersona = 'admin', options: Controls = {}) {
  f = fixture(options)
  const actorId = 'ops:p1:' + persona[0].toUpperCase().repeat(43)
  const pending: ProofRequired = { status: 'proof_required', provider: 'privado', principalKind: 'human', mode: 'renew', sourceProfile: 'demo-privado', actorId,
    browserSessionId: '22222222-2222-4222-8222-222222222222', requestId: '11111111-2222-4333-8444-555555555555', requestUri: origin + '/api/v2/auth/privado/requests/11111111-2222-4333-8444-555555555555', expiresAt: future() }
  f.set({ phase: 'proof-pending', pending })
  writeMultiMarker({ version: 2, phase: 'require-login', actorId, browserSessionId: pending.browserSessionId, sourceProfile: pending.sourceProfile, provider: 'privado',
    pendingFlow: { kind: 'privado', mode: 'renew', requestId: pending.requestId, sourceProfile: pending.sourceProfile, expiresAt: pending.expiresAt, expectedActorId: actorId, expectedSessionId: pending.browserSessionId } })
  return pending
}

function ordinaryLogin(options: Controls = {}) {
  f = fixture(options)
  const pending: LoginPending = { status: 'login_in_progress', provider: 'privado', sourceProfile: 'demo-privado', requestId: '11111111-2222-4333-8444-555555555555',
    requestUri: origin + '/api/v2/auth/privado/requests/11111111-2222-4333-8444-555555555555', expiresAt: future() }
  f.set({ phase: 'proof-pending', pending })
  writeMultiMarker({ version: 2, phase: 'require-login', actorId: null, browserSessionId: null, sourceProfile: null, provider: null,
    pendingFlow: { kind: 'privado', mode: 'login', requestId: pending.requestId!, sourceProfile: pending.sourceProfile, expiresAt: pending.expiresAt, expectedActorId: null, expectedSessionId: null } })
  return pending
}

describe('explicit demo choice may replace only the captured unconfirmed QR login', () => {
  it.each(demoPersonas)('binds %s to its expected holder after wallet readiness, not on entry', async persona => {
    const pending = ordinaryLogin(), raw = localStorage.getItem('ops-v2.browser-context'), identity = config.personas.find(p => p.id === persona)!
    expect(canAssistDemoLogin(f.state())).toBe(true); f.driver.start(persona)
    expect(f.native.login).not.toHaveBeenCalled(); expect(f.native.cancel).not.toHaveBeenCalled(); expect(f.native.confirm).not.toHaveBeenCalled()
    expect(f.state().pending).toBe(pending)
    await vi.advanceTimersByTimeAsync(20000)
    expect(f.state().pending).toBe(pending); expect(localStorage.getItem('ops-v2.browser-context')).toBe(raw); expect(f.popups[0].sent).toEqual([])
    await f.ready()
    expect(f.native.login).toHaveBeenCalledTimes(1); expect(f.native.login).toHaveBeenCalledWith(identity.profileId, 'privado', identity.holderDid, raw)
    expect(f.state().pending).not.toBe(pending)
    expect(f.popups[0].sent).toEqual([{ v: 1, type: 'prove', nonce: '1'.repeat(64), persona, requestUri: f.state().pending!.requestUri }])
    f.candidate(persona); await flush(); expect(f.native.confirm).toHaveBeenCalledTimes(1)
  })
  it.each(['absent', 'bound', 'request', 'profile', 'expiry', 'uri', 'azure'] as const)('rejects %s ownership before opening a helper', async kind => {
    const pending = ordinaryLogin(), key = 'ops-v2.browser-context', marker = JSON.parse(localStorage.getItem(key)!)
    if (kind === 'absent') localStorage.removeItem(key)
    if (kind === 'bound') marker.pendingFlow.expectedActorId = 'ops:p1:' + 'A'.repeat(43)
    if (kind === 'request') marker.pendingFlow.requestId = '44444444-4444-4444-4444-444444444444'
    if (kind === 'profile') marker.pendingFlow.sourceProfile = 'other-profile'
    if (kind === 'expiry') marker.pendingFlow.expiresAt--
    if (kind === 'uri') pending.requestUri = 'https://evil.test/api/v2/auth/privado/requests/' + pending.requestId
    if (kind === 'azure') pending.provider = 'azure'
    if (kind !== 'absent') localStorage.setItem(key, JSON.stringify(marker))
    const raw = localStorage.getItem(key); f.driver.start('admin'); await flush()
    expect(f.popups).toHaveLength(0); expect(f.native.login).not.toHaveBeenCalled(); expect(f.native.cancel).not.toHaveBeenCalled()
    expect(f.state().pending).toBe(pending); expect(localStorage.getItem(key)).toBe(raw)
  })
  it.each(['reference', 'raw-marker', 'candidate', 'profile', 'expiry', 'revision'] as const)('rejects %s changes while wallet setup is waiting', async kind => {
    const pending = ordinaryLogin(); f.driver.start('admin')
    if (kind === 'reference') f.set({ pending: { ...pending } })
    if (kind === 'raw-marker') localStorage.setItem('ops-v2.browser-context', localStorage.getItem('ops-v2.browser-context')! + ' ')
    if (kind === 'candidate') f.candidate('admin')
    if (kind === 'profile') pending.sourceProfile = 'other-profile'
    if (kind === 'expiry') pending.expiresAt++
    if (kind === 'revision') f.replace({ pending })
    await f.ready()
    expect(f.native.login).not.toHaveBeenCalled(); expect(f.native.cancel).not.toHaveBeenCalled(); expect(f.native.confirm).not.toHaveBeenCalled(); expect(f.popups[0].sent).toEqual([])
    expect(f.popups[0].closed).toBe(true)
  })
  it('does not replace an existing candidate or a nonmatching demo profile', async () => {
    ordinaryLogin(); f.candidate('reader'); expect(canAssistDemoLogin(f.state())).toBe(false); f.driver.start('admin'); await flush()
    expect(f.popups).toHaveLength(0); expect(f.native.login).not.toHaveBeenCalled()
    f.driver.dispose(); const pending = ordinaryLogin(); pending.sourceProfile = 'other-profile'
    const marker = JSON.parse(localStorage.getItem('ops-v2.browser-context')!); marker.pendingFlow.sourceProfile = pending.sourceProfile; localStorage.setItem('ops-v2.browser-context', JSON.stringify(marker))
    f.set({ profiles: [...f.state().profiles, { id: 'other-profile', provider: 'privado', principalKind: 'human' }] })
    f.driver.start('admin'); await f.ready(); expect(f.native.login).not.toHaveBeenCalled(); expect(f.native.cancel).not.toHaveBeenCalled(); expect(f.popups[0].sent).toEqual([])
  })
  it.each(['cancel', 'blocked', 'expiry'] as const)('%s preserves the preexisting QR before a replacement starts', async reason => {
    const pending = ordinaryLogin(), raw = localStorage.getItem('ops-v2.browser-context')
    if (reason === 'blocked') f.env.open = () => null
    f.driver.start('admin')
    if (reason === 'cancel') f.driver.cancel()
    if (reason === 'expiry') await vi.advanceTimersByTimeAsync(120001)
    await flush()
    expect(f.native.login).not.toHaveBeenCalled(); expect(f.native.cancel).not.toHaveBeenCalled(); expect(f.state().pending).toBe(pending); expect(localStorage.getItem('ops-v2.browser-context')).toBe(raw)
  })
})

describe('explicit demo assistance owns only the popup for the original renewal', () => {
  it.each(['absent', 'actor', 'family', 'request', 'profile'] as const)('refuses %s marker ownership at the click without opening or changing authentication', async kind => {
    const pending = renewing(), key = 'ops-v2.browser-context', marker = JSON.parse(localStorage.getItem(key)!)
    if (kind === 'absent') localStorage.removeItem(key)
    if (kind === 'actor') marker.actorId = marker.pendingFlow.expectedActorId = 'ops:p1:' + 'X'.repeat(43)
    if (kind === 'family') marker.browserSessionId = marker.pendingFlow.expectedSessionId = '33333333-3333-4333-8333-333333333333'
    if (kind === 'request') marker.pendingFlow.requestId = '44444444-4444-4444-4444-444444444444'
    if (kind === 'profile') marker.sourceProfile = marker.pendingFlow.sourceProfile = 'other-profile'
    if (kind !== 'absent') localStorage.setItem(key, JSON.stringify(marker))
    const raw = localStorage.getItem(key); f.driver.start('admin'); await flush()
    expect(f.popups).toHaveLength(0); expect(f.native.login).not.toHaveBeenCalled(); expect(f.native.cancel).not.toHaveBeenCalled(); expect(f.native.confirm).not.toHaveBeenCalled()
    expect(f.state().pending).toBe(pending); expect(localStorage.getItem(key)).toBe(raw)
  })
  it('verifies the existing family without login, navigation or an automatic gesture', async () => {
    const pending = renewing(); await flush()
    expect(f.native.login).not.toHaveBeenCalled(); expect(f.native.confirm).not.toHaveBeenCalled(); expect(f.popups).toHaveLength(0)
    f.driver.start('admin'); await f.ready()
    expect(f.state().pending).toBe(pending); expect(f.native.login).not.toHaveBeenCalled()
    expect(f.popups[0].sent).toEqual([{ v: 1, type: 'prove', nonce: '1'.repeat(64), persona: 'admin', requestUri: pending.requestUri }])
    f.candidate('admin'); await flush()
    expect(f.native.confirm).toHaveBeenCalledTimes(1); expect(f.native.cancel).not.toHaveBeenCalled(); expect(f.navigate).not.toHaveBeenCalled()
    expect(f.driver.snapshot().active).toBe(false)
  })
  it('does not publish helper navigation or retry after a changed owner during confirmation', async () => {
    const held = deferred(); renewing('admin', { holdConfirm: held.promise }); f.driver.start('admin'); await f.ready(); f.candidate('admin'); await flush()
    expect(f.native.confirm).toHaveBeenCalledTimes(1); expect(f.driver.snapshot().cancellable).toBe(false)
    f.replace({ pending: null, candidate: null, phase: 'anonymous' }); held.resolve(); await flush()
    expect(f.native.cancel).not.toHaveBeenCalled(); expect(f.navigate).not.toHaveBeenCalled(); expect(f.native.continue).not.toHaveBeenCalled(); expect(f.native.confirm).toHaveBeenCalledTimes(1)
  })
  it.each(['cancel', 'closed', 'blocked', 'failed', 'transport-throw', 'navigation'] as const)('%s retires helper work while leaving the existing pending and marker intact', async reason => {
    const pending = renewing(), raw = localStorage.getItem('ops-v2.browser-context')
    if (reason === 'blocked') f.env.open = () => null
    f.driver.start('admin')
    if (reason === 'transport-throw') f.popups[0].postMessage = () => { throw Error('closed') }
    if (reason !== 'blocked') await f.ready()
    if (reason === 'cancel') f.driver.cancel()
    if (reason === 'closed') { f.popups[0].closed = true; await vi.advanceTimersByTimeAsync(201) }
    if (reason === 'failed') f.receive({ v: 1, type: 'status', nonce: '1'.repeat(64), status: 'failed' })
    if (reason === 'navigation') f.driver.navigation()
    await flush()
    expect(f.driver.snapshot().active).toBe(false); expect(f.native.cancel).not.toHaveBeenCalled(); expect(f.native.login).not.toHaveBeenCalled(); expect(f.native.confirm).not.toHaveBeenCalled()
    expect(f.state().pending).toBe(pending); expect(localStorage.getItem('ops-v2.browser-context')).toBe(raw)
  })
  it.each(['holder', 'actor', 'profile', 'network', 'request', 'expiry'] as const)('rejects a mismatched candidate %s without canceling the family', async field => {
    const pending = renewing(); f.driver.start('reader'); await f.ready()
    // Even the correct pending actor cannot substitute a different holder.
    const changes: Partial<Candidate> = { actorId: pending.actorId }
    if (field === 'holder') changes.holderDid = config.personas[0].holderDid
    if (field === 'actor') changes.actorId = 'ops:p1:' + 'X'.repeat(43)
    if (field === 'profile') changes.sourceProfile = 'other-profile'
    if (field === 'network') changes.network = 'polygon:amoy'
    if (field === 'request') changes.requestId = '33333333-3333-4333-8333-333333333333'
    if (field === 'expiry') changes.expiresAt = pending.expiresAt + 1
    f.candidate('reader', changes); await flush()
    // The holder case deliberately mismatches the selected reader; the other
    // cases also cannot turn a renewal into an account switch.
    expect(f.native.confirm).not.toHaveBeenCalled(); expect(f.native.cancel).not.toHaveBeenCalled(); expect(f.state().pending).toBe(pending)
  })
  it('a wrong persona may generate proof but cannot renew another actor or discard its draft', async () => {
    const pending = renewing(); f.driver.start('reader'); await f.ready(); f.candidate('reader'); await flush()
    expect(f.native.confirm).not.toHaveBeenCalled(); expect(f.native.cancel).not.toHaveBeenCalled(); expect(f.state().pending).toBe(pending)
    f.set({ candidate: null }); f.driver.start('admin'); await f.ready(); f.candidate('admin'); await flush()
    expect(f.native.confirm).toHaveBeenCalledTimes(1); expect(f.native.login).not.toHaveBeenCalled()
  })
  it.each(['ready', 'proof'] as const)('does not adopt changed raw marker bytes during %s, including a same-pair change', async phase => {
    const pending = renewing(); f.driver.start('admin'); if (phase === 'proof') await f.ready()
    const raw = localStorage.getItem('ops-v2.browser-context')!; localStorage.setItem('ops-v2.browser-context', raw + ' ')
    if (phase === 'ready') await f.ready(); else { f.candidate('admin'); await flush() }
    expect(f.native.confirm).not.toHaveBeenCalled(); expect(f.native.cancel).not.toHaveBeenCalled(); expect(f.state().pending).toBe(pending)
    expect(localStorage.getItem('ops-v2.browser-context')).toBe(raw + ' ')
  })
  it.each(['reference', 'revision', 'expiry', 'flow'] as const)('rejects changed %s ownership without canceling a replacement request', async kind => {
    const flow = { id: '33333333-3333-4333-8333-333333333333', clientId: 'explorer', displayName: 'Explorer', expiresAt: future() }
    const pending = renewing('admin', { flow }); f.driver.start('admin'); await f.ready()
    if (kind === 'reference') f.set({ pending: { ...pending } })
    if (kind === 'revision') f.replace({ pending })
    if (kind === 'expiry') pending.expiresAt++
    if (kind === 'flow') flow.expiresAt++
    f.candidate('admin'); await flush()
    expect(f.native.confirm).not.toHaveBeenCalled(); expect(f.native.cancel).not.toHaveBeenCalled(); expect(f.native.login).not.toHaveBeenCalled()
  })
  it('never extends the original pending expiry while waiting for wallet setup', async () => {
    const pending = renewing(); pending.expiresAt = Date.now() / 1000 + 1
    // Re-pin the matching server-style marker for the short original request.
    const marker = JSON.parse(localStorage.getItem('ops-v2.browser-context')!); marker.pendingFlow.expiresAt = pending.expiresAt; localStorage.setItem('ops-v2.browser-context', JSON.stringify(marker))
    f.driver.start('admin'); await vi.advanceTimersByTimeAsync(1001); await f.ready()
    expect(f.popups[0].closed).toBe(true); expect(f.native.confirm).not.toHaveBeenCalled(); expect(f.native.cancel).not.toHaveBeenCalled(); expect(f.state().pending).toBe(pending)
  })
})

describe('one explicit public demo identity owns the normal native login', () => {
  it.each(demoPersonas)('completes %s from verified candidate and current roles, not its label', async persona => {
    f = fixture({ admin: persona === 'reader' }); f.driver.start(persona)
    expect(f.events).toEqual(['listen', 'open']); expect(f.native.login).not.toHaveBeenCalled(); await f.ready()
    const p = config.personas.find(p => p.id === persona)!
    expect(f.native.login).toHaveBeenCalledWith(p.profileId, 'privado', p.holderDid, null)
    expect(f.popups[0].sent).toEqual([{ v: 1, type: 'prove', nonce: '1'.repeat(64), persona, requestUri: f.state().pending!.requestUri }])
    f.receive({ v: 1, type: 'status', nonce: '1'.repeat(64), status: 'submitted' }); await flush(); expect(f.native.confirm).not.toHaveBeenCalled()
    f.candidate(persona); await flush()
    expect(f.native.confirm).toHaveBeenCalledTimes(1); expect(f.native.continue).not.toHaveBeenCalled()
    expect(f.navigate).toHaveBeenCalledWith(persona === 'reader' ? '/admin/rbac/organizations' : '/account')
    expect(f.popups[0].closed).toBe(true); expect(f.driver.snapshot().active).toBe(false)
  })
  it('ignores a foreign window/origin and rejects substituted metadata before native start', async () => {
    f = fixture(); f.driver.start('admin'); const ready = { v: 1, type: 'ready', nonce: '1'.repeat(64), config }
    f.receive(ready, {}, wallet); f.receive(ready, f.popups[0], 'https://evil.test'); await flush()
    expect(f.native.login).not.toHaveBeenCalled(); expect(f.driver.snapshot().active).toBe(true)
    f.receive({ ...ready, config: { ...config, network: 'polygon:amoy' } }); await flush()
    expect(f.native.login).not.toHaveBeenCalled(); expect(f.popups[0].closed).toBe(true)
  })
  it('does not let a delayed ready replace a changed shared account even before a storage event arrives', async () => {
    f = fixture(); f.driver.start('admin')
    localStorage.setItem('ops-v2.browser-context', 'another explicit login now owns this marker')
    await f.ready()
    expect(f.native.login).not.toHaveBeenCalled(); expect(f.popups[0].closed).toBe(true)
    expect(f.driver.snapshot().error).toMatch(/account changed/)
    expect(localStorage.getItem('ops-v2.browser-context')).toBe('another explicit login now owns this marker')
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
    expect(f.native.confirm).toHaveBeenCalledTimes(1); expect(f.state().self?.sourceProfile).toBe('demo-privado'); expect(f.popups.every(p => p.closed)).toBe(true)
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
  it('allows first-use certificate setup beyond 15 seconds without starting authentication early', async () => {
    f = fixture(); f.driver.start('admin'); await vi.advanceTimersByTimeAsync(20000)
    expect(f.driver.snapshot().active).toBe(true); expect(f.popups[0].closed).toBe(false)
    expect(f.native.login).not.toHaveBeenCalled(); expect(f.native.confirm).not.toHaveBeenCalled()
    await f.ready(); f.candidate('admin'); await flush()
    expect(f.native.login).toHaveBeenCalledTimes(1); expect(f.native.confirm).toHaveBeenCalledTimes(1)
  })
  it('bounds certificate setup by its own wait and the original application expiry', async () => {
    f = fixture(); f.driver.start('admin'); await vi.advanceTimersByTimeAsync(120001)
    expect(f.popups[0].closed).toBe(true); expect(f.native.login).not.toHaveBeenCalled()
    f.driver.dispose()
    f = fixture({ flow: { id: '33333333-3333-4333-8333-333333333333', clientId: 'explorer', displayName: 'Explorer', expiresAt: Date.now() / 1000 + 5 } })
    f.driver.start('admin'); await vi.advanceTimersByTimeAsync(5001); await f.ready()
    expect(f.popups[0].closed).toBe(true); expect(f.native.login).not.toHaveBeenCalled()
    expect(f.native.confirm).not.toHaveBeenCalled(); expect(f.native.continue).not.toHaveBeenCalled()
  })
})

describe('bounded local demo renewal', () => {
  async function signIn(options: Controls = {}) {
    f = fixture(Object.assign(options, { autoRenew: true, admin: true })); f.driver.start('admin'); await f.ready()
    expect(f.popups[0].sent[0]).toMatchObject({ persona: 'admin', keepAlive: true })
    f.candidate('admin'); await flush()
    expect(f.state().phase).toBe('selected'); expect(f.popups[0].closed).toBe(false)
  }
  function requireProof(changes: Partial<ProofRequired> = {}) {
    const pending: ProofRequired = { status: 'proof_required', provider: 'privado', principalKind: 'human', mode: 'renew', sourceProfile: 'demo-privado', actorId: f.state().self!.actorId,
      browserSessionId: '22222222-2222-4222-8222-222222222222', requestId: 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee', requestUri: origin + '/api/v2/auth/privado/requests/aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee', expiresAt: future(), ...changes }
    writeMultiMarker({ version: 2, phase: 'require-login', actorId: pending.actorId, browserSessionId: pending.browserSessionId, sourceProfile: pending.sourceProfile, provider: 'privado', pendingFlow: { kind: 'privado', mode: 'renew', requestId: pending.requestId, sourceProfile: pending.sourceProfile, expiresAt: pending.expiresAt, expectedActorId: pending.actorId, expectedSessionId: pending.browserSessionId } })
    f.set({ phase: 'proof-pending', self: null, pending, candidate: null }); return pending
  }
  it('uses the same window for a fresh, same-session proof and never issues a new login', async () => {
    await signIn(); const pending = requireProof(); await flush()
    expect(f.popups).toHaveLength(1); expect(f.popups[0].sent[1]).toEqual({ v: 1, type: 'prove', nonce: '1'.repeat(64), persona: 'admin', requestUri: pending.requestUri })
    f.candidate('admin'); await flush()
    expect(f.native.confirm).toHaveBeenCalledTimes(2); expect(f.native.login).toHaveBeenCalledTimes(1)
    expect(f.state().phase).toBe('selected'); expect(f.popups[0].closed).toBe(false)
  })
  it('handles two successive fresh challenges for the same family without another popup or login', async () => {
    await signIn(); requireProof(); await flush(); f.candidate('admin'); await flush()
    const requestId = 'bbbbbbbb-bbbb-4ccc-8ddd-eeeeeeeeeeee'
    requireProof({ requestId, requestUri: origin + '/api/v2/auth/privado/requests/' + requestId }); await flush()
    expect(f.popups).toHaveLength(1); expect(f.popups[0].sent).toHaveLength(3)
    f.candidate('admin'); await flush()
    expect(f.native.login).toHaveBeenCalledTimes(1); expect(f.native.confirm).toHaveBeenCalledTimes(3)
    expect(f.state().phase).toBe('selected'); expect(f.popups[0].closed).toBe(false)
  })
  it('does not confirm a renewal proof arriving after the thirty-minute helper deadline', async () => {
    await signIn(); await vi.advanceTimersByTimeAsync(30 * 60 * 1000 - 1000)
    requireProof(); await flush(); expect(f.popups[0].sent).toHaveLength(2)
    await vi.advanceTimersByTimeAsync(1201); expect(f.popups[0].closed).toBe(true)
    f.candidate('admin'); await flush(); expect(f.native.confirm).toHaveBeenCalledTimes(1)
  })
  it('does not retry an already-dispatched confirmation after the assistance deadline', async () => {
    const options: Controls = {}; await signIn(options)
    await vi.advanceTimersByTimeAsync(30 * 60 * 1000 - 1000)
    requireProof(); await flush()
    const held = deferred(); options.holdConfirm = held.promise
    f.candidate('admin'); await flush(); expect(f.native.confirm).toHaveBeenCalledTimes(2)
    await vi.advanceTimersByTimeAsync(1201); expect(f.popups[0].closed).toBe(true)
    held.resolve(); await flush()
    expect(f.native.confirm).toHaveBeenCalledTimes(2); expect(f.popups[0].sent).toHaveLength(2)
  })
  it('stops at thirty minutes, on logout and on replacement by a different actor', async () => {
    for (const reason of ['deadline', 'logout', 'actor'] as const) {
      await signIn()
      if (reason === 'deadline') await vi.advanceTimersByTimeAsync(30 * 60 * 1000 + 1)
      if (reason === 'logout') { f.set({ phase: 'anonymous', self: null }); await flush() }
      if (reason === 'actor') { writeMultiMarker(activeMulti({ actorId: 'ops:p1:' + 'B'.repeat(42) + 'A', browserSessionId: '22222222-2222-4222-8222-222222222222', provider: 'privado', sourceProfile: 'demo-privado' })); await vi.advanceTimersByTimeAsync(1001) }
      expect(f.popups[0].closed, reason).toBe(true); expect(f.native.confirm).toHaveBeenCalledTimes(1)
      f.driver.dispose()
    }
  })
  it('stops instead of proving when the renewal challenge belongs to another family', async () => {
    await signIn(); requireProof({ browserSessionId: '99999999-9999-4999-8999-999999999999' }); await flush()
    expect(f.popups[0].closed).toBe(true); expect(f.popups[0].sent).toHaveLength(1); expect(f.native.confirm).toHaveBeenCalledTimes(1)
  })
  it.each(['candidate', 'busy'] as const)('does not adopt a renewal already being handled elsewhere: %s', async reason => {
    await signIn(); requireProof()
    if (reason === 'candidate') f.candidate('admin')
    else f.set({ busy: true })
    await flush()
    expect(f.popups[0].closed).toBe(true); expect(f.popups[0].sent).toHaveLength(1)
    expect(f.native.confirm).toHaveBeenCalledTimes(1)
  })
  it('stops when the user closes the wallet or the owning document is disposed', async () => {
    for (const reason of ['close', 'dispose'] as const) {
      await signIn()
      if (reason === 'close') { f.popups[0].closed = true; await vi.advanceTimersByTimeAsync(1001) }
      else f.driver.dispose()
      expect(f.popups[0].closed).toBe(true)
      expect(f.native.confirm).toHaveBeenCalledTimes(1)
      f.driver.dispose()
    }
  })
  it('never confirms a fresh proof for another holder or actor', async () => {
    await signIn(); requireProof(); await flush()
    f.candidate('reader'); await flush()
    expect(f.native.confirm).toHaveBeenCalledTimes(1); expect(f.popups[0].closed).toBe(true)
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
