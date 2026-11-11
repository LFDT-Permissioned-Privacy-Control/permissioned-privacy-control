import { NewMultiClient, MultiBrowserAuthClient } from '../auth/multiClient'
import { CONTEXT_KEY } from '../auth/context'
import { multiPair, readMultiMarker } from '../auth/multiContext'
import { AccessOutcome, Candidate, MultiAccess, MultiSession, Pending, sameSession } from '../auth/multiProtocol'
import { AuthError, session } from '../auth/protocol'
import { completeFlow, Flow, FLOW_KEY, inspectFlow, ownSelf, readContinuation, saveContinuation, Self } from './protocol'

export type Phase = 'booting' | 'anonymous' | 'selected' | 'proof-pending' | 'context-changed' | 'failed'
type Profiles = Awaited<ReturnType<MultiBrowserAuthClient['providers']>>
export interface State {
  phase: Phase; profiles: Profiles['profiles']; self: Self | null; flow: Flow | null
  pending: Pending | null; candidate: Candidate | null; busy: boolean; error: string | null
}
interface Owner { epoch: number; revision: number; operation: number; kind: string; pair: MultiSession | null; abort: AbortController }
class Stale extends Error {}

// One controller per document. No component effect performs restore or owns a
// token; asynchronous UI results must still own the exact context AND flow.
export class Controller {
  private client: MultiBrowserAuthClient
  private state: State = { phase: 'booting', profiles: [], self: null, flow: null, pending: null, candidate: null, busy: false, error: null }
  private selected: MultiSession | null = null
  private epoch = 0
  private revision = 0
  private serial = 0
  private alive = true
  private started = false
  private latest = new Map<string, Owner>()
  private listeners = new Set<() => void>()
  private pollTimer: ReturnType<typeof setTimeout> | undefined
  private tickTimer: ReturnType<typeof setInterval> | undefined
  private expiryTimer: ReturnType<typeof setTimeout> | undefined
  private completing = false
  constructor(client = NewMultiClient(), private flushSuspension: (clear: () => void) => void = clear => clear()) { this.client = client }
  snapshot = (): State => this.state
  subscribe = (listener: () => void): (() => void) => { this.listeners.add(listener); return () => this.listeners.delete(listener) }
  private set(next: Partial<State>): void { this.state = { ...this.state, ...next }; for (const f of this.listeners) f() }
  private invalidate(): void {
    this.epoch++; this.revision++
    for (const op of this.latest.values()) op.abort.abort()
    this.latest.clear(); clearTimeout(this.pollTimer); this.completing = false
    clearTimeout(this.expiryTimer)
  }
  private changed(): void {
    this.invalidate(); this.selected = null
    this.set({ phase: 'context-changed', self: null, pending: null, candidate: null, busy: false, error: null })
  }
  private owner(kind: string): Owner {
    this.latest.get(kind)?.abort.abort()
    const op: Owner = { epoch: this.epoch, revision: this.revision, operation: ++this.serial,
      kind, pair: this.selected && { ...this.selected }, abort: new AbortController() }
    this.latest.set(kind, op)
    return op
  }
  private owns(op: Owner): boolean {
    return this.alive && op.epoch === this.epoch && op.revision === this.revision && this.latest.get(op.kind) === op && !op.abort.signal.aborted
  }
  private check(op: Owner): void {
    if (!this.owns(op)) throw new Stale()
    if (this.state.flow && this.state.flow.expiresAt <= Date.now() / 1000) throw new AuthError('login_required')
    if (op.pair) {
      try {
        const marker = readMultiMarker()
        if (!marker || !sameSession(op.pair, multiPair(marker)) || !this.selected || !sameSession(op.pair, this.selected)) throw new Error()
      } catch { this.changed(); throw new Stale() }
    }
  }
  private signal(op: Owner): AbortSignal { return AbortSignal.any([op.abort.signal, AbortSignal.timeout(25000)]) }
  private error(op: Owner, error: unknown): void {
    if (error instanceof Stale) return
    try { this.check(op) } catch { return }
    if (error instanceof AuthError && error.code === 'session_changed') { this.changed(); return }
    this.set({ phase: error instanceof AuthError && error.code === 'login_required' ? 'anonymous' : 'failed',
      self: null, candidate: null, pending: null, busy: false,
      error: error instanceof AuthError ? error.code : 'authentication_unavailable' })
  }
  private async work(kind: string, action: (op: Owner) => Promise<void>): Promise<void> {
    const op = this.owner(kind)
    try { this.check(op); await action(op); this.check(op) }
    catch (error) { this.error(op, error) }
    finally { if (this.latest.get(kind) === op) this.latest.delete(kind) }
  }
  // Called synchronously at module entry on the Azure callback page. The helper
  // scrubs query credentials BEFORE providers, rendering or any awaited work.
  callback(): Promise<{ access?: MultiAccess; error?: unknown }> {
    return this.client.completeAzureCallback().then(access => ({ access }), error => ({ error }))
  }
  async start(callback?: Promise<{ access?: MultiAccess; error?: unknown }>): Promise<void> {
    if (this.started || !this.alive) return
    this.started = true
    window.addEventListener('storage', this.storage)
    window.addEventListener('pagehide', this.suspend)
    window.addEventListener('popstate', this.navigation)
    document.addEventListener('visibilitychange', this.visibility)
    this.tickTimer = setInterval(this.tick, 1000)
    await this.work('bootstrap', async op => {
      const providers = await this.client.providers(); this.check(op)
      if (!['/login', '/auth/sso', '/auth/azure/callback', providers.completionPath].includes(location.pathname)) throw new AuthError('invalid_response')
      this.set({ profiles: providers.profiles })
      let saved = readContinuation()
      if (location.pathname === '/auth/sso') {
        const query = new URLSearchParams(location.search)
        if (query.size !== 1 || query.getAll('flow').length !== 1 || !session(query.get('flow'))) throw new AuthError('invalid_response')
        const id = query.get('flow')!
        if (saved?.id !== id) saved = { id, expiresAt: Math.floor(Date.now() / 1000) + 300 }
      } else if (location.pathname !== '/auth/azure/callback' && (location.search || location.hash)) throw new AuthError('invalid_response')
      if (saved) {
        // This inspect is bounded by the earlier local/original expiry. Only
        // the first current inspect may set it, and it can never extend it.
        const flow = await inspectFlow(saved.id, AbortSignal.any([this.signal(op), AbortSignal.timeout(Math.max(1, saved.expiresAt * 1000 - Date.now()))])); this.check(op)
        if (flow.expiresAt > saved.expiresAt) throw new AuthError('invalid_response')
        this.set({ flow }); saveContinuation(flow)
      }
      if (callback) {
        const result = await callback; this.check(op)
        if (!result.access) throw result.error
        await this.accept(op, result.access)
      } else {
        const result = await this.client.restore(); this.check(op)
        await this.outcome(op, result)
      }
    })
  }
  private async accept(op: Owner, access: MultiAccess): Promise<void> {
    this.check(op)
    if (this.selected && !sameSession(this.selected, access)) { this.changed(); throw new Stale() }
    const self = await ownSelf(access, this.signal(op)); this.check(op)
    // The helper checked the marker after its response. A later change, even
    // while self was in flight, must not publish an older account's identity.
    const marker = readMultiMarker()
    if (!marker || marker.phase !== 'active' || !sameSession(access, multiPair(marker))) { this.changed(); throw new Stale() }
    this.selected = { actorId: access.actorId, browserSessionId: access.browserSessionId, provider: access.provider, sourceProfile: access.sourceProfile }
    this.set({ phase: 'selected', self, pending: null, candidate: null, busy: false, error: null })
    clearTimeout(this.expiryTimer)
    this.expiryTimer = setTimeout(this.tick, Math.max(1, self.expiresAt * 1000 - Date.now()))
  }
  private async outcome(op: Owner, result: AccessOutcome): Promise<void> {
    if (result.status === 'access') { await this.accept(op, result.access); return }
    this.check(op)
    if (result.status === 'proof_required') {
      if (this.selected && !sameSession(this.selected, result)) { this.changed(); throw new Stale() }
      this.selected = { actorId: result.actorId, browserSessionId: result.browserSessionId, provider: result.provider, sourceProfile: result.sourceProfile }
    }
    this.set({ phase: 'proof-pending', self: null, pending: result, candidate: null, busy: false, error: null })
    this.schedulePoll()
  }
  private replace(): boolean {
    if (!this.alive) return false
    this.invalidate(); this.selected = null; this.client = NewMultiClient()
    this.set({ phase: 'booting', self: null, candidate: null, pending: null, busy: true, error: null })
    return true
  }
  // An explicit user action is the only way a live document adopts a changed
  // account; restore/status/timers never perform this replacement.
  useCurrent = async (): Promise<void> => {
    if (!this.replace()) return
    await this.work('accept', async op => {
      const result = await this.client.restore(); this.check(op); await this.outcome(op, result)
    })
  }
  login = async (profile: string, kind: 'azure' | 'privado'): Promise<void> => {
    if (!this.state.profiles.some(p => p.id === profile && p.provider === kind)) return
    if (!this.replace()) return
    await this.work('login', async op => {
      if (kind === 'azure') {
        const result = await this.client.startAzureLogin(profile); this.check(op)
        location.replace(result.authorizationUrl)
      } else {
        const result = await this.client.startPrivadoLogin(profile); this.check(op)
        this.set({ phase: 'proof-pending', busy: false, pending: { status: 'login_in_progress', provider: 'privado', sourceProfile: profile,
          expiresAt: result.expiresAt, requestId: result.requestId, requestUri: result.requestUri } })
        this.schedulePoll()
      }
    })
  }
  refresh = async (): Promise<void> => {
    if (!this.selected || this.state.busy || this.state.phase === 'context-changed') return
    this.set({ busy: true, error: null })
    const expected = { ...this.selected }
    await this.work('refresh', async op => {
      const result = await this.client.needAccess(expected); this.check(op); await this.outcome(op, result)
    })
  }
  private schedulePoll(): void {
    clearTimeout(this.pollTimer)
    if (!this.alive || document.visibilityState === 'hidden' || this.state.candidate || this.state.pending?.provider !== 'privado') return
    this.pollTimer = setTimeout(() => { void this.poll() }, 1000)
  }
  private async poll(): Promise<void> {
    const pending = this.state.pending
    if (!pending?.requestId || pending.provider !== 'privado' || document.visibilityState === 'hidden' || this.latest.has('poll')) return
    if (pending.expiresAt <= Date.now() / 1000) { this.set({ phase: 'anonymous', pending: null, candidate: null, error: 'login_required' }); return }
    await this.work('poll', async op => {
      const result = await this.client.previewPrivado(pending.requestId!); this.check(op)
      if (this.state.pending?.requestId !== pending.requestId) throw new Stale()
      this.set({ candidate: result.status === 'candidate' ? result : null })
    })
    this.schedulePoll()
  }
  confirm = async (): Promise<void> => {
    const candidate = this.state.candidate
    if (!candidate || this.state.busy) return
    clearTimeout(this.pollTimer); this.set({ busy: true, error: null })
    await this.work('confirm', async op => {
      const result = await this.client.confirmPrivado(candidate); this.check(op); await this.accept(op, result)
    })
  }
  cancel = async (): Promise<void> => {
    if (!this.alive) return
    const id = this.state.pending?.requestId
    this.invalidate(); this.set({ self: null, pending: null, candidate: null, busy: false, phase: 'anonymous', error: null })
    if (!id) return
    await this.work('cancel', async op => { await this.client.cancelPrivado(id); this.check(op) })
  }
  continue = async (): Promise<void> => {
    const pair = this.selected && { ...this.selected }, flow = this.state.flow
    if (!pair || !flow || this.completing || this.state.busy || this.state.phase !== 'selected') return
    this.completing = true; this.set({ busy: true, error: null })
    await this.work('complete', async op => {
      try {
        const result = await this.client.withAccess(pair, async token => {
          this.check(op) // Helper renewal may have awaited; fence BEFORE action.
          const redirect = await completeFlow(flow, pair, token, this.signal(op)); this.check(op)
          return redirect
        }); this.check(op)
        if (result.status !== 'completed') { this.completing = false; await this.outcome(op, result); return }
        sessionStorage.removeItem(FLOW_KEY)
        this.check(op)
        location.replace(result.value) // No await between final fence and navigation.
      } finally {
        // Retire only THIS attempt, including ambiguous POST outcomes. A stale
        // finally must not erase a later account's flow, busy state or storage.
        if (this.owns(op) && this.completing) {
          this.completing = false
          this.set({ flow: null, busy: false }); sessionStorage.removeItem(FLOW_KEY)
        }
      }
    })
  }
  logout = async (): Promise<void> => {
    const pair = this.selected && { ...this.selected }
    if (!pair || this.state.busy) return
    this.invalidate(); this.set({ self: null, pending: null, candidate: null, busy: true })
    await this.work('logout', async op => {
      await this.client.logout(pair); this.check(op)
      this.selected = null; this.set({ phase: 'anonymous', busy: false, error: null })
    })
  }
  private storage = (event: StorageEvent): void => {
    if (event.key !== CONTEXT_KEY && event.key !== null || !this.selected) return
    try { const m = readMultiMarker(); if (!m || !sameSession(this.selected, multiPair(m))) this.changed() }
    catch { this.changed() }
  }
  private visibility = (): void => {
    clearTimeout(this.pollTimer)
    // Abandon any late preview on hide; completion/action owners are retained
    // and independently checked. Becoming visible never adopts another actor.
    this.latest.get('poll')?.abort.abort(); this.latest.delete('poll')
    if (document.visibilityState !== 'hidden') { this.tick(); this.schedulePoll() }
  }
  private tick = (): void => {
    if (!this.alive) return
    if (this.state.flow && this.state.flow.expiresAt <= Date.now() / 1000) {
      this.invalidate(); sessionStorage.removeItem(FLOW_KEY)
      this.set({ flow: null, self: null, pending: null, candidate: null, busy: false, phase: 'failed', error: 'login_required' }); return
    }
    if (this.state.pending && this.state.pending.expiresAt <= Date.now() / 1000) {
      this.invalidate()
      this.set({ self: null, pending: null, candidate: null, busy: false, phase: 'anonymous', error: 'login_required' }); return
    }
    if (this.state.self && this.state.self.expiresAt <= Date.now() / 1000) this.set({ self: null })
    if (this.selected && this.state.phase === 'selected' && !this.state.busy && document.visibilityState !== 'hidden' &&
      (!this.state.self || this.state.self.expiresAt <= Date.now() / 1000 + 5)) void this.refresh()
  }
  private navigation = (): void => { this.invalidate(); this.set({ phase: 'failed', self: null, pending: null, candidate: null, busy: false, error: 'login_required' }) }
  private suspend = (event: PageTransitionEvent): void => {
    this.flushSuspension(this.stop)
    if (event.persisted) window.addEventListener('pageshow', this.resume, { once: true })
  }
  private resume = (event: PageTransitionEvent): void => {
    // A BFCache document has a stopped helper and no live selection. Use a
    // fresh document and genuine broker restoration, never revive stale DOM.
    if (event.persisted) location.reload()
  }
  stop = (): void => {
    this.alive = false; this.invalidate(); clearInterval(this.tickTimer)
    this.selected = null; this.client = NewMultiClient()
    this.set({ phase: 'failed', self: null, flow: null, pending: null, candidate: null, busy: false, error: 'login_required' })
    window.removeEventListener('storage', this.storage); window.removeEventListener('pagehide', this.suspend)
    window.removeEventListener('pageshow', this.resume)
    window.removeEventListener('popstate', this.navigation); document.removeEventListener('visibilitychange', this.visibility)
  }
}
