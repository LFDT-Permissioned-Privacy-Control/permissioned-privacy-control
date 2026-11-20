import { NewMultiClient, MultiBrowserAuthClient } from '../auth/multiClient'
import { CONTEXT_KEY } from '../auth/context'
import { multiPair, readMultiMarker, readLoginContext, unchangedLoginContext, type LoginContext } from '../auth/multiContext'
import { AccessOutcome, Candidate, MultiAccess, MultiSession, Pending, sameSession } from '../auth/multiProtocol'
import { AuthError, session } from '../auth/protocol'
import { completeFlow, Flow, FLOW_KEY, inspectFlow, ownSelf, readContinuation, saveContinuation, Self } from './protocol'
import { forgetRemembered, remember, remembered } from './remembered'
import { WalletController, WalletHTTPError, WalletScope } from './wallet'
import { walletRequest } from './walletTransport'
import { OperationHTTPError, operationRequest } from './operationsTransport'
import { adminLocation, plainLoginLocation } from './routes'

export type Phase = 'booting' | 'anonymous' | 'selected' | 'proof-pending' | 'context-changed' | 'failed'
type Profiles = Awaited<ReturnType<MultiBrowserAuthClient['providers']>>
export interface State {
  phase: Phase; profiles: Profiles['profiles']; self: Self | null; flow: Flow | null
  pending: Pending | null; candidate: Candidate | null; busy: boolean; error: string | null
}
interface Owner { epoch: number; revision: number; operation: number; kind: string; pair: MultiSession | null; abort: AbortController }
export interface OperationScope extends WalletScope { readonly self: Self }
class Stale extends Error {}

// One controller per document. No component effect performs restore or owns a
// token; asynchronous UI results must still own the exact context AND flow.
export class Controller {
  private client: MultiBrowserAuthClient
  private state: State = { phase: 'booting', profiles: [], self: null, flow: null, pending: null, candidate: null, busy: false, error: null }
  private selected: MultiSession | null = null
  private epoch = 0
  private uiRevision = 0
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
  readonly wallet: WalletController
  private walletRevision = 0
  private walletScopes = new Set<AbortController>()
  constructor(client = NewMultiClient(), private flushSuspension: (clear: () => void) => void = clear => clear()) {
    this.client = client
    this.wallet = new WalletController(signal => this.captureWallet(signal), { flush: clear => this.flushSuspension(clear) })
  }
  snapshot = (): State => this.state
  subscribe = (listener: () => void): (() => void) => { this.listeners.add(listener); return () => this.listeners.delete(listener) }
  // Noncredential document ownership for imported UI drafts. Renewing the same
  // context preserves it; replacement/logout/suspension invalidates it.
  get scopeRevision(): number { return this.uiRevision }
  ownsScope(revision: number, actor: string): boolean {
    if (!this.alive || revision !== this.uiRevision || !this.selected || this.state.phase !== 'selected' || this.state.flow || this.state.pending ||
      !this.state.self || this.state.self.actorId !== actor || this.state.self.expiresAt <= Date.now() / 1000) return false
    try {
      const marker = readMultiMarker()
      if (marker?.phase === 'active' && sameSession(this.selected, multiPair(marker))) return true
    } catch { /* A corrupt marker invalidates the same private context. */ }
    this.changed(); return false
  }
  private set(next: Partial<State>): void { this.state = { ...this.state, ...next }; for (const f of this.listeners) f() }
  private invalidate(): void {
    this.retireWallet()
    this.epoch++; this.revision++; this.uiRevision++
    for (const op of this.latest.values()) op.abort.abort()
    this.latest.clear(); clearTimeout(this.pollTimer); this.completing = false
    clearTimeout(this.expiryTimer)
  }
  private retireWallet(): void {
    this.walletRevision++
    for (const scope of this.walletScopes) scope.abort()
    this.walletScopes.clear(); this.wallet.cancel()
  }
  captureOperations = async (signal: AbortSignal): Promise<OperationScope> => {
    const scope = await this.captureWallet(signal, operationRequest, 'operations-warmup')
    try {
      scope.check()
      const self = this.state.self
      if (!self || self.actorId !== scope.identity.actor || self.expiresAt !== scope.identity.expires) throw new Stale()
      return Object.freeze({ ...scope, self })
    } catch (error) { scope.dispose(); throw error }
  }
  private async captureWallet(signal: AbortSignal, transport = walletRequest, kind = 'wallet-warmup'): Promise<WalletScope> {
    if (!this.alive || !this.selected || !this.state.self || this.state.self.expiresAt <= Date.now() / 1000 || this.state.phase !== 'selected' || this.state.flow || this.state.pending) throw new Stale()
    const op = this.owner(kind), pair = { ...this.selected }, walletRevision = this.walletRevision, warmExpiry = this.state.self.expiresAt
    const warm = () => { this.check(op); if (signal.aborted || walletRevision !== this.walletRevision || warmExpiry <= Date.now() / 1000) throw new Stale() }
    try {
      warm()
      // One explicit pre-scope warm-up. Confirm never invokes a helper again.
      const result = await this.client.needAccess(pair); warm()
      if (result.status !== 'access') { await this.outcome(op, result); throw new Stale() }
      const access = result.access
      const self = await ownSelf(access, AbortSignal.any([signal, this.signal(op)])); warm()
      const marker = readMultiMarker()
      if (!marker || marker.phase !== 'active' || !sameSession(pair, multiPair(marker)) || !sameSession(pair, access) || self.actorId !== access.actorId || self.sourceProfile !== access.sourceProfile || self.expiresAt !== access.expiresAt) throw new Stale()
      Object.freeze(self)
      this.set({ self })
      clearTimeout(this.expiryTimer)
      this.expiryTimer = setTimeout(this.tick, Math.max(1, self.expiresAt * 1000 - Date.now()))
      warm()
      const epoch = this.epoch, revision = this.revision, abort = new AbortController(), token = access.accessToken, originalExpiry = self.expiresAt
      this.walletScopes.add(abort)
      const check = () => {
        if (!this.alive || signal.aborted || abort.signal.aborted || epoch !== this.epoch || revision !== this.revision || walletRevision !== this.walletRevision || this.state.self !== self || originalExpiry <= Date.now() / 1000 || !this.selected || !sameSession(pair, this.selected)) throw new Stale()
        const current = readMultiMarker()
        if (!current || current.phase !== 'active' || !sameSession(pair, multiPair(current))) { this.changed(); throw new Stale() }
      }
      const scope: WalletScope = Object.freeze({
        identity: Object.freeze({ actor: self.actorId, expires: originalExpiry }), signal: AbortSignal.any([signal, abort.signal]), check,
        request: async <T,>(endpoint: string, options: RequestInit = {}): Promise<T> => {
          check()
          try {
            const value = await transport(token, endpoint, options, AbortSignal.any([signal, abort.signal]), check); check()
            return value as T
          } catch (error) {
            check()
            if ((error instanceof WalletHTTPError || error instanceof OperationHTTPError) && error.status === 401) this.changed()
            throw error
          }
        },
        dispose: () => { abort.abort(); this.walletScopes.delete(abort) },
      })
      check(); return scope
    } catch (error) {
      if (this.owns(op) && !signal.aborted && walletRevision === this.walletRevision && error instanceof AuthError && (error.code === 'login_required' || error.code === 'session_changed')) this.error(op, error)
      throw error
    } finally { if (this.latest.get(op.kind) === op) this.latest.delete(op.kind) }
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
    try { this.check(op) } catch {
      // check() also rejects an expired application flow. Its own failure
      // must clear that flow instead of silently leaving a selected/busy UI.
      if (this.owns(op) && this.state.flow && this.state.flow.expiresAt <= Date.now() / 1000) this.expireFlow()
      return
    }
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
      const initialMarker = readMultiMarker()
      const providers = await this.client.providers(); this.check(op)
      const admin = adminLocation(location)
      if (!['/login', '/auth/sso', '/auth/azure/callback', providers.completionPath].includes(location.pathname) && !admin) throw new AuthError('invalid_response')
      this.set({ profiles: providers.profiles })
      // An explicit workspace visit starts a different task. Never silently
      // complete an old application's SSO flow while opening the Admin UI.
      if (admin) sessionStorage.removeItem(FLOW_KEY)
      let saved = admin ? null : readContinuation()
      if (location.pathname === '/auth/sso') {
        const query = new URLSearchParams(location.search)
        if (query.size !== 1 || query.getAll('flow').length !== 1 || !session(query.get('flow'))) throw new AuthError('invalid_response')
        const id = query.get('flow')!
        if (saved?.id !== id) saved = { id, expiresAt: Math.floor(Date.now() / 1000) + 300 }
      } else if (location.pathname !== '/auth/azure/callback' && !admin && (location.search || location.hash)) throw new AuthError('invalid_response')
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
        let result: AccessOutcome
        try { result = await this.client.restore(); this.check(op) }
        catch (error) {
          this.check(op)
          const empty = (marker: ReturnType<typeof readMultiMarker>) => !marker || marker.phase === 'require-login' && marker.actorId === null && marker.pendingFlow === null
          // A fresh bootstrap denial is ordinary signed-out state. Do not
          // relabel a prior identity, app flow, callback or real outage.
          if (!saved && !callback && (admin || plainLoginLocation(location)) && empty(initialMarker) &&
            error instanceof AuthError && error.code === 'login_required' && empty(readMultiMarker())) {
            this.set({ phase: 'anonymous', self: null, pending: null, candidate: null, busy: false, error: null }); return
          }
          throw error
        }
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
    const flow = this.state.flow, pair = this.selected && { ...this.selected }, epoch = this.epoch, revision = this.revision
    if (flow && pair && remembered(flow, self, pair)) queueMicrotask(() => {
      if (this.alive && epoch === this.epoch && revision === this.revision && this.state.flow === flow && this.state.self === self && this.selected && sameSession(pair, this.selected)) void this.finish(true)
    })
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
  login = async (profile: string, kind: 'azure' | 'privado', expectedHolderDid?: string, clickedContext?: LoginContext): Promise<void> => {
    if (!this.state.profiles.some(p => p.id === profile && p.provider === kind)) return
    if (!this.replace()) return
    await this.work('login', async op => {
      const expectedContext = clickedContext === undefined ? readLoginContext() : clickedContext
      // Recheck inside the existing browser lock, immediately before any
      // marker write or provider request. A queued old click owns neither.
      const requireCurrent = () => { this.check(op); unchangedLoginContext(expectedContext) }
      if (kind === 'azure') {
        const result = await this.client.startAzureLogin(profile, requireCurrent); this.check(op)
        location.replace(result.authorizationUrl)
      } else {
        const result = await this.client.startPrivadoLogin(profile, expectedHolderDid, requireCurrent); this.check(op)
        this.set({ phase: 'proof-pending', busy: false, pending: { status: 'login_in_progress', provider: 'privado', sourceProfile: profile,
          expiresAt: result.expiresAt, requestId: result.requestId, requestUri: result.requestUri } })
        this.schedulePoll()
      }
    })
  }
  refresh = async (): Promise<void> => {
    if (!this.selected || this.state.busy || this.state.phase === 'context-changed') return
    this.retireWallet()
    this.set({ busy: true, error: null })
    const expected = { ...this.selected }
    await this.work('refresh', async op => {
      const result = await this.client.needAccess(expected); this.check(op); await this.outcome(op, result)
    })
  }
  // Explicit compatibility handoff to the local wallet helper. The credential
  // stays in this action and its download Blob; it is never a UI state value.
  downloadOwnWalletToken = async (): Promise<void> => {
    await this.ownCredentialAction('wallet-token-download', (token, current) => {
      const url = URL.createObjectURL(new Blob([token], { type: 'text/plain' }))
      try {
        const link = document.createElement('a')
        link.href = url; link.download = 'ops-wallet-token.jwt'
        current(); link.click()
      } finally { URL.revokeObjectURL(url) }
    })
  }
  copyOwnRPCCredential = async (format: 'token' | 'header' | 'foundry'): Promise<boolean> => {
    if (!['token', 'header', 'foundry'].includes(format)) return false
    return this.ownCredentialAction('rpc-credential-copy', async (token, current) => {
    if (!navigator.clipboard?.writeText) throw Error('Clipboard access is unavailable. Download your wallet token instead.')
    // Shell-ready text accepts only a compact JWT; no arbitrary credential can
    // become shell syntax. No token is returned to a component or persisted.
    if (format === 'foundry' && !/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(token)) throw Error('This credential cannot be copied as a shell command. Copy the token instead.')
    const value = format === 'token' ? token : format === 'header' ? `Authorization: Bearer ${token}` : `export ETH_RPC_HEADERS="Authorization: Bearer ${token}"`
    current(); await navigator.clipboard.writeText(value); current()
    })
  }
  private async ownCredentialAction(kind: string, action: (token: string, current: () => void) => void | Promise<void>): Promise<boolean> {
    const pair = this.selected && { ...this.selected }, original = this.state.self
    if (!pair || !original || this.state.busy || this.state.phase !== 'selected' || this.state.flow || this.state.pending) return false
    this.set({ busy: true, error: null })
    let completed = false
    await this.work(kind, async op => {
      const current = () => {
        this.check(op)
        if (this.state.phase !== 'selected' || this.state.flow || this.state.pending || this.state.self !== original ||
          original.expiresAt <= Date.now() / 1000) throw new Stale()
      }
      try {
        current()
        const result = await this.client.needAccess(pair); current()
        if (result.status !== 'access') { await this.outcome(op, result); return }
        const access = result.access
        if (!sameSession(pair, access)) throw new AuthError('session_changed')
        const verified = await ownSelf(access, this.signal(op)); current()
        const marker = readMultiMarker()
        if (!marker || marker.phase !== 'active' || !sameSession(pair, multiPair(marker))) { this.changed(); throw new Stale() }
        if (verified.actorId !== original.actorId || verified.sourceProfile !== original.sourceProfile ||
          verified.actorId !== access.actorId || verified.sourceProfile !== access.sourceProfile ||
          verified.expiresAt !== access.expiresAt || verified.expiresAt <= Date.now() / 1000) throw new AuthError('invalid_response')
        current(); await action(access.accessToken, current); current(); completed = true
      } finally { if (this.owns(op)) this.set({ busy: false }) }
    })
    return completed
  }
  private schedulePoll(): void {
    clearTimeout(this.pollTimer)
    if (!this.alive || document.visibilityState === 'hidden' || this.state.candidate || this.state.pending?.provider !== 'privado') return
    this.pollTimer = setTimeout(() => { void this.poll() }, 1000)
  }
  private async poll(): Promise<void> {
    const pending = this.state.pending
    if (!pending?.requestId || pending.provider !== 'privado' || document.visibilityState === 'hidden' || this.latest.has('poll')) return
    if (pending.expiresAt <= Date.now() / 1000) { this.set({ phase: 'anonymous', pending: null, candidate: null, error: 'proof_expired' }); return }
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
    this.retireWallet()
    clearTimeout(this.pollTimer); this.set({ busy: true, error: null })
    await this.work('confirm', async op => {
      const result = await this.client.confirmPrivado(candidate); this.check(op); await this.accept(op, result)
    })
  }
  cancel = async (): Promise<void> => {
    if (!this.alive) return
    const id = this.state.pending?.requestId
    // Cancellation also changes the shared browser marker under its lock.
    // Keep new sign-in gestures disabled until that owned change finishes.
    this.invalidate(); this.set({ self: null, pending: null, candidate: null, busy: !!id, phase: 'anonymous', error: null })
    if (!id) return
    await this.work('cancel', async op => { await this.client.cancelPrivado(id); this.check(op); this.set({ busy: false }) })
  }
  continue = async (): Promise<void> => this.finish(false)
  forgetAppChoices = (): void => { forgetRemembered() }
  private finish = async (automatic: boolean): Promise<void> => {
    const pair = this.selected && { ...this.selected }, flow = this.state.flow
    if (!pair || !flow || this.completing || this.state.busy || this.state.phase !== 'selected') return
    const self = this.state.self
    if (automatic && (!self || !remembered(flow, self, pair))) return
    this.retireWallet()
    this.completing = true; this.set({ busy: true, error: null })
    await this.work('complete', async op => {
      try {
        const result = await this.client.withAccess(pair, async token => {
          this.check(op) // Helper renewal may have awaited; fence BEFORE action.
          const redirect = await completeFlow(flow, pair, token, this.signal(op)); this.check(op)
          return redirect
        }); this.check(op)
        if (result.status !== 'completed') { this.completing = false; await this.outcome(op, result); return }
        if (!automatic && self && self === this.state.self) remember(flow, self, pair)
        sessionStorage.removeItem(FLOW_KEY)
        this.check(op)
        location.replace(result.value) // No await between final fence and navigation.
      } finally {
        // Retire only THIS attempt, including ambiguous POST outcomes. A stale
        // finally must not erase a later account's flow, busy state or storage.
        if (this.owns(op) && this.completing) {
          this.completing = false
          if (flow.expiresAt <= Date.now() / 1000) this.expireFlow()
          else { this.set({ flow: null, busy: false }); sessionStorage.removeItem(FLOW_KEY) }
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
    if (event.key !== CONTEXT_KEY && event.key !== null) return
    // A completed same-pair renewal may restore byte-identical marker bytes.
    // Every relevant foreign event still retires wallet work, never adopts it.
    this.flushSuspension(() => this.retireWallet())
    if (!this.selected) { this.changed(); return }
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
      this.expireFlow(); return
    }
    if (this.state.pending && this.state.pending.expiresAt <= Date.now() / 1000) {
      this.invalidate()
      this.set({ self: null, pending: null, candidate: null, busy: false, phase: 'anonymous', error: 'proof_expired' }); return
    }
    if (this.state.self && this.state.self.expiresAt <= Date.now() / 1000) { this.retireWallet(); this.uiRevision++; this.set({ self: null }) }
    if (this.selected && this.state.phase === 'selected' && !this.state.busy && document.visibilityState !== 'hidden' &&
      (!this.state.self || this.state.self.expiresAt <= Date.now() / 1000 + 5)) void this.refresh()
  }
  private expireFlow(): void {
    this.invalidate(); sessionStorage.removeItem(FLOW_KEY)
    this.set({ flow: null, self: null, pending: null, candidate: null, busy: false, phase: 'failed', error: 'flow_expired' })
  }
  private navigation = (): void => {
    // Back/Forward inside the ordinary selected-account UI is presentation
    // navigation, not a new authentication flow. Check freshness and the same
    // shared marker before retaining private context; retire wallet actions.
    if (this.alive && this.selected && this.state.phase === 'selected' && this.state.self && !this.state.flow && !this.state.pending &&
      this.state.self.expiresAt > Date.now() / 1000 && (adminLocation(location) || plainLoginLocation(location))) {
      try {
        const marker = readMultiMarker()
        if (marker?.phase === 'active' && sameSession(this.selected, multiPair(marker))) { this.retireWallet(); return }
      } catch { /* Invalid shared context falls through to the original deny. */ }
    }
    this.invalidate(); this.set({ phase: 'failed', self: null, pending: null, candidate: null, busy: false, error: 'login_required' })
  }
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
