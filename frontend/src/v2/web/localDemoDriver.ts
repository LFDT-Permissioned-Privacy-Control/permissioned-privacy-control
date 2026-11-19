import type { Candidate, Pending, ProofRequired } from '../auth/multiProtocol'
import type { Controller, State } from './controller'
import type { Flow } from './protocol'
import { readLoginContext, readMultiMarker, unchangedLoginContext, type LoginContext } from '../auth/multiContext'
import { demoOrigin, demoReady, demoRequestURI, demoStatus, type DemoConfig, type DemoIdentity, type DemoPersona } from './localDemoProtocol'

export interface DemoView { active: boolean; persona: DemoPersona | null; status: string; error: string | null; cancellable: boolean; renewing: boolean }
export interface DemoPopup { closed: boolean; close(): void; postMessage(value: unknown, origin: string): void }
export interface DemoEnvironment {
  origin: string; walletOrigin: string
  open(url: string): DemoPopup | null
  nonce(): string
  listen(fn: (event: MessageEvent) => void): () => void
  navigate(path: string): void
}
interface Intent {
  persona: DemoPersona; nonce: string; popup: DemoPopup | null; flow: Flow | null; flowExpiry?: number
  initialRevision: number; initialSelf: State['self']; revision: number
  clickedContext: LoginContext
  phase: 'ready' | 'starting' | 'proof' | 'confirming' | 'continuing'
  deadline: number; identity?: DemoIdentity; config?: DemoConfig; pending?: Pending; candidate?: Candidate
  renewal?: ProofRequired
  confirmSent: boolean; confirmedSelf?: State['self']
}
const initial: DemoView = { active: false, persona: null, status: '', error: null, cancellable: false, renewing: false }

export function canAssistDemoRenewal(state: State): boolean {
  return state.phase === 'proof-pending' && !state.self && !state.error && state.pending?.status === 'proof_required' && state.pending.provider === 'privado' && state.pending.mode === 'renew'
}

// The popup carries public proof progress only. Permission/session authority
// remains the existing controller's verified candidate and current Self.
export class LocalDemoDriver {
  private view = initial
  private listeners = new Set<() => void>()
  private intent: Intent | null = null
  private stopMessages: (() => void) | null = null
  private timer: ReturnType<typeof setTimeout> | undefined
  private stopController: () => void
  private queued = false
  private disposed = false
  constructor(private controller: Controller, private env: DemoEnvironment) {
    this.stopController = controller.subscribe(() => this.schedule())
  }
  snapshot = (): DemoView => this.view
  subscribe = (fn: () => void): (() => void) => { this.listeners.add(fn); return () => this.listeners.delete(fn) }
  private set(next: Partial<DemoView>) { this.view = { ...this.view, ...next }; for (const fn of this.listeners) fn() }
  start = (persona: DemoPersona): void => {
    if (this.disposed || this.intent || !demoOrigin(this.env.walletOrigin)) return
    const state = this.controller.snapshot()
    const renewal = canAssistDemoRenewal(state) ? { ...state.pending as ProofRequired } : undefined
    if (state.busy || state.pending && !renewal || state.phase === 'booting') return
    const now = Date.now(), flow = state.flow
    if (flow && flow.expiresAt * 1000 <= now) return
    let nonce: string, clickedContext: LoginContext
    try {
      clickedContext = readLoginContext(); nonce = this.env.nonce(); if (!/^[0-9a-f]{64}$/.test(nonce)) throw Error()
      if (renewal) {
        const marker = readMultiMarker(), request = marker?.pendingFlow
        if (!marker || marker.actorId !== renewal.actorId || marker.browserSessionId !== renewal.browserSessionId || marker.provider !== 'privado' || marker.sourceProfile !== renewal.sourceProfile || request?.kind !== 'privado' || request.mode !== 'renew' || request.requestId !== renewal.requestId || request.sourceProfile !== renewal.sourceProfile || request.expectedActorId !== renewal.actorId || request.expectedSessionId !== renewal.browserSessionId || request.expiresAt !== renewal.expiresAt || renewal.expiresAt * 1000 <= now || !demoRequestURI(renewal.requestUri, renewal.requestId, this.env.origin)) throw Error()
        unchangedLoginContext(clickedContext)
      }
    } catch { this.set({ error: 'The local demo could not verify ownership of this sign-in. Use the original verification request or start again explicitly.' }); return }
    const intent: Intent = { persona, nonce, popup: null, flow, flowExpiry: flow?.expiresAt, initialRevision: this.controller.scopeRevision,
      // First use can pause at Chrome's local certificate prompt. This wait
      // starts no native login and never extends the original app flow.
      initialSelf: state.self, clickedContext, revision: renewal ? this.controller.scopeRevision : -1, renewal, pending: renewal ? state.pending! : undefined, phase: 'ready', deadline: Math.min(now + 120000, renewal ? renewal.expiresAt * 1000 : Infinity, flow?.expiresAt ? flow.expiresAt * 1000 : Infinity), confirmSent: false }
    this.intent = intent
    this.stopMessages = this.env.listen(event => this.message(intent, event))
    this.set({ active: true, persona, renewing: !!renewal, status: 'Connecting to the demo wallet. If its window shows a local certificate warning, accept it to continue.', error: null, cancellable: true })
    // This stays synchronous inside the explicit persona click.
    try { intent.popup = this.env.open(this.env.walletOrigin + '/bridge#' + intent.nonce) } catch { /* The same bounded failure applies to blocked popups. */ }
    if (!intent.popup) { this.fail(intent, 'The demo wallet could not open. Allow this local popup, then try again.'); return }
    this.schedule()
  }
  private schedule(): void {
    if (this.queued || this.disposed) return
    this.queued = true
    queueMicrotask(() => { this.queued = false; this.check() })
  }
  private sameFlow(i: Intent): boolean { return this.controller.snapshot().flow === i.flow && (!i.flow || i.flow.expiresAt === i.flowExpiry && i.flowExpiry * 1000 > Date.now()) }
  private owned(i: Intent): boolean { return !this.disposed && this.intent === i }
  private renewalPinned(i: Intent): boolean {
    const saved = i.renewal, state = this.controller.snapshot(), pending = state.pending
    if (!saved) return true
    try { unchangedLoginContext(i.clickedContext) } catch { return false }
    return pending === i.pending && !state.self && pending?.status === 'proof_required' && pending.provider === saved.provider && pending.mode === saved.mode && pending.principalKind === saved.principalKind && pending.actorId === saved.actorId && pending.browserSessionId === saved.browserSessionId && pending.sourceProfile === saved.sourceProfile && pending.requestId === saved.requestId && pending.requestUri === saved.requestUri && pending.expiresAt === saved.expiresAt && saved.expiresAt * 1000 > Date.now()
  }
  private context(i: Intent): boolean {
    const state = this.controller.snapshot()
    return this.owned(i) && this.controller.scopeRevision === i.revision && this.sameFlow(i) && !state.error && state.phase !== 'failed' && state.phase !== 'context-changed' && (!i.renewal || i.confirmSent || this.renewalPinned(i))
  }
  private message(i: Intent, event: MessageEvent): void {
    if (!this.owned(i) || !i.popup || event.source !== (i.popup as unknown) || event.origin !== this.env.walletOrigin) return
    if (i.phase === 'ready') {
      const ready = demoReady(event.data, i.nonce, this.env.origin)
      if (!ready) { this.fail(i, 'The demo wallet identity configuration could not be verified.'); return }
      try { unchangedLoginContext(i.clickedContext) } catch { this.fail(i, 'The account changed. Choose a demo identity again.'); return }
      const state = this.controller.snapshot(), identity = ready.config.personas.find(p => p.id === i.persona)!
      if (Date.now() >= i.deadline || this.controller.scopeRevision !== i.initialRevision || state.self !== i.initialSelf || (i.renewal ? !this.renewalPinned(i) || identity.profileId !== i.renewal.sourceProfile : !!state.pending) || !this.sameFlow(i) || !state.profiles.some(p => p.provider === 'privado' && p.id === identity.profileId)) { this.fail(i, 'The sign-in changed. Start a fresh demo sign-in.'); return }
      i.config = ready.config; i.identity = identity
      if (i.renewal) { this.prove(i, i.pending!); return }
      i.phase = 'starting'; i.deadline = Math.min(Date.now() + 25000, i.flow ? i.flow.expiresAt * 1000 : Infinity)
      void this.begin(i).catch(() => this.fail(i, 'The demo sign-in could not start. Start a fresh sign-in; it is not retried.'))
      return
    }
    // A replacement ready/config is never adopted after native start.
    if (event.data && typeof event.data === 'object' && event.data.type === 'ready') { this.fail(i, 'The demo wallet configuration changed. Start a fresh sign-in.'); return }
    const status = demoStatus(event.data, i.nonce)
    if (!status) return
    if (status.status === 'failed') { this.fail(i, 'The demo proof could not finish. Start a fresh sign-in; the request is not retried.'); return }
    if (i.phase === 'proof') this.set({ status: status.status === 'submitted' ? 'Proof submitted. Verifying the selected identity…' : 'Generating a fresh Privado proof…' })
  }
  private async begin(i: Intent): Promise<void> {
    const action = this.controller.login(i.identity!.profileId, 'privado', i.identity!.holderDid, i.clickedContext)
    i.revision = this.controller.scopeRevision
    await action
    if (!this.owned(i)) return
    const state = this.controller.snapshot(), pending = state.pending
    if (!this.context(i) || Date.now() >= i.deadline || !pending || pending.provider !== 'privado' || pending.sourceProfile !== i.identity!.profileId || !demoRequestURI(pending.requestUri, pending.requestId, this.env.origin) || pending.expiresAt * 1000 <= Date.now()) { this.fail(i, 'The selected demo sign-in could not start. Start a fresh sign-in.'); return }
    this.prove(i, pending)
  }
  private prove(i: Intent, pending: Pending): void {
    if (!this.context(i) || !demoRequestURI(pending.requestUri, pending.requestId, this.env.origin)) { this.fail(i, 'The original verification request changed.'); return }
    i.pending = pending; i.phase = 'proof'; i.deadline = Math.min(Date.now() + 150000, (i.renewal ?? pending).expiresAt * 1000, i.flow ? i.flow.expiresAt * 1000 : Infinity)
    try { i.popup!.postMessage({ v: 1, type: 'prove', nonce: i.nonce, persona: i.persona, requestUri: pending.requestUri }, this.env.walletOrigin) }
    catch { this.fail(i, 'The demo wallet could not receive the original verification request.'); return }
    this.set({ status: 'Generating a fresh Privado proof…' }); this.schedule()
  }
  private check(): void {
    clearTimeout(this.timer)
    const i = this.intent
    if (!i) return
    if (!i.popup || i.popup.closed || Date.now() >= i.deadline) { this.fail(i, i.phase === 'ready' ? 'The demo wallet did not connect. Check that it is running and its local certificate is accepted, then try again.' : 'The demo wallet closed or sign-in expired. Start a fresh sign-in.'); return }
    const state = this.controller.snapshot()
    if (i.phase === 'ready') {
      if (this.controller.scopeRevision !== i.initialRevision || state.self !== i.initialSelf || (i.renewal ? !this.renewalPinned(i) : !!state.pending) || !this.sameFlow(i)) { this.fail(i, 'The sign-in changed. Start a fresh demo sign-in.'); return }
    } else if (i.phase !== 'starting') {
      if (i.phase === 'continuing' && this.controller.scopeRevision === i.revision && state.self === i.confirmedSelf && state.phase === 'selected' && !state.error && state.flow === null) { this.finish(i); return }
      if (!this.context(i)) { this.fail(i, 'The sign-in changed. Start a fresh demo sign-in.'); return }
      if (i.phase === 'proof') {
        if (state.pending !== i.pending || state.self) { this.fail(i, 'The original verification request changed. Start a fresh sign-in.'); return }
        if (state.candidate) {
          const c = state.candidate
          if (state.busy || c.requestId !== i.pending!.requestId || c.sourceProfile !== i.identity!.profileId || c.holderDid !== i.identity!.holderDid || c.network !== i.config!.network || c.expiresAt * 1000 <= Date.now() || c.expiresAt > (i.renewal ?? i.pending!).expiresAt || i.renewal && c.actorId !== i.renewal.actorId) { this.fail(i, 'The verified identity does not match the demo identity you chose.'); return }
          i.candidate = c; i.phase = 'confirming'
          this.set({ status: 'Finishing sign-in as the selected demo identity…', cancellable: false })
          void this.confirm(i).catch(() => this.fail(i, 'Sign-in was interrupted. Return to the application to start again; it is not retried.'))
        }
      }
    }
    if (this.owned(i)) this.timer = setTimeout(() => this.check(), 200)
  }
  private async confirm(i: Intent): Promise<void> {
    // No await between the original candidate/owner check and this one action.
    if (!this.context(i) || Date.now() >= i.deadline || this.controller.snapshot().candidate !== i.candidate || this.controller.snapshot().pending !== i.pending) { this.fail(i, 'The verification changed before confirmation.'); return }
    i.confirmSent = true
    await this.controller.confirm()
    if (!this.owned(i)) return
    const state = this.controller.snapshot(), self = state.self
    if (!this.context(i) || state.phase !== 'selected' || !self || self.actorId !== i.candidate!.actorId || self.sourceProfile !== i.identity!.profileId || self.expiresAt * 1000 <= Date.now()) { this.fail(i, 'Sign-in could not be confirmed. Start a fresh sign-in; it is not retried.'); return }
    i.confirmedSelf = self
    if (i.flow) {
      i.phase = 'continuing'; this.set({ status: 'Continuing to ' + i.flow.displayName + '…' })
      // A remembered choice may already own normal Continue. Never dispatch
      // another action or retry an ambiguous handoff. The original pagehide
      // disposes this popup when the existing controller navigates.
      if (state.busy) return
      await this.controller.continue()
      if (this.owned(i)) this.finish(i)
    } else {
      if (i.renewal) { this.finish(i); return }
      const target = self.organizations.some(o => o.isOrgAdmin || o.isOrgReadonlyAdmin) ? '/admin/rbac/organizations' : '/admin/account'
      this.finish(i); this.env.navigate(target)
    }
  }
  private finish(i: Intent): void {
    if (!this.owned(i)) return
    this.intent = null; clearTimeout(this.timer); this.stopMessages?.(); this.stopMessages = null
    i.popup?.close(); this.set({ active: false, cancellable: false, renewing: false, status: '', error: null })
  }
  private fail(i: Intent, error: string): void {
    if (!this.owned(i)) return
    // A newer attempt or a selected account must never be canceled by cleanup.
    const state = this.controller.snapshot()
    const starting = i.phase === 'starting' && !state.pending && state.phase === 'booting'
    const cancel = !i.renewal && !i.confirmSent && this.controller.scopeRevision === i.revision && !state.self && (starting || !!i.pending && state.pending === i.pending && !state.busy)
    // During start, cancel has no request ID to POST; it only retires that
    // exact in-flight controller owner so a late start cannot republish it.
    if (cancel) void this.controller.cancel()
    const message = i.renewal ? state.pending === i.pending ? 'Demo verification stopped. This sign-in was not canceled. Use the matching demo identity or your wallet while the original request is valid.' : 'The original verification changed. The demo helper did not change another sign-in.' : error
    this.finish(i); this.set({ error: i.confirmSent ? 'Demo sign-in was interrupted after confirmation started. Check the current account or return to the application; no action was retried.' : message })
  }
  cancel = (): void => { const i = this.intent; if (i && !i.confirmSent) this.fail(i, 'Demo sign-in canceled. You can choose another identity.') }
  navigation = (): void => { const i = this.intent; if (i) this.fail(i, 'Demo sign-in was interrupted by navigation.') }
  dispose = (): void => {
    this.navigation(); this.disposed = true; this.stopController(); this.listeners.clear()
  }
}
