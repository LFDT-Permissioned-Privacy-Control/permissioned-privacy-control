import type { Controller } from './controller'
import type { Self } from './protocol'
import type { SourceProject } from './sourceProject'
import { multiPair, readMultiMarker, type MultiMarker } from '../auth/multiContext'
import { sameSession, type MultiSession } from '../auth/multiProtocol'
import { retainAuthoring, type AuthoringEntry, type AuthoringState } from './sourceAuthoring'
import { hasAdminRole } from './adminAccess'

interface Owner extends MultiSession {
  digest: string; kind: Self['principalKind']; scope: number; expiresAt: number
}
export interface DraftMemoryView { project: SourceProject | null; authoring: AuthoringState; epoch: number; locked: boolean; dirty: boolean; unfinished: boolean }
const noAuthoring: AuthoringState = {}
const empty: DraftMemoryView = { project: null, authoring: noAuthoring, epoch: 0, locked: false, dirty: false, unfinished: false }

// This buffer contains only files the operator imported or edited. It is never
// credential storage or a source of live policy/operational authority.
export class SourceDraftMemory {
  private owner: Owner | null = null
  private project: SourceProject | null = null
  private authoring: AuthoringState = noAuthoring
  private epoch = 0
  private view = empty
  private listeners = new Set<() => void>()
  constructor(private controller: Pick<Controller, 'snapshot' | 'scopeRevision' | 'ownsScope'>,
    private marker: () => MultiMarker | null = readMultiMarker, private clock = () => Date.now()) {}
  snapshot = (): DraftMemoryView => this.view
  subscribe = (listener: () => void) => { this.listeners.add(listener); return () => this.listeners.delete(listener) }
  private publish(locked: boolean) {
    const project = locked ? null : this.project, authoring = locked ? noAuthoring : this.authoring
    const unfinished = Object.values(this.authoring).some(entry => entry.dirty), dirty = !!this.project?.dirty || unfinished
    if (this.view.project === project && this.view.authoring === authoring && this.view.epoch === this.epoch && this.view.locked === locked && this.view.dirty === dirty && this.view.unfinished === unfinished) return
    this.view = { project, authoring, epoch: this.epoch, locked, dirty, unfinished }; this.listeners.forEach(fn => fn())
  }
  clear = () => { this.owner = null; this.project = null; this.authoring = noAuthoring; this.epoch++; this.publish(false) }
  private currentPair(marker: MultiMarker | null): MultiSession | null {
    try { return marker && multiPair(marker) } catch { return null }
  }
  private sameIdentity(self: Self, owner: Owner) {
    return self.actorId === owner.actorId && self.sourceProfile === owner.sourceProfile &&
      self.sourceProfileDigest === owner.digest && self.principalKind === owner.kind
  }
  observe = (): void => {
    const owner = this.owner
    if (!owner || !this.project) return
    const state = this.controller.snapshot()
    if (state.self && !hasAdminRole(state.self)) { this.clear(); return }
    let marker: MultiMarker | null
    try { marker = this.marker() } catch { this.clear(); return }
    const pair = this.currentPair(marker)
    if (!pair || !sameSession(pair, owner) || state.flow || state.error) { this.clear(); return }
    const pending = marker?.pendingFlow
    const renewal = !pending || pending.kind === 'privado' && pending.mode === 'renew' &&
      pending.expectedActorId === owner.actorId && pending.expectedSessionId === owner.browserSessionId && pending.sourceProfile === owner.sourceProfile
    if (!renewal) { this.clear(); return }
    // A denied marker without an owned renewal is logout/unknown continuity,
    // not permission to retain a recoverable draft for a future login.
    if (marker?.phase !== 'active' && !pending && !state.busy) { this.clear(); return }
    if (state.phase === 'proof-pending') {
      const proof = state.pending
      if (!proof || proof.status !== 'proof_required' || !sameSession(proof, owner) || proof.expiresAt * 1000 <= this.clock()) { this.clear(); return }
      this.publish(true); return
    }
    if (state.phase !== 'selected' || state.pending) { this.clear(); return }
    if (!state.self) {
      // The controller retires expired UI authority before requesting renewed
      // access. Only that same-family expiry can bridge this intermediate state.
      if (owner.expiresAt * 1000 <= this.clock()) this.publish(true)
      else this.clear()
      return
    }
    if (!this.sameIdentity(state.self, owner)) { this.clear(); return }
    if (state.busy || marker?.phase !== 'active' || state.self.expiresAt * 1000 <= this.clock()) { this.publish(true); return }
    if (owner.scope !== this.controller.scopeRevision && !this.view.locked) { this.clear(); return }
    if (!this.controller.ownsScope(this.controller.scopeRevision, owner.actorId)) { this.clear(); return }
    owner.scope = this.controller.scopeRevision; owner.expiresAt = state.self.expiresAt
    this.publish(false)
  }
  write(next: SourceProject | null, scope: number, actor: string, replace = false): void {
    if (this.view.locked || !this.controller.ownsScope(scope, actor)) throw Error('The source editor is locked while your account is checked.')
    const state = this.controller.snapshot(), self = state.self
    let marker: MultiMarker | null
    try { marker = this.marker() } catch { throw Error('The selected account changed. Import the source again.') }
    const pair = this.currentPair(marker)
    if (!self || !hasAdminRole(self) || self.actorId !== actor || state.busy || state.flow || state.pending || self.expiresAt * 1000 <= this.clock() ||
      marker?.phase !== 'active' || !pair || pair.actorId !== actor || pair.sourceProfile !== self.sourceProfile) throw Error('The selected account changed. Import the source again.')
    if (this.owner && (!sameSession(pair, this.owner) || !this.sameIdentity(self, this.owner))) throw Error('The selected account changed. Import the source again.')
    if (!next) { this.clear(); return }
    this.owner = {...pair, digest: self.sourceProfileDigest, kind: self.principalKind, scope, expiresAt: self.expiresAt}
    if (replace) { this.authoring = noAuthoring; this.epoch++ }
    else if (this.project !== next) this.authoring = retainAuthoring(this.authoring, next)
    this.project = next; this.publish(false)
  }
  writeAuthoring(key: string, entry: AuthoringEntry, scope: number, actor: string, epoch: number): void {
    if (epoch !== this.epoch) return
    if (!this.project) throw Error('Import source before editing a proposal.')
    this.write(this.project, scope, actor)
    if (!retainAuthoring({ [key]: entry }, this.project)[key]) return
    this.authoring = { ...this.authoring, [key]: entry }; this.publish(false)
  }
  clearAuthoring(prefix: string, scope: number, actor: string, epoch: number): void {
    if (epoch !== this.epoch) return
    if (!this.project) return
    this.write(this.project, scope, actor)
    this.authoring = Object.fromEntries(Object.entries(this.authoring).filter(([key]) => !key.startsWith(prefix))); this.publish(false)
  }
}
