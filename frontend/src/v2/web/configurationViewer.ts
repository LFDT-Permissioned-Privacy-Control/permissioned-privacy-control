import type { Controller, OperationScope } from './controller'
import { hasAdminRole } from './adminAccess'
import { decodeSourceProject, type SourceProject } from './sourceProject'
import { OperationHTTPError, type SourceResponse } from './operationsTransport'

export interface ConfigurationSource { id: string; label: string }
export interface ConfigurationView {
  sources: ConfigurationSource[]; selected: string | null; project: SourceProject | null
  busy: boolean; error: string | null; observation: number; viewState: Readonly<Record<string, unknown>>
}
const empty = (): ConfigurationView => ({ sources: [], selected: null, project: null, busy: false, error: null, observation: 0, viewState: {} })
const sourcePath = '/api/v2/configuration/sources'
function sources(value: unknown): ConfigurationSource[] {
  if (!value || typeof value !== 'object' || Array.isArray(value) || Object.keys(value).join() !== 'sources') throw Error('The configuration list is invalid.')
  const rows = (value as { sources: unknown }).sources
  if (!Array.isArray(rows) || rows.length > 128) throw Error('The configuration list exceeds its limit.')
  const ids = new Set<string>()
  return rows.map(raw => {
    if (!raw || typeof raw !== 'object' || Array.isArray(raw)) throw Error('The configuration list is invalid.')
    const row = raw as Record<string, unknown>
    if (Object.keys(row).sort().join() !== 'id,label' || typeof row.id !== 'string' || !/^[a-z0-9][a-z0-9_-]{0,63}$/.test(row.id) || ids.has(row.id) || typeof row.label !== 'string' || !row.label || row.label.length > 256 || /[\u0000-\u001f\u007f]/.test(row.label)) throw Error('The configuration list is invalid.')
    ids.add(row.id); return { id: row.id, label: row.label }
  })
}

// One in-memory view per document. It owns no credentials, edits or revisions.
// Source content never controls live authorization or operational scope.
export class ConfigurationViewer {
  private state = empty()
  private owner: string | null = null
  private generation = 0
  private abort: AbortController | null = null
  private initial = true
  private tag: string | null = null
  private active = false
  private listeners = new Set<() => void>()
  constructor(private controller: Pick<Controller, 'snapshot' | 'scopeRevision' | 'ownsScope' | 'captureOperations'>) {}
  snapshot = () => this.state
  subscribe = (listener: () => void) => { this.listeners.add(listener); return () => this.listeners.delete(listener) }
  private publish(next: Partial<ConfigurationView>) { this.state = { ...this.state, ...next }; this.listeners.forEach(fn => fn()) }
  private currentOwner(): string | null {
    const state = this.controller.snapshot(), self = state.self
    if (!self || state.phase !== 'selected' || state.flow || state.pending || state.busy || self.expiresAt * 1000 <= Date.now() || !hasAdminRole(self) || !this.controller.ownsScope(this.controller.scopeRevision, self.actorId)) return null
    return JSON.stringify([this.controller.scopeRevision, self.actorId, self.sourceProfile, self.sourceProfileDigest, self.principalKind,
      self.organizations.map(o => [o.id, o.isOrgAdmin, o.isOrgReadonlyAdmin]).sort((a, b) => String(a[0]).localeCompare(String(b[0])))])
  }
  observe = () => {
    const current = this.currentOwner()
    if (current !== this.owner) { this.clear(); this.owner = current }
  }
  clear = () => {
    this.generation++; this.abort?.abort(); this.abort = null; this.owner = null; this.tag = null; this.initial = true
    this.state = { ...empty(), observation: this.state.observation + 1 }; this.listeners.forEach(fn => fn())
  }
  setActive = (active: boolean) => {
    this.active = active
    if (!active) { this.generation++; this.abort?.abort(); this.abort = null; if (this.state.busy) this.publish({ busy: false }) }
  }
  setViewState = (key: string, value: unknown, observation: number) => {
    this.observe()
    if (this.owner && observation === this.state.observation) this.publish({ viewState: { ...this.state.viewState, [key]: value } })
  }
  select = (id: string) => {
    this.observe()
    if (!this.owner || !this.state.sources.some(source => source.id === id)) return
    this.generation++; this.abort?.abort(); this.abort = null; this.tag = null; this.initial = false
    this.publish({ selected: id, project: null, busy: false, error: null, viewState: {}, observation: this.state.observation + 1 })
    void this.refresh()
  }
  refresh = async (force = false) => {
    this.observe()
    if (!this.active || !this.owner || this.abort) return
    const owner = this.owner, generation = ++this.generation, abort = new AbortController()
    this.abort = abort; this.publish({ busy: true })
    let scope: OperationScope | undefined, readingCatalog = true
    const check = () => {
      if (abort.signal.aborted || generation !== this.generation || this.currentOwner() !== owner || this.owner !== owner) throw Error('The configuration view changed.')
      scope?.check()
    }
    try {
      scope = await this.controller.captureOperations(abort.signal); check()
      const available = sources(await scope.request(sourcePath)); check(); readingCatalog = false
      let selected = this.state.selected
      if (selected && !available.some(source => source.id === selected)) {
        this.tag = null; selected = null
        this.publish({ project: null, selected: null, viewState: {}, observation: this.state.observation + 1, error: 'The selected configuration is no longer available. Choose another configuration.' })
      }
      if (this.initial) { this.initial = false; if (available.length === 1) selected = available[0].id }
      this.publish({ sources: available, selected })
      if (!selected) return
      const response = await scope.request<SourceResponse>(sourcePath + '/' + selected, { headers: { ...(this.tag && this.state.project ? { 'If-None-Match': this.tag } : {}), ...(force ? { 'Cache-Control': 'no-cache' } : {}) } }); check()
      if (response.notModified) {
        if (!this.state.project || response.etag !== this.tag) throw Error('The configuration response is invalid.')
        this.publish({ error: null }); return
      }
      const project = await decodeSourceProject(response.value, check); check()
      this.tag = response.etag
      this.publish({ project, error: null, observation: this.state.observation + 1 })
    } catch (error) {
      this.observe()
      if (!abort.signal.aborted && generation === this.generation && this.owner === owner && this.currentOwner() === owner) {
        this.tag = null
        const denied = error instanceof OperationHTTPError && [401, 403].includes(error.status), removed = error instanceof OperationHTTPError && error.status === 404
        const clearCatalog = readingCatalog || denied
        const selected = this.state.selected
        if (clearCatalog || removed) this.initial = false
        this.publish({ project: null, ...(clearCatalog ? { sources: [], selected: null } : removed ? { sources: this.state.sources.filter(source => source.id !== selected), selected: null } : {}), viewState: {}, observation: this.state.observation + 1, error: error instanceof OperationHTTPError && error.status >= 500 ? 'Configuration files are unavailable. Try Refresh or ask your operator to check the source directory.' : error instanceof Error ? error.message : 'The configuration cannot be read. Try Refresh.' })
      }
    } finally {
      scope?.dispose()
      if (this.abort === abort) { this.abort = null; this.publish({ busy: false }) }
    }
  }
}
