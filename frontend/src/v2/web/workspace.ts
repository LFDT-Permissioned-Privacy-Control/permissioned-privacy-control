import { closedJSON, session, text } from '../auth/protocol'

export interface SourceFile {
  path: string
  size: number
  read(): Promise<string>
  readBytes?(): Promise<Uint8Array>
}
export interface DraftGroup {
  id: string; slug: string; name: string; description: string
  isOrgAdmin: boolean; isOrgReadonlyAdmin: boolean
  allowedMethods: string[]; claims: string[]; verboseErrors: boolean
  rpcCredential?: { fromEnv: string }
}
export interface DraftOrganization { id: string; slug: string; name: string; groups: DraftGroup[] }
export interface Workspace {
  sourceRevision: string; environment: string; chainId: string
  organizations: DraftOrganization[]; displayedFiles: string[]
}
export class WorkspaceError extends Error {
  constructor(message: string) { super(message); this.name = 'WorkspaceError' }
}
const fail = (message = 'This source package cannot be displayed. Select draft.json and its matching groups documents.') => { throw new WorkspaceError(message) }
const record = (value: unknown, required: string[], optional: string[] = []): Record<string, unknown> => {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return fail()
  const v = value as Record<string, unknown>
  if (required.some(k => !Object.prototype.hasOwnProperty.call(v, k)) || Object.keys(v).some(k => !required.includes(k) && !optional.includes(k))) return fail()
  return v
}
const path = (v: unknown): v is string => typeof v === 'string' && v.length <= 1024 && !/[\\\u0000-\u0020\u007f]/.test(v)
  && !v.startsWith('/') && v.split('/').every(part => part !== '' && part !== '.' && part !== '..') && v.endsWith('.json')
const names = (v: unknown): v is string[] => Array.isArray(v) && v.length <= 4096 && v.every(item => text(item, 256)) && new Set(v).size === v.length

// This is a bounded display adapter, not the policy compiler/approval check.
// Only the explicitly chosen draft and groups documents are read. Other files
// in a selected folder (including deployment secrets) are never read or sent.
export async function loadWorkspace(files: readonly SourceFile[], check: () => void = () => {}): Promise<Workspace> {
  if (files.length < 1 || files.length > 2048) return fail('Select a policy source folder containing draft.json.')
  const source = new Map<string, SourceFile>()
  for (const file of files) {
    if (!path(file.path)) continue
    if (source.has(file.path)) return fail('The selection contains duplicate source paths.')
    source.set(file.path, file)
  }
  let remaining = 64 << 20
  const displayedFiles: string[] = []
  async function read(name: string): Promise<unknown> {
    check()
    const f = source.get(name)
    if (!f || !Number.isSafeInteger(f.size) || f.size < 0 || f.size > 1 << 20 || f.size > remaining) return fail('A required source document is missing or exceeds the display size limit.')
    remaining -= f.size
    const raw = await f.read(); check()
    if (new TextEncoder().encode(raw).length !== f.size) return fail()
    displayedFiles.push(name)
    try { return closedJSON(raw, 1 << 20) } catch { return fail('A source document has invalid, duplicate or unsupported JSON fields.') }
  }
  const draft = record(await read('draft.json'), ['apiVersion', 'kind', 'environment', 'chainId', 'evaluatorVersion', 'profile', 'sourceRevision', 'organizations', 'documents'],
    ['identityCatalog', 'runtimeCatalog', 'disclosureCatalog', 'complianceCatalog', 'authCatalog'])
  if (draft.apiVersion !== 'ops.policy-draft/v1alpha1' || draft.kind !== 'PolicyDraft' || !text(draft.sourceRevision, 1024) || !text(draft.environment, 128)
    || typeof draft.chainId !== 'string' || !/^[1-9][0-9]{0,19}$/.test(draft.chainId) || !text(draft.profile, 256) || !text(draft.evaluatorVersion, 256)
    || !Array.isArray(draft.organizations) || draft.organizations.length > 256 || !Array.isArray(draft.documents) || draft.documents.length > 1024) return fail()
  const organizations: DraftOrganization[] = []
  for (const entry of draft.organizations) {
    const org = record(entry, ['id', 'slug', 'name'])
    if (!session(org.id) || !text(org.slug, 100) || !text(org.name, 256) || organizations.some(o => o.id === org.id || o.slug === org.slug)) return fail()
    organizations.push({ id: org.id, slug: org.slug, name: org.name, groups: [] })
  }
  const groupRefs = new Map<string, string>(), usedPaths = new Set<string>(['draft.json'])
  for (const entry of draft.documents) {
    const ref = record(entry, ['kind', 'organizationId', 'path'])
    if (!['groups', 'contract-registry', 'execution-rules'].includes(String(ref.kind)) || !session(ref.organizationId)
      || !organizations.some(o => o.id === ref.organizationId) || !path(ref.path) || usedPaths.has(ref.path)) return fail()
    usedPaths.add(ref.path)
    if (ref.kind === 'groups') {
      if (groupRefs.has(ref.organizationId)) return fail()
      groupRefs.set(ref.organizationId, ref.path)
    }
  }
  for (const key of ['identityCatalog', 'runtimeCatalog', 'disclosureCatalog', 'complianceCatalog', 'authCatalog']) {
    if (draft[key] !== undefined) {
      const ref = record(draft[key], ['path'])
      if (!path(ref.path) || usedPaths.has(ref.path)) return fail()
      usedPaths.add(ref.path)
    }
  }
  for (const org of organizations) {
    const groupPath = groupRefs.get(org.id)
    if (!groupPath) return fail('Every displayed organization needs its groups source document.')
    const document = record(await read(groupPath), ['apiVersion', 'kind', 'organizationId', 'spec'])
    const spec = record(document.spec, ['groups'])
    if (document.apiVersion !== 'ops.policy-document/v1alpha1' || document.kind !== 'groups' || document.organizationId !== org.id
      || !Array.isArray(spec.groups) || spec.groups.length > 4096) return fail()
    for (const item of spec.groups) {
      const group = record(item, ['id', 'slug', 'name', 'description', 'isOrgAdmin', 'isOrgReadonlyAdmin', 'allowedMethods', 'claims', 'verboseErrors'], ['rpcCredential'])
      if (!session(group.id) || !text(group.slug, 100) || !text(group.name, 256) || typeof group.description !== 'string' || new TextEncoder().encode(group.description).length > 4096
        || typeof group.isOrgAdmin !== 'boolean' || typeof group.isOrgReadonlyAdmin !== 'boolean' || group.isOrgAdmin && group.isOrgReadonlyAdmin
        || typeof group.verboseErrors !== 'boolean' || !names(group.allowedMethods) || !names(group.claims)
        || org.groups.some(g => g.id === group.id || g.slug === group.slug)) return fail()
      if (group.rpcCredential !== undefined) {
        const credential = record(group.rpcCredential, ['fromEnv'])
        if (!text(credential.fromEnv, 256) || !/^[A-Z][A-Z0-9_]*$/.test(credential.fromEnv)) return fail()
      }
      org.groups.push(group as unknown as DraftGroup)
    }
  }
  check()
  return { sourceRevision: draft.sourceRevision, environment: draft.environment, chainId: draft.chainId, organizations, displayedFiles }
}

export function selectedSources(files: FileList | readonly File[]): SourceFile[] {
  const selected = Array.from(files)
  const root = (selected[0]?.webkitRelativePath ?? '').split('/')[0]
  return selected.map(file => {
    const relative = file.webkitRelativePath ?? ''
    const name = relative ? relative.split('/').slice(1).join('/') : file.name
    if (relative && relative.split('/')[0] !== root) return fail('Select one policy source folder at a time.')
    return { path: name, size: file.size, read: () => file.text(),
      readBytes: typeof file.arrayBuffer === 'function' ? async () => new Uint8Array(await file.arrayBuffer()) : undefined }
  })
}
