import { closedJSON, session, text } from '../auth/protocol'
import type { DraftGroup, SourceFile } from './workspace'

// Immutable public source observations. The Go deployment tools validate policy;
// displaying a source never approves it or changes the running configuration.
export type JSONObject = Record<string, unknown>
export interface SourceDocument { path: string; originalBytes: Uint8Array; originalText: string }
export interface DraftReference { kind: 'groups' | 'contract-registry' | 'execution-rules'; organizationId: string; path: string }
export interface SourceDraft extends JSONObject {
  apiVersion: string; kind: string; sourceRevision: string; environment: string; chainId: string; evaluatorVersion: string; profile: string
  organizations: { id: string; slug: string; name: string }[]; documents: DraftReference[]
}
export interface SourceRoot { id: string; files: SourceDocument[]; draft: SourceDraft }
export interface SourceProject { roots: SourceRoot[] }
export class SourceError extends Error {}
const maxBytes = 64 << 20, maxFile = 1 << 20
const globals = ['identityCatalog', 'runtimeCatalog', 'disclosureCatalog', 'complianceCatalog', 'authCatalog']
const kinds = ['groups', 'contract-registry', 'execution-rules']
const name = (v: unknown): v is string => typeof v === 'string' && v.length <= 128 && /^[a-z0-9][a-z0-9_-]*\.json$/.test(v)
const rootName = (v: string) => /^[a-z0-9][a-z0-9_-]{0,63}$/.test(v)
function fail(message: string): never { throw new SourceError(message) }
export const object = (v: unknown): JSONObject => v && typeof v === 'object' && !Array.isArray(v) ? v as JSONObject : fail('A source object is required.')
const parse = (raw: string): JSONObject => object(closedJSON(raw, maxFile, 32))
const encode = (raw: string) => new TextEncoder().encode(raw)
export const sourceText = (f: SourceDocument): string => f.originalText

function draftValue(value: JSONObject): SourceDraft {
  if (value.apiVersion !== 'ops.policy-draft/v1alpha1' || value.kind !== 'PolicyDraft' ||
    !text(value.sourceRevision, 1024) || !text(value.environment, 128) || typeof value.chainId !== 'string' || !/^[1-9][0-9]{0,19}$/.test(value.chainId) ||
    !text(value.profile, 256) || !text(value.evaluatorVersion, 256) || !Array.isArray(value.organizations) || value.organizations.length > 256 ||
    !Array.isArray(value.documents) || value.documents.length > 1024) fail('Unsupported or incomplete configuration source metadata.')
  const ids = new Set(), slugs = new Set()
  for (const raw of value.organizations) {
    const org = object(raw)
    if (!session(org.id) || !text(org.name, 256) || !text(org.slug, 100) || ids.has(org.id) || slugs.has(org.slug)) fail('Organizations need unique stable IDs, names and slugs.')
    ids.add(org.id); slugs.add(org.slug)
  }
  const refs = new Set<string>(['draft.json'])
  for (const raw of value.documents) {
    const ref = object(raw)
    if (!kinds.includes(String(ref.kind)) || !ids.has(ref.organizationId) || !name(ref.path) || refs.has(ref.path)) fail('Document references must use unique flat lowercase JSON filenames and a declared organization.')
    refs.add(ref.path)
  }
  for (const key of globals) if (value[key] !== undefined) {
    const ref = object(value[key])
    if (!name(ref.path) || refs.has(ref.path)) fail('Catalog references must use unique flat lowercase JSON filenames.')
    refs.add(ref.path)
  }
  return value as SourceDraft
}
function requiredFiles(draft: SourceDraft): string[] {
  return ['draft.json', ...draft.documents.map(d => d.path), ...globals.flatMap(key => draft[key] === undefined ? [] : [object(draft[key]).path as string])]
}

export async function loadSourceProject(files: readonly SourceFile[], check: () => void = () => {}): Promise<SourceProject> {
  if (files.length < 1 || files.length > 2048) fail('Select a source folder containing draft.json and its referenced files.')
  const selected = new Map<string, SourceFile>()
  for (const f of files) {
    const parts = f.path.split('/')
    if (parts.length > 2 || !name(parts.at(-1)) || parts.length === 2 && !rootName(parts[0])) continue
    if (selected.has(f.path)) fail('The selection has duplicate source paths.')
    selected.set(f.path, f)
  }
  const drafts = [...selected.keys()].filter(p => p === 'draft.json' || p.endsWith('/draft.json')).sort()
  if (!drafts.length || drafts.length > 16 || drafts.includes('draft.json') && drafts.length > 1) fail('Select one draft root or named core/broker draft folders.')
  let remaining = maxBytes
  const roots: SourceRoot[] = []
  for (const selectedDraft of drafts) {
    const prefix = selectedDraft === 'draft.json' ? '' : selectedDraft.slice(0, -'draft.json'.length)
    const id = prefix ? prefix.slice(0, -1) : 'source'
    const loaded = new Map<string, SourceDocument>()
    async function read(path: string): Promise<SourceDocument> {
      check()
      if (!name(path)) fail('Use flat lowercase JSON filenames in each draft root.')
      if (loaded.has(path)) return loaded.get(path)!
      const f = selected.get(prefix + path)
      if (!f || !Number.isSafeInteger(f.size) || f.size < 0 || f.size > maxFile || f.size > remaining) fail('A referenced source file is missing or exceeds the source size limit.')
      remaining -= f.size
      const bytes = f.readBytes ? await f.readBytes() : encode(await f.read()); check()
      if (bytes.byteLength !== f.size) fail('Source file changed while it was read. Select the files again.')
      let raw: string
      try { raw = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes) } catch { return fail('Referenced source files must be valid UTF-8.') }
      parse(raw)
      const result = { path, originalBytes: bytes.slice(), originalText: raw }
      loaded.set(path, result)
      return result
    }
    const draft = draftValue(parse(sourceText(await read('draft.json'))))
    for (const path of requiredFiles(draft)) await read(path)
    // Broker public contexts are named in authCatalog; never read adjacent
    // credentials or arbitrary files merely because a directory was selected.
    if (draft.authCatalog !== undefined) {
      const auth = parse(sourceText(await read(object(draft.authCatalog).path as string)))
      if (auth.pinnedDocuments !== undefined) {
        if (!Array.isArray(auth.pinnedDocuments) || auth.pinnedDocuments.length > 1024) fail('Unsupported broker pinned-document selection.')
        for (const pinned of auth.pinnedDocuments) await read(object(pinned).path as string)
      }
    }
    roots.push({ id, draft, files: [...loaded.values()] })
  }
  check()
  const result: SourceProject = { roots }
  return result
}

export function rootOf(project: SourceProject, id: string): SourceRoot { return project.roots.find(r => r.id === id) ?? fail('Select a configuration source root.') }
export function documentText(project: SourceProject, root: string, path: string): string {
  return sourceText(rootOf(project, root).files.find(f => f.path === path) ?? fail('The referenced source document is missing.'))
}
export function documentValue(project: SourceProject, root: string, path: string): JSONObject { return parse(documentText(project, root, path)) }
// Display gates prevent rounded numeric values or unsupported envelopes from
// being shown as meaningful permission data. Raw source remains inspectable.
export function browserNumbersSafe(value: unknown): boolean {
  if (typeof value === 'number') return Number.isFinite(value) && (!Number.isInteger(value) || Number.isSafeInteger(value))
  if (Array.isArray(value)) return value.every(browserNumbersSafe)
  return !value || typeof value !== 'object' || Object.values(value).every(browserNumbersSafe)
}
const catalogShapes: Record<string, { kind: string; versions: string[] }> = {
  identityCatalog: { kind: 'IdentityCatalog', versions: ['ops.identity-catalog/v1alpha1'] },
  runtimeCatalog: { kind: 'RuntimePolicy', versions: Array.from({ length: 7 }, (_, i) => 'ops.runtime-policy/v1alpha' + (i + 1)) },
  disclosureCatalog: { kind: 'DisclosurePolicy', versions: ['ops.disclosure-policy/v1alpha1'] },
  complianceCatalog: { kind: 'CompliancePolicy', versions: ['ops.compliance-policy/v1alpha1'] },
  authCatalog: { kind: 'AuthBroker', versions: ['ops.auth-broker/v1alpha1', 'ops.auth-broker/v1alpha2'] },
}
function semanticValueIssue(root: SourceRoot, path: string, value: JSONObject): string | null {
  if (!browserNumbersSafe(value)) return 'This document contains numbers that cannot be displayed exactly in structured views. Inspect its original source.'
  if (path === 'draft.json') return value.apiVersion === 'ops.policy-draft/v1alpha1' && value.kind === 'PolicyDraft' ? null : 'This draft version is supported only as raw source.'
  const ref = root.draft.documents.find(d => d.path === path)
  if (ref) {
    if (value.apiVersion !== 'ops.policy-document/v1alpha1' || value.kind !== ref.kind || value.organizationId !== ref.organizationId) return 'This document envelope version or scope is supported only as raw source.'
    if (ref.kind === 'execution-rules') {
      const policy = object(object(value.spec).policy)
      if (!['privacy.gateway.fm/v1alpha1', 'privacy.gateway.fm/v1alpha2', 'privacy.gateway.fm/v1alpha3', 'privacy.gateway.fm/v1alpha4'].includes(String(policy.apiVersion)) || policy.kind !== 'ContractExecutionPolicy' || policy.org !== ref.organizationId) return 'This execution policy version or scope is supported only as raw source.'
      if (policy.nestedCalls !== 'requireOwnRule') return 'This nested-call policy is supported only as raw source. Inspect its original declaration.'
    }
    return null
  }
  const key = globals.find(key => root.draft[key] !== undefined && object(root.draft[key]).path === path)
  if (!key) return 'This file is supported only as raw source.'
  const shape = catalogShapes[key]
  return shape.kind === value.kind && shape.versions.includes(String(value.apiVersion)) ? null : 'This catalog version is supported only as raw source.'
}
export function sourceDisplayIssue(project: SourceProject, rootID: string): string | null {
  const root = rootOf(project, rootID)
  for (const path of requiredFiles(root.draft)) {
    try { const issue = semanticValueIssue(root, path, documentValue(project, rootID, path)); if (issue) return path + ': ' + issue }
    catch { return path + ': This document cannot be displayed in structured views. Inspect its original source.' }
  }
  return null
}
export function documentFor(root: SourceRoot, organization: string, kind: DraftReference['kind']): string {
  return root.draft.documents.find(d => d.organizationId === organization && d.kind === kind)?.path ?? fail('This organization is missing its ' + kind + ' document.')
}
export function groupsOf(project: SourceProject, rootID: string, organization: string): DraftGroup[] {
  const root = rootOf(project, rootID), value = documentValue(project, rootID, documentFor(root, organization, 'groups'))
  const groups = object(value.spec).groups
  if (value.kind !== 'groups' || value.organizationId !== organization || !Array.isArray(groups) || groups.length > 4096) fail('This groups document cannot be displayed by this version.')
  const ids = new Set<string>()
  for (const raw of groups) {
    const group = object(raw)
    if (!session(group.id) || ids.has(group.id) || !text(group.slug, 100) || !text(group.name, 256) || typeof group.description !== 'string' ||
      typeof group.isOrgAdmin !== 'boolean' || typeof group.isOrgReadonlyAdmin !== 'boolean' || typeof group.verboseErrors !== 'boolean' ||
      !Array.isArray(group.allowedMethods) || group.allowedMethods.some(m => !text(m, 256)) || !Array.isArray(group.claims) || group.claims.some(c => !text(c, 256))) fail('Unsupported group fields. Inspect the source and run the matching Go checker.')
    ids.add(group.id as string)
  }
  return groups as DraftGroup[]
}
export async function decodeSourceProject(value: unknown, check: () => void = () => {}): Promise<SourceProject> {
  check()
  const envelope = object(value)
  if (Object.keys(envelope).some(k => !['apiVersion', 'roots'].includes(k)) || envelope.apiVersion !== 'ops.ui-source-package/v1' || !Array.isArray(envelope.roots) || !envelope.roots.length || envelope.roots.length > 16) fail('The configuration source response is invalid.')
  const files: SourceFile[] = [], ids = new Set<string>(); let total = 0
  for (const entry of envelope.roots) {
    const root = object(entry)
    if (Object.keys(root).some(k => !['id', 'files'].includes(k)) || typeof root.id !== 'string' || !rootName(root.id) || ids.has(root.id) || !Array.isArray(root.files)) fail('The configuration has invalid source roots.')
    ids.add(root.id)
    for (const entry of root.files) {
      check()
      const f = object(entry)
      if (Object.keys(f).some(k => !['path', 'dataBase64'].includes(k)) || !name(f.path) || typeof f.dataBase64 !== 'string' || f.dataBase64.length > 4 * Math.ceil(maxFile / 3) || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(f.dataBase64)) fail('The configuration has invalid source bytes.')
      const decoded = atob(f.dataBase64), bytes = Uint8Array.from(decoded, c => c.charCodeAt(0)); total += bytes.length
      if (total > maxBytes || bytes.length > maxFile || files.length >= 2048 || btoa(decoded) !== f.dataBase64) fail('The configuration exceeds the source file limits.')
      files.push({ path: `${root.id}/${f.path}`, size: bytes.length, readBytes: async () => bytes, read: async () => new TextDecoder('utf-8', { fatal: true }).decode(bytes) })
    }
  }
  const project = await loadSourceProject(files, check)
  if (project.roots.reduce((n, r) => n + r.files.length, 0) !== files.length) fail('The configuration contains files outside its declared source references.')
  return project
}
