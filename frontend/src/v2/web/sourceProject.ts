import { closedJSON, session, text } from '../auth/protocol'
import type { DraftGroup, SourceFile, Workspace } from './workspace'

// This model edits local source bytes. The matching Go tool remains the only
// complete compiler/checker; neither these views nor an imported report approve
// a bundle or change the selected deployment.
export type JSONObject = Record<string, unknown>
export interface SourceDocument { path: string; originalBytes: Uint8Array; originalText: string; editedText: string | null }
export interface DraftReference { kind: 'groups' | 'contract-registry' | 'execution-rules'; organizationId: string; path: string }
export interface SourceDraft extends JSONObject {
  apiVersion: string; kind: string; sourceRevision: string; environment: string; chainId: string; evaluatorVersion: string; profile: string
  organizations: { id: string; slug: string; name: string }[]; documents: DraftReference[]
}
export interface SourceRoot { id: string; files: SourceDocument[]; draft: SourceDraft; draftState?: 'raw-only' }
export interface SourceProject { roots: SourceRoot[]; dirty: boolean; generation: number; validation: 'not-checked' }
export interface SourcePackage { apiVersion: 'ops.ui-source-package/v1'; roots: { id: string; files: { path: string; dataBase64: string }[] }[] }
export class SourceError extends Error {}
const maxBytes = 64 << 20, maxFile = 1 << 20
const globals = ['identityCatalog', 'runtimeCatalog', 'disclosureCatalog', 'complianceCatalog', 'authCatalog']
const kinds = ['groups', 'contract-registry', 'execution-rules']
const name = (v: unknown): v is string => typeof v === 'string' && v.length <= 128 && /^[a-z0-9][a-z0-9_-]*\.json$/.test(v)
const rootName = (v: string) => /^[a-z0-9][a-z0-9_-]{0,63}$/.test(v)
function fail(message: string): never { throw new SourceError(message) }
export const object = (v: unknown): JSONObject => v && typeof v === 'object' && !Array.isArray(v) ? v as JSONObject : fail('A source object is required.')
const parse = (raw: string): JSONObject => object(closedJSON(raw, maxFile, 32))
const json = (v: unknown) => JSON.stringify(v, null, 2) + '\n'
const encode = (raw: string) => new TextEncoder().encode(raw)
export const sourceText = (f: SourceDocument): string => f.editedText ?? f.originalText
export const sourceBytes = (f: SourceDocument): Uint8Array => f.editedText === null ? f.originalBytes : encode(f.editedText)

function draftValue(value: JSONObject): SourceDraft {
  if (value.apiVersion !== 'ops.policy-draft/v1alpha1' || value.kind !== 'PolicyDraft' ||
    !text(value.sourceRevision, 1024) || !text(value.environment, 128) || typeof value.chainId !== 'string' || !/^[1-9][0-9]{0,19}$/.test(value.chainId) ||
    !text(value.profile, 256) || !text(value.evaluatorVersion, 256) || !Array.isArray(value.organizations) || value.organizations.length > 256 ||
    !Array.isArray(value.documents) || value.documents.length > 1024) fail('Unsupported or incomplete draft source. Open a matching native policy draft.')
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
      const result = { path, originalBytes: bytes.slice(), originalText: raw, editedText: null }
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
  const result: SourceProject = { roots, generation: 0, dirty: false, validation: 'not-checked' }
  for (const root of roots) workspaceView(result, root.id)
  return result
}

export function rootOf(project: SourceProject, id: string): SourceRoot { return project.roots.find(r => r.id === id) ?? fail('Select an imported source root.') }
export function documentText(project: SourceProject, root: string, path: string): string {
  return sourceText(rootOf(project, root).files.find(f => f.path === path) ?? fail('The referenced source document is missing.'))
}
export function documentValue(project: SourceProject, root: string, path: string): JSONObject { return parse(documentText(project, root, path)) }
// These are fidelity/version gates for browser rewrites, not native schema or
// policy validation. Raw source and exact-byte export do not use this path.
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
  if (!browserNumbersSafe(value)) return 'Browser forms cannot preserve this document’s numeric values exactly. Use raw source editing and the matching Go tool.'
  if (path === 'draft.json') return value.apiVersion === 'ops.policy-draft/v1alpha1' && value.kind === 'PolicyDraft' ? null : 'This draft version is supported only as raw source.'
  const ref = root.draft.documents.find(d => d.path === path)
  if (ref) {
    if (value.apiVersion !== 'ops.policy-document/v1alpha1' || value.kind !== ref.kind || value.organizationId !== ref.organizationId) return 'This document envelope version or scope is supported only as raw source.'
    if (ref.kind === 'execution-rules') {
      const policy = object(object(value.spec).policy)
      if (!['privacy.gateway.fm/v1alpha1', 'privacy.gateway.fm/v1alpha2', 'privacy.gateway.fm/v1alpha3', 'privacy.gateway.fm/v1alpha4'].includes(String(policy.apiVersion)) || policy.kind !== 'ContractExecutionPolicy' || policy.org !== ref.organizationId) return 'This execution policy version or scope is supported only as raw source.'
    }
    return null
  }
  const key = globals.find(key => root.draft[key] !== undefined && object(root.draft[key]).path === path)
  if (!key) return 'This file is supported only as raw source.'
  const shape = catalogShapes[key]
  return shape.kind === value.kind && shape.versions.includes(String(value.apiVersion)) ? null : 'This catalog version is supported only as raw source.'
}
export function semanticEditingIssue(project: SourceProject, rootID: string): string | null {
  const root = rootOf(project, rootID)
  if (root.draftState === 'raw-only') return 'draft.json: Repair the raw draft before using browser forms. Source metadata is unavailable.'
  for (const path of requiredFiles(root.draft)) {
    try { const issue = semanticValueIssue(root, path, documentValue(project, rootID, path)); if (issue) return path + ': ' + issue }
    catch { return path + ': This source needs raw editing before browser forms can use it.' }
  }
  return null
}
export function documentFor(root: SourceRoot, organization: string, kind: DraftReference['kind']): string {
  return root.draft.documents.find(d => d.organizationId === organization && d.kind === kind)?.path ?? fail('This organization is missing its ' + kind + ' document.')
}
function replaceRoot(project: SourceProject, root: SourceRoot): SourceProject {
  const next = { ...project, generation: project.generation + 1, validation: 'not-checked' as const, roots: project.roots.map(r => r.id === root.id ? root : r) }
  return { ...next, dirty: next.roots.some(r => r.files.some(f => f.editedText !== null)) }
}
export function updateSourceText(project: SourceProject, rootID: string, path: string, raw: string): SourceProject {
  const root = rootOf(project, rootID)
  if (encode(raw).length > maxFile) fail('Each source document must be at most 1 MiB.')
  let found = false
  const files = root.files.map(f => {
    if (f.path !== path) return f
    found = true
    return { ...f, editedText: raw === f.originalText ? null : raw }
  })
  if (!found) fail('Select a source document first.')
  if (project.roots.reduce((sum, r) => sum + (r.id === rootID ? files : r.files).reduce((n, f) => n + sourceBytes(f).length, 0), 0) > maxBytes) fail('The source project exceeds 64 MiB.')
  // Retain unfinished text exactly. The last parsed selection is navigation
  // context only; semanticEditingIssue blocks forms until the text is repaired.
  let draft = root.draft
  let draftState = root.draftState
  if (path === 'draft.json') { try { draft = draftValue(parse(raw)); draftState = undefined } catch { draftState = 'raw-only' } }
  return replaceRoot(project, { ...root, draft, draftState, files })
}
export function updateDocument(project: SourceProject, root: string, path: string, value: JSONObject): SourceProject {
  const rootIssue = semanticEditingIssue(project, root)
  if (rootIssue) fail(rootIssue)
  const selected = rootOf(project, root)
  const issue = semanticValueIssue(selected, path, documentValue(project, root, path)) ?? semanticValueIssue(selected, path, value)
  if (issue) fail(issue)
  return updateSourceText(project, root, path, json(value))
}
function addDocument(root: SourceRoot, path: string, value: unknown): SourceRoot {
  if (!name(path) || root.files.some(f => f.path === path)) fail('A generated source filename is already used.')
  const raw = json(value)
  return { ...root, files: [...root.files, { path, originalBytes: new Uint8Array(), originalText: '', editedText: raw }] }
}
export function createCatalog(project: SourceProject, rootID: string, key: string, value: JSONObject): SourceProject {
  let root = rootOf(project, rootID)
  if (!globals.includes(key) || root.draft[key] !== undefined) fail('Select a missing supported catalog.')
  const path = key.replace(/Catalog$/, '').toLowerCase() + '-catalog.json'
  root = addDocument(root, path, value)
  root = { ...root, draft: { ...root.draft, [key]: { path } } }
  return updateDocument(replaceRoot(project, root), rootID, 'draft.json', root.draft)
}
export function importReferencedDocument(project: SourceProject, rootID: string, path: string, raw: string): SourceProject {
  const root = rootOf(project, rootID)
  const allowed = new Set(requiredFiles(root.draft))
  if (root.draft.authCatalog !== undefined) {
    const auth = documentValue(project, rootID, String(object(root.draft.authCatalog).path))
    if (Array.isArray(auth.pinnedDocuments)) auth.pinnedDocuments.forEach(pin => allowed.add(String(object(pin).path)))
  }
  if (!name(path) || !allowed.has(path) || root.files.some(f => f.path === path)) fail('Choose a missing document explicitly referenced by this draft or its broker pins.')
  parse(raw)
  if (project.roots.reduce((n, r) => n + r.files.length, 0) >= 2048) fail('The source project has too many files.')
  const next = replaceRoot(project, { ...root, files: [...root.files, { path, originalBytes: new Uint8Array(), originalText: '', editedText: raw }] })
  return updateSourceText(next, rootID, path, raw)
}
export function createOrganization(project: SourceProject, rootID: string, org: { id: string; name: string; slug: string }): SourceProject {
  let root = rootOf(project, rootID)
  if (!session(org.id) || !text(org.name, 256) || !text(org.slug, 100) || root.draft.organizations.some(o => o.id === org.id || o.slug === org.slug)) fail('Use a new stable organization ID, name and slug.')
  const draft = { ...root.draft, organizations: [...root.draft.organizations, org], documents: [...root.draft.documents] }
  const version = /v1alpha([1-4])$/.exec(draft.evaluatorVersion)?.[1] ?? fail('Choose a supported native evaluator before adding an organization.')
  for (const kind of kinds as DraftReference['kind'][]) {
    const path = `${kind}-${org.id}.json`
    const spec = kind === 'groups' ? { groups: [] } : kind === 'contract-registry' ? { contracts: [] } : { policy: { apiVersion: `privacy.gateway.fm/v1alpha${version}`, kind: 'ContractExecutionPolicy', org: org.id, nestedCalls: 'requireOwnRule', bindings: [] } }
    root = addDocument(root, path, { apiVersion: 'ops.policy-document/v1alpha1', kind, organizationId: org.id, spec })
    draft.documents.push({ kind, organizationId: org.id, path })
  }
  root = { ...root, draft }
  const next = replaceRoot(project, root)
  return updateDocument(next, rootID, 'draft.json', draft)
}
export function updateOrganization(project: SourceProject, rootID: string, id: string, value: { name: string; slug: string }): SourceProject {
  const root = rootOf(project, rootID)
  if (!root.draft.organizations.some(o => o.id === id) || !text(value.name, 256) || !text(value.slug, 100) ||
    root.draft.organizations.some(o => o.id !== id && (o.slug === value.slug || o.name.toLowerCase() === value.name.toLowerCase()))) fail('Choose a unique organization name and slug.')
  return updateDocument(project, rootID, 'draft.json', { ...root.draft, organizations: root.draft.organizations.map(o => o.id === id ? { ...o, ...value } : o) })
}
export function referenceFiles(project: SourceProject, rootID: string, identifier: string, excludePath?: string): string[] {
  const contains = (value: unknown): boolean => value === identifier || (Array.isArray(value) ? value.some(contains)
    : value && typeof value === 'object' ? Object.values(value).some(contains) : false)
  return rootOf(project, rootID).files.filter(f => f.path !== excludePath && contains(parse(sourceText(f)))).map(f => f.path)
}
export function removeOrganization(project: SourceProject, rootID: string, id: string): SourceProject {
  const root = rootOf(project, rootID), removed = new Set(root.draft.documents.filter(d => d.organizationId === id).map(d => d.path))
  const draft = { ...root.draft, organizations: root.draft.organizations.filter(o => o.id !== id), documents: root.draft.documents.filter(d => d.organizationId !== id) }
  if (draft.organizations.length === root.draft.organizations.length) fail('The selected organization changed.')
  const next = replaceRoot(project, { ...root, draft, files: root.files.filter(f => !removed.has(f.path)) })
  return updateDocument(next, rootID, 'draft.json', draft)
}
export function groupsOf(project: SourceProject, rootID: string, organization: string): DraftGroup[] {
  const root = rootOf(project, rootID), value = documentValue(project, rootID, documentFor(root, organization, 'groups'))
  const groups = object(value.spec).groups
  if (value.kind !== 'groups' || value.organizationId !== organization || !Array.isArray(groups) || groups.length > 4096) fail('This groups document cannot be edited by this version.')
  for (const raw of groups) {
    const group = object(raw)
    if (!session(group.id) || !text(group.slug, 100) || !text(group.name, 256) || typeof group.description !== 'string' ||
      typeof group.isOrgAdmin !== 'boolean' || typeof group.isOrgReadonlyAdmin !== 'boolean' || typeof group.verboseErrors !== 'boolean' ||
      !Array.isArray(group.allowedMethods) || group.allowedMethods.some(m => !text(m, 256)) || !Array.isArray(group.claims) || group.claims.some(c => !text(c, 256))) fail('Unsupported group fields. Inspect the source and run the matching Go checker.')
  }
  return groups as DraftGroup[]
}
export function createGroup(project: SourceProject, rootID: string, organization: string, value: { id: string; slug: string; name: string }): SourceProject {
  if (!session(value.id) || !text(value.slug, 100) || !text(value.name, 256)) fail('A group needs a stable ID, name and slug.')
  const groups = groupsOf(project, rootID, organization)
  if (groups.some(g => g.id === value.id || g.slug === value.slug || g.name.toLowerCase() === value.name.toLowerCase())) fail('Choose a unique group name, slug and ID.')
  const path = documentFor(rootOf(project, rootID), organization, 'groups'), doc = documentValue(project, rootID, path), spec = object(doc.spec)
  return updateDocument(project, rootID, path, { ...doc, spec: { ...spec, groups: [...groups, { ...value, description: '', isOrgAdmin: false, isOrgReadonlyAdmin: false, allowedMethods: [], claims: [], verboseErrors: false }] } })
}
export function updateGroup(project: SourceProject, rootID: string, organization: string, id: string, patch: Partial<DraftGroup>): SourceProject {
  const groups = groupsOf(project, rootID, organization)
  if (!groups.some(g => g.id === id) || patch.id !== undefined && patch.id !== id) fail('The selected group changed.')
  const path = documentFor(rootOf(project, rootID), organization, 'groups'), doc = documentValue(project, rootID, path)
  const next = groups.map(group => {
    if (group.id !== id) return group
    const changed = { ...group, ...patch, id }
    if (patch.isOrgAdmin) changed.isOrgReadonlyAdmin = false
    if (patch.isOrgReadonlyAdmin) changed.isOrgAdmin = false
    return changed
  })
  return updateDocument(project, rootID, path, { ...doc, spec: { ...object(doc.spec), groups: next } })
}
export function removeGroup(project: SourceProject, rootID: string, organization: string, id: string): SourceProject {
  const path = documentFor(rootOf(project, rootID), organization, 'groups'), doc = documentValue(project, rootID, path)
  const groups = groupsOf(project, rootID, organization)
  if (!groups.some(g => g.id === id)) fail('The selected group changed.')
  return updateDocument(project, rootID, path, { ...doc, spec: { ...object(doc.spec), groups: groups.filter(g => g.id !== id) } })
}
export function workspaceView(project: SourceProject, rootID: string): Workspace {
  const root = rootOf(project, rootID)
  return { sourceRevision: root.draft.sourceRevision, environment: root.draft.environment, chainId: root.draft.chainId,
    organizations: root.draft.organizations.map(org => ({ ...org, groups: groupsOf(project, rootID, org.id) })), displayedFiles: root.files.map(f => f.path) }
}
function base64(bytes: Uint8Array): string {
  let raw = ''
  for (let i = 0; i < bytes.length; i += 16384) raw += String.fromCharCode(...bytes.subarray(i, i + 16384))
  return btoa(raw)
}
export function sourcePackage(project: SourceProject): SourcePackage {
  return { apiVersion: 'ops.ui-source-package/v1', roots: project.roots.map(root => ({ id: root.id, files: root.files.map(file => ({ path: file.path, dataBase64: base64(sourceBytes(file)) })) })) }
}
export async function loadSavedSourcePackage(raw: string, check: () => void = () => {}): Promise<SourceProject> {
  check()
  const value = object(closedJSON(raw, 90 << 20))
  if (Object.keys(value).some(k => !['apiVersion', 'roots'].includes(k)) || value.apiVersion !== 'ops.ui-source-package/v1' || !Array.isArray(value.roots) || !value.roots.length || value.roots.length > 16) fail('Choose an exported OPS source package.')
  const files: SourceFile[] = [], ids = new Set<string>(); let total = 0
  for (const entry of value.roots) {
    const root = object(entry)
    if (Object.keys(root).some(k => !['id', 'files'].includes(k)) || typeof root.id !== 'string' || !rootName(root.id) || ids.has(root.id) || !Array.isArray(root.files)) fail('The source package has invalid roots.')
    ids.add(root.id)
    for (const entry of root.files) {
      const f = object(entry)
      if (Object.keys(f).some(k => !['path', 'dataBase64'].includes(k)) || !name(f.path) || typeof f.dataBase64 !== 'string' || f.dataBase64.length > 4 * Math.ceil(maxFile / 3) || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(f.dataBase64)) fail('The source package has invalid file bytes.')
      const decoded = atob(f.dataBase64), bytes = Uint8Array.from(decoded, c => c.charCodeAt(0)); total += bytes.length
      if (total > maxBytes || bytes.length > maxFile || files.length >= 2048 || btoa(decoded) !== f.dataBase64) fail('The source package exceeds the bounded file limits.')
      files.push({ path: `${root.id}/${f.path}`, size: bytes.length, readBytes: async () => bytes, read: async () => new TextDecoder('utf-8', { fatal: true }).decode(bytes) })
    }
  }
  // A saved package is an explicit prior selection. Keep repairable/orphaned
  // files too; unlike a folder import, it must not silently shrink that set.
  const roots: SourceRoot[] = []
  for (const id of ids) {
    const documents: SourceDocument[] = [], retained = new Set<string>()
    for (const file of files.filter(f => f.path.startsWith(id + '/'))) {
      const path = file.path.slice(id.length + 1)
      if (retained.has(path)) fail('The saved source package has duplicate paths.')
      check(); const bytes = await file.readBytes!(); check()
      let raw: string
      try { raw = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes) } catch { return fail('Saved source files must be valid UTF-8.') }
      documents.push({ path, originalBytes: bytes.slice(), originalText: raw, editedText: null })
      retained.add(path)
    }
    const draftFile = documents.find(f => f.path === 'draft.json')
    if (!draftFile) fail('Every saved source root must include its own draft.json.')
    let draft: SourceDraft, draftState: SourceRoot['draftState']
    try { draft = draftValue(parse(draftFile.originalText)) }
    catch {
      // No metadata is invented when recovering unfinished draft text. This
      // root can only use the raw editor until an exact known draft is parsed.
      draftState = 'raw-only'
      draft = { apiVersion: '', kind: '', sourceRevision: '', environment: '', chainId: '', evaluatorVersion: '', profile: '', organizations: [], documents: [] }
    }
    roots.push({ id, files: documents, draft, draftState })
  }
  return { roots, dirty: false, generation: 0, validation: 'not-checked' }
}
