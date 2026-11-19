import { describe, expect, it, vi } from 'vitest'
import { importReferencedDocument, loadSavedSourcePackage, loadSourceProject, sourcePackage, createOrganization, createGroup, updateGroup, updateSourceText, documentText, documentValue, updateDocument, semanticEditingIssue } from './sourceProject'
import type { SourceFile } from './workspace'

const org = '11111111-1111-1111-1111-111111111111'
const group = '22222222-2222-2222-2222-222222222222'
const second = '33333333-3333-3333-3333-333333333333'
function file(path: string, value: unknown): SourceFile {
  const raw = typeof value === 'string' ? value : JSON.stringify(value)
  return { path, size: new TextEncoder().encode(raw).length, read: vi.fn(async () => raw) }
}
function files(prefix = '') {
  return [file(prefix + 'draft.json', {
    apiVersion: 'ops.policy-draft/v1alpha1', kind: 'PolicyDraft', environment: 'test', chainId: '31337',
    evaluatorVersion: 'policycore/native-v1alpha4', profile: 'catalog-runtime-creation-observed/v1', sourceRevision: 'original',
    organizations: [{ id: org, slug: 'bank', name: 'Bank' }],
    documents: ['groups', 'contract-registry', 'execution-rules'].map((kind, index) => ({ kind, organizationId: org, path: ['groups.json', 'registry.json', 'execution.json'][index] })),
    identityCatalog: { path: 'identity.json' },
  }), file(prefix + 'groups.json', { apiVersion: 'ops.policy-document/v1alpha1', kind: 'groups', organizationId: org, spec: { groups: [
    { id: group, slug: 'reader', name: 'Reader', description: '', isOrgAdmin: false, isOrgReadonlyAdmin: true, allowedMethods: ['eth_call'], claims: [], verboseErrors: false },
  ] } }), file(prefix + 'registry.json', '{\r\n  "apiVersion":"ops.policy-document/v1alpha1","kind":"contract-registry","organizationId":"' + org + '","spec":{"contracts":[]}\r\n}\r\n'),
  file(prefix + 'execution.json', { apiVersion: 'ops.policy-document/v1alpha1', kind: 'execution-rules', organizationId: org, spec: { policy: { apiVersion: 'privacy.gateway.fm/v1alpha4', kind: 'ContractExecutionPolicy', org, nestedCalls: 'requireOwnRule', bindings: [] } } }),
  file(prefix + 'identity.json', { apiVersion: 'ops.identity-catalog/v1alpha1', kind: 'IdentityCatalog', issuers: [], profiles: [], mappings: [] })]
}

describe('complete local source projects', () => {
  it('imports every selected referenced document and exports untouched source bytes exactly', async () => {
    const selected = files()
    const secret = { path: 'private-key.json', size: 100, read: vi.fn(async () => { throw Error('not selected by draft') }) }
    const project = await loadSourceProject([...selected, secret])
    expect(project.roots[0].files.map(f => f.path).sort()).toEqual(['draft.json', 'groups.json', 'registry.json', 'execution.json', 'identity.json'].sort())
    expect(secret.read).not.toHaveBeenCalled()
    const packed = sourcePackage(project)
    expect(packed.apiVersion).toBe('ops.ui-source-package/v1')
    const registry = packed.roots[0].files.find(f => f.path === 'registry.json')!
    expect(atob(registry.dataBase64)).toBe(await selected[2].read())
    expect(project.dirty).toBe(false)
  })
  it('creates a new org with deny-all native documents, then edits a general group without touching old files', async () => {
    let project = await loadSourceProject(files())
    const before = sourcePackage(project).roots[0].files.find(f => f.path === 'registry.json')!.dataBase64
    project = createOrganization(project, 'source', { id: second, slug: 'new-bank', name: 'New Bank' })
    project = createGroup(project, 'source', second, { id: '44444444-4444-4444-4444-444444444444', slug: 'operations', name: 'Operations' })
    project = updateGroup(project, 'source', second, '44444444-4444-4444-4444-444444444444', { allowedMethods: ['eth_call', 'eth_chainId'], claims: ['member'], isOrgAdmin: true })
    const root = project.roots[0]
    const refs = root.draft.documents.filter(d => d.organizationId === second)
    expect(refs.map(d => d.kind).sort()).toEqual(['contract-registry', 'execution-rules', 'groups'])
    const groups = JSON.parse(documentText(project, 'source', refs.find(d => d.kind === 'groups')!.path)).spec.groups
    expect(groups[0]).toMatchObject({ name: 'Operations', isOrgAdmin: true, isOrgReadonlyAdmin: false, allowedMethods: ['eth_call', 'eth_chainId'] })
    expect(sourcePackage(project).roots[0].files.find(f => f.path === 'registry.json')!.dataBase64).toBe(before)
    expect(project.dirty).toBe(true)
  })
  it('recovers an exported multi-root proposal with exact untouched bytes and rejects duplicate or aliased recovery paths', async () => {
    let project = await loadSourceProject([...files('core/'), ...files('broker/')])
    project = updateSourceText(project, 'core', 'identity.json', documentText(project, 'core', 'identity.json').replace('"mappings":[]', '"mappings":[],"futureField":true'))
    const packed = sourcePackage(project), recovered = await loadSavedSourcePackage(JSON.stringify(packed))
    expect(sourcePackage(recovered)).toEqual(packed)
    expect(recovered.dirty).toBe(false)
    const duplicate = structuredClone(packed); duplicate.roots[0].files.push(duplicate.roots[0].files[0])
    await expect(loadSavedSourcePackage(JSON.stringify(duplicate))).rejects.toThrow('duplicate')
    const alias = structuredClone(packed); alias.roots[0].files[0].path = '../draft.json'
    await expect(loadSavedSourcePackage(JSON.stringify(alias))).rejects.toThrow('invalid')
  })
  it('preserves a nested ABI within the native document depth bound', async () => {
    const selected = files(), tuple = { type: 'tuple', components: [{ type: 'tuple', components: [{ type: 'tuple', components: [{ type: 'uint256', name: 'value' }] }] }] }
    selected[2] = file('registry.json', { apiVersion: 'ops.policy-document/v1alpha1', kind: 'contract-registry', organizationId: org, spec: { contracts: [{ id: second, abi: [{ type: 'function', name: 'nested', inputs: [tuple] }] }] } })
    const project = await loadSourceProject(selected)
    expect(atob(sourcePackage(project).roots[0].files.find(f => f.path === 'registry.json')!.dataBase64)).toBe(await selected[2].read())
  })
  it('adds only a newly named source dependency, without importing unrelated adjacent JSON', async () => {
    let project = await loadSourceProject(files())
    const draft = JSON.parse(documentText(project, 'source', 'draft.json'))
    draft.disclosureCatalog = { path: 'disclosure.json' }
    project = updateSourceText(project, 'source', 'draft.json', JSON.stringify(draft))
    expect(() => importReferencedDocument(project, 'source', 'credentials.json', '{}')).toThrow('explicitly referenced')
    project = importReferencedDocument(project, 'source', 'disclosure.json', '{"apiVersion":"ops.disclosure-policy/v1alpha1","kind":"DisclosurePolicy","rules":[]}\n')
    expect(sourcePackage(project).roots[0].files.map(f => f.path)).toContain('disclosure.json')
    expect(project.dirty).toBe(true)
  })
  it.each(['9007199254740993', '1e400'])('preserves unsafe numeric bytes %s and permits raw editing while refusing an unrelated semantic rewrite', async literal => {
    const selected = files()
    selected[3] = file('execution.json', '{"apiVersion":"ops.policy-document/v1alpha1","kind":"execution-rules","organizationId":"' + org + '","spec":{"policy":{"apiVersion":"privacy.gateway.fm/v1alpha1","kind":"ContractExecutionPolicy","org":"' + org + '","nestedCalls":"requireOwnRule","bindings":[{"group":"' + group + '","allow":[{"storageAddress":"0x' + '1'.repeat(40) + '","selector":"*","abiDigest":"","maxDepth":9007199254740993}]}]}}}'.replace('9007199254740993', literal))
    let project = await loadSourceProject(selected)
    const original = documentText(project, 'source', 'execution.json'), proposed = documentValue(project, 'source', 'execution.json')
    expect(semanticEditingIssue(project, 'source')).toContain('numeric values exactly')
    expect(() => updateDocument(project, 'source', 'execution.json', { ...proposed, annotation: 'unrelated edit' })).toThrow('numeric values exactly')
    expect(atob(sourcePackage(project).roots[0].files.find(f => f.path === 'execution.json')!.dataBase64)).toBe(original)
    project = updateSourceText(project, 'source', 'execution.json', original.replace('"selector":"*"', '"selector":"0x"'))
    expect(documentText(project, 'source', 'execution.json')).toContain(literal)
  })
  it.each(['catalog', 'envelope', 'policy'] as const)('keeps an unsupported %s version as raw source only', async kind => {
    const selected = files()
    const index = kind === 'catalog' ? 4 : 3
    const raw = await selected[index].read()
    selected[index] = file(selected[index].path, kind === 'catalog' ? raw.replace('ops.identity-catalog/v1alpha1', 'ops.identity-catalog/v999') : kind === 'envelope' ? raw.replace('ops.policy-document/v1alpha1', 'ops.policy-document/v999') : raw.replace('privacy.gateway.fm/v1alpha4', 'privacy.gateway.fm/v999'))
    const project = await loadSourceProject(selected), path = selected[index].path, value = documentValue(project, 'source', path)
    expect(semanticEditingIssue(project, 'source')).toContain('raw source')
    expect(() => updateDocument(project, 'source', path, value)).toThrow('raw source')
    expect(atob(sourcePackage(project).roots[0].files.find(f => f.path === path)!.dataBase64)).toBe(await selected[index].read())
  })
  it('recovers every explicitly saved file after its reference is removed, including an orphan needing raw repair', async () => {
    let project = await loadSourceProject(files())
    const draft = JSON.parse(documentText(project, 'source', 'draft.json')); delete draft.identityCatalog
    project = updateSourceText(project, 'source', 'draft.json', JSON.stringify(draft))
    project = updateSourceText(project, 'source', 'identity.json', '{unfinished raw repair')
    const saved = sourcePackage(project), recovered = await loadSavedSourcePackage(JSON.stringify(saved))
    expect(recovered.roots[0].files).toHaveLength(5)
    for (const expected of saved.roots[0].files) expect(sourcePackage(recovered).roots[0].files.find(f => f.path === expected.path)).toEqual(expected)
    expect(documentText(recovered, 'source', 'identity.json')).toBe('{unfinished raw repair')
  })
  it('recovers unfinished raw draft text without inventing metadata, then restores forms after explicit repair', async () => {
    let project = await loadSourceProject(files())
    const original = documentText(project, 'source', 'draft.json')
    project = updateSourceText(project, 'source', 'draft.json', '{unfinished draft')
    const saved = sourcePackage(project), recovered = await loadSavedSourcePackage(JSON.stringify(saved))
    expect(documentText(recovered, 'source', 'draft.json')).toBe('{unfinished draft')
    expect(recovered.roots[0].draftState).toBe('raw-only')
    expect(recovered.roots[0].draft.chainId).toBe('')
    expect(sourcePackage(recovered)).toEqual(saved)
    expect(semanticEditingIssue(recovered, 'source')).toContain('metadata is unavailable')
    const repaired = updateSourceText(recovered, 'source', 'draft.json', original)
    expect(repaired.roots[0].draftState).toBeUndefined()
    expect(repaired.roots[0].draft.chainId).toBe('31337')
  })
  it.each(['chainId', 'organizations'] as const)('keeps invalid known-version draft %s text raw-only instead of overwriting it from old parsed metadata', async key => {
    let project = await loadSourceProject(files()), draft = JSON.parse(documentText(project, 'source', 'draft.json'))
    draft[key] = key === 'chainId' ? 'unfinished-value' : { unfinished: true }
    const raw = JSON.stringify(draft)
    project = updateSourceText(project, 'source', 'draft.json', raw)
    expect(project.roots[0].draftState).toBe('raw-only')
    expect(semanticEditingIssue(project, 'source')).toContain('Repair the raw draft')
    expect(() => updateDocument(project, 'source', 'draft.json', { ...project.roots[0].draft, sourceRevision: 'unrelated edit' })).toThrow('Repair the raw draft')
    expect(atob(sourcePackage(project).roots[0].files.find(f => f.path === 'draft.json')!.dataBase64)).toBe(raw)
  })
  it('supports separate explicitly selected core/broker roots and refuses path aliases or incomplete exports', async () => {
    const project = await loadSourceProject([...files('core/'), ...files('broker/')])
    expect(project.roots.map(r => r.id)).toEqual(['broker', 'core'])
    const incomplete = files().filter(f => f.path !== 'execution.json')
    await expect(loadSourceProject(incomplete)).rejects.toThrow('referenced')
    const selected = files()
    selected[0] = file('draft.json', (await selected[0].read()).replace('groups.json', '../groups.json'))
    await expect(loadSourceProject(selected)).rejects.toThrow('flat')
  })
  it('invalidates the draft when edited and checks the original owner after asynchronous reads', async () => {
    let project = await loadSourceProject(files())
    const original = documentText(project, 'source', 'identity.json')
    project = updateSourceText(project, 'source', 'identity.json', original.replace('"mappings":[]', '"mappings":[],"futureField":{"keep":true}'))
    expect(documentText(project, 'source', 'identity.json')).toContain('futureField')
    expect(project.validation).toBe('not-checked')
    let active = true
    const selected = files(), read = selected[0].read
    selected[0].read = async () => { const value = await read(); active = false; return value }
    await expect(loadSourceProject(selected, () => { if (!active) throw Error('owner changed') })).rejects.toThrow('owner changed')
    expect(selected[1].read).not.toHaveBeenCalled()
  })
})
