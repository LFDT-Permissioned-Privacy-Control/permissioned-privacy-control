import { describe, expect, it, vi } from 'vitest'
import { decodeSourceProject, documentText, documentValue, loadSourceProject, sourceDisplayIssue, groupsOf } from './sourceProject'
import { fixtureDocuments, fixtureEnvelope, fixtureFiles, org, sourceFile } from './configurationFixtures.test-support'

describe('read-only public source observations', () => {
  it('reads only explicit references, preserving exact UTF-8 bytes and CRLF source', async () => {
    const selected = fixtureFiles(), original = '{\r\n"apiVersion":"ops.policy-document/v1alpha1","kind":"contract-registry","organizationId":"' + org + '","spec":{"contracts":[]}\r\n}\r\n'
    selected[2] = sourceFile('registry.json', original)
    const secret = { path: 'credentials.json', size: 99, read: vi.fn(async () => { throw Error('secret read') }) }
    const project = await loadSourceProject([...selected, secret])
    expect(secret.read).not.toHaveBeenCalled(); expect(project.roots[0].files).toHaveLength(5)
    expect(documentText(project, 'source', 'registry.json')).toBe(original)
    expect(groupsOf(project, 'source', org).map(group => group.name)).toEqual(['Deployer', 'Reader'])
    expect(project).not.toHaveProperty('dirty'); expect(project).not.toHaveProperty('validation')
  })
  it('decodes the server envelope and named roots, rejecting duplicates, aliases and unreferenced files', async () => {
    const envelope = await fixtureEnvelope(), project = await decodeSourceProject(envelope)
    expect(documentValue(project, 'source', 'draft.json').organizations).toEqual(fixtureDocuments()['draft.json'].organizations)
    expect((await loadSourceProject([...fixtureFiles('core/'), ...fixtureFiles('broker/')])).roots.map(root => root.id)).toEqual(['broker', 'core'])
    const duplicate = structuredClone(envelope); duplicate.roots[0].files.push(duplicate.roots[0].files[0]); await expect(decodeSourceProject(duplicate)).rejects.toThrow('duplicate')
    const alias = structuredClone(envelope); alias.roots[0].files[0].path = '../draft.json'; await expect(decodeSourceProject(alias)).rejects.toThrow('invalid')
    const orphan = structuredClone(envelope); orphan.roots[0].files.push({ path: 'private.json', dataBase64: btoa('{}') }); await expect(decodeSourceProject(orphan)).rejects.toThrow('outside')
    const wrong64 = structuredClone(envelope); wrong64.roots[0].files[0].dataBase64 = 'e31='; await expect(decodeSourceProject(wrong64)).rejects.toThrow()
  })
  it.each(['9007199254740993', '1e400'])('keeps unsafe numeric bytes %s inspectable without misleading structured values', async literal => {
    const files = fixtureFiles(), raw = (await files[3].read()).replace('"maxDepth":1', '"maxDepth":' + literal); files[3] = sourceFile('execution.json', raw)
    const project = await loadSourceProject(files)
    expect(sourceDisplayIssue(project, 'source')).toContain('cannot be displayed exactly')
    expect(documentText(project, 'source', 'execution.json')).toContain(literal)
  })
  it.each(['catalog', 'envelope', 'policy'])('preserves unsupported %s versions as source instead of claiming supported permissions', async kind => {
    const files = fixtureFiles(), index = kind === 'catalog' ? 4 : 3, raw = await files[index].read()
    files[index] = sourceFile(files[index].path, kind === 'catalog' ? raw.replace('ops.identity-catalog/v1alpha1', 'ops.identity-catalog/v999') : kind === 'envelope' ? raw.replace('ops.policy-document/v1alpha1', 'ops.policy-document/v999') : raw.replace('privacy.gateway.fm/v1alpha4', 'privacy.gateway.fm/v999'))
    const project = await loadSourceProject(files); expect(sourceDisplayIssue(project, 'source')).toContain('raw source'); expect(documentText(project, 'source', files[index].path)).toContain('v999')
  })
  it('rejects incomplete references, duplicate JSON, traversal, invalid UTF8 and changed byte counts', async () => {
    await expect(loadSourceProject(fixtureFiles().slice(0, 4))).rejects.toThrow('referenced')
    await expect(loadSourceProject([sourceFile('draft.json', '{"kind":1,"kind":2}')])).rejects.toThrow('invalid_response')
    const traversal = fixtureFiles(); traversal[0] = sourceFile('draft.json', (await traversal[0].read()).replace('groups.json', '../groups.json')); await expect(loadSourceProject(traversal)).rejects.toThrow('flat')
    const invalid = fixtureFiles(); invalid[0] = { ...invalid[0], size: 1, readBytes: async () => new Uint8Array([255]) }; await expect(loadSourceProject(invalid)).rejects.toThrow('UTF-8')
    const changing = fixtureFiles(); changing[0] = { ...changing[0], size: 1 }; await expect(loadSourceProject(changing)).rejects.toThrow('changed')
  })
  it('bounds source reads and checks original ownership after every asynchronous read', async () => {
    const read = vi.fn(async () => '{}')
    await expect(loadSourceProject([{ path: 'draft.json', size: (1 << 20) + 1, read }])).rejects.toThrow('size limit'); expect(read).not.toHaveBeenCalled()
    const files = fixtureFiles(); let active = true; const original = files[0].read; files[0].read = async () => { const raw = await original(); active = false; return raw }
    await expect(loadSourceProject(files, () => { if (!active) throw Error('owner changed') })).rejects.toThrow('owner changed')
  })
})
