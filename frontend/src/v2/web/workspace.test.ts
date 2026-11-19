import { describe, expect, it, vi } from 'vitest'
import { loadWorkspace, selectedSources, SourceFile } from './workspace'

const org = '11111111-1111-1111-1111-111111111111'
const group = '22222222-2222-2222-2222-222222222222'
function source(path: string, value: unknown): SourceFile {
  const raw = typeof value === 'string' ? value : JSON.stringify(value)
  return { path, size: new TextEncoder().encode(raw).length, read: vi.fn(async () => raw) }
}
function packageFiles() {
  return [source('draft.json', {
    apiVersion: 'ops.policy-draft/v1alpha1', kind: 'PolicyDraft', environment: 'test', chainId: '31337',
    evaluatorVersion: 'policycore/native-v1alpha4', profile: 'catalog-runtime-creation-observed/v1', sourceRevision: 'reviewed-example',
    organizations: [{ id: org, slug: 'example-bank', name: 'Example Bank' }],
    documents: [{ kind: 'groups', organizationId: org, path: 'groups/bank.json' },
      { kind: 'execution-rules', organizationId: org, path: 'execution.json' }],
    identityCatalog: { path: 'identity.json' },
  }), source('groups/bank.json', {
    apiVersion: 'ops.policy-document/v1alpha1', kind: 'groups', organizationId: org,
    spec: { groups: [{ id: group, slug: 'ops', name: 'Bank operations', description: 'Operations team', isOrgAdmin: false,
      isOrgReadonlyAdmin: true, allowedMethods: ['eth_call', 'eth_getLogs'], claims: ['bank-a-ops'], verboseErrors: false,
      rpcCredential: { fromEnv: 'BANK_A_RPC_TOKEN' } }] },
  })]
}
async function replaceJSON(file: SourceFile, change: (v: Record<string, unknown>) => void) {
  const value = JSON.parse(await file.read()); change(value); return source(file.path, value)
}

describe('explicit confidential policy source display', () => {
  it('reads actual organizations/groups while leaving policy payloads and unrelated secrets unread', async () => {
    const files = packageFiles()
    const extra = ['identity.json', 'execution.json', 'deployment.env', 'private-key.json'].map(path => ({ path, size: 100, read: vi.fn(async () => { throw Error('must not read') }) }))
    const workspace = await loadWorkspace([...files, ...extra])
    expect(workspace.sourceRevision).toBe('reviewed-example')
    expect(workspace.organizations).toEqual([{ id: org, name: 'Example Bank', slug: 'example-bank', groups: [expect.objectContaining({
      id: group, allowedMethods: ['eth_call', 'eth_getLogs'], claims: ['bank-a-ops'], isOrgReadonlyAdmin: true,
    })] }])
    expect(workspace.displayedFiles).toEqual(['draft.json', 'groups/bank.json'])
    for (const file of extra) expect(file.read).not.toHaveBeenCalled()
  })
  it('rejects a missing or differently scoped group document instead of inventing empty permissions', async () => {
    const files = packageFiles()
    await expect(loadWorkspace(files.slice(0, 1))).rejects.toThrow('required source document')
    files[1] = await replaceJSON(files[1], v => { v.organizationId = group })
    await expect(loadWorkspace(files)).rejects.toThrow('cannot be displayed')
  })
  it('rejects duplicate JSON fields, unsafe references and unexpected inline credential fields', async () => {
    await expect(loadWorkspace([source('draft.json', '{"apiVersion":"a","apiVersion":"b"}')])).rejects.toThrow('duplicate')
    const files = packageFiles()
    files[0] = await replaceJSON(files[0], v => { (v.documents as { path: string }[])[0].path = '../groups.json' })
    await expect(loadWorkspace(files)).rejects.toThrow('cannot be displayed')
    const credentialFiles = packageFiles()
    credentialFiles[1] = await replaceJSON(credentialFiles[1], v => { ((v.spec as { groups: Record<string, unknown>[] }).groups[0]).rpcCredential = { value: 'not-a-source-reference' } })
    await expect(loadWorkspace(credentialFiles)).rejects.toThrow('cannot be displayed')
  })
  it('bounds file size before reading and checks context again after an asynchronous file read', async () => {
    const files = packageFiles(), read = vi.fn(async () => '{}')
    await expect(loadWorkspace([{ path: 'draft.json', size: (1 << 20) + 1, read }])).rejects.toThrow('size limit')
    expect(read).not.toHaveBeenCalled()
    let valid = true
    const original = files[0].read
    files[0].read = async () => { const raw = await original(); valid = false; return raw }
    await expect(loadWorkspace(files, () => { if (!valid) throw Error('retired context') })).rejects.toThrow('retired context')
    expect(files[1].read).not.toHaveBeenCalled()
  })
  it('retains nested paths relative to one explicitly selected folder', () => {
    const one = new File(['{}'], 'draft.json'), two = new File(['{}'], 'bank.json')
    Object.defineProperty(one, 'webkitRelativePath', { value: 'source/draft.json' })
    Object.defineProperty(two, 'webkitRelativePath', { value: 'source/groups/bank.json' })
    expect(selectedSources([one, two]).map(v => v.path)).toEqual(['draft.json', 'groups/bank.json'])
    const other = new File(['{}'], 'other.json')
    Object.defineProperty(other, 'webkitRelativePath', { value: 'another/other.json' })
    expect(() => selectedSources([one, other])).toThrow('one policy source folder')
  })
})
