import { afterEach, expect, it } from 'vitest'
import { SourceDraftMemory } from './sourceDraftMemory'
import { activeMulti, writeMultiMarker } from '../auth/multiContext'
import { documentText, loadSourceProject, updateSourceText } from './sourceProject'
import type { Controller, State } from './controller'

const actor = 'ops:p1:' + 'A'.repeat(43), org = '11111111-1111-1111-1111-111111111111'
async function fixture() {
  const values = {
    'draft.json': { apiVersion: 'ops.policy-draft/v1alpha1', kind: 'PolicyDraft', sourceRevision: 'local', environment: 'local', chainId: '31337', evaluatorVersion: 'policycore/native-v1alpha4', profile: 'catalog-runtime-creation-observed/v1', organizations: [{ id: org, name: 'Bank', slug: 'bank' }], documents: [{ kind: 'groups', organizationId: org, path: 'groups.json' }] },
    'groups.json': { apiVersion: 'ops.policy-document/v1alpha1', kind: 'groups', organizationId: org, spec: { groups: [] } },
  }
  const project = await loadSourceProject(Object.entries(values).map(([path, value]) => { const raw = JSON.stringify(value); return { path, size: raw.length, read: async () => raw } }))
  const state: State = { phase: 'selected', busy: false, pending: null, candidate: null, flow: null, error: null, profiles: [], self: { actorId: actor, sourceProfile: 'bank', sourceProfileDigest: 'sha256:' + 'a'.repeat(64), principalKind: 'human', expiresAt: Math.floor(Date.now() / 1000) + 300, organizations: [{ id: org, slug: 'bank', name: 'Bank', isOrgAdmin: true, isOrgReadonlyAdmin: false }] } }
  const controller = { snapshot: () => state, scopeRevision: 0, ownsScope: (scope: number, who: string) => scope === 0 && who === actor } as Pick<Controller, 'snapshot' | 'scopeRevision' | 'ownsScope'>
  writeMultiMarker(activeMulti({ actorId: actor, sourceProfile: 'bank', provider: 'privado', browserSessionId: '22222222-2222-4222-8222-222222222222' }))
  const memory = new SourceDraftMemory(controller); memory.write(project, 0, actor, true)
  return { memory, project, state }
}
afterEach(() => localStorage.clear())

it('invalidates unfinished fields only for changed source documents and rejects callbacks from their old versions', async () => {
  const { memory, project } = await fixture(), epoch = memory.snapshot().epoch
  const groupEntry = { value: 'unfinished input', base: 'group-node', dirty: true, source: { root: 'source', path: 'groups.json', text: documentText(project, 'source', 'groups.json') } }
  const orgEntry = { value: 'another unfinished field', base: 'org-node', dirty: true, source: { root: 'source', path: 'draft.json', text: documentText(project, 'source', 'draft.json') } }
  memory.writeAuthoring('/groups/form', groupEntry, 0, actor, epoch)
  memory.writeAuthoring('/organizations/form', orgEntry, 0, actor, epoch)
  const updated = updateSourceText(project, 'source', 'groups.json', documentText(project, 'source', 'groups.json') + '\n')
  memory.write(updated, 0, actor)
  expect(memory.snapshot().authoring['/groups/form']).toBeUndefined()
  expect(memory.snapshot().authoring['/organizations/form']?.value).toBe('another unfinished field')
  memory.writeAuthoring('/groups/form', groupEntry, 0, actor, epoch)
  expect(memory.snapshot().authoring['/groups/form']).toBeUndefined()
})

it('retires every old form callback after reimport, even if the source bytes and account are identical', async () => {
  const { memory, project } = await fixture(), epoch = memory.snapshot().epoch
  const entry = { value: 'private unfinished input', base: 'node', dirty: true }
  memory.writeAuthoring('/form', entry, 0, actor, epoch)
  memory.write(project, 0, actor, true)
  memory.writeAuthoring('/form', entry, 0, actor, epoch)
  expect(memory.snapshot().authoring).toEqual({})
  expect(memory.snapshot().unfinished).toBe(false)
  expect(memory.snapshot().dirty).toBe(false)
})

it('clears a same-account draft on loss of console roles and refuses stale write callbacks', async () => {
  const { memory, project, state } = await fixture(), epoch = memory.snapshot().epoch
  memory.writeAuthoring('/form', { value: 'private input', base: 'node', dirty: true }, 0, actor, epoch)
  state.self = { ...state.self!, organizations: state.self!.organizations.map(org => ({ ...org, isOrgAdmin: false })) }
  // A callback captured before downgrade must fail even before observe runs.
  expect(() => memory.write(project, 0, actor)).toThrow()
  memory.observe()
  expect(memory.snapshot().project).toBeNull()
  expect(memory.snapshot().authoring).toEqual({})
  state.self = { ...state.self, organizations: state.self.organizations.map(org => ({ ...org, isOrgAdmin: true })) }
  memory.observe()
  expect(memory.snapshot().project).toBeNull()
  memory.writeAuthoring('/form', { value: 'stale input', base: 'node', dirty: true }, 0, actor, epoch)
  expect(memory.snapshot().authoring).toEqual({})
})
