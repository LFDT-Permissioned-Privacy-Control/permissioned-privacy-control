import { useState, type FormEvent } from 'react'
import { Plus, Pencil, Settings, Trash2 } from 'lucide-react'
import { OrganizationTable } from '../../components/rbac/OrganizationTable'
import { OrganizationFormView } from '../../components/rbac/OrganizationFormView'
import { GroupCards } from '../../components/rbac/GroupCards'
import { Button } from '../../components/ui/button'
import { Input } from '../../components/ui/input'
import { Textarea } from '../../components/ui/textarea'
import { Badge } from '../../components/ui/badge'
import { Dialog, DialogContent, DialogHeader, DialogTitle } from '../../components/ui/dialog'
import { SourceAuthoringScope } from './SourceAuthoringScope'
import { useAuthoringState, useClearAuthoring } from './sourceAuthoring'
import { METHOD_SECTIONS } from '../../types/rbac'
import type { DraftGroup } from './workspace'
import { createGroup, createOrganization, documentFor, groupsOf, referenceFiles, removeGroup, removeOrganization, rootOf, updateGroup, updateOrganization, type SourceProject } from './sourceProject'

interface Props { project: SourceProject; root: string; organization: string; groupsPage: boolean; editing: boolean; onChange(value: SourceProject): void; onOrganization(id: string, groups?: boolean): void }
type Modal = { kind: 'org'; id?: string } | { kind: 'group'; id?: string } | { kind: 'inspect'; group: DraftGroup } | { kind: 'delete-org' | 'delete-group'; id: string }
export function SourceOrganizations({ project, root, organization, groupsPage, editing, onChange, onOrganization }: Props) {
  const selected = rootOf(project, root), org = selected.draft.organizations.find(o => o.id === organization)
  const clear = useClearAuthoring()
  const [pendingModal, setModal] = useAuthoringState<Exclude<Modal, { kind: 'inspect' }> | null>('modal', null), [search, setSearch] = useAuthoringState('search', ''), [error, setError] = useState<string | null>(null)
  const [inspection, setInspection] = useState<Extract<Modal, { kind: 'inspect' }> | null>(null)
  const modal = inspection ?? (editing ? pendingModal : null)
  const groups = org ? groupsOf(project, root, org.id).filter(g => !search || `${g.name} ${g.slug}`.toLowerCase().includes(search.toLowerCase())) : []
  const close = () => { if (inspection) setInspection(null); else { clear('form'); setModal(null) } setError(null) }
  function remove() {
    try {
      if (modal?.kind === 'delete-org') { onChange(removeOrganization(project, root, modal.id)); onOrganization('') }
      if (modal?.kind === 'delete-group') onChange(removeGroup(project, root, organization, modal.id))
      close()
    } catch (e) { setError(e instanceof Error ? e.message : 'Could not update this draft.') }
  }
  const deleting = modal?.kind === 'delete-org' || modal?.kind === 'delete-group'
  const dependencies = deleting ? referenceFiles(project, root, modal.id, modal.kind === 'delete-group' && org ? documentFor(selected, org.id, 'groups') : 'draft.json') : []
  return <div className="space-y-4">
    <div className="flex flex-wrap items-start justify-between gap-3"><div><h3 className="text-sm font-medium text-neutral-700">{groupsPage ? 'Groups' : 'Organizations'}</h3><p className="text-xs text-neutral-500 mt-0.5">{groupsPage ? 'Groups define methods, operational claims and organization administration.' : 'Top-level tenants that contain groups, contracts and execution rules.'}</p></div>
      {editing && <Button size="sm" disabled={groupsPage && !org} onClick={() => setModal({ kind: groupsPage ? 'group' : 'org' })}><Plus className="w-4 h-4 mr-2" />{groupsPage ? 'New group' : 'New organization'}</Button>}
    </div>
    {groupsPage ? !org ? <p className="py-12 text-center text-neutral-500">Select an organization from the imported source</p>
      : <><Input aria-label="Search groups" placeholder="Search by name or slug..." className="max-w-sm" value={search} onChange={e => setSearch(e.target.value)} />
        {groups.length ? <GroupCards groups={groups.map(g => ({ ...g, methodCount: g.allowedMethods.length }))} renderActions={id => <>
          <Button variant="ghost" size="sm" title="View declared permissions" onClick={() => setInspection({ kind: 'inspect', group: groups.find(g => g.id === id)! })}><Settings className="w-4 h-4" /></Button>
          {editing && <><Button variant="ghost" size="sm" title="Edit group draft" onClick={() => setModal({ kind: 'group', id })}><Pencil className="w-4 h-4" /></Button><Button variant="ghost" size="sm" title="Remove group from draft" onClick={() => setModal({ kind: 'delete-group', id })}><Trash2 className="w-4 h-4" /></Button></>}
        </>} /> : <p className="py-8 text-center text-neutral-500">No groups match this source selection.</p>}</>
      : <><OrganizationTable organizations={selected.draft.organizations} onSelect={id => onOrganization(id, true)} canEdit={() => editing} onEdit={id => setModal({ kind: 'org', id })} />
        {editing && org && <Button variant="outline" size="sm" onClick={() => setModal({ kind: 'delete-org', id: org.id })}><Trash2 className="w-4 h-4 mr-2" />Remove selected organization from draft</Button>}</>}
    <Dialog open={!!modal} onOpenChange={open => { if (!open) close() }}><DialogContent className="max-w-3xl max-h-[85vh] overflow-y-auto"><DialogHeader><DialogTitle>
      {modal?.kind === 'org' ? `${modal.id ? 'Edit' : 'New'} organization draft` : modal?.kind === 'group' ? `${modal.id ? 'Edit' : 'New'} group draft` : modal?.kind === 'inspect' ? `${modal.group.name} — declared permissions` : 'Remove from local draft'}
    </DialogTitle></DialogHeader>
      {modal?.kind === 'org' && <SourceAuthoringScope id="form"><SourceAuthoringScope id={'org:' + (modal.id ?? 'new')}><OrganizationDraftForm key={modal.id ?? 'new'} value={selected.draft.organizations.find(o => o.id === modal.id)} onClose={close} onSave={value => {
        const next = modal.id ? updateOrganization(project, root, modal.id, value) : createOrganization(project, root, { ...value, id: crypto.randomUUID() })
        onChange(next); close()
      }} /></SourceAuthoringScope></SourceAuthoringScope>}
      {modal?.kind === 'group' && org && <SourceAuthoringScope id="form"><SourceAuthoringScope id={'group:' + (modal.id ?? 'new')}><GroupDraftForm key={modal.id ?? 'new'} value={groupsOf(project, root, org.id).find(g => g.id === modal.id)} onClose={close} onSave={value => {
        let next = project, id = modal.id
        if (!id) { id = crypto.randomUUID(); next = createGroup(next, root, org.id, { id, name: value.name, slug: value.slug }) }
        onChange(updateGroup(next, root, org.id, id, value)); close()
      }} /></SourceAuthoringScope></SourceAuthoringScope>}
      {modal?.kind === 'inspect' && <div className="space-y-4"><p className="text-sm text-neutral-500">Declared source permissions; effective access also depends on verified current claims and contract/execution rules.</p><p>{modal.group.description}</p>
        <div><h4 className="text-sm font-medium mb-2">RPC methods</h4><div className="flex flex-wrap gap-2">{modal.group.allowedMethods.map(m => <Badge key={m} variant="outline" className="font-mono">{m}</Badge>)}</div></div>
        <div><h4 className="text-sm font-medium mb-2">Claims</h4><div className="flex flex-wrap gap-2">{modal.group.claims.map(c => <Badge key={c} variant="outline">{c}</Badge>)}</div></div>
      </div>}
      {deleting && <div className="space-y-4"><p className="text-sm">This removes only the selected organization/group and its own documents. Other policy references are preserved for review.</p>
        {!!dependencies.length && <div className="rounded-lg bg-warning-light p-3 text-sm text-warning-dark"><p>Review these files for dependent references:</p><ul className="list-disc ml-5">{dependencies.map(p => <li key={p}>{p}</li>)}</ul><p className="mt-2">The Go checker will reject any unresolved references.</p></div>}
        {error && <p role="alert" className="text-error-dark">{error}</p>}<div className="flex justify-end gap-2"><Button variant="ghost" onClick={close}>Cancel</Button><Button variant="destructive" onClick={remove}>Remove from draft</Button></div>
      </div>}
    </DialogContent></Dialog>
  </div>
}

function OrganizationDraftForm({ value, onSave, onClose }: { value?: { name: string; slug: string }; onSave(v: { name: string; slug: string }): void; onClose(): void }) {
  const [name, setName] = useAuthoringState('name', value?.name ?? '', { draft: true, base: value }), [slug, setSlug] = useAuthoringState('slug', value?.slug ?? '', { draft: true, base: value }), [error, setError] = useState<string | null>(null)
  return <OrganizationFormView name={name} slug={slug} editing={!!value} busy={false} error={error} onClose={onClose}
    onNameChange={v => { setName(v); if (!value) setSlug(v.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '')) }} onSlugChange={setSlug} submitLabel="Save organization draft"
    onSubmit={event => { event.preventDefault(); try { onSave({ name: name.trim(), slug: slug.trim() }) } catch (e) { setError(e instanceof Error ? e.message : 'Could not update this draft.') } }} />
}
function GroupDraftForm({ value, onSave, onClose }: { value?: DraftGroup; onSave(v: Omit<DraftGroup, 'id'>): void; onClose(): void }) {
  const [name, setName] = useAuthoringState('name', value?.name ?? '', { draft: true, base: value }), [slug, setSlug] = useAuthoringState('slug', value?.slug ?? '', { draft: true, base: value }), [description, setDescription] = useAuthoringState('description', value?.description ?? '', { draft: true, base: value })
  const [role, setRole] = useAuthoringState('role', value?.isOrgAdmin ? 'admin' : value?.isOrgReadonlyAdmin ? 'readonly' : 'member', { draft: true, base: value })
  const [methods, setMethods] = useAuthoringState<string[]>('methods', value?.allowedMethods ?? [], { draft: true, base: value }), [extra, setExtra] = useAuthoringState('extra-methods', '', { draft: true, base: value }), [claims, setClaims] = useAuthoringState<string[]>('claims', value?.claims ?? [], { draft: true, base: value })
  const [verboseErrors, setVerbose] = useAuthoringState('verbose', value?.verboseErrors ?? false, { draft: true, base: value }), [credential, setCredential] = useAuthoringState('credential-reference', value?.rpcCredential?.fromEnv ?? '', { draft: true, base: value }), [error, setError] = useState<string | null>(null)
  const toggle = (items: string[], item: string) => items.includes(item) ? items.filter(i => i !== item) : [...items, item]
  function submit(event: FormEvent) {
    event.preventDefault()
    try {
      const allowedMethods = [...new Set([...methods, ...extra.split(/[\s,]+/).filter(Boolean)])].sort()
      if (credential && !/^[A-Z][A-Z0-9_]*$/.test(credential)) throw Error('Use an environment variable reference, never a credential value.')
      onSave({ name: name.trim(), slug: slug.trim(), description, isOrgAdmin: role === 'admin', isOrgReadonlyAdmin: role === 'readonly', allowedMethods, claims: role === 'admin' ? [] : claims, verboseErrors,
        rpcCredential: credential ? { fromEnv: credential } : undefined })
    } catch (e) { setError(e instanceof Error ? e.message : 'Could not update this draft.') }
  }
  return <form onSubmit={submit} className="space-y-5">
    {error && <p role="alert" className="rounded-lg bg-error-light p-3 text-error-dark">{error}</p>}
    <label className="block text-sm font-medium">Name<Input required value={name} onChange={e => { setName(e.target.value); if (!value) setSlug(e.target.value.toLowerCase().replace(/[^a-z0-9]+/g, '_').replace(/^_|_$/g, '')) }} /></label>
    <label className="block text-sm font-medium">Slug<Input required value={slug} onChange={e => setSlug(e.target.value)} pattern="[a-z0-9]+([_-][a-z0-9]+)*" /></label>
    <label className="block text-sm font-medium">Description<Textarea value={description} onChange={e => setDescription(e.target.value)} /></label>
    <label className="block text-sm font-medium">Organization role<select className="mt-1 block w-full rounded-lg border border-neutral-300 p-2" value={role} onChange={e => setRole(e.target.value)}><option value="member">Member</option><option value="admin">Organization admin</option><option value="readonly">Read-only organization admin</option></select></label>
    <fieldset className="space-y-2"><legend className="text-sm font-medium">Execution claims</legend>{role === 'admin' ? <p className="text-xs text-neutral-500">Organization admin groups have no execution claim flags. Their RPC methods remain explicit below.</p> : ['admin', 'deploy', 'upgrade'].map(c => <label key={c} className="inline-flex gap-2 mr-5 text-sm"><input type="checkbox" checked={claims.includes(c)} onChange={() => setClaims(toggle(claims, c))} />{c}</label>)}</fieldset>
    <fieldset className="space-y-3"><legend className="text-sm font-medium">RPC methods</legend>{Object.entries(METHOD_SECTIONS).map(([section, data]) => <details key={section} open><summary className="text-sm font-medium">{section}</summary><div className="grid gap-2 mt-2 sm:grid-cols-2">{data.methods.map(m => <label key={m} className="inline-flex items-center gap-2 text-xs"><input type="checkbox" checked={methods.includes(m)} onChange={() => setMethods(toggle(methods, m))} /><code>{m}</code></label>)}</div></details>)}
      <label className="block text-sm">Additional method names<Input value={extra} onChange={e => setExtra(e.target.value)} placeholder="Exact names, separated by spaces" /></label><p className="text-xs text-neutral-500">Existing additional names are preserved. The matching Go tool checks the complete method catalog and the deployed runtime checks supported operations.</p>
      {!!methods.filter(m => !Object.values(METHOD_SECTIONS).some(s => (s.methods as readonly string[]).includes(m))).length && <div className="flex flex-wrap gap-2">{methods.filter(m => !Object.values(METHOD_SECTIONS).some(s => (s.methods as readonly string[]).includes(m))).map(m => <Button key={m} type="button" variant="outline" size="sm" onClick={() => setMethods(methods.filter(v => v !== m))}>{m} ×</Button>)}</div>}
    </fieldset>
    <label className="block text-sm font-medium">RPC credential environment reference<Input value={credential} onChange={e => setCredential(e.target.value)} placeholder="BANK_RPC_TOKEN" /><span className="text-xs font-normal text-neutral-500">Optional reference only. The operator must bind it to this organization's configured node.</span></label>
    <label className="inline-flex gap-2 text-sm"><input type="checkbox" checked={verboseErrors} onChange={e => setVerbose(e.target.checked)} />Verbose error policy</label>
    <div className="flex justify-end gap-2"><Button type="button" variant="ghost" onClick={onClose}>Cancel</Button><Button type="submit">Save group draft</Button></div>
  </form>
}
