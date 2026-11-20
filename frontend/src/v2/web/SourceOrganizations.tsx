import { useState, type FormEvent } from 'react'
import { Plus, Pencil, Settings, Trash2, Search, X } from 'lucide-react'
import { OrganizationTable } from '../../components/rbac/OrganizationTable'
import { OrganizationFormView } from '../../components/rbac/OrganizationFormView'
import { GroupCards } from '../../components/rbac/GroupCards'
import { GroupFormView } from '../../components/rbac/GroupFormView'
import { Checkbox } from '../../components/ui/checkbox'
import Pagination from '../../components/ui/Pagination'
import { PermissionCheck, permissionMethodClasses } from '../../components/rbac/PermissionSelectionView'
import { Button } from '../../components/ui/button'
import { Input } from '../../components/ui/input'
import { Dialog, DialogContent, DialogHeader, DialogTitle } from '../../components/ui/dialog'
import { SourceAuthoringScope } from './SourceAuthoringScope'
import { useAuthoringState, useClearAuthoring } from './sourceAuthoring'
import { SourcePermissionChoices } from './SourcePermissions'
import type { DraftGroup } from './workspace'
import { createGroup, createOrganization, documentFor, groupsOf, referenceFiles, removeGroup, removeOrganization, rootOf, updateGroup, updateOrganization, type SourceProject } from './sourceProject'

interface Props { project: SourceProject; root: string; organization: string; groupsPage: boolean; editing: boolean; onChange(value: SourceProject): void; onOrganization(id: string, groups?: boolean): void }
type Modal = { kind: 'org'; id?: string } | { kind: 'group'; id?: string } | { kind: 'access'; id: string } | { kind: 'inspect'; group: DraftGroup } | { kind: 'delete-groups'; ids: string[] } | { kind: 'delete-org' | 'delete-group'; id: string }
export function SourceOrganizations({ project, root, organization, groupsPage, editing, onChange, onOrganization }: Props) {
  const selected = rootOf(project, root), org = selected.draft.organizations.find(o => o.id === organization)
  const clear = useClearAuthoring()
  const [pendingModal, setModal] = useAuthoringState<Exclude<Modal, { kind: 'inspect' }> | null>('modal', null), [search, setSearch] = useAuthoringState('search', ''), [pageOffset, setPageOffset] = useAuthoringState('page-offset', 0), [selectedGroupIDs, setSelectedGroupIDs] = useAuthoringState<string[]>('selected-groups', []), [error, setError] = useState<string | null>(null)
  const [inspection, setInspection] = useState<Extract<Modal, { kind: 'inspect' }> | null>(null)
  const modal = inspection ?? (editing ? pendingModal : null)
  const allGroups = org ? groupsOf(project, root, org.id) : []
  const groups = allGroups.filter(g => !search || `${g.name} ${g.slug}`.toLowerCase().includes(search.toLowerCase()))
  const pageSize = groupsPage ? 50 : 25, total = groupsPage ? groups.length : selected.draft.organizations.length
  const offset = Math.min(pageOffset, Math.max(0, Math.floor((total - 1) / pageSize) * pageSize))
  const pageGroups = groups.slice(offset, offset + pageSize)
  const selectedIDs = new Set(selectedGroupIDs.filter(id => allGroups.some(group => group.id === id)))
  const selectedOnPage = pageGroups.filter(group => selectedIDs.has(group.id)).length
  const toggleGroup = (id: string) => setSelectedGroupIDs(selectedIDs.has(id) ? [...selectedIDs].filter(value => value !== id) : [...selectedIDs, id])
  const searchGroups = (value: string) => { setSearch(value); setPageOffset(0); setSelectedGroupIDs([]) }
  const close = () => { if (inspection) setInspection(null); else { clear('form'); setModal(null) } setError(null) }
  function remove() {
    try {
      if (modal?.kind === 'delete-org') { onChange(removeOrganization(project, root, modal.id)); onOrganization('') }
      if (modal?.kind === 'delete-group') onChange(removeGroup(project, root, organization, modal.id))
      if (modal?.kind === 'delete-groups') { onChange(modal.ids.reduce((next, id) => removeGroup(next, root, organization, id), project)); setSelectedGroupIDs([]) }
      close()
    } catch (e) { setError(e instanceof Error ? e.message : 'Could not update this draft.') }
  }
  const deleting = modal?.kind === 'delete-org' || modal?.kind === 'delete-group' || modal?.kind === 'delete-groups'
  const dependencies = deleting ? [...new Set((modal.kind === 'delete-groups' ? modal.ids : [modal.id]).flatMap(id => referenceFiles(project, root, id, modal.kind !== 'delete-org' && org ? documentFor(selected, org.id, 'groups') : 'draft.json')))] : []
  return <div className="space-y-4">
    <div className="flex flex-wrap items-start justify-between gap-3"><div><h3 className="text-sm font-medium text-neutral-700">{groupsPage ? 'Groups' : 'Organizations'}</h3><p className="text-xs text-neutral-500 mt-0.5">{groupsPage ? 'Groups define methods, operational claims and organization administration.' : 'Top-level tenants that contain groups, contracts and execution rules.'}</p></div>
      {editing && <Button size="sm" disabled={groupsPage && !org} onClick={() => setModal({ kind: groupsPage ? 'group' : 'org' })}><Plus className="w-4 h-4 mr-2" />{groupsPage ? 'New group' : 'New organization'}</Button>}
    </div>
    {groupsPage ? !org ? <p className="py-12 text-center text-neutral-500">Select an organization from the imported source</p>
      : <><div className="flex items-center gap-3"><div className="relative flex-1 max-w-sm"><Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-neutral-400" /><Input aria-label="Search groups" placeholder="Search by name or slug..." className="pl-9" value={search} onChange={e => searchGroups(e.target.value)} /></div>{search && <Button variant="ghost" size="sm" onClick={() => searchGroups('')}><X className="h-4 w-4 mr-1" />Clear search</Button>}</div>
        {editing && selectedIDs.size > 0 && <div data-testid="selection-toolbar" className="flex flex-wrap items-center gap-3 rounded-lg border border-error/20 bg-error-light px-4 py-2"><span className="text-sm font-medium text-error-dark">{selectedIDs.size} selected</span><Button size="sm" variant="destructive" onClick={() => setModal({ kind: 'delete-groups', ids: [...selectedIDs] })}>Remove selected from draft</Button><Button variant="ghost" size="sm" onClick={() => setSelectedGroupIDs([])}>Clear selection</Button></div>}
        {editing && pageGroups.length > 0 && <div className="flex items-center gap-3 border-b border-neutral-200 px-3 py-2"><Checkbox aria-label="Select all groups on this page" checked={selectedOnPage === pageGroups.length ? true : selectedOnPage ? 'indeterminate' : false} onCheckedChange={checked => setSelectedGroupIDs(checked ? [...new Set([...selectedIDs, ...pageGroups.map(group => group.id)])] : [...selectedIDs].filter(id => !pageGroups.some(group => group.id === id)))} /><span className="text-xs text-neutral-500">{selectedOnPage ? `${selectedOnPage} of ${pageGroups.length} on this page selected` : 'Select all on this page'}</span></div>}
        {groups.length ? <GroupCards selectedIds={selectedIDs} onToggle={editing ? toggleGroup : undefined} groups={pageGroups.map(g => ({ ...g, methodCount: g.allowedMethods.length }))} renderActions={id => <>
          <Button variant="ghost" size="sm" title={editing ? 'Edit access settings' : 'View declared permissions'} onClick={() => editing ? setModal({ kind: 'access', id }) : setInspection({ kind: 'inspect', group: allGroups.find(g => g.id === id)! })}><Settings className="w-4 h-4" /></Button>
          {editing && <><Button variant="ghost" size="sm" title="Edit group draft" onClick={() => setModal({ kind: 'group', id })}><Pencil className="w-4 h-4" /></Button><Button variant="ghost" size="sm" title="Remove group from draft" onClick={() => setModal({ kind: 'delete-group', id })}><Trash2 className="w-4 h-4" /></Button></>}
        </>} /> : <p className="py-8 text-center text-neutral-500">No groups match this source selection.</p>}</>
      : <><OrganizationTable organizations={selected.draft.organizations.slice(offset, offset + pageSize)} showCreated={false} onSelect={id => onOrganization(id, true)} canEdit={() => editing} onEdit={id => setModal({ kind: 'org', id })} />
        {editing && org && <Button variant="outline" size="sm" onClick={() => setModal({ kind: 'delete-org', id: org.id })}><Trash2 className="w-4 h-4 mr-2" />Remove selected organization from draft</Button>}</>}
    <Pagination total={total} limit={pageSize} offset={offset} onPageChange={setPageOffset} />
    <Dialog open={!!modal} onOpenChange={open => { if (!open) close() }}><DialogContent className="max-w-3xl max-h-[85vh] overflow-y-auto"><DialogHeader><DialogTitle>
      {modal?.kind === 'org' ? `${modal.id ? 'Edit' : 'New'} organization draft` : modal?.kind === 'group' ? `${modal.id ? 'Edit' : 'New'} group draft` : modal?.kind === 'access' ? 'Edit access settings draft' : modal?.kind === 'inspect' ? `${modal.group.name} — declared permissions` : 'Remove from local draft'}
    </DialogTitle></DialogHeader>
      {modal?.kind === 'org' && <SourceAuthoringScope id="form"><SourceAuthoringScope id={'org:' + (modal.id ?? 'new')}><OrganizationDraftForm key={modal.id ?? 'new'} value={selected.draft.organizations.find(o => o.id === modal.id)} onClose={close} onSave={value => {
        const next = modal.id ? updateOrganization(project, root, modal.id, value) : createOrganization(project, root, { ...value, id: crypto.randomUUID() })
        onChange(next); close()
      }} /></SourceAuthoringScope></SourceAuthoringScope>}
      {modal?.kind === 'group' && org && <SourceAuthoringScope id="form"><SourceAuthoringScope id={'group:' + (modal.id ?? 'new')}><GroupDraftForm key={modal.id ?? 'new'} siblings={allGroups} value={allGroups.find(g => g.id === modal.id)} onClose={close} onSave={value => {
        let next = project, id = modal.id
        if (!id) { id = crypto.randomUUID(); next = createGroup(next, root, org.id, { id, name: value.name, slug: value.slug }) }
        onChange(updateGroup(next, root, org.id, id, value)); close()
      }} /></SourceAuthoringScope></SourceAuthoringScope>}
      {modal?.kind === 'access' && org && <SourceAuthoringScope id="form"><SourceAuthoringScope id={'access:' + modal.id}><GroupAccessDraftForm value={allGroups.find(group => group.id === modal.id)!} onClose={close} onSave={value => { onChange(updateGroup(project, root, org.id, modal.id, value)); close() }} /></SourceAuthoringScope></SourceAuthoringScope>}
      {modal?.kind === 'inspect' && <div className="space-y-4"><p className="text-sm text-neutral-500">Declared source permissions; effective access also depends on verified current claims and contract/execution rules.</p><p>{modal.group.description}</p>
        <SourcePermissionChoices methods={modal.group.allowedMethods} claims={modal.group.claims} isAdmin={modal.group.isOrgAdmin} /><div className="flex justify-end"><Button variant="outline" onClick={close}>Close</Button></div>
      </div>}
      {deleting && <div className="space-y-4"><p className="text-sm">This removes only the selected organization/group{modal?.kind === 'delete-groups' ? 's (' + modal.ids.length + ')' : ''} and its own documents. Other policy references are preserved for review.</p>
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
function GroupDraftForm({ value, siblings, onSave, onClose }: { value?: DraftGroup; siblings: DraftGroup[]; onSave(v: Pick<DraftGroup, 'name' | 'slug' | 'description' | 'isOrgAdmin' | 'isOrgReadonlyAdmin' | 'claims'>): void; onClose(): void }) {
  const [name, setName] = useAuthoringState('name', value?.name ?? '', { draft: true, base: value }), [slug, setSlug] = useAuthoringState('slug', value?.slug ?? '', { draft: true, base: value }), [description, setDescription] = useAuthoringState('description', value?.description ?? '', { draft: true, base: value })
  const [role, setRole] = useAuthoringState('role', value?.isOrgAdmin ? 'admin' : value?.isOrgReadonlyAdmin ? 'readonly' : 'member', { draft: true, base: value }), [error, setError] = useState<string | null>(null)
  const nameConflict = siblings.some(group => group.id !== value?.id && group.name.toLowerCase() === name.trim().toLowerCase()), slugConflict = !value && siblings.some(group => group.slug.toLowerCase() === slug.trim().toLowerCase())
  return <GroupFormView name={name} slug={slug} description={description} saving={false} error={error} isEditing={!!value} isOrgAdminGroup={role === 'admin'} isOrgReadonlyAdmin={role === 'readonly'} nameConflict={nameConflict} slugConflict={slugConflict} trimmedName={name.trim()}
    onNameChange={next => { setName(next); if (!value) setSlug(next.toLowerCase().replace(/[^a-z0-9]+/g, '_').replace(/^_|_$/g, '')) }} onSlugChange={setSlug} onDescriptionChange={setDescription} onReadonlyChange={readonly => setRole(readonly ? 'readonly' : 'member')} onClose={onClose} submitLabel="Save group draft" slugPattern="[a-z0-9]+([_-][a-z0-9]+)*" slugHelp="Lowercase letters, numbers, underscores or hyphens"
    roleControl={<fieldset className="space-y-2" aria-label="Organization role"><legend className="text-sm font-medium">Organization role</legend>{[['member', 'Member', 'Permissions come from the group’s explicit access settings.'], ['readonly', 'Read-only organization admin', 'Can inspect the organization’s admin pages and audit records.'], ['admin', 'Organization admin', 'Full organization administration and implicit execution claims. RPC methods still need configuration.']].map(([id, label, help]) => <label key={id} className={`flex items-start gap-3 rounded-lg border p-3 cursor-pointer transition-colors focus-within:ring-2 focus-within:ring-primary/40 ${role === id ? 'border-primary-200 bg-primary-50' : 'border-neutral-200 bg-white hover:bg-neutral-50'}`}><input className="sr-only" aria-label={label} type="radio" name="source-group-role" value={id} checked={role === id} onChange={() => setRole(id)} /><PermissionCheck checked={role === id} /><span><span className="text-sm font-medium text-neutral-900">{label}</span><span className="mt-1 block text-xs text-neutral-500">{help}</span></span></label>)}</fieldset>}
    onSubmit={event => { event.preventDefault(); try { if (nameConflict || slugConflict) throw Error('Choose a unique group name and slug.'); onSave({ name: name.trim(), slug: slug.trim(), description, isOrgAdmin: role === 'admin', isOrgReadonlyAdmin: role === 'readonly', claims: role === 'admin' ? [] : value?.claims ?? [] }) } catch (e) { setError(e instanceof Error ? e.message : 'Could not save this group draft.') } }} />
}

function GroupAccessDraftForm({ value, onSave, onClose }: { value: DraftGroup; onSave(v: Pick<DraftGroup, 'allowedMethods' | 'claims' | 'verboseErrors' | 'rpcCredential'>): void; onClose(): void }) {
  const [methods, setMethods] = useAuthoringState<string[]>('methods', value?.allowedMethods ?? [], { draft: true, base: value }), [extra, setExtra] = useAuthoringState('extra-methods', '', { draft: true, base: value }), [claims, setClaims] = useAuthoringState<string[]>('claims', value?.claims ?? [], { draft: true, base: value })
  const [verboseErrors, setVerbose] = useAuthoringState('verbose', value?.verboseErrors ?? false, { draft: true, base: value }), [credential, setCredential] = useAuthoringState('credential-reference', value?.rpcCredential?.fromEnv ?? '', { draft: true, base: value }), [error, setError] = useState<string | null>(null)
  function submit(event: FormEvent) {
    event.preventDefault()
    try {
      const additional = extra.split(/[\s,]+/).filter(Boolean)
      if (additional.some(m => !/^[a-zA-Z][a-zA-Z0-9]*_[a-zA-Z][a-zA-Z0-9_]*$/.test(m))) throw Error('Additional methods must be exact method names, without wildcards.')
      const allowedMethods = [...new Set([...methods, ...additional])].sort()
      if (credential && !/^[A-Z][A-Z0-9_]*$/.test(credential)) throw Error('Use an environment variable reference, never a credential value.')
      onSave({ allowedMethods, claims: value.isOrgAdmin ? [] : claims, verboseErrors,
        rpcCredential: credential ? { ...value?.rpcCredential, fromEnv: credential } : undefined })
    } catch (e) { setError(e instanceof Error ? e.message : 'Could not update this draft.') }
  }
  return <form onSubmit={submit} className="space-y-5">
    {error && <p role="alert" className="rounded-lg bg-error-light p-3 text-error-dark">{error}</p>}
    <SourcePermissionChoices methods={methods} claims={claims} isAdmin={value.isOrgAdmin} onMethods={setMethods} onClaims={setClaims} pendingAdditionalMethods={!!extra.trim()} />
    <label className="block text-sm">Additional exact method names<Input aria-label="Additional method names" value={extra} onChange={e => setExtra(e.target.value)} placeholder="Exact names, separated by spaces" /><span className="text-xs text-neutral-500">Explicit names only; source validation and runtime configuration decide support.</span></label>
    <label className="block text-sm font-medium">RPC credential environment reference<Input value={credential} onChange={e => setCredential(e.target.value)} placeholder="BANK_RPC_TOKEN" /><span className="text-xs font-normal text-neutral-500">Optional reference only. The operator must bind it to this organization's configured node.</span></label>
    <label className={permissionMethodClasses()}><input className="sr-only" aria-label="Verbose error policy" type="checkbox" checked={verboseErrors} onChange={e => setVerbose(e.target.checked)} /><PermissionCheck checked={verboseErrors} /><span className="text-sm text-neutral-700">Verbose error policy</span></label>
    <div className="flex justify-end gap-2"><Button type="button" variant="ghost" onClick={onClose}>Cancel</Button><Button type="submit">Save access draft</Button></div>
  </form>
}
