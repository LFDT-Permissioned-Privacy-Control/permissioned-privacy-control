import { ChangeEvent, useEffect, useRef, useState } from 'react'
import { useLocation, useNavigate } from 'react-router-dom'
import { Building2, FileUp, FolderTree, Search, Settings, Shield, X } from 'lucide-react'
import { Card, CardContent, CardHeader, CardTitle } from '../../components/ui/card'
import { Button } from '../../components/ui/button'
import { Input } from '../../components/ui/input'
import { Badge } from '../../components/ui/badge'
import { Tabs, TabsList, TabsTrigger } from '../../components/ui/tabs'
import { Dialog, DialogContent, DialogHeader, DialogTitle } from '../../components/ui/dialog'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '../../components/ui/select'
import Pagination from '../../components/ui/Pagination'
import { OrganizationTable } from '../../components/rbac/OrganizationTable'
import { GroupCards } from '../../components/rbac/GroupCards'
import { Controller } from './controller'
import { DraftGroup, loadWorkspace, selectedSources, Workspace, WorkspaceError } from './workspace'

interface WorkspacePageProps {
  controller: Controller
  workspace: Workspace | null
  onWorkspace(value: Workspace | null): void
}
const PAGE_SIZE = 50

export function WorkspacePage({ controller, workspace, onWorkspace }: WorkspacePageProps) {
  const location = useLocation(), navigate = useNavigate()
  const picker = useRef<HTMLInputElement>(null), generation = useRef(0)
  const [busy, setBusy] = useState(false), [error, setError] = useState<string | null>(null)
  const [search, setSearch] = useState(''), [offset, setOffset] = useState(0), [inspected, setInspected] = useState<DraftGroup | null>(null)
  const groupsPage = location.pathname.endsWith('/groups')
  const orgID = new URLSearchParams(location.search).get('org') ?? ''
  const selectedOrg = workspace?.organizations.find(org => org.id === orgID) ?? null
  useEffect(() => () => { generation.current++ }, [])
  useEffect(() => { setOffset(0); setSearch(''); setInspected(null) }, [orgID, groupsPage, workspace])

  async function importSource(event: ChangeEvent<HTMLInputElement>) {
    const files = event.currentTarget.files
    if (!files?.length) return
    const selectedFiles = Array.from(files)
    event.currentTarget.value = ''
    const current = ++generation.current, scope = controller.scopeRevision, actor = controller.snapshot().self?.actorId
    const check = () => {
      if (current !== generation.current || !actor || !controller.ownsScope(scope, actor)) throw new Error('Source import context changed')
    }
    setBusy(true); setError(null)
    try {
      const imported = await loadWorkspace(selectedSources(selectedFiles), check); check()
      onWorkspace(imported)
      const first = imported.organizations.length === 1 ? imported.organizations[0].id : ''
      navigate('/admin/rbac/organizations' + (first ? '?org=' + first : ''))
    } catch (e) {
      if (current === generation.current && scope === controller.scopeRevision) setError(e instanceof WorkspaceError ? e.message : 'The source import could not complete. Choose the files again.')
    } finally { if (current === generation.current) setBusy(false) }
  }
  function selectOrg(id: string) { navigate('/admin/rbac/' + (groupsPage ? 'groups' : 'organizations') + '?org=' + id) }
  const groups = [...(selectedOrg?.groups ?? [])].filter(group => !search || `${group.name} ${group.slug}`.toLocaleLowerCase().includes(search.toLocaleLowerCase()))
    .sort((a, b) => a.name.localeCompare(b.name))
  const organizations = (workspace?.organizations ?? []).slice(offset, offset + PAGE_SIZE)

  return <Card className="animate-fade-in" data-testid="rbac-manager">
    <CardHeader className="pb-4">
      <div className="flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-lg bg-primary-50 flex items-center justify-center"><Shield className="w-5 h-5 text-primary" /></div>
          <div><CardTitle className="text-lg" data-testid="rbac-title">Access Control</CardTitle>
            <p className="text-sm text-neutral-500 mt-0.5">Organizations, groups and permissions from your policy source</p></div>
        </div>
        <div className="flex w-full flex-col gap-2 sm:flex-row sm:items-center sm:gap-3 lg:w-auto">
          <span className="text-sm text-neutral-500">Scope:</span>
          <Select value={selectedOrg?.id ?? ''} onValueChange={selectOrg} disabled={!workspace?.organizations.length}>
            <SelectTrigger className="w-full sm:w-[280px]" aria-label="Select organization scope" data-testid="org-selector"><SelectValue placeholder="Select organization" /></SelectTrigger>
            <SelectContent>{workspace?.organizations.map(org => <SelectItem key={org.id} value={org.id}>
              <div className="flex items-center gap-2"><Building2 className="w-4 h-4 text-neutral-400" /><span>{org.name}</span><span className="text-neutral-400 text-xs">({org.slug})</span></div>
            </SelectItem>)}</SelectContent>
          </Select>
        </div>
      </div>
    </CardHeader>
    <CardContent className="pt-0">
      <section className="mb-5 rounded-lg border border-neutral-200 bg-neutral-50 p-4" aria-label="Policy source workspace">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div><div className="text-sm font-medium text-neutral-900">Policy source workspace <Badge variant="outline" className="ml-2">Local draft</Badge></div>
            <p className="text-xs text-neutral-500 mt-1">Import a source folder you are entitled to read. This preview does not apply changes to OPS.</p></div>
          <div className="flex gap-2"><Button variant="outline" size="sm" disabled={busy} onClick={() => picker.current?.click()}><FileUp className="w-4 h-4 mr-2" />{busy ? 'Reading source…' : 'Import source folder'}</Button>
            {workspace && <Button variant="ghost" size="sm" onClick={() => { generation.current++; setBusy(false); setError(null); onWorkspace(null) }}><X className="w-4 h-4 mr-1" />Close source</Button>}</div>
        </div>
        <input ref={picker} type="file" className="sr-only" aria-label="Policy source folder" multiple {...{ webkitdirectory: '' }} onChange={event => void importSource(event)} />
        {workspace && <div className="mt-3 text-xs text-neutral-500 break-words" data-testid="workspace-source">
          <p>Imported revision: <strong className="text-neutral-700">{workspace.sourceRevision}</strong> · Environment: {workspace.environment} · Chain: {workspace.chainId}</p>
          <p className="mt-1">The imported revision is not proof of the live deployment. Only organization/group documents are displayed here; full policy validation still uses the matching Go tool.</p>
        </div>}
        {error && <p role="alert" className="mt-3 text-sm text-error-dark">{error}</p>}
      </section>
      <Tabs value={groupsPage ? 'groups' : 'organizations'} onValueChange={value => navigate('/admin/rbac/' + value + (orgID ? '?org=' + orgID : ''))} data-testid="rbac-tabs">
        <TabsList className="w-full justify-start mb-4 overflow-x-auto">
          <TabsTrigger value="organizations" className="gap-2" data-testid="tab-organizations"><Building2 className="w-4 h-4" />Organizations</TabsTrigger>
          <TabsTrigger value="groups" className="gap-2" data-testid="tab-groups"><FolderTree className="w-4 h-4" />Groups</TabsTrigger>
        </TabsList>
      </Tabs>
      {!workspace ? <div className="text-center py-12"><div className="w-16 h-16 mx-auto mb-4 rounded-full bg-neutral-100 flex items-center justify-center"><Building2 className="w-8 h-8 text-neutral-400" /></div>
        <p className="text-neutral-500">Open your policy source to view organizations and groups</p><p className="text-sm text-neutral-400 mt-2">Choose the folder containing draft.json and its group documents.</p></div>
        : groupsPage ? !selectedOrg ? <div className="text-center py-12"><p className="text-neutral-500">Select an organization from the imported source</p></div>
          : <div className="space-y-4">
            <div><h3 className="text-sm font-medium text-neutral-700">Groups</h3><p className="text-xs text-neutral-500 mt-0.5">Groups define what methods and addresses users can access</p></div>
            <div className="relative max-w-sm"><Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-neutral-400" /><Input className="pl-9" placeholder="Search by name or slug..." value={search} onChange={event => { setSearch(event.target.value); setOffset(0) }} /></div>
            {groups.length ? <GroupCards groups={groups.slice(offset, offset + PAGE_SIZE).map(group => ({ ...group, methodCount: group.allowedMethods.length }))}
              renderActions={id => <Button variant="ghost" size="sm" title="View declared permissions" onClick={() => setInspected(groups.find(group => group.id === id) ?? null)}><Settings className="w-4 h-4" /></Button>} />
              : <p className="text-sm text-neutral-500 py-8 text-center">No groups match this source selection.</p>}
            <Pagination total={groups.length} limit={PAGE_SIZE} offset={offset} onPageChange={setOffset} />
          </div>
          : <div className="space-y-4"><div><h3 className="text-sm font-medium text-neutral-700">Organizations</h3><p className="text-xs text-neutral-500 mt-0.5">Top-level tenants that contain groups and contracts</p></div>
            <OrganizationTable organizations={organizations} onSelect={id => navigate('/admin/rbac/groups?org=' + id)} />
            <Pagination total={workspace.organizations.length} limit={PAGE_SIZE} offset={offset} onPageChange={setOffset} />
          </div>}
      <Dialog open={!!inspected} onOpenChange={open => { if (!open) setInspected(null) }}><DialogContent className="max-w-2xl"><DialogHeader><DialogTitle>{inspected?.name} — declared permissions</DialogTitle></DialogHeader>
        {inspected && <div className="space-y-4 max-h-[65vh] overflow-y-auto"><p className="text-sm text-neutral-500">Read-only source view. Effective permissions also depend on verified identity claims and contract/execution rules.</p>
          {inspected.description && <p className="text-sm">{inspected.description}</p>}
          <div><h4 className="text-sm font-medium mb-2">RPC methods</h4>{inspected.allowedMethods.length ? <div className="flex flex-wrap gap-2">{inspected.allowedMethods.map(method => <Badge key={method} variant="outline" className="font-mono">{method}</Badge>)}</div> : <p className="text-sm text-neutral-500">No RPC methods declared.</p>}</div>
          <div><h4 className="text-sm font-medium mb-2">Claims</h4>{inspected.claims.length ? <div className="flex gap-2">{inspected.claims.map(claim => <Badge key={claim} variant="outline">{claim}</Badge>)}</div> : <p className="text-sm text-neutral-500">No claims declared.</p>}</div>
          {inspected.rpcCredential && <p className="text-xs text-neutral-500">RPC credential reference: <code>{inspected.rpcCredential.fromEnv}</code></p>}
        </div>}
      </DialogContent></Dialog>
    </CardContent>
  </Card>
}
