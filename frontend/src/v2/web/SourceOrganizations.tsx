import { useEffect, useState } from 'react'
import { Settings, Search, X } from 'lucide-react'
import { OrganizationTable } from '../../components/rbac/OrganizationTable'
import { GroupCards } from '../../components/rbac/GroupCards'
import Pagination from '../../components/ui/Pagination'
import { Button } from '../../components/ui/button'
import { Input } from '../../components/ui/input'
import { Dialog, DialogContent, DialogHeader, DialogTitle } from '../../components/ui/dialog'
import { SourceViewScope, useSourceViewState } from './sourceViewState'
import { SourcePermissionChoices } from './SourcePermissions'
import type { MethodCatalogState } from './methodCatalog'
import { groupsOf, rootOf, type SourceProject } from './sourceProject'

interface Props { catalog?: MethodCatalogState; project: SourceProject; root: string; organization: string; groupsPage: boolean; onOrganization(id: string, groups?: boolean): void }
export function SourceOrganizations(props: Props) {
  const scope = `organizations:${props.root}:${props.organization}:${props.groupsPage}`
  return <SourceViewScope key={scope} id={scope}><OrganizationsContent {...props} /></SourceViewScope>
}
function OrganizationsContent({ project, root, organization, groupsPage, onOrganization, catalog }: Props) {
  const selected = rootOf(project, root), org = selected.draft.organizations.find(o => o.id === organization)
  const [search, setSearch] = useSourceViewState('search', ''), [pageOffset, setPageOffset] = useSourceViewState('page-offset', 0)
  const [inspectedID, setInspectedID] = useState<string | null>(null)
  const allGroups = org ? groupsOf(project, root, org.id) : []
  const inspected = allGroups.find(group => group.id === inspectedID)
  useEffect(() => { if (inspectedID !== null && !inspected) setInspectedID(null) }, [inspectedID, inspected])
  const groups = allGroups.filter(g => !search || `${g.name} ${g.slug}`.toLowerCase().includes(search.toLowerCase()))
  const pageSize = groupsPage ? 50 : 25, total = groupsPage ? groups.length : selected.draft.organizations.length
  const offset = Math.min(pageOffset, Math.max(0, Math.floor((total - 1) / pageSize) * pageSize))
  const searchGroups = (value: string) => { setSearch(value); setPageOffset(0) }
  return <div className="space-y-4">
    <div><h3 className="text-sm font-medium text-neutral-700">{groupsPage ? 'Groups' : 'Organizations'}</h3><p className="text-xs text-neutral-500 mt-0.5">{groupsPage ? 'Groups define methods, operational claims and organization administration.' : 'Top-level tenants that contain groups, contracts and execution rules.'}</p></div>
    {groupsPage && <p className="text-xs text-neutral-500">Membership comes from verified external claims. Identity → Claim mappings shows which claims grant these groups.</p>}
    {groupsPage ? !org ? <p className="py-12 text-center text-neutral-500">Select an organization from this configuration</p>
      : <><div className="flex items-center gap-3"><div className="relative flex-1 max-w-sm"><Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-neutral-400" /><Input aria-label="Search groups" placeholder="Search by name or slug..." className="pl-9" value={search} onChange={e => searchGroups(e.target.value)} /></div>{search && <Button variant="ghost" size="sm" onClick={() => searchGroups('')}><X className="h-4 w-4 mr-1" />Clear search</Button>}</div>
        {groups.length ? <GroupCards groups={groups.slice(offset, offset + pageSize).map(g => ({ ...g, methodCount: g.allowedMethods.length }))} renderActions={id => <Button variant="ghost" size="sm" title="View declared permissions" aria-label={`View permissions for ${allGroups.find(g => g.id === id)?.name ?? id}`} onClick={() => setInspectedID(id)}><Settings className="w-4 h-4" /></Button>} /> : <p className="py-8 text-center text-neutral-500">No groups match this configuration.</p>}</>
      : <OrganizationTable organizations={selected.draft.organizations.slice(offset, offset + pageSize)} showCreated={false} onSelect={id => onOrganization(id, true)} />}
    <Pagination total={total} limit={pageSize} offset={offset} onPageChange={setPageOffset} />
    <Dialog open={!!inspected} onOpenChange={open => { if (!open) setInspectedID(null) }}><DialogContent className="max-w-3xl max-h-[85vh] overflow-y-auto"><DialogHeader><DialogTitle>{inspected?.name} — declared permissions</DialogTitle></DialogHeader>
      {inspected && <div className="space-y-4"><p className="text-sm text-neutral-500">Declared configuration permissions; effective access also depends on verified current claims and contract/execution rules.</p><p>{inspected.description}</p>
        <SourcePermissionChoices catalog={catalog} methods={inspected.allowedMethods} claims={inspected.claims} isAdmin={inspected.isOrgAdmin} />
        <dl className="rounded-lg border border-neutral-200 p-3 text-sm space-y-2"><div><dt className="font-medium">Verbose errors</dt><dd>{inspected.verboseErrors ? 'Enabled' : 'Disabled'}</dd></div>{inspected.rpcCredential?.fromEnv && <div><dt className="font-medium">RPC credential environment reference</dt><dd className="font-mono break-all">{inspected.rpcCredential.fromEnv}</dd></div>}</dl>
        <div className="flex justify-end"><Button variant="outline" onClick={() => setInspectedID(null)}>Close</Button></div>
      </div>}
    </DialogContent></Dialog>
  </div>
}
