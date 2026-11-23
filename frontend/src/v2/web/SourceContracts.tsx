import { useEffect, useState, type ReactNode } from 'react'
import { Link, useInRouterContext } from 'react-router-dom'
import { Eye, FileCode2, Info, Search, Shield } from 'lucide-react'
import { Button } from '../../components/ui/button'
import { Input } from '../../components/ui/input'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '../../components/ui/table'
import Pagination from '../../components/ui/Pagination'
import { Dialog, DialogContent, DialogHeader, DialogTitle } from '../../components/ui/dialog'
import { ContractAddress, ContractEmpty, ContractHeader } from '../../components/rbac/ContractPresentation'
import { PermissionCheck, permissionClaimClasses } from '../../components/rbac/PermissionSelectionView'
import { SourceViewScope, useSourceViewState } from './sourceViewState'
import { SourceContractABI, abiSummary } from './SourceContractABI'
import { SourceReadGrants } from './SourceReadGrants'
import { assertRuleDisplay } from './ExecutionRuleDetails'
import { sourcePagePath, type SourcePageId } from './navigation'
import { documentFor, documentValue, groupsOf, object, rootOf, type JSONObject, type SourceProject } from './sourceProject'

interface Props { project: SourceProject; root: string; organization: string }
type Modal = { kind: 'grants' | 'inspect'; id: string }
function contractRows(value: unknown): JSONObject[] {
  if (!Array.isArray(value)) throw Error('Contracts must be an array. Inspect the source files for this configuration.')
  const ids = new Set<string>()
  return value.map(raw => {
    const contract = object(raw)
    if (typeof contract.id !== 'string' || !contract.id || ids.has(contract.id) || typeof contract.name !== 'string' || typeof contract.address !== 'string' || !Array.isArray(contract.abi) || !Array.isArray(contract.readGrants)) throw Error('A contract has an unsupported identity, ABI or read-grant shape. Inspect the source file.')
    for (const key of ['allowVisibleToUnlock', 'eventsAllowDynamicPayload']) if (typeof contract[key] !== 'boolean') throw Error('Event visibility flags must be booleans. Inspect the source file.')
    const grantIDs = new Set<string>()
    for (const rawGrant of contract.readGrants) {
      const grant = object(rawGrant)
      if (typeof grant.id !== 'string' || !grant.id || grantIDs.has(grant.id) || typeof grant.groupId !== 'string' || !grant.groupId) throw Error('Read grants need unique IDs and string group references. Inspect the source file.')
      grantIDs.add(grant.id)
    }
    ids.add(contract.id)
    return contract
  })
}
export function SourcePolicyLink({ page, organization, children }: { page: SourcePageId; organization: string; children: ReactNode }) {
  const inside = useInRouterContext(), path = sourcePagePath(page) + (organization ? '?org=' + encodeURIComponent(organization) : '')
  return inside ? <Link to={path} className="text-primary hover:underline">{children}</Link> : <a href={path} className="text-primary hover:underline">{children}</a>
}
export function SourceContracts(props: Props) {
  if (!props.organization) return <p className="py-12 text-center text-sm text-neutral-500">Select an organization from this configuration</p>
  const path = documentFor(rootOf(props.project, props.root), props.organization, 'contract-registry'), scope = `contracts:${props.root}:${props.organization}`
  return <SourceViewScope key={scope} id={scope}><ContractsContent {...props} path={path} /></SourceViewScope>
}
function ContractsContent({ project, root, organization, path }: Props & { path: string }) {
  const doc = documentValue(project, root, path), spec = object(doc.spec)
  const contracts = contractRows(spec.contracts), groups = groupsOf(project, root, organization)
  const [modal, setModal] = useState<Modal | null>(null)
  const [search, setSearch] = useSourceViewState('search', ''), [offset, setOffset] = useSourceViewState('offset', 0)
  const current = modal ? contracts.find(c => c.id === modal.id) : null
  useEffect(() => { if (modal && !current) setModal(null) }, [modal, current])
  const filtered = contracts.filter(c => (String(c.name) + ' ' + String(c.address)).toLowerCase().includes(search.trim().toLowerCase()))
  const pageOffset = offset < filtered.length ? offset : 0, page = filtered.slice(pageOffset, pageOffset + 25)
  let bindings: JSONObject[] = []
  const executionRef = rootOf(project, root).draft.documents.find(d => d.organizationId === organization && d.kind === 'execution-rules')
  if (executionRef) {
    const policy = object(object(documentValue(project, root, executionRef.path).spec).policy)
    if (!Array.isArray(policy.bindings)) throw Error('Execution bindings must be an array. Inspect the source file.')
    bindings = policy.bindings.map(object)
    if (bindings.some(binding => typeof binding.group !== 'string' || !Array.isArray(binding.allow))) throw Error('Execution bindings need a group and an allow array. Inspect the source file.')
    for (const binding of bindings) (binding.allow as unknown[]).map(object).forEach(assertRuleDisplay)
  }
  const executionCount = (contract: JSONObject) => bindings.flatMap(b => (b.allow as unknown[]).map(object)).filter(r => r.storageAddress === contract.address || r.codeAddress === contract.address).length
  const inspect = (contract: JSONObject, kind: Modal['kind']) => setModal({ kind, id: String(contract.id) })
  return <section className="space-y-5">
    <div><h3 className="flex items-center gap-2 text-lg font-semibold text-neutral-900"><FileCode2 className="h-5 w-5 text-primary" />Contracts</h3><p className="mt-1 max-w-3xl text-sm text-neutral-500">Registered addresses, public ABI, read grants and event visibility in this configuration. <SourcePolicyLink page="execution-policy" organization={organization}>Execution Policy</SourcePolicyLink> shows execution permissions.</p></div>
    <div className="relative max-w-md"><Search className="absolute left-3 top-3 h-4 w-4 text-neutral-400" /><Input aria-label="Search contracts" placeholder="Search by name or address…" className="pl-9 pr-16" value={search} onChange={e => { setSearch(e.target.value); setOffset(0) }} />{search && <button type="button" className="absolute right-3 top-2.5 text-xs text-primary hover:underline" onClick={() => { setSearch(''); setOffset(0) }}>Clear</button>}</div>
    {!contracts.length ? <ContractEmpty title="No contracts registered" description="This configuration declares no contract addresses. Registration does not establish deployed code or grant execution access." /> : <>
      <div className="overflow-hidden rounded-xl border border-neutral-200"><Table><TableHeader><TableRow><TableHead>Address</TableHead><TableHead>Name</TableHead><TableHead className="text-center">ABI</TableHead><TableHead className="text-center">Read groups</TableHead><TableHead className="text-center">Execution rules</TableHead><TableHead className="text-right">Actions</TableHead></TableRow></TableHeader><TableBody>{page.map(contract => {
        const grants = (contract.readGrants as unknown[]).map(object), summary = abiSummary(contract.abi), count = executionCount(contract)
        return <TableRow key={String(contract.id)}><TableCell><ContractAddress address={String(contract.address)} compact /></TableCell><TableCell><button type="button" className="text-left text-sm font-medium text-primary hover:underline" onClick={() => inspect(contract, 'inspect')}>{String(contract.name)}</button>{contract.allowVisibleToUnlock === true && <Eye className="ml-2 inline h-4 w-4 text-amber-500" aria-label="Visible to unlock enabled in source" />}</TableCell><TableCell className="text-center"><SourceContractABI contract={contract} /><span className="sr-only">{summary.entries ? 'ABI loaded' : 'No ABI loaded'}</span></TableCell><TableCell className="text-center"><span className={`rounded-full px-2 py-0.5 text-xs font-medium ${grants.length ? 'bg-primary-50 text-primary' : 'bg-neutral-100 text-neutral-400'}`} title={grants.map(g => groups.find(group => group.id === g.groupId)?.name ?? String(g.groupId)).join(', ') || 'No read groups assigned'}>{grants.length}</span></TableCell><TableCell className="text-center"><SourcePolicyLink page="execution-policy" organization={organization}>{count} source rules</SourcePolicyLink></TableCell><TableCell><div className="flex items-center justify-end gap-1"><Button variant="ghost" size="sm" title="View read permissions" onClick={() => inspect(contract, 'grants')}><Shield className="mr-1 h-4 w-4 text-primary" />Read grants</Button></div></TableCell></TableRow>
      })}{!filtered.length && <TableRow><TableCell colSpan={6}><ContractEmpty title="No matching contracts" description="Try a different contract name or address." action={<Button variant="outline" onClick={() => setSearch('')}>Clear search</Button>} /></TableCell></TableRow>}</TableBody></Table></div><Pagination total={filtered.length} limit={25} offset={pageOffset} onPageChange={setOffset} />
    </>}
    <p className="flex items-start gap-2 text-xs text-neutral-500"><Info className="mt-0.5 h-4 w-4 shrink-0" />These counts describe the displayed configuration. Opening it does not change running permissions.</p>
    <Dialog open={!!modal && !!current} onOpenChange={open => { if (!open) setModal(null) }}><DialogContent className="max-w-5xl max-h-[85vh] overflow-y-auto"><DialogHeader><DialogTitle>{String(current?.name ?? '')} — {modal?.kind === 'grants' ? 'read grants' : 'contract'}</DialogTitle></DialogHeader>
      {current && <div className="space-y-5"><ContractHeader name={String(current.name)} address={String(current.address)}>{modal?.kind === 'grants' && <p className="rounded-lg border border-primary-100 bg-primary-50 p-3 text-sm text-primary">Read grants control history eligibility and event visibility. They do not permit execution. <SourcePolicyLink page="execution-policy" organization={organization}>Review execution rules</SourcePolicyLink>.</p>}</ContractHeader><SourceContractFlags value={current} /><SourceContractABI contract={current} />
        {modal?.kind === 'grants' ? <SourceViewScope id={'read-grants:' + String(current.id)}><SourceReadGrants contract={current} groups={groups} /></SourceViewScope> : <details><summary className="cursor-pointer text-sm font-medium">Advanced contract source</summary><pre className="mt-2 whitespace-pre-wrap break-all text-xs">{JSON.stringify(current, null, 2)}</pre></details>}
        <div className="flex justify-end"><Button variant="outline" onClick={() => setModal(null)}>Close {modal?.kind === 'grants' ? 'read grants' : 'contract'}</Button></div>
      </div>}
    </DialogContent></Dialog>
  </section>
}
export function SourceContractFlags({ value }: { value: JSONObject }) {
  for (const key of ['allowVisibleToUnlock', 'eventsAllowDynamicPayload']) if (typeof value[key] !== 'boolean') throw Error('Event visibility flags must be booleans. Inspect the source file.')
  return <div className="space-y-3"><h4 className="text-sm font-medium">Event visibility</h4>{(['allowVisibleToUnlock', 'eventsAllowDynamicPayload'] as const).map(key => {
    const selected = value[key] === true
    return <label key={key} className={permissionClaimClasses(selected, false)}><input type="checkbox" aria-label={key === 'allowVisibleToUnlock' ? 'Visible to unlock' : 'Allow dynamic event payload'} className="sr-only" checked={selected} disabled /><PermissionCheck checked={selected} size="claim" /><span><span className="flex items-center gap-2 text-sm font-medium">{key === 'allowVisibleToUnlock' ? <><Eye className="h-4 w-4 text-amber-500" />Visible to unlock</> : 'Allow dynamic event payload'}<span className={`rounded px-1.5 py-0.5 text-[10px] ${selected ? 'bg-primary-50 text-primary' : 'bg-neutral-100 text-neutral-500'}`}>{selected ? 'Enabled in source' : 'Disabled'}</span></span><span className="mt-1 block text-xs text-neutral-500">{key === 'allowVisibleToUnlock' ? 'For eligible readers, visibleTo membership may unlock matched event visibility. A read grant or admin eligibility and a supported matching event ABI are still required. This does not permit execution.' : 'Matched events with dynamic non-indexed parameters may enter history rendering. Other event privacy gates still apply; disabled payloads are dropped.'}</span></span></label>
  })}</div>
}
