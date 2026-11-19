import { useEffect, useMemo, useRef, useState, type ChangeEvent } from 'react'
import { useLocation, useNavigate } from 'react-router-dom'
import { Building2, FileUp, Shield, X } from 'lucide-react'
import { Card, CardContent, CardHeader, CardTitle } from '../../components/ui/card'
import { Button } from '../../components/ui/button'
import { Badge } from '../../components/ui/badge'
import { Tabs, TabsList, TabsTrigger } from '../../components/ui/tabs'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '../../components/ui/select'
import { Dialog, DialogContent, DialogHeader, DialogTitle } from '../../components/ui/dialog'
import { Controller } from './controller'
import { selectedSources } from './workspace'
import { loadSavedSourcePackage, loadSourceProject, semanticEditingIssue, sourcePackage, type SourceProject } from './sourceProject'
import { SourceOrganizations } from './SourceOrganizations'
import { SourceCatalogs } from './SourceCatalogs'
import { SourceReview, download } from './SourceReview'
import { SourceExecution } from './SourceExecution'

const pages = [['organizations', 'Organizations'], ['groups', 'Groups'], ['contracts', 'Contracts'], ['execution-policy', 'Execution Policy'], ['identity-profiles', 'Identity Profiles'], ['claim-mappings', 'Claim Mappings'], ['azure-tenants', 'Azure Tenants'], ['platform-configuration', 'Platform'], ['disclosure-source', 'Disclosure Rules'], ['compliance-source', 'Compliance Policy'], ['configuration', 'Configuration']]
export function SourceWorkspacePage({ controller, project, onProject }: { controller: Controller; project: SourceProject | null; onProject(project: SourceProject | null): void }) {
  const location = useLocation(), navigate = useNavigate(), picker = useRef<HTMLInputElement>(null), packagePicker = useRef<HTMLInputElement>(null), generation = useRef(0)
  const [rootID, setRoot] = useState(''), [editing, setEditing] = useState(false), [busy, setBusy] = useState(false), [error, setError] = useState<string | null>(null), [pending, setPending] = useState<{ files?: File[]; saved?: boolean } | null>(null)
  const [now, setNow] = useState(Date.now())
  const [reviewPath, setReviewPath] = useState('draft.json')
  const root = project?.roots.find(r => r.id === rootID) ?? project?.roots[0], orgID = new URLSearchParams(location.search).get('org') ?? ''
  const selectedOrg = root?.draft.organizations.find(o => o.id === orgID), page = pages.some(([p]) => location.pathname.endsWith('/' + p)) ? location.pathname.split('/').pop()! : 'organizations'
  const sourceIssue = useMemo(() => project && root ? semanticEditingIssue(project, root.id) : null, [project, root])
  const scope = controller.scopeRevision, actor = controller.snapshot().self?.actorId
  const check = () => { if (!actor || !controller.ownsScope(scope, actor)) throw Error('The selected account changed. Import the source again.') }
  useEffect(() => () => { generation.current++ }, [])
  useEffect(() => { const timer = setInterval(() => setNow(Date.now()), 1000); return () => clearInterval(timer) }, [])
  async function importSource(files: File[], saved = false) {
    const current = ++generation.current
    const own = () => { check(); if (current !== generation.current) throw Error('Source import was superseded.') }
    setBusy(true); setError(null)
    try {
      if (saved && (files.length !== 1 || files[0].size > 90 << 20)) throw Error('Choose one exported source package up to 90 MiB.')
      const next = saved ? await loadSavedSourcePackage(await files[0].text(), own) : await loadSourceProject(selectedSources(files), own); own()
      onProject(next); setRoot(next.roots.find(r => r.id === 'core')?.id ?? next.roots[0].id); setEditing(false)
      navigate('/admin/rbac/organizations')
    } catch (e) { if (current === generation.current && controller.scopeRevision === scope) setError(e instanceof Error ? e.message : 'Choose the source files again.') }
    finally { if (current === generation.current) setBusy(false) }
  }
  function choose(event: ChangeEvent<HTMLInputElement>, saved = false) {
    const files = Array.from(event.currentTarget.files ?? []); event.currentTarget.value = ''
    if (!files.length) return
    if (project?.dirty) setPending({ files, saved }); else void importSource(files, saved)
  }
  function close() { check(); generation.current++; onProject(null); setEditing(false); setBusy(false); setError(null) }
  const go = (p: string, org = orgID) => navigate('/admin/rbac/' + p + (org ? '?org=' + org : ''))
  function change(next: SourceProject) { check(); onProject(next) }
  let content: React.ReactNode = null
  if (project && root) {
    try {
      content = page === 'configuration' ? <>{sourceIssue && <p className="text-sm text-warning-dark mb-4" role="status">{sourceIssue}</p>}<SourceReview key={root.id} project={project} root={root.id} editing={editing} onChange={change} check={check} initialPath={reviewPath} /></>
        : sourceIssue ? <div className="rounded-lg border border-warning/30 bg-warning-light p-4 space-y-3"><p role="status" className="text-sm text-warning-dark">{sourceIssue}</p><p className="text-sm text-neutral-500">Original bytes and raw text editing/export remain available in Configuration. Browser forms are disabled for this source root.</p><Button variant="outline" onClick={() => go('configuration')}>Open source for repair</Button></div>
        : page === 'organizations' || page === 'groups' ? <SourceOrganizations key={`${root.id}:${page}:${orgID}`} project={project} root={root.id} organization={orgID} groupsPage={page === 'groups'} editing={editing} onChange={change} onOrganization={(id, groups) => go(groups ? 'groups' : page, id)} />
          : page === 'execution-policy' ? <SourceExecution key={`${root.id}:${orgID}`} project={project} root={root.id} organization={orgID} editing={editing} onChange={change} check={check} onOpenSource={path => { setReviewPath(path); go('configuration') }} />
            : <SourceCatalogs key={`${root.id}:${orgID}:${page}`} project={project} root={root.id} organization={orgID} page={page} editing={editing} onChange={change} />
    } catch (e) { content = <div className="rounded-lg bg-error-light p-4 text-sm text-error-dark"><p role="alert">{e instanceof Error ? e.message : 'This source cannot be displayed.'}</p><Button className="mt-3" variant="outline" onClick={() => go('configuration')}>Open source for repair</Button></div> }
  }
  return <Card className="animate-fade-in" data-testid="rbac-manager"><CardHeader className="pb-4"><div className="flex flex-wrap items-center justify-between gap-4"><div className="flex items-center gap-3"><div className="w-10 h-10 rounded-lg bg-primary-50 flex items-center justify-center"><Shield className="w-5 h-5 text-primary" /></div><div><CardTitle className="text-lg" data-testid="rbac-title">Access Control</CardTitle><p className="text-sm text-neutral-500 mt-0.5">Organizations, groups and permissions from your policy source</p></div></div><div className="flex w-full min-w-0 items-center gap-3 sm:w-auto"><span className="shrink-0 text-sm text-neutral-500">Scope:</span><Select value={selectedOrg?.id ?? ''} onValueChange={id => go(page, id)} disabled={!root?.draft.organizations.length}><SelectTrigger className="min-w-0 w-full sm:w-[280px]" aria-label="Select organization scope" data-testid="org-selector"><SelectValue placeholder="Select organization" /></SelectTrigger><SelectContent>{root?.draft.organizations.map(org => <SelectItem key={org.id} value={org.id}><span className="flex gap-2 items-center"><Building2 className="w-4 h-4" />{org.name}<span className="text-xs text-neutral-400">({org.slug})</span></span></SelectItem>)}</SelectContent></Select></div></div></CardHeader><CardContent className="pt-0">
    <section className="mb-5 rounded-lg border border-neutral-200 bg-neutral-50 p-4" aria-label="Policy source workspace"><div className="flex flex-wrap items-center justify-between gap-3"><div><div className="text-sm font-medium">Policy source workspace <Badge variant="outline" className="ml-2">{project?.dirty ? 'Changed local draft' : 'Local draft'}</Badge></div><p className="text-xs text-neutral-500 mt-1">Import source you are entitled to read. Draft edits stay in this page until exported; Git review and deployment make changes effective.</p></div><div className="flex flex-wrap gap-2"><Button variant="outline" size="sm" disabled={busy} onClick={() => picker.current?.click()}><FileUp className="w-4 h-4 mr-2" />{busy ? 'Reading source…' : 'Import source folder'}</Button><Button variant="outline" size="sm" disabled={busy} onClick={() => packagePicker.current?.click()}>Open saved package</Button>{project && <><Button variant={editing ? 'secondary' : 'outline'} size="sm" onClick={() => { check(); setEditing(!editing) }}>{editing ? 'Inspect proposal' : 'Edit local proposal'}</Button><Button variant="ghost" size="sm" onClick={() => { if (project.dirty) setPending({}); else close() }}><X className="w-4 h-4 mr-1" />Close source</Button></>}</div></div>
      <input ref={picker} type="file" className="sr-only" aria-label="Policy source folder" multiple {...{ webkitdirectory: '' }} onChange={choose} /><input ref={packagePicker} type="file" accept=".json" className="sr-only" aria-label="Saved source package" onChange={e => choose(e, true)} />
      {project && root && <div className="mt-3 text-xs text-neutral-500 space-y-2" data-testid="workspace-source"><p>Imported revision: <strong className="text-neutral-700">{root.draft.sourceRevision || 'Unavailable'}</strong> · Environment: {root.draft.environment || 'Unavailable'} · Chain: {root.draft.chainId || 'Unavailable'}</p><p>Go validation has not run in this browser. The imported revision does not prove the serving deployment.</p>{project.roots.length > 1 && <label className="flex items-center gap-2">Source root<select aria-label="Source root" className="rounded border border-neutral-300 p-1" value={root.id} onChange={e => { check(); setRoot(e.target.value) }}>{project.roots.map(r => <option key={r.id}>{r.id}</option>)}</select></label>}<p>Export before signing out or session expiry. Source files are removed when the selected account changes.</p></div>}
      {error && <p role="alert" className="mt-3 text-sm text-error-dark">{error}</p>}
    </section>
    {project?.dirty && (controller.snapshot().self?.expiresAt ?? 0) * 1000 - now < 60000 && <div role="alert" className="mb-5 rounded-lg border border-warning/30 bg-warning-light p-4 text-sm text-warning-dark"><p>Your verified session needs renewal soon. Export the changed source now; renewal or expiry may close this private workspace.</p><Button className="mt-3" variant="outline" size="sm" onClick={() => { check(); download('ops-source-package.json', JSON.stringify(sourcePackage(project))) }}>Export source before renewal</Button></div>}
    <Tabs value={page} onValueChange={p => go(p)} data-testid="rbac-tabs"><TabsList className="w-full justify-start mb-5 overflow-x-auto">{pages.map(([p, title]) => <TabsTrigger value={p} key={p} data-testid={`tab-${p}`}>{title}</TabsTrigger>)}</TabsList></Tabs>
    {!project ? <div className="text-center py-12"><Building2 className="w-12 h-12 mx-auto mb-4 text-neutral-400" /><p className="text-neutral-500">Open your policy source to view organizations and groups</p><p className="text-sm text-neutral-400 mt-2">Choose the folder containing draft.json and its referenced documents, or a parent containing Core and broker roots.</p></div> : <SourcePane key={`${root?.id}:${orgID}:${page}`} fallback={() => go('configuration')}>{content}</SourcePane>}
    <Dialog open={pending !== null} onOpenChange={open => { if (!open) setPending(null) }}><DialogContent><DialogHeader><DialogTitle>Keep your changed source</DialogTitle></DialogHeader><p className="text-sm text-neutral-500">This page is the only copy of these edits until you export them. Export a source package or explicitly discard the draft before continuing.</p><div className="flex flex-wrap justify-end gap-2"><Button variant="ghost" onClick={() => setPending(null)}>Cancel</Button><Button variant="outline" onClick={() => { check(); if (project) download('ops-source-package.json', JSON.stringify(sourcePackage(project))) }}>Export source</Button><Button variant="destructive" onClick={() => { const files = pending?.files, saved = pending?.saved; setPending(null); if (files) void importSource(files, saved); else close() }}>Discard and continue</Button></div></DialogContent></Dialog>
  </CardContent></Card>
}
import { Component, type ReactNode } from 'react'
class SourcePane extends Component<{ children: ReactNode; fallback(): void }, { error: string | null }> {
  state = { error: null as string | null }
  static getDerivedStateFromError(e: unknown) { return { error: e instanceof Error ? e.message : 'This source needs repair.' } }
  render() { return this.state.error ? <div className="rounded-lg bg-error-light p-4"><p role="alert" className="text-sm text-error-dark">{this.state.error}</p><Button className="mt-3" variant="outline" onClick={this.props.fallback}>Open source for repair</Button></div> : this.props.children }
}
