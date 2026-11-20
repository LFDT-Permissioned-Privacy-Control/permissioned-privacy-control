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
import { documentFor, loadSavedSourcePackage, loadSourceProject, object, semanticEditingIssue, sourcePackage, type SourceProject } from './sourceProject'
import { SourceOrganizations } from './SourceOrganizations'
import { SourceCatalogs } from './SourceCatalogs'
import { SourceReview, download } from './SourceReview'
import { SourceExecution } from './SourceExecution'
import { SourceAuthoringScope } from './SourceAuthoringScope'
import { useAuthoringState } from './sourceAuthoring'
import { ServingSelection } from './ServingSelection'
import { getSourcePage, sourcePages, sourcePagePath, sourceSections, type SourcePageId } from './navigation'

export function SourceWorkspacePage({ controller, project, onProject, unfinished = false }: { controller: Controller; project: SourceProject | null; onProject(project: SourceProject | null, replace?: boolean): void; unfinished?: boolean }) {
  const location = useLocation(), navigate = useNavigate(), picker = useRef<HTMLInputElement>(null), packagePicker = useRef<HTMLInputElement>(null), generation = useRef(0)
  const [rootID, setRoot] = useAuthoringState('root', ''), [editing, setEditing] = useAuthoringState('editing', false), [busy, setBusy] = useState(false), [error, setError] = useState<string | null>(null), [pending, setPending] = useState<{ files?: File[]; saved?: boolean } | null>(null)
  const [now, setNow] = useState(Date.now())
  const [reviewPath, setReviewPath] = useAuthoringState('review-path', 'draft.json')
  const editMode = useRef(editing); editMode.current = editing
  const root = project?.roots.find(r => r.id === rootID) ?? project?.roots.find(r => r.id === 'core') ?? project?.roots[0], orgID = new URLSearchParams(location.search).get('org') ?? ''
  const selectedOrg = root?.draft.organizations.find(o => o.id === orgID)
  const view = getSourcePage(location.pathname) ?? getSourcePage('/admin')!
  const page = view.id, presentation = sourceSections[view.section]
  const tabs = view.section === 'rbac' || view.section === 'identity' ? sourcePages.filter(p => p.section === view.section) : []
  const showScope = view.section === 'rbac' || page === 'claim-mappings' || view.section === 'disclosure' || view.section === 'compliance'
  const authoringOrg = ['organizations', 'identity-profiles', 'platform-configuration', 'configuration'].includes(page) ? '' : orgID
  const sourceIssue = useMemo(() => project && root ? semanticEditingIssue(project, root.id) : null, [project, root])
  const scope = controller.scopeRevision, actor = controller.snapshot().self?.actorId
  const check = () => { if (!actor || !controller.ownsScope(scope, actor)) throw Error('The selected account changed. Import the source again.') }
  useEffect(() => () => { generation.current++ }, [])
  useEffect(() => { const timer = setInterval(() => setNow(Date.now()), 1000); return () => clearInterval(timer) }, [])
  async function importSource(files: File[], saved = false) {
    const current = ++generation.current
    const own = () => { if (current !== generation.current) throw Error('Source import was superseded.'); check() }
    setBusy(true); setError(null)
    try {
      if (saved && (files.length !== 1 || files[0].size > 90 << 20)) throw Error('Choose one exported configuration draft up to 90 MiB.')
      const next = saved ? await loadSavedSourcePackage(await files[0].text(), own) : await loadSourceProject(selectedSources(files), own); own()
      onProject(next, true)
      const selected = next.roots.some(root => root.draft.organizations.some(org => org.id === orgID)) ? orgID : ''
      navigate(sourcePagePath(page) + (selected ? '?org=' + selected : ''))
    } catch (e) { if (current === generation.current && controller.scopeRevision === scope) setError(e instanceof Error ? e.message : 'Choose the source files again.') }
    finally { if (current === generation.current) setBusy(false) }
  }
  function choose(event: ChangeEvent<HTMLInputElement>, saved = false) {
    const files = Array.from(event.currentTarget.files ?? []); event.currentTarget.value = ''
    if (!files.length) return
    if (project?.dirty || unfinished) setPending({ files, saved }); else void importSource(files, saved)
  }
  function close() { check(); generation.current++; onProject(null); setBusy(false); setError(null) }
  const go = (p: SourcePageId, org = orgID) => navigate(sourcePagePath(p) + (org ? '?org=' + org : ''))
  function change(next: SourceProject) { check(); if (!editMode.current) throw Error('Choose Edit local proposal before changing source.'); onProject(next) }
  let document: string | undefined
  if (root) {
    try {
      if (page === 'organizations') document = 'draft.json'
      else if (page === 'groups' && orgID) document = documentFor(root, orgID, 'groups')
      else if (page === 'execution-policy' && orgID) document = documentFor(root, orgID, 'execution-rules')
      else if (page === 'contracts' && orgID) document = documentFor(root, orgID, 'contract-registry')
      else { const catalog = page === 'identity-profiles' || page === 'claim-mappings' ? 'identityCatalog' : page === 'disclosure-source' ? 'disclosureCatalog' : page === 'compliance-source' ? 'complianceCatalog' : null; if (catalog && root.draft[catalog]) document = String(object(root.draft[catalog]).path) }
    } catch { /* Incomplete source is handled by the repair view. */ }
  }
  let content: React.ReactNode = null
  if (project && root) {
    try {
      content = page === 'configuration' ? <>{sourceIssue && <p className="text-sm text-warning-dark mb-4" role="status">{sourceIssue}</p>}<SourceReview key={root.id} unfinished={unfinished} project={project} root={root.id} editing={editing} onChange={change} check={check} initialPath={reviewPath} /></>
        : sourceIssue ? <div className="rounded-lg border border-warning/30 bg-warning-light p-4 space-y-3"><p role="status" className="text-sm text-warning-dark">{sourceIssue}</p><p className="text-sm text-neutral-500">Original bytes and raw text editing/export remain available in Review & export. Browser forms are disabled for this source root.</p><Button variant="outline" onClick={() => go('configuration')}>Open source for repair</Button></div>
        : page === 'organizations' || page === 'groups' ? <SourceOrganizations key={`${root.id}:${page}:${orgID}`} project={project} root={root.id} organization={orgID} groupsPage={page === 'groups'} editing={editing} onChange={change} onOrganization={(id, groups) => go(groups ? 'groups' : page, id)} />
          : page === 'execution-policy' ? <SourceExecution key={`${root.id}:${orgID}`} project={project} root={root.id} organization={orgID} editing={editing} onChange={change} check={check} onOpenSource={path => { setReviewPath(path); go('configuration') }} />
            : <SourceCatalogs key={`${root.id}:${orgID}:${page}`} project={project} root={root.id} organization={orgID} page={page} editing={editing} onChange={change} />
    } catch (e) { content = <div className="rounded-lg bg-error-light p-4 text-sm text-error-dark"><p role="alert">{e instanceof Error ? e.message : 'This source cannot be displayed.'}</p><Button className="mt-3" variant="outline" onClick={() => go('configuration')}>Open source for repair</Button></div> }
  }
  return <Card className="animate-fade-in" data-testid="rbac-manager"><CardHeader className="pb-4"><div className="flex flex-wrap items-center justify-between gap-4"><div className="flex items-center gap-3"><div className="w-10 h-10 rounded-lg bg-primary-50 flex items-center justify-center"><Shield className="w-5 h-5 text-primary" /></div><div><CardTitle className="text-lg" data-testid="rbac-title">{presentation.title}</CardTitle><p className="text-sm text-neutral-500 mt-0.5">{presentation.description}</p></div></div>{showScope && <div className="flex w-full min-w-0 items-center gap-3 sm:w-auto"><span className="shrink-0 text-sm text-neutral-500">Scope:</span><Select value={selectedOrg?.id ?? ''} onValueChange={id => go(page, id)} disabled={!root?.draft.organizations.length}><SelectTrigger className="min-w-0 w-full sm:w-[280px]" aria-label="Select organization scope" data-testid="org-selector"><SelectValue placeholder="Select organization" /></SelectTrigger><SelectContent>{root?.draft.organizations.map(org => <SelectItem key={org.id} value={org.id}><span className="flex gap-2 items-center"><Building2 className="w-4 h-4" />{org.name}<span className="text-xs text-neutral-400">({org.slug})</span></span></SelectItem>)}</SelectContent></Select></div>}</div></CardHeader><CardContent className="pt-0">
    <section className="mb-5 rounded-lg border border-neutral-200 bg-neutral-50 p-4" aria-label="Policy source workspace"><div className="flex flex-wrap items-center justify-between gap-3"><div><div className="text-sm font-medium">Policy source workspace <Badge variant="outline" className="ml-2">{project?.dirty || unfinished ? 'Changed local draft' : 'Local draft'}</Badge></div><p className="text-xs text-neutral-500 mt-1">Import source you are entitled to read. Draft edits stay in this page until exported; Git review and deployment make changes effective.</p></div><div className="flex flex-wrap gap-2"><Button variant="outline" size="sm" disabled={busy} onClick={() => picker.current?.click()}><FileUp className="w-4 h-4 mr-2" />{busy ? 'Reading source…' : 'Import source folder'}</Button><Button variant="outline" size="sm" disabled={busy} title="Restore a configuration draft you exported earlier. This does not change the running configuration." onClick={() => packagePicker.current?.click()}>Open saved draft</Button>{project && <><Button variant={editing ? 'secondary' : 'outline'} size="sm" onClick={() => { check(); setEditing(!editing) }}>{editing ? 'Inspect proposal' : 'Edit local proposal'}</Button><Button variant="ghost" size="sm" onClick={() => { if (project.dirty || unfinished) setPending({}); else close() }}><X className="w-4 h-4 mr-1" />Close source</Button></>}</div></div>
      <input ref={picker} type="file" className="sr-only" aria-label="Policy source folder" multiple {...{ webkitdirectory: '' }} onChange={choose} /><input ref={packagePicker} type="file" accept=".json" className="sr-only" aria-label="Saved configuration draft" onChange={e => choose(e, true)} />
      {project && root && <div className="mt-3 text-xs text-neutral-500 space-y-2" data-testid="workspace-source"><p>Imported revision: <strong className="text-neutral-700">{root.draft.sourceRevision || 'Unavailable'}</strong> · Environment: {root.draft.environment || 'Unavailable'} · Chain: {root.draft.chainId || 'Unavailable'}</p><p>Go validation has not run in this browser. The imported revision does not prove the serving deployment.</p>{project.roots.length > 1 && <label className="flex items-center gap-2">Source root<select aria-label="Source root" className="rounded border border-neutral-300 p-1" value={root.id} onChange={e => { check(); setRoot(e.target.value) }}>{project.roots.map(r => <option key={r.id}>{r.id}</option>)}</select></label>}<p>Export a copy to keep your source after a page reload or account change.</p></div>}
      <ServingSelection controller={controller} draft={root?.draft} />
      {error && <p role="alert" className="mt-3 text-sm text-error-dark">{error}</p>}
    </section>
    {(project?.dirty || unfinished) && (controller.snapshot().self?.expiresAt ?? 0) * 1000 - now < 60000 && <div role="alert" className="mb-5 rounded-lg border border-warning/30 bg-warning-light p-4 text-sm text-warning-dark"><p>Your session needs renewal soon. This tab keeps your draft locked until the same account is verified again. Export a copy to keep it after a page reload or browser restart.</p><Button className="mt-3" variant="outline" size="sm" disabled={unfinished} onClick={() => { check(); if (project && !unfinished) download('ops-source-package.json', JSON.stringify(sourcePackage(project))) }}>Export source before renewal</Button>{unfinished && <p className="mt-2 text-xs">Save or cancel unfinished form fields before exporting source.</p>}</div>}
    <>{tabs.length > 0 && <Tabs value={page} onValueChange={p => go(p as SourcePageId)} data-testid={`${view.section}-tabs`}><TabsList className="mb-5 flex h-auto w-full flex-wrap justify-start">{tabs.map(p => <TabsTrigger value={p.id} key={p.id} data-testid={`tab-${p.id}`}>{p.title}</TabsTrigger>)}</TabsList></Tabs>}</>
    {!project ? <div className="text-center py-12"><Building2 className="w-12 h-12 mx-auto mb-4 text-neutral-400" /><p className="text-neutral-500">{view.section === 'rbac' ? 'Open your policy source to view organizations and groups' : 'Import configuration files to view ' + presentation.title.toLowerCase()}</p><p className="text-sm text-neutral-400 mt-2">Choose the folder containing draft.json and its referenced documents, or a parent containing Core and broker roots.</p></div> : <SourceAuthoringScope id={`${root?.id}:${authoringOrg}:${page}`} root={root?.id} path={document}><SourcePane key={`${root?.id}:${authoringOrg}:${page}`} fallback={() => go('configuration')}>{content}</SourcePane></SourceAuthoringScope>}
    <Dialog open={pending !== null} onOpenChange={open => { if (!open) setPending(null) }}><DialogContent><DialogHeader><DialogTitle>Keep your changed source</DialogTitle></DialogHeader><p className="text-sm text-neutral-500">This page is the only copy of these edits until you export them. Export your configuration draft or explicitly discard it before continuing.</p>{unfinished && <p className="text-sm text-warning-dark">Unfinished form fields are not part of a source export. Cancel this action, then save or cancel those fields first.</p>}<div className="flex flex-wrap justify-end gap-2"><Button variant="ghost" onClick={() => setPending(null)}>Cancel</Button><Button variant="outline" disabled={unfinished} onClick={() => { check(); if (project && !unfinished) download('ops-source-package.json', JSON.stringify(sourcePackage(project))) }}>Export source</Button><Button variant="destructive" onClick={() => { const files = pending?.files, saved = pending?.saved; setPending(null); if (files) void importSource(files, saved); else close() }}>Discard and continue</Button></div></DialogContent></Dialog>
  </CardContent></Card>
}
import { Component, type ReactNode } from 'react'
class SourcePane extends Component<{ children: ReactNode; fallback(): void }, { error: string | null }> {
  state = { error: null as string | null }
  static getDerivedStateFromError(e: unknown) { return { error: e instanceof Error ? e.message : 'This source needs repair.' } }
  render() { return this.state.error ? <div className="rounded-lg bg-error-light p-4"><p role="alert" className="text-sm text-error-dark">{this.state.error}</p><Button className="mt-3" variant="outline" onClick={this.props.fallback}>Open source for repair</Button></div> : this.props.children }
}
