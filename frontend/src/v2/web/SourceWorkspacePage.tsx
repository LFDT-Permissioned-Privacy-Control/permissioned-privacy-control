import { Component, useEffect, type ReactNode } from 'react'
import { useLocation, useNavigate } from 'react-router-dom'
import { Building2, FolderOpen, RefreshCw, Shield } from 'lucide-react'
import { Card, CardContent, CardHeader, CardTitle } from '../../components/ui/card'
import { Button } from '../../components/ui/button'
import { Tabs, TabsList, TabsTrigger } from '../../components/ui/tabs'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '../../components/ui/select'
import { documentText, sourceDisplayIssue } from './sourceProject'
import { SourceOrganizations } from './SourceOrganizations'
import { SourceCatalogs } from './SourceCatalogs'
import { SourceExecution } from './SourceExecution'
import { SourceViewScope, useSourceViewState } from './sourceViewState'
import { getSourcePage, sourcePages, sourcePagePath, sourceSections, type SourcePageId } from './navigation'
import type { ConfigurationViewer, ConfigurationView } from './configurationViewer'

export function SourceWorkspacePage({ viewer, view }: { viewer: ConfigurationViewer; view: ConfigurationView }) {
  const location = useLocation(), navigate = useNavigate(), project = view.project
  const [rootID, setRoot] = useSourceViewState('root', ''), [sourcePath, setSourcePath] = useSourceViewState('source-file', 'draft.json')
  const root = project?.roots.find(r => r.id === rootID) ?? project?.roots.find(r => r.id === 'core') ?? project?.roots[0]
  useEffect(() => { if (project && rootID && !project.roots.some(r => r.id === rootID)) setRoot('') }, [project, rootID])
  useEffect(() => { if (root && !root.files.some(file => file.path === sourcePath)) setSourcePath('draft.json') }, [root, sourcePath])
  const orgID = new URLSearchParams(location.search).get('org') ?? '', selectedOrg = root?.draft.organizations.find(o => o.id === orgID)
  const page = getSourcePage(location.pathname) ?? getSourcePage('/admin')!, presentation = sourceSections[page.section]
  const tabs = page.section === 'rbac' || page.section === 'identity' ? sourcePages.filter(p => p.section === page.section) : []
  const go = (id: SourcePageId, organization = orgID) => navigate(sourcePagePath(id) + (organization ? '?org=' + organization : ''))
  const showScope = page.id !== 'configuration' && (page.section === 'rbac' || page.id === 'claim-mappings' || page.section === 'disclosure' || page.section === 'compliance')
  const sourceIssue = project && root ? sourceDisplayIssue(project, root.id) : null
  const openSource = (path?: string) => { if (path) setSourcePath(path); go('configuration') }
  let content: ReactNode = null
  if (project && root) {
    if (page.id === 'configuration') {
      const selectedFile = root.files.find(f => f.path === sourcePath) ?? root.files[0]
      content = <section aria-label="Source files" className="space-y-4">{sourceIssue && <p role="status" className="rounded-lg bg-warning-light p-3 text-sm text-warning-dark">{sourceIssue}</p>}<h3 className="font-medium text-neutral-900">Source files</h3><div className="flex flex-wrap gap-2">{root.files.map(file => <Button key={file.path} size="sm" variant={selectedFile?.path === file.path ? 'secondary' : 'outline'} aria-pressed={selectedFile?.path === file.path} onClick={() => setSourcePath(file.path)}>{file.path}</Button>)}</div>{selectedFile && <div className="rounded-lg border border-neutral-200"><p className="border-b border-neutral-200 bg-neutral-50 p-3 font-mono text-xs">{selectedFile.path}</p><pre aria-label={'Source ' + selectedFile.path} className="max-h-[65vh] overflow-auto whitespace-pre-wrap break-all p-4 text-xs">{documentText(project, root.id, selectedFile.path)}</pre></div>}</section>
    } else if (sourceIssue) content = <div className="space-y-3 rounded-lg border border-warning/30 bg-warning-light p-4"><p role="status" className="text-sm text-warning-dark">{sourceIssue}</p><Button variant="outline" onClick={() => openSource()}>View source files</Button></div>
    else content = page.id === 'organizations' || page.id === 'groups' ? <SourceOrganizations catalog={view.methodCatalog} project={project} root={root.id} organization={orgID} groupsPage={page.id === 'groups'} onOrganization={(id, groups) => go(groups ? 'groups' : page.id, id)} />
      : page.id === 'execution-policy' ? <SourceExecution project={project} root={root.id} organization={orgID} onOpenSource={openSource} />
      : <SourceCatalogs project={project} root={root.id} organization={orgID} page={page.id} />
  }
  return <Card className="animate-fade-in" data-testid="rbac-manager"><CardHeader className="pb-4"><div className="flex flex-wrap items-center justify-between gap-4"><div className="flex items-center gap-3"><div className="w-10 h-10 rounded-lg bg-primary-50 flex items-center justify-center"><Shield className="w-5 h-5 text-primary" /></div><div><CardTitle className="text-lg" data-testid="rbac-title">{presentation.title}</CardTitle><p className="text-sm text-neutral-500 mt-0.5">{presentation.description}</p></div></div>{showScope && <div className="flex w-full min-w-0 items-center gap-3 sm:w-auto"><span className="shrink-0 text-sm text-neutral-500">Scope:</span><Select value={selectedOrg?.id ?? ''} onValueChange={id => go(page.id, id)} disabled={!root?.draft.organizations.length}><SelectTrigger className="min-w-0 w-full sm:w-[280px]" aria-label="Select organization scope" data-testid="org-selector"><SelectValue placeholder="Select organization" /></SelectTrigger><SelectContent>{root?.draft.organizations.map(org => <SelectItem key={org.id} value={org.id}><span className="flex gap-2 items-center"><Building2 className="w-4 h-4" />{org.name}<span className="text-xs text-neutral-400">({org.slug})</span></span></SelectItem>)}</SelectContent></Select></div>}</div></CardHeader><CardContent className="pt-0">
    <section aria-label="Configurations" className="mb-5 space-y-3 rounded-lg border border-neutral-200 bg-neutral-50 p-4"><div className="flex flex-wrap items-center justify-between gap-3"><div><h3 className="flex items-center gap-2 text-sm font-medium"><FolderOpen className="h-4 w-4 text-primary" />Configurations</h3><p className="mt-1 text-xs text-neutral-500">Read configurations supplied by your operator. Choosing a folder changes this view; configuration changes and approvals happen externally.</p></div><Button size="sm" variant="outline" disabled={view.busy} onClick={() => void viewer.refresh(true)}><RefreshCw className={'mr-2 h-4 w-4' + (view.busy ? ' animate-spin' : '')} />Refresh</Button></div>
      {view.sources.length > 0 && <Tabs value={view.selected ?? ''} onValueChange={viewer.select} aria-label="Available configurations"><TabsList className="h-auto max-w-full flex-wrap justify-start">{view.sources.map(source => <TabsTrigger value={source.id} key={source.id} data-testid={'configuration-source-' + source.id}>{source.label}</TabsTrigger>)}</TabsList></Tabs>}
      {project && root && <div className="text-xs text-neutral-500" data-testid="workspace-source">{project.roots.length > 1 && <label className="flex items-center gap-2">Source root<select aria-label="Source root" className="rounded border border-neutral-300 bg-white p-1" value={root.id} onChange={event => { setRoot(event.target.value); setSourcePath('draft.json') }}>{project.roots.map(r => <option key={r.id}>{r.id}</option>)}</select></label>}</div>}
      {view.error && <p role="alert" className="text-sm text-error-dark">{view.error}</p>}
    </section>
    {tabs.length > 0 && <Tabs value={page.id} onValueChange={id => go(id as SourcePageId)} data-testid={`${page.section}-tabs`}><TabsList className="mb-5 flex h-auto w-full flex-wrap justify-start">{tabs.map(p => <TabsTrigger value={p.id} key={p.id} data-testid={`tab-${p.id}`}>{p.title}</TabsTrigger>)}</TabsList></Tabs>}
    {!project || !root ? <div className="py-12 text-center"><Building2 className="mx-auto mb-4 h-12 w-12 text-neutral-400" /><p className="text-neutral-500">{view.busy ? 'Reading configuration…' : view.sources.length ? 'Choose a configuration folder to inspect' : 'No configurations are available for this account'}</p></div> : <SourceViewScope id={`${view.selected}:${root.id}:${page.id}:${orgID}`}><SourcePane key={`${view.selected}:${root.id}:${page.id}:${orgID}:${sourceIssue ?? ''}`} fallback={() => openSource()} observation={view.observation}>{content}</SourcePane></SourceViewScope>}
  </CardContent></Card>
}
class SourcePane extends Component<{ children: ReactNode; fallback(): void; observation: number }, { error: string | null; observation: number }> {
  state = { error: null as string | null, observation: this.props.observation }
  static getDerivedStateFromError(error: unknown) { return { error: error instanceof Error ? error.message : 'This configuration cannot be displayed.' } }
  static getDerivedStateFromProps(props: { observation: number }, state: { observation: number }) { return props.observation !== state.observation ? { error: null, observation: props.observation } : null }
  render() { return this.state.error ? <div className="rounded-lg bg-error-light p-4"><p role="alert" className="text-sm text-error-dark">{this.state.error}</p><Button className="mt-3" variant="outline" onClick={this.props.fallback}>View source files</Button></div> : this.props.children }
}
