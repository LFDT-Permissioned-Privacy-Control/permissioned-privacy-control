import React, { lazy, Suspense, useEffect, useMemo, useState, useSyncExternalStore } from 'react'
import ReactDOM from 'react-dom/client'
import { BrowserRouter, useLocation, useNavigate } from 'react-router-dom'
import { AdminLayout } from '../../components/AdminLayout'
import { AccountMenu } from '../../components/auth/AccountMenu'
import { Badge } from '../../components/ui/badge'
import { Controller, State } from './controller'
import { AuthenticationPage } from './AuthenticationPage'
import { NativeAccountPage } from './AccountPage'
import { SourceWorkspacePage } from './SourceWorkspacePage'
import { sourcePackage, type SourceProject } from './sourceProject'
import { download } from './SourceReview'
import { NativeOperationsPage } from './NativeOperationsPages'
import { Button } from '../../components/ui/button'
import { Dialog, DialogContent, DialogHeader, DialogTitle } from '../../components/ui/dialog'
import { adminLocation } from './routes'
import { CONTEXT_KEY } from '../auth/context'
import { SourceDraftMemory } from './sourceDraftMemory'
import { SourceAuthoringProvider } from './SourceAuthoringScope'
import { hasAdminRole } from './adminAccess'
import { AdminAccessDenied } from '../../components/auth/AdminAccessDenied'
import { Tabs, TabsList, TabsTrigger } from '../../components/ui/tabs'
import { Users, KeyRound, Scale, FileKey, ScrollText, Activity, Settings, FileCheck } from 'lucide-react'
import { getSourcePage, sourcePagePath } from './navigation'
import './style.css'

const LocalDemoHost = import.meta.env.VITE_OPS_LOCAL_DEMO === '1' ? lazy(() => import('./LocalDemoHost')) : null

type AccountAction = 'sign-out' | 'switch-account' | 'refresh-session' | 'download-wallet-token' | 'copy-token' | 'copy-header' | 'copy-foundry'
const actionLabels: Record<AccountAction, string> = { 'sign-out': 'sign out', 'switch-account': 'switch account', 'refresh-session': 'refresh session', 'download-wallet-token': 'download wallet token', 'copy-token': 'copy access token', 'copy-header': 'copy Authorization header', 'copy-foundry': 'copy for Foundry' }

function SelectedAccount({ controller, state, draft }: { controller: Controller; state: State; draft: SourceDraftMemory }) {
  const location = useLocation(), navigate = useNavigate()
  const {project, authoring, epoch, locked, dirty, unfinished} = useSyncExternalStore(draft.subscribe, draft.snapshot)
  const [leaving, setLeaving] = useState<AccountAction | null>(null)
  const self = state.self!
  const admin = hasAdminRole(self)
  const scope = controller.scopeRevision
  const setProject = (next: SourceProject | null, replace = false) => { if (epoch === draft.snapshot().epoch) draft.write(next, scope, self.actorId, replace, project, authoring) }
  const account = location.pathname === '/admin/account'
  const profile = state.profiles.find(p => p.id === self.sourceProfile)
  const provider = profile?.provider === 'azure' ? 'Microsoft Entra ID' : profile?.provider === 'privado' ? 'Privado ID' : 'Verified OPS account'
  const section = location.pathname === '/admin/compliance' ? 'compliance' : ['/admin/disclosure', '/admin/disclosures', '/disclosures'].includes(location.pathname) ? 'disclosures' : location.pathname === '/admin/logs' ? 'logs' : location.pathname === '/admin/diagnostics' ? 'diagnostics' : null
  const sourcePage = getSourcePage(location.pathname)
  const activeSection = account ? null : sourcePage?.section === 'configuration' ? null : sourcePage?.section ?? (section === 'disclosures' ? 'disclosure' : section)
  const withScope = (path: string) => path + location.search
  const navigation = {
    activeId: activeSection,
    items: [
      { id: 'rbac', label: 'RBAC', path: withScope('/admin/rbac/organizations'), icon: <Users className="h-4 w-4" /> },
      { id: 'identity', label: 'Identity', path: withScope('/admin/identity/profiles'), icon: <KeyRound className="h-4 w-4" /> },
      { id: 'compliance', label: 'Compliance', path: withScope('/admin/compliance'), icon: <Scale className="h-4 w-4" /> },
      { id: 'disclosure', label: 'Disclosure', path: withScope('/admin/disclosure'), icon: <FileKey className="h-4 w-4" /> },
      { id: 'logs', label: 'Access Logs', path: withScope('/admin/logs'), icon: <ScrollText className="h-4 w-4" />, secondary: true },
      { id: 'diagnostics', label: 'Diagnostics', path: withScope('/admin/diagnostics'), icon: <Activity className="h-4 w-4" />, secondary: true },
      { id: 'settings', label: 'Settings', path: withScope('/admin/settings'), icon: <Settings className="h-4 w-4" />, secondary: true },
    ],
    action: <Button variant={sourcePage?.id === 'configuration' ? 'secondary' : 'outline'} size="sm" data-testid="review-export-action" onClick={() => navigate(withScope(sourcePagePath('configuration')))}><FileCheck className="h-4 w-4 mr-2" />Review &amp; export</Button>,
  }
  const policySection = activeSection === 'compliance' || activeSection === 'disclosure' ? activeSection : null
  const policyDraft = sourcePage?.id === 'compliance-source' || sourcePage?.id === 'disclosure-source'
  async function runAccountAction(action: AccountAction) {
    if (!controller.ownsScope(controller.scopeRevision, self.actorId)) return false
    if (action === 'sign-out') await controller.logout()
    else if (action === 'switch-account') navigate('/login', { state: { switchAccount: true } })
    else if (action === 'refresh-session') await controller.refresh()
    else if (action === 'download-wallet-token') await controller.downloadOwnWalletToken()
    else return controller.copyOwnRPCCredential(action === 'copy-token' ? 'token' : action === 'copy-header' ? 'header' : 'foundry')
    return false
  }
  async function requestAccountAction(action: AccountAction) { if (dirty) { setLeaving(action); return false }; return runAccountAction(action) }
  const signOut = async () => { await requestAccountAction('sign-out') }
  const switchAccount = () => { void requestAccountAction('switch-account') }
  const menu = <AccountMenu userDID={self.actorId} providerLabel={provider} busy={state.busy} isAccountPage={account}
    onAccount={() => navigate('/admin/account')} onDashboard={admin ? () => navigate('/admin/rbac/organizations') : undefined} dashboardLabel="Configuration workspace"
    onSignOut={signOut} />
  return <AdminLayout accountMenu={menu} showNavigation={admin} navigation={navigation}>
    <SourceAuthoringProvider project={project} state={authoring} update={(key, entry) => draft.writeAuthoring(key, entry, scope, self.actorId, epoch)} clear={prefix => draft.clearAuthoring(prefix, scope, self.actorId, epoch)}>
    {admin && policySection && <Tabs value={policyDraft ? 'draft' : 'live'} onValueChange={value => navigate(withScope(value === 'draft' ? sourcePagePath(policySection === 'compliance' ? 'compliance-source' : 'disclosure-source') : '/admin/' + policySection))} aria-label={policySection === 'compliance' ? 'Compliance pages' : 'Disclosure pages'}>
      <TabsList className="mb-5"><TabsTrigger value="live">{policySection === 'compliance' ? 'Live data' : 'Cases'}</TabsTrigger><TabsTrigger value="draft">{policySection === 'compliance' ? 'Policy draft' : 'Rules draft'}</TabsTrigger></TabsList>
    </Tabs>}
    {account ? <NativeAccountPage controller={controller} state={state} onSignOut={signOut} onSwitchAccount={switchAccount} onRefreshSession={() => { void requestAccountAction('refresh-session') }} onDownloadWalletToken={() => { void requestAccountAction('download-wallet-token') }} onCopyRPCCredential={format => requestAccountAction(format === 'token' ? 'copy-token' : format === 'header' ? 'copy-header' : 'copy-foundry')} />
      : !admin ? <AdminAccessDenied onAccount={() => navigate('/admin/account', { replace: true })} accountLabel="Go to your account" />
      : !sourcePage && section ? <NativeOperationsPage controller={controller} state={state} section={section} />
      : <>
        {locked ? <p className="rounded-lg border border-neutral-200 bg-neutral-50 p-4 text-sm text-neutral-500" role="status">Your source draft is kept in this tab while your session is checked.</p> : <SourceWorkspacePage key={epoch} controller={controller} project={project} onProject={setProject} unfinished={unfinished} />}
        <section className="mt-5 text-xs text-neutral-500" aria-label="Current verified organization roles">
          <p className="font-medium text-neutral-700 mb-2">Your current verified organization roles</p>
          {self.organizations.length ? <ul className="space-y-2">{self.organizations.map(org => <li key={org.id} className="flex flex-wrap items-center gap-2">
            <span>{org.name}</span><Badge variant="outline">{org.isOrgAdmin ? 'Organization admin' : org.isOrgReadonlyAdmin ? 'Read-only organization admin' : 'Member'}</Badge>
          </li>)}</ul> : <p>No organizations are assigned to this identity by the current approved rules.</p>}
          <p className="mt-2">These roles describe your live session. Imported source files are a local proposal; Git review and deployment control whether a policy change takes effect.</p>
        </section>
      </>}
    </SourceAuthoringProvider>
    <Dialog open={leaving !== null} onOpenChange={open => { if (!open) setLeaving(null) }}><DialogContent><DialogHeader><DialogTitle>Keep your changed source before continuing</DialogTitle></DialogHeader><p className="text-sm text-neutral-500">This action may replace or renew the account context. Export the source first or explicitly discard the local draft before continuing.</p>{unfinished && <p className="text-sm text-warning-dark">Unfinished form fields are not part of a source export. Cancel this action, then save or cancel those fields first.</p>}<div className="flex justify-end flex-wrap gap-2"><Button variant="ghost" onClick={() => setLeaving(null)}>Cancel</Button><Button variant="outline" disabled={unfinished} onClick={() => { if (project && !unfinished && controller.ownsScope(controller.scopeRevision, self.actorId)) download('ops-source-package.json', JSON.stringify(sourcePackage(project))) }}>Export source</Button><Button variant="destructive" onClick={() => { const action = leaving; setProject(null); setLeaving(null); if (action) void runAccountAction(action) }}>{leaving ? 'Discard and ' + actionLabels[leaving] : 'Discard and continue'}</Button></div></DialogContent></Dialog>
  </AdminLayout>
}

export function NativeAdminApp({ controller }: { controller: Controller }) {
  const state = useSyncExternalStore(controller.subscribe, controller.snapshot)
  const draft = useMemo(() => new SourceDraftMemory(controller), [controller])
  const draftView = useSyncExternalStore(draft.subscribe, draft.snapshot)
  const location = useLocation(), navigate = useNavigate()
  useEffect(() => {
    const stop = controller.subscribe(draft.observe)
    const storage = (event: StorageEvent) => { if (event.key === CONTEXT_KEY || event.key === null) draft.observe() }
    const beforeUnload = (event: BeforeUnloadEvent) => { if (draft.snapshot().dirty) { event.preventDefault(); event.returnValue = '' } }
    window.addEventListener('storage', storage); window.addEventListener('beforeunload', beforeUnload)
    window.addEventListener('pagehide', draft.clear)
    draft.observe()
    return () => { stop(); window.removeEventListener('storage', storage); window.removeEventListener('beforeunload', beforeUnload); window.removeEventListener('pagehide', draft.clear); draft.clear() }
  }, [controller, draft])
  useEffect(() => {
    if (state.phase === 'anonymous' && location.pathname.startsWith('/admin')) navigate('/login', { replace: true })
  }, [location.pathname, navigate, state.phase])
  const content = (demoSlot: React.ReactNode = null, demoBusy = false) => state.phase === 'selected' && state.self && state.self.expiresAt * 1000 > Date.now() && !state.flow && !state.pending && adminLocation(location)
    ? <SelectedAccount key={`${controller.scopeRevision}:${state.self.actorId}`} controller={controller} state={state} draft={draft} />
    : <AuthenticationPage controller={controller} demoSlot={demoSlot} demoBusy={demoBusy} notice={draftView.locked && <p role="status" className="mb-5 rounded-lg border border-primary/20 bg-primary-50 p-3 text-xs text-neutral-700">Your draft is kept here while you verify this account. It is discarded if sign-in fails or is canceled, you change account, or you close or reload this tab.</p>} />
  // The buffer stays above short-lived selected-account components. No source
  // bytes are rendered during proof_required or other locked transitions.
  return LocalDemoHost ? <Suspense fallback={content()}><LocalDemoHost controller={controller}>{content}</LocalDemoHost></Suspense> : content()

}

export function mount(controller: Controller) {
  ReactDOM.createRoot(document.getElementById('root')!).render(<React.StrictMode><BrowserRouter><NativeAdminApp controller={controller} /></BrowserRouter></React.StrictMode>)
}
