import React, { lazy, Suspense, useEffect, useState, useSyncExternalStore } from 'react'
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
import './style.css'

const LocalDemoHost = import.meta.env.VITE_OPS_LOCAL_DEMO === '1' ? lazy(() => import('./LocalDemoHost')) : null

type AccountAction = 'sign-out' | 'switch-account' | 'refresh-session' | 'download-wallet-token'
const actionLabels: Record<AccountAction, string> = { 'sign-out': 'sign out', 'switch-account': 'switch account', 'refresh-session': 'refresh session', 'download-wallet-token': 'download wallet token' }

function SelectedAccount({ controller, state }: { controller: Controller; state: State }) {
  const location = useLocation(), navigate = useNavigate()
  // Confidential imported files are owned by this selected document context.
  // This component is keyed/unmounted by the controller epoch, never persisted.
  const [project, setProject] = useState<SourceProject | null>(null), [leaving, setLeaving] = useState<AccountAction | null>(null)
  useEffect(() => {
    const guard = (event: BeforeUnloadEvent) => { if (project?.dirty) { event.preventDefault(); event.returnValue = '' } }
    window.addEventListener('beforeunload', guard)
    return () => window.removeEventListener('beforeunload', guard)
  }, [project?.dirty])
  const self = state.self!
  const account = location.pathname === '/admin/account'
  const profile = state.profiles.find(p => p.id === self.sourceProfile)
  const provider = profile?.provider === 'azure' ? 'Microsoft Entra ID' : profile?.provider === 'privado' ? 'Privado ID' : 'Verified OPS account'
  const section = location.pathname === '/admin/compliance' ? 'compliance' : ['/admin/disclosure', '/admin/disclosures', '/disclosures'].includes(location.pathname) ? 'disclosures' : location.pathname === '/admin/logs' ? 'logs' : location.pathname === '/admin/diagnostics' ? 'diagnostics' : null
  async function runAccountAction(action: AccountAction) {
    if (!controller.ownsScope(controller.scopeRevision, self.actorId)) return
    if (action === 'sign-out') await controller.logout()
    else if (action === 'switch-account') navigate('/login', { state: { switchAccount: true } })
    else if (action === 'refresh-session') await controller.refresh()
    else await controller.downloadOwnWalletToken()
  }
  async function requestAccountAction(action: AccountAction) { if (project?.dirty) setLeaving(action); else await runAccountAction(action) }
  const signOut = () => requestAccountAction('sign-out')
  const switchAccount = () => { void requestAccountAction('switch-account') }
  const menu = <AccountMenu userDID={self.actorId} providerLabel={provider} busy={state.busy} isAccountPage={account}
    onAccount={() => navigate('/admin/account')} onDashboard={() => navigate('/admin/rbac/organizations')} dashboardLabel="Configuration workspace"
    onSignOut={signOut} />
  return <AdminLayout accountMenu={menu}>
    {account ? <NativeAccountPage controller={controller} state={state} onSignOut={signOut} onSwitchAccount={switchAccount} onRefreshSession={() => { void requestAccountAction('refresh-session') }} onDownloadWalletToken={() => { void requestAccountAction('download-wallet-token') }} />
      : section ? <NativeOperationsPage controller={controller} state={state} section={section} />
      : <>
        <SourceWorkspacePage controller={controller} project={project} onProject={setProject} />
        <section className="mt-5 text-xs text-neutral-500" aria-label="Current verified organization roles">
          <p className="font-medium text-neutral-700 mb-2">Your current verified organization roles</p>
          {self.organizations.length ? <ul className="space-y-2">{self.organizations.map(org => <li key={org.id} className="flex flex-wrap items-center gap-2">
            <span>{org.name}</span><Badge variant="outline">{org.isOrgAdmin ? 'Organization admin' : org.isOrgReadonlyAdmin ? 'Read-only organization admin' : 'Member'}</Badge>
          </li>)}</ul> : <p>No organizations are assigned to this identity by the current approved rules.</p>}
          <p className="mt-2">These roles describe your live session. Imported source files are a local proposal; Git review and deployment control whether a policy change takes effect.</p>
        </section>
      </>}
    <Dialog open={leaving !== null} onOpenChange={open => { if (!open) setLeaving(null) }}><DialogContent><DialogHeader><DialogTitle>Keep your changed source before continuing</DialogTitle></DialogHeader><p className="text-sm text-neutral-500">This action may replace or renew the account context. Export the source first or explicitly discard the local draft before continuing.</p><div className="flex justify-end flex-wrap gap-2"><Button variant="ghost" onClick={() => setLeaving(null)}>Cancel</Button><Button variant="outline" onClick={() => { if (project && controller.ownsScope(controller.scopeRevision, self.actorId)) download('ops-source-package.json', JSON.stringify(sourcePackage(project))) }}>Export source</Button><Button variant="destructive" onClick={() => { const action = leaving; setProject(null); setLeaving(null); if (action) void runAccountAction(action) }}>{leaving ? 'Discard and ' + actionLabels[leaving] : 'Discard and continue'}</Button></div></DialogContent></Dialog>
  </AdminLayout>
}

export function NativeAdminApp({ controller }: { controller: Controller }) {
  const state = useSyncExternalStore(controller.subscribe, controller.snapshot)
  const location = useLocation(), navigate = useNavigate()
  useEffect(() => {
    if (state.phase === 'anonymous' && location.pathname.startsWith('/admin')) navigate('/login', { replace: true })
  }, [location.pathname, navigate, state.phase])
  const content = (demoSlot: React.ReactNode = null, demoBusy = false) => state.phase === 'selected' && state.self && !state.flow && !state.pending && adminLocation(location)
    ? <SelectedAccount key={`${controller.scopeRevision}:${state.self.actorId}`} controller={controller} state={state} />
    : <AuthenticationPage controller={controller} demoSlot={demoSlot} demoBusy={demoBusy} />
  return LocalDemoHost ? <Suspense fallback={content()}><LocalDemoHost controller={controller}>{content}</LocalDemoHost></Suspense> : content()

}

export function mount(controller: Controller) {
  ReactDOM.createRoot(document.getElementById('root')!).render(<React.StrictMode><BrowserRouter><NativeAdminApp controller={controller} /></BrowserRouter></React.StrictMode>)
}
