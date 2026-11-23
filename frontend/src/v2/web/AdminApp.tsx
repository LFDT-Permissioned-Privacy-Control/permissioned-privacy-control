import React, { lazy, Suspense, useEffect, useMemo, useSyncExternalStore } from 'react'
import ReactDOM from 'react-dom/client'
import { BrowserRouter, useLocation, useNavigate } from 'react-router-dom'
import { AdminLayout } from '../../components/AdminLayout'
import { AccountMenu } from '../../components/auth/AccountMenu'
import { Controller, State } from './controller'
import { AuthenticationPage } from './AuthenticationPage'
import { NativeAccountPage } from './AccountPage'
import { SourceWorkspacePage } from './SourceWorkspacePage'
import { NativeOperationsPage } from './NativeOperationsPages'
import { adminLocation } from './routes'
import { CONTEXT_KEY } from '../auth/context'
import { hasAdminRole } from './adminAccess'
import { AdminAccessDenied } from '../../components/auth/AdminAccessDenied'
import { Tabs, TabsList, TabsTrigger } from '../../components/ui/tabs'
import { Users, KeyRound, Scale, FileKey, ScrollText, Activity, Settings } from 'lucide-react'
import { getSourcePage, sourcePagePath } from './navigation'
import { ConfigurationViewer } from './configurationViewer'
import { SourceViewProvider } from './sourceViewState'
import './style.css'

const LocalDemoHost = import.meta.env.VITE_OPS_LOCAL_DEMO === '1' ? lazy(() => import('./LocalDemoHost')) : null
function SelectedAccount({ controller, state, viewer }: { controller: Controller; state: State; viewer: ConfigurationViewer }) {
  const location = useLocation(), navigate = useNavigate(), view = useSyncExternalStore(viewer.subscribe, viewer.snapshot)
  const self = state.self!, admin = hasAdminRole(self), account = location.pathname === '/admin/account'
  const profile = state.profiles.find(p => p.id === self.sourceProfile)
  const provider = profile?.provider === 'azure' ? 'Microsoft Entra ID' : profile?.provider === 'privado' ? 'Privado ID' : 'Verified OPS account'
  const section = location.pathname === '/admin/compliance' ? 'compliance' : ['/admin/disclosure', '/admin/disclosures', '/disclosures'].includes(location.pathname) ? 'disclosures' : location.pathname === '/admin/logs' ? 'logs' : location.pathname === '/admin/diagnostics' ? 'diagnostics' : null
  const sourcePage = getSourcePage(location.pathname)
  const activeSection = account ? null : sourcePage?.section === 'configuration' ? 'rbac' : sourcePage?.section ?? (section === 'disclosures' ? 'disclosure' : section)
  const withScope = (path: string) => path + location.search
  useEffect(() => {
    viewer.setActive(admin && !!sourcePage)
    const poll = () => { if (document.visibilityState !== 'hidden') void viewer.refresh() }
    poll()
    const timer = setInterval(poll, 2000)
    window.addEventListener('focus', poll); document.addEventListener('visibilitychange', poll)
    return () => { clearInterval(timer); window.removeEventListener('focus', poll); document.removeEventListener('visibilitychange', poll); viewer.setActive(false) }
  }, [viewer, admin, !!sourcePage])
  const navigation = { activeId: activeSection, items: [
    { id: 'rbac', label: 'RBAC', path: withScope('/admin/rbac/organizations'), icon: <Users className="h-4 w-4" /> },
    { id: 'identity', label: 'Identity', path: withScope('/admin/identity/profiles'), icon: <KeyRound className="h-4 w-4" /> },
    { id: 'compliance', label: 'Compliance', path: withScope('/admin/compliance'), icon: <Scale className="h-4 w-4" /> },
    { id: 'disclosure', label: 'Disclosure', path: withScope('/admin/disclosure'), icon: <FileKey className="h-4 w-4" /> },
    { id: 'logs', label: 'Access Logs', path: withScope('/admin/logs'), icon: <ScrollText className="h-4 w-4" />, secondary: true },
    { id: 'diagnostics', label: 'Diagnostics', path: withScope('/admin/diagnostics'), icon: <Activity className="h-4 w-4" />, secondary: true },
    { id: 'settings', label: 'Settings', path: withScope('/admin/settings'), icon: <Settings className="h-4 w-4" />, secondary: true },
  ] }
  const signOut = () => controller.logout(), switchAccount = () => navigate('/login', { state: { switchAccount: true } })
  const menu = <AccountMenu userDID={self.actorId} providerLabel={provider} busy={state.busy} isAccountPage={account}
    onAccount={() => navigate('/admin/account')} onDashboard={admin ? () => navigate('/admin/rbac/organizations') : undefined} dashboardLabel="Admin dashboard" onSignOut={signOut} />
  const policySection = activeSection === 'compliance' || activeSection === 'disclosure' ? activeSection : null
  const policySource = sourcePage?.id === 'compliance-source' || sourcePage?.id === 'disclosure-source'
  return <AdminLayout accountMenu={menu} showNavigation={admin} navigation={navigation}>
    {admin && policySection && <Tabs value={policySource ? 'source' : 'live'} onValueChange={value => navigate(withScope(value === 'source' ? sourcePagePath(policySection === 'compliance' ? 'compliance-source' : 'disclosure-source') : '/admin/' + policySection))} aria-label={policySection === 'compliance' ? 'Compliance pages' : 'Disclosure pages'}>
      <TabsList className="mb-5"><TabsTrigger value="live">{policySection === 'compliance' ? 'Live data' : 'Cases'}</TabsTrigger><TabsTrigger value="source">{policySection === 'compliance' ? 'Policy' : 'Rules'}</TabsTrigger></TabsList>
    </Tabs>}
    {account ? <NativeAccountPage controller={controller} state={state} onSignOut={signOut} onSwitchAccount={switchAccount} onRefreshSession={() => { void controller.refresh() }} onDownloadWalletToken={() => { void controller.downloadOwnWalletToken() }} onCopyRPCCredential={format => controller.copyOwnRPCCredential(format)} />
      : !admin ? <AdminAccessDenied onAccount={() => navigate('/admin/account', { replace: true })} accountLabel="Go to your account" />
      : !sourcePage && section ? <NativeOperationsPage controller={controller} state={state} section={section} />
      : <SourceViewProvider viewer={viewer} view={view}><SourceWorkspacePage viewer={viewer} view={view} /></SourceViewProvider>}
  </AdminLayout>
}

export function NativeAdminApp({ controller }: { controller: Controller }) {
  const state = useSyncExternalStore(controller.subscribe, controller.snapshot), viewer = useMemo(() => new ConfigurationViewer(controller), [controller])
  const location = useLocation(), navigate = useNavigate()
  useEffect(() => {
    const stop = controller.subscribe(viewer.observe)
    const storage = (event: StorageEvent) => { if (event.key === CONTEXT_KEY || event.key === null) viewer.observe() }
    const timer = setInterval(viewer.observe, 1000)
    window.addEventListener('storage', storage); window.addEventListener('pagehide', viewer.clear); viewer.observe()
    return () => { stop(); clearInterval(timer); window.removeEventListener('storage', storage); window.removeEventListener('pagehide', viewer.clear); viewer.clear() }
  }, [controller, viewer])
  useEffect(() => { if (state.phase === 'anonymous' && location.pathname.startsWith('/admin')) navigate('/login', { replace: true }) }, [location.pathname, navigate, state.phase])
  const content = (demoSlot: React.ReactNode = null, demoBusy = false) => state.phase === 'selected' && state.self && state.self.expiresAt * 1000 > Date.now() && !state.flow && !state.pending && adminLocation(location)
    ? <SelectedAccount key={`${controller.scopeRevision}:${state.self.actorId}`} controller={controller} state={state} viewer={viewer} />
    : <AuthenticationPage controller={controller} demoSlot={demoSlot} demoBusy={demoBusy} />
  return LocalDemoHost ? <Suspense fallback={content()}><LocalDemoHost controller={controller}>{content}</LocalDemoHost></Suspense> : content()
}
export function mount(controller: Controller) {
  ReactDOM.createRoot(document.getElementById('root')!).render(<React.StrictMode><BrowserRouter><NativeAdminApp controller={controller} /></BrowserRouter></React.StrictMode>)
}
