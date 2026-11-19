import { useEffect, useRef, useState, useSyncExternalStore, type ReactNode } from 'react'
import { useLocation, useNavigate } from 'react-router-dom'
import { Loader2 } from 'lucide-react'
import { DevelopmentIdentityPicker } from '../../components/auth/DevelopmentIdentityPicker'
import { LoginStatus } from '../../components/auth/LoginPresentation'
import { Button } from '../../components/ui/button'
import type { Controller } from './controller'
import { LocalDemoDriver, type DemoEnvironment } from './localDemoDriver'
import { demoOrigin, demoPersonas, type DemoPersona } from './localDemoProtocol'

const labels = { admin: 'Demo Admin', deployer: 'Demo Deployer', reader: 'Demo Reader', outsider: 'Demo Outsider' } as const
function DemoControls({ driver, controller }: { driver: LocalDemoDriver; controller: Controller }) {
  const state = useSyncExternalStore(driver.subscribe, driver.snapshot)
  const native = useSyncExternalStore(controller.subscribe, controller.snapshot)
  return <DevelopmentIdentityPicker identities={demoPersonas.map(id => ({ id, name: labels[id], testId: 'demo-persona-' + id }))}
    disabled={state.active || native.busy} onSelect={id => driver.start(id as DemoPersona)}>
    <p className="mb-3 text-xs text-center text-neutral-500">Public local test identities. These buttons generate a real Privado proof.</p>
    {state.active && <div className="space-y-3" data-testid="demo-signin-progress"><LoginStatus tone="loading" title={'Signing in as ' + labels[state.persona!]}><span className="inline-flex items-center gap-2"><Loader2 className="h-4 w-4 animate-spin" />{state.status}</span></LoginStatus>
      {state.cancellable && <Button variant="ghost" size="sm" className="w-full" onClick={driver.cancel}>Cancel demo sign in</Button>}</div>}
    {state.error && <LoginStatus tone="warning" title="Demo sign-in stopped">{state.error}</LoginStatus>}
  </DevelopmentIdentityPicker>
}
function DriverSlot({ driver, controller, children }: { driver: LocalDemoDriver; controller: Controller; children(slot: ReactNode, active: boolean): ReactNode }) {
  const view = useSyncExternalStore(driver.subscribe, driver.snapshot)
  return <>{children(<DemoControls driver={driver} controller={controller} />, view.active)}</>
}

// This module is dynamically included only in the explicitly selected local
// demo build. It remains mounted while AuthenticationPage branches change.
export default function LocalDemoHost({ controller, children }: { controller: Controller; children(slot: ReactNode, active: boolean): ReactNode }) {
  const navigate = useNavigate(), location = useLocation(), navigateRef = useRef(navigate), previousLocation = useRef(location.key)
  navigateRef.current = navigate
  const [driver, setDriver] = useState<LocalDemoDriver | null>(null)
  const walletOrigin = demoOrigin(import.meta.env.VITE_OPS_DEMO_WALLET_ORIGIN)
  useEffect(() => {
    if (!walletOrigin) return
    const env: DemoEnvironment = {
      walletOrigin, origin: window.location.origin,
      nonce: () => Array.from(crypto.getRandomValues(new Uint8Array(32)), b => b.toString(16).padStart(2, '0')).join(''),
      open: url => window.open(url, '_blank', 'popup,width=480,height=560'),
      listen: fn => { window.addEventListener('message', fn); return () => window.removeEventListener('message', fn) },
      navigate: path => navigateRef.current(path, { replace: true }),
    }
    const current = new LocalDemoDriver(controller, env)
    const stop = () => current.dispose()
    setDriver(current); window.addEventListener('pagehide', stop)
    return () => { window.removeEventListener('pagehide', stop); current.dispose() }
  }, [controller, walletOrigin])
  useEffect(() => {
    if (previousLocation.current !== location.key) { previousLocation.current = location.key; driver?.navigation() }
  }, [driver, location.key])
  if (!walletOrigin) return <>{children(<DevelopmentIdentityPicker identities={demoPersonas.map(id => ({ id, name: labels[id], testId: 'demo-persona-' + id }))} disabled onSelect={() => {}}>
    <LoginStatus tone="warning" title="Demo sign-in is unavailable">The local demo has no valid wallet address. Rebuild it using the local demo setup guide.</LoginStatus>
  </DevelopmentIdentityPicker>, false)}</>
  return driver ? <DriverSlot driver={driver} controller={controller}>{children}</DriverSlot> : <>{children(null, false)}</>
}
