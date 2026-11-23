import { useEffect, useState, useSyncExternalStore, type ReactNode } from 'react'
import { Link, useLocation } from 'react-router-dom'
import { ExternalLink, Loader2 } from 'lucide-react'
import { QRCodeSVG } from 'qrcode.react'
import { LoginCard, LoginFrame, LoginStatus, MicrosoftLoginPanel, PrivadoBrandPanel } from '../../components/auth/LoginPresentation'
import { MicrosoftIcon, PrivadoIcon } from '../../components/auth/ProviderIcons'
import { Button } from '../../components/ui/button'
import { Controller, State } from './controller'
import { hasAdminRole } from './adminAccess'
import { walletLinks } from './protocol'

type Provider = 'azure' | 'privado'
export function authenticationFeedback(error: string): { tone: 'warning' | 'error'; title: string; message: string } {
  if (error === 'flow_expired') return { tone: 'warning', title: 'Application sign-in expired', message: 'Return to the application and start sign-in again.' }
  if (error === 'proof_expired') return { tone: 'warning', title: 'Wallet verification expired', message: 'Start a new sign-in to generate another verification request.' }
  if (error === 'login_required') return { tone: 'warning', title: 'Sign in to continue', message: 'Your previous sign-in could not be restored. If you came from an application, return there and start sign-in again.' }
  if (error === 'provider_rejected') return { tone: 'error', title: 'Sign-in was declined', message: 'Your identity provider declined this sign-in. You can start again.' }
  if (error === 'invalid_response' || error === 'invalid_callback') return { tone: 'error', title: 'Sign-in could not be verified', message: 'Start a new sign-in. An interrupted request is not retried.' }
  return { tone: 'error', title: 'Sign-in is unavailable', message: 'Try again, or contact your administrator if this continues. An interrupted request is not retried.' }
}
function Feedback({ state }: { state: State }) {
  if (!state.error || state.ordinaryEntry && state.error === 'login_required') return null
  const feedback = authenticationFeedback(state.error)
  return <LoginStatus tone={feedback.tone} title={feedback.title}>{feedback.message}</LoginStatus>
}

export function AuthenticationPage({ controller, demoSlot, demoBusy = false, notice }: { controller: Controller; demoSlot?: ReactNode; demoBusy?: boolean; notice?: ReactNode }) {
  const state = useSyncExternalStore(controller.subscribe, controller.snapshot)
  const location = useLocation()
  const [preferred, setPreferred] = useState<Provider>('privado')
  useEffect(() => { if (state.ordinaryEntry && !demoBusy) void controller.prepareLogin() }, [controller, state.ordinaryEntry, demoBusy])
  const providers = [...new Set(state.profiles.map(profile => profile.provider))]
  const active = state.pending?.provider ?? (providers.includes(preferred) ? preferred : providers[0])
  const profiles = state.profiles.filter(profile => profile.provider === active)
  const links = state.pending?.requestUri ? walletLinks(state.pending.requestUri) : null
  const demoRenewal = !!demoSlot && state.pending?.status === 'proof_required' && state.pending.provider === 'privado' && state.pending.mode === 'renew'
  const demoLogin = !!demoSlot && state.pending?.status === 'login_in_progress' && state.pending.provider === 'privado' && !state.candidate
  const switching = (location.state as { switchAccount?: boolean } | null)?.switchAccount === true
  const selected = state.phase === 'selected' && !!state.self && state.self.expiresAt * 1000 > Date.now() && !state.pending && (!switching || !!state.flow)
  const title = state.phase === 'context-changed' ? 'Choose your account' : selected ? state.flow ? 'Continue to application' : 'Signed In' : state.pending?.status === 'proof_required' ? 'Verify Your Identity' : 'Sign In'
  const description = state.flow ? <>Continue to <strong data-field="app">{state.flow.displayName}</strong> after signing in.</> : active === 'azure' ? 'Use your Microsoft or corporate account' : 'Verify with your Privado ID wallet'
  const canChoose = !state.pending && !selected && state.phase !== 'booting' && !demoBusy
  const chooseMicrosoft = async () => {
    const flow = state.flow
    await controller.cancel()
    const current = controller.snapshot()
    if (current.phase === 'anonymous' && !current.pending && !current.self && !current.error && current.flow === flow) setPreferred('azure')
  }
  const walletPrompt = links && !state.candidate && <><div className="flex flex-col items-center gap-4"><div className="p-4 bg-white rounded-2xl shadow-lg" role="img" aria-label="QR code for Privado ID authentication" data-testid="qr-code"><QRCodeSVG value={links.mobile} size={200} level="M" aria-hidden="true" /></div><p className="text-center text-sm text-neutral-500">Scan with your Privado ID wallet</p></div><div className="border-t border-neutral-200 pt-4"><p className="mb-3 text-center text-xs text-neutral-700">Or open the wallet on this device</p><Button asChild variant="outline" size="sm" className="w-full"><a href={links.mobile} rel="noreferrer"><ExternalLink className="h-4 w-4 mr-2" />Open Wallet App</a></Button><a className="block mt-3 text-center text-xs text-primary underline underline-offset-2" href={links.web} target="_blank" rel="noreferrer noopener">Open Privado web wallet</a></div><div className="flex items-center justify-center gap-2 text-sm text-neutral-700" role="status"><Loader2 className="h-4 w-4 animate-spin" /><span>Waiting for wallet confirmation…</span></div></>
  const options = profiles.map(profile => <div key={profile.id} className="w-full">
    <Button onClick={() => void controller.login(profile.id, profile.provider)} disabled={state.busy} aria-describedby={profiles.length > 1 ? 'connection-' + profile.id : undefined} className={`w-full ${profile.provider === 'azure' ? 'bg-[#0078d4] hover:bg-[#106ebe] text-white' : ''}`} size="lg" data-profile-id={profile.id} data-testid={profile.provider === 'azure' ? 'azure-signin-btn' : 'privado-signin-btn'}>
      {state.busy ? <Loader2 className="h-5 w-5 mr-2 animate-spin" /> : profile.provider === 'azure' ? <MicrosoftIcon className="h-5 w-5 mr-2" /> : <PrivadoIcon className="h-5 w-5 mr-2" />}
      Continue with {profile.provider === 'azure' ? 'Microsoft' : 'Privado ID'}
    </Button>
    {profiles.length > 1 && <p id={'connection-' + profile.id} className="mt-1 text-center text-xs text-neutral-500">Connection: {profile.id}</p>}
  </div>)
  const providerTabs = canChoose && providers.length > 1 && <div className="flex border-b border-neutral-200 mx-6" role="tablist" aria-label="Sign-in provider">{providers.map(provider => <button key={provider} disabled={state.busy} onClick={() => setPreferred(provider)} role="tab" aria-selected={active === provider} className={`flex-1 py-2 text-sm font-medium transition-colors ${active === provider ? 'border-b-2 border-primary text-primary' : 'text-neutral-500 hover:text-neutral-700'}`} data-testid={provider === 'azure' ? 'tab-azuread' : 'tab-privado'}>{provider === 'azure' ? 'Microsoft' : 'Privado ID'}</button>)}</div>
  const providerPanel = active === 'azure' ? <MicrosoftLoginPanel><div className="w-full space-y-4">{options}</div></MicrosoftLoginPanel> : active === 'privado' ? <div className="space-y-6 py-6"><PrivadoBrandPanel /><div className="space-y-4">{options}</div></div> : <p className="py-6 text-center text-sm text-neutral-500">No browser login profiles are available.</p>
  return <LoginFrame>
    <LoginCard title={title} description={description} tabs={demoSlot ? undefined : providerTabs}>
      {state.phase === 'booting' && <LoginStatus tone="loading" title={state.busy ? 'Preparing authentication…' : 'Checking your session…'} />}
      {state.phase === 'context-changed' && <><LoginStatus tone="warning" title="The account changed in another tab">Previous account data has been cleared. Use the current session or choose a sign-in below.</LoginStatus><Button className="w-full mb-5" onClick={() => void controller.useCurrent()}>Use current session</Button></>}
      <Feedback state={state} />
      {notice}
      {selected && state.self && !demoBusy && <div className="space-y-5">
        <LoginStatus tone="success" title="Authentication successful!">{state.flow ? 'Confirm this account to continue to the application.' : 'Your account is ready.'}</LoginStatus>
        <div className="rounded-lg bg-neutral-50 p-3"><p className="text-xs text-neutral-400 uppercase tracking-wide mb-1">OPS identity</p><p data-field="actorId" className="break-all font-mono text-xs text-neutral-700">{state.self.actorId}</p></div>
        {state.flow ? <Button className="w-full" disabled={state.busy} onClick={() => void controller.continue()}>{state.busy && <Loader2 className="h-4 w-4 mr-2 animate-spin" />}{state.busy ? 'Continuing…' : 'Continue to application'}</Button> : <><Button asChild className="w-full"><Link to="/admin/account">Open account</Link></Button>{hasAdminRole(state.self) && <Button asChild variant="outline" className="w-full"><Link to="/admin/rbac/organizations">Open configuration viewer</Link></Button>}</>}
        <Button variant="ghost" size="sm" className="w-full" disabled={state.busy} onClick={() => void controller.logout()}>Sign out of OPS</Button>
      </div>}
      {state.pending && !demoBusy && <div className="space-y-6" aria-label="Pending authentication">
        {state.pending.provider === 'azure' && <LoginStatus tone="warning" title="Microsoft sign-in is unfinished">Finish the Microsoft sign-in you started. If it was interrupted, cancel this attempt and start again.</LoginStatus>}
        {state.pending.provider === 'privado' && !demoRenewal && <PrivadoBrandPanel />}
        {state.pending.status === 'proof_required' && <p className="text-sm text-neutral-500 text-center">Your identity needs a fresh wallet proof. Verify again to continue; previous account data stays hidden.</p>}
        {walletPrompt}
        {state.candidate && <div className="space-y-4" aria-label="Choose account"><LoginStatus tone="success" title="Confirm your identity">Use this verified wallet identity to sign in.</LoginStatus><dl className="space-y-3 rounded-lg bg-neutral-50 p-4 text-xs"><div><dt className="text-neutral-400 uppercase tracking-wide">Holder DID</dt><dd data-field="holderDid" className="mt-1 break-all font-mono text-neutral-700">{state.candidate.holderDid}</dd></div><div><dt className="text-neutral-400 uppercase tracking-wide">Network</dt><dd data-field="network" className="mt-1 text-neutral-700">{state.candidate.network}</dd></div><div><dt className="text-neutral-400 uppercase tracking-wide">Connection</dt><dd className="mt-1 text-neutral-700">{state.candidate.sourceProfile}</dd></div></dl><Button className="w-full" disabled={state.busy} onClick={() => void controller.confirm()}>{state.busy && <Loader2 className="h-4 w-4 mr-2 animate-spin" />}{state.busy ? 'Confirming identity…' : 'Use this identity'}</Button></div>}
        {state.pending.requestUri && <details className="text-xs text-neutral-500"><summary className="cursor-pointer">Verification request details</summary><code data-field="requestUri" className="block mt-2 break-all rounded-lg bg-neutral-50 p-3">{state.pending.requestUri}</code></details>}
        <Button variant="ghost" size="sm" disabled={state.busy} className="w-full" onClick={() => void controller.cancel()}>Cancel sign in</Button>
        {state.pending.status === 'login_in_progress' && state.pending.provider === 'privado' && !state.candidate && providers.includes('azure') && <Button variant="outline" className="w-full" disabled={state.busy} onClick={() => { void chooseMicrosoft() }}>Sign in with Microsoft instead</Button>}
      </div>}
      {(canChoose || demoBusy || demoRenewal || demoLogin) && demoSlot}
      {demoRenewal && demoBusy && <Button variant="ghost" size="sm" disabled={state.busy} className="w-full" onClick={() => void controller.cancel()}>Cancel sign in</Button>}
      {canChoose && <>{demoSlot && providerTabs}{providerPanel}</>}
      {switching && state.self && !state.pending && <Button asChild variant="ghost" size="sm" className="w-full"><Link to="/admin/account">Keep current account</Link></Button>}
    </LoginCard>
    {active === 'privado' && !selected && !demoSlot && <div className="mt-6 text-center"><p className="text-sm text-neutral-700">Don't have Privado ID? <a href="https://docs.privado.id/docs/wallet/wallet-app/privadoid-app/" target="_blank" rel="noopener noreferrer" className="text-primary underline underline-offset-2 hover:text-primary-300">Download the wallet</a></p></div>}
  </LoginFrame>
}
