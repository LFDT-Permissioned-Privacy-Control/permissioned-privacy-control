import React, { useSyncExternalStore } from 'react'
import ReactDOM from 'react-dom/client'
import { flushSync } from 'react-dom'
import { QRCodeSVG } from 'qrcode.react'
import { Controller } from './web/controller'
import { walletLinks } from './web/protocol'
import './web/style.css'

// Deliberately document-owned, outside React/StrictMode effects. Azure query
// scrubbing happens synchronously before rendering or any providers request.
const controller = new Controller(undefined, clear => flushSync(clear))
const callback = location.pathname === '/auth/azure/callback' ? controller.callback() : undefined

function App() {
  const state = useSyncExternalStore(controller.subscribe, controller.snapshot)
  const links = state.pending?.requestUri ? walletLinks(state.pending.requestUri) : null
  return <main>
    <h1>OPS sign in</h1>
    {state.flow && <p>Continue to <strong data-field="app">{state.flow.displayName}</strong> after signing in.</p>}
    {state.phase === 'booting' && <p role="status">Checking your session…</p>}
    {state.phase === 'context-changed' && <section role="alert">
      <h2>The account changed in another tab</h2>
      <p>Previous account data has been cleared. Choose whether to use the current session or sign in again.</p>
      <button onClick={() => void controller.useCurrent()}>Use current session</button>
    </section>}
    {state.error && <p role="alert">{state.error === 'login_required'
      ? 'Sign in again. If an application login expired or was interrupted, return to that application and start a new login.'
      : 'This operation could not be completed. Start a new login; an interrupted operation is not retried.'}</p>}
    {state.self && <section aria-label="Current account">
      <h2>Your account</h2>
      <dl>
        <dt>Actor</dt><dd data-field="actorId">{state.self.actorId}</dd>
        <dt>Profile</dt><dd data-field="sourceProfile">{state.self.sourceProfile}</dd>
        <dt>Session expires</dt><dd>{new Date(state.self.expiresAt * 1000).toISOString()}</dd>
      </dl>
      <h3>Organizations</h3>
      {state.self.organizations.length ? <ul>{state.self.organizations.map(org => <li key={org.id}>
        <strong>{org.name}</strong> ({org.slug}){org.isOrgAdmin ? ' · Organization admin' : org.isOrgReadonlyAdmin ? ' · Read-only organization admin' : ''}
      </li>)}</ul> : <p>No organizations are assigned by the current approved rules.</p>}
      {state.flow && <button disabled={state.busy} onClick={() => void controller.continue()}>Continue to application</button>}
      <button disabled={state.busy} onClick={() => void controller.refresh()}>Refresh session</button>
      <button disabled={state.busy} onClick={() => void controller.logout()}>Sign out of OPS</button>
    </section>}
    {state.pending && <section aria-label="Pending authentication">
      <h2>{state.pending.status === 'proof_required' ? 'Verify your current account again' : 'Complete sign in'}</h2>
      <p>Provider: <strong data-field="provider">{state.pending.provider === 'privado' ? 'Privado' : 'Azure'}</strong></p>
      <p>Profile: <strong data-field="pendingProfile">{state.pending.sourceProfile}</strong></p>
      {links && <>
        <p>Open your Privado wallet or scan this code. Keep this OPS tab open.</p>
        <QRCodeSVG value={links.mobile} size={224} level="M" aria-label="Open the Privado verification request" />
        <p><a href={links.mobile} rel="noreferrer">Open mobile wallet</a> · <a href={links.web} target="_blank" rel="noreferrer noopener">Open web wallet</a></p>
        <details><summary>Verification request</summary><code data-field="requestUri">{state.pending.requestUri}</code></details>
      </>}
      {state.candidate && <section aria-label="Choose account">
        <h3>Choose this account to sign in</h3>
        <dl>
          <dt>Holder DID</dt><dd data-field="holderDid">{state.candidate.holderDid}</dd>
          <dt>Network</dt><dd data-field="network">{state.candidate.network}</dd>
          <dt>Profile</dt><dd>{state.candidate.sourceProfile}</dd>
        </dl>
        <p>This confirms your identity for sign in.</p>
        <button disabled={state.busy} onClick={() => void controller.confirm()}>Use this identity</button>
      </section>}
      <button disabled={state.busy} onClick={() => void controller.cancel()}>Cancel sign in</button>
    </section>}
    {state.phase !== 'booting' && <section aria-label="Sign in options">
      <h2>{state.self ? 'Use another account' : 'Sign in'}</h2>
      {state.profiles.map(profile => <button key={profile.id} disabled={state.busy}
        onClick={() => void controller.login(profile.id, profile.provider)}>
        Sign in with {profile.provider === 'azure' ? 'Azure' : 'Privado'} · {profile.id}
      </button>)}
      {!state.profiles.length && <p>No browser login profiles are available.</p>}
    </section>}
  </main>
}

ReactDOM.createRoot(document.getElementById('root')!).render(<React.StrictMode><App /></React.StrictMode>)
void controller.start(callback)
