import { useEffect, useSyncExternalStore } from 'react'
import { AlertCircle, Link2, Loader2, RefreshCw, Wallet } from 'lucide-react'
import { LinkedAddressesCard, LinkedAddressRows } from '../../components/auth/AccountPresentation'
import { Button } from '../../components/ui/button'
import { WalletController } from './wallet'

export function WalletPanel({ wallet, sessionBusy = false }: { wallet: WalletController; sessionBusy?: boolean }) {
  const state = useSyncExternalStore(wallet.subscribe, wallet.snapshot)
  useEffect(() => {
    let mounted = true
    // StrictMode's discarded mount must not start a second owned read.
    queueMicrotask(() => { if (mounted && !sessionBusy) void wallet.load() })
    return () => { mounted = false; wallet.cancel() }
  }, [wallet, sessionBusy])
  const activeLink = state.task === 'linking'
  const cancel = () => { wallet.cancel(); void wallet.load() }
  return <LinkedAddressesCard actions={<Button variant="ghost" size="icon" disabled={sessionBusy || state.busy || activeLink || !!state.unlink} onClick={() => void wallet.load()} aria-label="Refresh linked addresses" title="Refresh linked addresses"><RefreshCw className="h-4 w-4" /></Button>}>
    <section aria-label="Your wallet links" className="space-y-4">
      {state.error && <div role="alert" className="flex items-start gap-3 rounded-lg border border-error/30 bg-error-light p-3"><AlertCircle className="mt-0.5 h-5 w-5 flex-shrink-0 text-error-dark" /><p className="text-sm text-error-dark">{state.error}</p></div>}
      {state.links.length > 0 && <LinkedAddressRows addresses={state.links.map(link => ({ address: link.address, secondary: 'Verified ' + new Date(link.verifiedAt).toLocaleString() }))} actions={address => <Button variant="ghost" size="sm" disabled={state.busy || !!state.unlink || activeLink} onClick={() => wallet.prepareUnlink(address)}>Unlink</Button>} />}
      {!state.links.length && !activeLink && !state.unlink && <p className="text-sm text-neutral-400">{sessionBusy ? 'Checking your session…' : state.loaded ? 'No linked Ethereum addresses' : state.busy ? 'Loading linked addresses…' : 'Linked addresses could not be checked. Refresh to try again.'}</p>}
      {!activeLink && !state.unlink && <Button variant="outline" size="sm" disabled={sessionBusy || state.busy} className="gap-2" onClick={() => void wallet.connect()}><Wallet className="h-4 w-4" />Link Wallet</Button>}
      {activeLink && <div className="space-y-4 rounded-xl border border-neutral-200 bg-white p-4 shadow-card" data-testid="wallet-link-step">
        <div className="flex items-center gap-3"><div className="flex h-10 w-10 items-center justify-center rounded-full bg-primary-50"><Wallet className="h-5 w-5 text-primary" /></div><div className="min-w-0"><p className="text-sm font-medium text-neutral-900">{state.stage === 'idle' ? 'Connect your wallet' : state.stage === 'choose' ? 'Choose an address' : state.stage === 'sign' ? 'Prove wallet ownership' : 'Confirm address link'}</p>{state.selected && <p className="break-all font-mono text-xs text-neutral-500">{state.selected}</p>}</div></div>
        {state.stage === 'idle' && <p className="text-sm text-neutral-500">OPS is checking your identity and requesting available wallet addresses. Approve the connection in your wallet if prompted.</p>}
        {state.stage === 'choose' && <div className="space-y-2">{state.accounts.map(address => <Button key={address} variant="outline" className="w-full font-mono text-xs" disabled={state.busy} onClick={() => void wallet.select(address)}>{address}</Button>)}</div>}
        {state.stage === 'sign' && <><p className="text-sm text-neutral-500">Sign a message in your connected wallet to prove that you control this address. This does not authorize a transaction.</p><Button disabled={state.busy} className="w-full gap-2" onClick={() => void wallet.sign()}><Link2 className="h-4 w-4" />Sign ownership proof</Button></>}
        {state.stage === 'confirm' && <><p className="text-sm text-neutral-500">Your ownership proof is signed. Confirm to save the link to your OPS identity.</p><Button disabled={state.busy} className="w-full" onClick={() => void wallet.confirm()}>Confirm link</Button></>}
        {state.message && <details className="text-xs text-neutral-500"><summary className="cursor-pointer">Ownership proof details</summary><pre className="mt-2 max-h-48 overflow-auto whitespace-pre-wrap break-all rounded-lg bg-neutral-50 p-3">{state.message}</pre></details>}
        {!state.submitting && <Button variant="ghost" size="sm" onClick={cancel}>Cancel linking</Button>}
        {!state.submitting && state.busy && <p className="text-xs text-neutral-400">Canceling here stops this OPS step. Dismiss any open prompt in your wallet separately.</p>}
      </div>}
      {state.unlink && <div className="space-y-3 rounded-lg border border-warning/30 bg-warning-light p-4" role="alert"><p className="text-sm font-medium text-neutral-900">Permanently unlink this address?</p><p className="break-all font-mono text-xs text-neutral-700">{state.unlink}</p><p className="text-sm text-neutral-600">This address cannot be linked to this OPS identity again under the current deployment rules. There is no Undo.</p><div className="flex flex-wrap gap-2"><Button disabled={state.busy} variant="destructive" size="sm" onClick={() => void wallet.unlink()}>Confirm permanent unlink</Button>{!state.submitting && <Button disabled={state.busy} variant="outline" size="sm" onClick={cancel}>Cancel unlinking</Button>}</div></div>}
      {state.busy && <p role="status" className="flex items-center gap-2 text-sm text-neutral-500"><Loader2 className="h-4 w-4 animate-spin" />{state.submitting ? state.unlink ? 'Unlinking address…' : 'Saving address link…' : state.stage === 'sign' ? 'Waiting for your wallet…' : activeLink ? 'Connecting your wallet…' : 'Loading linked addresses…'}</p>}
      {state.submitting && <p className="text-xs text-neutral-500">The request has been submitted. Wait for its result; closing this page does not undo it.</p>}
      <p className="text-xs text-neutral-400">A linked address identifies your wallet. Permissions still come from your organization's approved rules.</p>
    </section>
  </LinkedAddressesCard>
}
