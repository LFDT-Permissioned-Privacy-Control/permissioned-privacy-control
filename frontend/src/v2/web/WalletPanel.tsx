import { useEffect, useSyncExternalStore } from 'react'
import { WalletController } from './wallet'

export function WalletPanel({ wallet }: { wallet: WalletController }) {
  const state = useSyncExternalStore(wallet.subscribe, wallet.snapshot)
  useEffect(() => () => wallet.cancel(), [wallet])
  return <section aria-label="Your wallet links">
    <h2>Wallets</h2>
    <p>Link an address you control to your OPS identity. Linking does not grant group membership or authorize a transaction.</p>
    {state.error && <p role="alert">{state.error}</p>}
    <button disabled={state.busy} onClick={() => void wallet.load()}>Refresh links</button>
    <button disabled={state.busy} onClick={() => void wallet.connect()}>Link wallet</button>
    <button onClick={wallet.cancel}>Cancel wallet operation</button>
    {state.busy && <p role="status">Waiting for the wallet operation…</p>}
    {state.links.length ? <ul>{state.links.map(link => <li key={link.address}><code>{link.address}</code> · Verified {link.verifiedAt} <button disabled={state.busy} onClick={() => wallet.prepareUnlink(link.address)}>Unlink</button></li>)}</ul> : <p>No wallet links are currently displayed. Refresh links to check the current state.</p>}
    {state.stage === 'choose' && <section><h3>Choose the address to link</h3>{state.accounts.map(value => <button key={value} onClick={() => void wallet.select(value)}><code>{value}</code></button>)}</section>}
    {state.message && <section><h3>Wallet ownership proof</h3><pre>{state.message}</pre>{state.stage === 'sign' && <button disabled={state.busy} onClick={() => void wallet.sign()}>Sign ownership proof</button>}{state.stage === 'confirm' && <button disabled={state.busy} onClick={() => void wallet.confirm()}>Confirm link</button>}</section>}
    {state.unlink && <section role="alert"><p>Unlink <code>{state.unlink}</code>? This address cannot be linked to this OPS identity again under the current deployment rules. There is no Undo.</p><button disabled={state.busy} onClick={() => void wallet.unlink()}>Confirm permanent unlink</button></section>}
  </section>
}
