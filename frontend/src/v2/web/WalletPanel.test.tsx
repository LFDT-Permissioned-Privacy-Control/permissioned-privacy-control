import '@testing-library/jest-dom/vitest'
import { StrictMode } from 'react'
import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { WalletPanel } from './WalletPanel'
import { WalletController, WalletScope, WalletState } from './wallet'

afterEach(cleanup)
const address = '0x' + '1'.repeat(40)
function scope(request: WalletScope['request']): WalletScope {
  const abort = new AbortController()
  return { identity: { actor: 'ops:test', expires: Math.floor(Date.now() / 1000) + 300 }, signal: abort.signal,
    check: () => { if (abort.signal.aborted) throw Error('retired') }, request, dispose: () => abort.abort() }
}
describe('account wallet tasks', () => {
  it('loads own links once under StrictMode and has no idle Cancel action', async () => {
    const request = vi.fn(async () => []), capture = vi.fn(async () => scope(request as WalletScope['request']))
    const wallet = new WalletController(capture)
    render(<StrictMode><WalletPanel wallet={wallet} /></StrictMode>)
    await screen.findByText('No linked Ethereum addresses')
    expect(capture).toHaveBeenCalledTimes(1); expect(request).toHaveBeenCalledWith('/eth/addresses')
    expect(screen.queryByRole('button', { name: /Cancel/ })).not.toBeInTheDocument()
  })
  it('lets the user cancel an initial extension prompt and ignores its late accounts result', async () => {
    let finish!: (value: string[]) => void
    const waiting = new Promise<string[]>(resolve => { finish = resolve })
    const request = vi.fn(async () => []), provider = { request: vi.fn(async () => waiting) }
    const wallet = new WalletController(async () => scope(request as WalletScope['request']), { provider: () => provider })
    render(<WalletPanel wallet={wallet} />); await screen.findByText('No linked Ethereum addresses')
    fireEvent.click(screen.getByRole('button', { name: 'Link Wallet' }))
    await waitFor(() => expect(provider.request).toHaveBeenCalledWith({ method: 'eth_requestAccounts' }))
    expect(screen.getByText('Connect your wallet')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Cancel linking' }))
    await act(async () => { finish([address]); await waiting })
    await screen.findByText('No linked Ethereum addresses')
    expect(screen.queryByText(address)).not.toBeInTheDocument()
    expect(request.mock.calls.every(call => call[0] === '/eth/addresses')).toBe(true)
  })
  it('does not offer cancellation after an owned write has been submitted', async () => {
    const state: WalletState = { links: [], accounts: [], selected: address, stage: 'confirm', message: 'Signed ownership proof',
      busy: true, error: null, unlink: null, loaded: false, submitting: true, task: 'linking' }
    const wallet = { snapshot: () => state, subscribe: () => () => {}, load: vi.fn(), cancel: vi.fn() }
    render(<WalletPanel wallet={wallet as unknown as WalletController} />)
    expect(screen.queryByRole('button', { name: /Cancel/ })).not.toBeInTheDocument()
    expect(screen.getByText(/closing this page does not undo it/)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Confirm link' })).toBeDisabled()
  })
  it('does not publish a delayed automatic link read after the account card unmounts', async () => {
    let finish!: (value: unknown) => void
    const held = new Promise(resolve => { finish = resolve })
    const request = vi.fn(async () => held), capture = vi.fn(async () => scope(request as WalletScope['request']))
    const wallet = new WalletController(capture)
    const view = render(<WalletPanel wallet={wallet} />)
    await waitFor(() => expect(request).toHaveBeenCalledTimes(1)); view.unmount()
    await act(async () => { finish([{ address, verifiedAt: '2026-11-19T00:00:00Z', proofVersion: 2 }]); await held })
    expect(wallet.snapshot().links).toEqual([]); expect(wallet.snapshot().loaded).toBe(false)
  })
  it('retires displayed links during session refresh and reloads them under a fresh owned scope afterwards', async () => {
    const request = vi.fn(async () => [{ address, verifiedAt: '2026-11-19T00:00:00Z', proofVersion: 2 }])
    const capture = vi.fn(async () => scope(request as WalletScope['request']))
    const wallet = new WalletController(capture)
    const view = render(<WalletPanel wallet={wallet} />)
    await screen.findByTestId('linked-address')
    view.rerender(<WalletPanel wallet={wallet} sessionBusy />)
    expect(screen.queryByTestId('linked-address')).not.toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Link Wallet' })).toBeDisabled()
    view.rerender(<WalletPanel wallet={wallet} sessionBusy={false} />)
    await screen.findByTestId('linked-address')
    expect(capture).toHaveBeenCalledTimes(2)
  })
})
