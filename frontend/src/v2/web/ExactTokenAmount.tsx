import { Field, SelectField } from './operationsUI'
import { decimalToBaseUnits, exactUint256 } from './exactAmounts'
import type { ApprovedToken } from './approvedTokens'
import { useState } from 'react'

const clearedAmountNotice = 'Amount cleared after changing units or entry mode. Enter the amount again.'
export function useExactAmountState(unitsKey: string, decimals: number | undefined) {
  const defaultMode = decimals === undefined ? 'base' : 'human'
  const [stored, setStored] = useState({ unitsKey, amount: '', mode: defaultMode, notice: null as string | null })
  // Adjust before rendering a new asset/catalog generation. Retained input may
  // never acquire a different decimal meaning, even before effects run.
  let current = stored
  if (stored.unitsKey !== unitsKey) {
    current = { unitsKey, amount: '', mode: defaultMode, notice: stored.amount ? clearedAmountNotice : stored.notice }
    setStored(current)
  }
  return {
    amount: current.amount, mode: current.mode, notice: current.notice,
    setAmount(amount: string) { setStored({ ...current, amount, notice: null }) },
    setMode(value: string) {
      const mode = value === 'human' && decimals !== undefined ? 'human' : 'base'
      if (mode !== current.mode) setStored({ ...current, mode, amount: '', notice: current.amount ? clearedAmountNotice : current.notice })
    },
  }
}

export function amountInBaseUnits(amount: string, mode: string, decimals: number | undefined): string {
  if (mode === 'base') return exactUint256(amount)
  if (decimals === undefined) throw Error('Approved decimals are unavailable. Select exact base units.')
  return decimalToBaseUnits(amount, decimals)
}
export function TokenChoice({ tokens, token, onChange, disabled = false }: { tokens: ApprovedToken[]; token: string; onChange(value: string): void; disabled?: boolean }) {
  const [search, setSearch] = useState('')
  return <div className="space-y-3"><Field label="Find approved token" value={search} onChange={setSearch} disabled={disabled} hint="Search symbol or full address. Selection always uses the address." />
    <SelectField label="Approved token" value={tokens.some(t => t.address === token) ? token : ''} onChange={onChange} disabled={disabled} options={[{ value: '', label: 'Other token — explicit address and base units' }, ...tokens.filter(t => t.address === token || `${t.symbol} ${t.address}`.toLowerCase().includes(search.toLowerCase())).map(t => ({ value: t.address, label: `${t.symbol} · ${t.address} · ${t.decimals} decimals` }))]} />
    <Field label="Token address" value={token} onChange={onChange} disabled={disabled} required />
  </div>
}
export function ExactAmount({ amount, mode, decimals, unit, onAmount, onMode, notice, disabled = false }: { amount: string; mode: string; decimals?: number; unit: string; onAmount(value: string): void; onMode(value: string): void; notice?: string | null; disabled?: boolean }) {
  let preview = '', error = ''
  if (amount) try { preview = amountInBaseUnits(amount, mode, decimals) } catch (e) { error = (e as Error).message }
  return <div className="space-y-3"><SelectField label="Amount entry" value={mode} onChange={onMode} disabled={disabled} options={[{ value: 'base', label: 'Exact base units' }, ...(decimals !== undefined ? [{ value: 'human', label: `${unit} (${decimals} decimals)` }] : [])]} />
    <Field label={mode === 'base' ? 'Amount in base units' : `Amount (${unit})`} value={amount} onChange={onAmount} required disabled={disabled} hint={decimals === undefined ? 'Decimals unavailable; no conversion is assumed.' : `Current units: ${unit}, ${decimals} decimals. Server valuation applies.`} />
    {notice && <p role="status" className="text-xs text-neutral-500">{notice}</p>}
    {preview && <p className="text-xs break-all">Exact base-unit preview: <code>{preview}</code></p>}{error && <p role="alert" className="text-sm text-error-dark">{error}</p>}
  </div>
}
