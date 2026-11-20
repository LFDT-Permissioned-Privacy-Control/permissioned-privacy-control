import { useState, type ReactNode } from 'react'
import { Check, FileCode2, Plus, Radio, Search, Shield, X } from 'lucide-react'
import { Button } from '../ui/button'
import { CopyValue } from '../ui/CopyValue'
import { Input } from '../ui/input'
import { PermissionCheck, permissionClaimClasses } from './PermissionSelectionView'

// Presentation extracted from ContractList/ContractGrantForm/ContractGrantsManager.
// These views deliberately know nothing about SQL grants, sessions or authority.
export function ContractAddress({ address, compact = false }: { address: string; compact?: boolean }) {
  return <span className="inline-flex max-w-full items-center gap-2"><FileCode2 className="h-4 w-4 shrink-0 text-primary" /><code className="break-all text-sm" title={address}>{compact && address.length > 20 ? address.slice(0, 8) + '…' + address.slice(-6) : address}</code><CopyValue value={address} label={`Copy address ${address}`} /></span>
}

export function ContractHeader({ name, address, children }: { name: string; address: string; children?: ReactNode }) {
  return <div className="space-y-3"><div className="flex flex-wrap items-start justify-between gap-3"><div><h3 className="text-lg font-semibold text-neutral-900">{name}</h3><div className="mt-1"><ContractAddress address={address} /></div></div><span className="rounded-full bg-neutral-100 px-2.5 py-1 text-xs text-neutral-600">Local proposal</span></div>{children}</div>
}

export function ContractEmpty({ title, description, action }: { title: string; description: string; action?: ReactNode }) {
  return <div className="rounded-xl border border-dashed border-neutral-300 px-5 py-10 text-center"><FileCode2 className="mx-auto mb-3 h-10 w-10 text-neutral-300" /><h4 className="font-medium text-neutral-900">{title}</h4><p className="mx-auto mt-1 max-w-xl text-sm text-neutral-500">{description}</p>{action && <div className="mt-4">{action}</div>}</div>
}

export function PermissionMode({ name, value, label, description, checked, editing, onChange }: { name: string; value: string; label: string; description: string; checked: boolean; editing: boolean; onChange(): void }) {
  return <label className={permissionClaimClasses(checked, editing)} data-selected={checked}><input type="radio" aria-label={label} name={name} value={value} checked={checked} disabled={!editing} className="sr-only" onChange={onChange} /><PermissionCheck checked={checked} size="claim" /><span><span className="block text-sm font-medium">{label}</span><span className="mt-0.5 block text-xs text-neutral-500">{description}</span></span></label>
}

export function PermissionPill({ kind = 'function', children }: { kind?: 'function' | 'event'; children: ReactNode }) {
  return <span className={`inline-flex max-w-full items-center gap-1 rounded px-2 py-1 text-xs ${kind === 'event' ? 'bg-violet-50 text-violet-700' : 'bg-primary-50 text-primary'}`}>{kind === 'event' ? <Radio className="h-3 w-3 shrink-0" /> : <Shield className="h-3 w-3 shrink-0" />}<span className="break-all">{children}</span></span>
}

export interface ABIFunctionView { signature: string; selector: string; stateMutability?: string; inputs?: readonly { name?: string; type: string }[] }
export interface ABIEventView { signature: string; topic0?: string; signatureHash?: string; anonymous?: boolean; inputs?: readonly { name?: string; type: string; indexed?: boolean }[] }
export function ABIFunctionBrowser({ functions, selected, onSelect, extra }: { functions: ABIFunctionView[]; selected?: string; onSelect?(selector: string): void; extra?: ReactNode }) {
  const [search, setSearch] = useState(''), visible = functions.filter(f => (f.signature + ' ' + f.selector).toLowerCase().includes(search.toLowerCase()))
  return <section className="space-y-2"><div className="flex items-center justify-between gap-2"><h4 className="text-sm font-medium">Contract functions <span className="rounded-full bg-primary-50 px-2 py-0.5 text-xs text-primary">{functions.length}</span></h4>{extra}</div>{functions.length > 5 && <div className="relative"><Search className="absolute left-3 top-3 h-4 w-4 text-neutral-400" /><Input aria-label="Search ABI functions" className="pl-9" placeholder="Search functions or selectors…" value={search} onChange={e => setSearch(e.target.value)} /></div>}<div className="max-h-64 overflow-y-auto rounded-lg border border-neutral-200 p-2 space-y-1">{visible.map(fn => { const chosen = selected === fn.selector; const content = <><span className="flex min-w-0 flex-1 flex-col gap-1"><span className="flex flex-wrap items-center gap-2"><span className="break-all font-mono text-xs">{fn.signature}</span>{['view', 'pure', 'payable'].includes(fn.stateMutability ?? '') && <span className="rounded bg-neutral-100 px-1.5 py-0.5 text-[10px] text-neutral-600">{fn.stateMutability}</span>}</span><code className="text-xs text-neutral-400">{fn.selector}</code></span>{chosen ? <Check className="h-4 w-4 shrink-0 text-primary" /> : onSelect ? <Plus className="h-4 w-4 shrink-0 text-neutral-400" /> : null}</>; return onSelect ? <button key={fn.selector} type="button" aria-label={fn.signature} aria-pressed={chosen} className={`flex w-full items-center gap-2 rounded-lg border p-2 text-left transition-colors focus-visible:ring-2 focus-visible:ring-primary ${chosen ? 'border-primary bg-primary-50' : 'border-transparent hover:border-primary-200 hover:bg-neutral-50'}`} onClick={() => onSelect(fn.selector)}>{content}</button> : <div key={fn.selector} className="flex items-center gap-2 rounded p-2">{content}</div> })}{!visible.length && <p className="p-3 text-sm text-neutral-500">{functions.length ? 'No functions match this search.' : 'No functions in this ABI.'}</p>}</div></section>
}

export function ABIEventBrowser({ events, selected = [], onSelect, editing = true }: { events: ABIEventView[]; selected?: string[]; onSelect?(topic: string): void; editing?: boolean }) {
  return <section className="space-y-2"><h4 className="text-sm font-medium">Contract events <span className="rounded-full bg-violet-50 px-2 py-0.5 text-xs text-violet-700">{events.length}</span></h4><div className="max-h-64 space-y-1 overflow-y-auto rounded-lg border border-neutral-200 p-2">{events.map(event => { const topic = event.topic0 ?? event.signatureHash ?? '', chosen = selected.includes(topic); const content = <><Radio className="h-4 w-4 shrink-0 text-violet-600" /><span className="min-w-0 flex-1"><span className="block break-all font-mono text-xs">{event.signature}</span><span className="block break-all text-[10px] text-neutral-400" title={topic}>{event.anonymous ? 'Anonymous · not eligible for topic0 rules' : topic}</span>{event.inputs?.map((p, i) => <span key={i} className="mr-1 mt-1 inline-block rounded bg-neutral-100 px-1.5 py-0.5 text-[10px] text-neutral-600">{p.name || `Parameter ${i + 1}`} · {p.type}{p.indexed ? ' · indexed' : ''}</span>)}</span>{chosen ? <Check className="h-4 w-4 shrink-0 text-primary" /> : onSelect ? <Plus className="h-3 w-3 shrink-0" /> : null}</>; return onSelect ? <button key={topic} type="button" aria-label={event.signature} aria-pressed={chosen} disabled={chosen || !editing || event.anonymous} className={`flex w-full items-center gap-2 rounded-lg border p-2 text-left ${chosen ? 'border-primary bg-primary-50' : 'border-transparent hover:border-primary-200 hover:bg-neutral-50'} focus-visible:ring-2 focus-visible:ring-primary`} onClick={() => onSelect(topic)}>{content}</button> : <div key={topic} className="flex items-start gap-2 p-2">{content}</div> })}{!events.length && <p className="p-3 text-sm text-neutral-500">No events in this ABI.</p>}</div></section>
}

export function SelectedToolbar({ count, onClear, children }: { count: number; onClear(): void; children?: ReactNode }) {
  return <div className="flex flex-wrap items-center justify-between gap-3 rounded-lg border border-primary-200 bg-primary-50 px-4 py-3"><span className="text-sm font-medium text-primary">{count} selected</span><div className="flex flex-wrap gap-2">{children}<Button type="button" variant="ghost" size="sm" onClick={onClear}><X className="mr-1 h-4 w-4" />Clear</Button></div></div>
}
