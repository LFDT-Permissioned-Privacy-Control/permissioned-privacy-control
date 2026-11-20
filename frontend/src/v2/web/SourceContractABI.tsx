import { useEffect, useRef, useState } from 'react'
import { Check, Upload } from 'lucide-react'
import { ABIFunctionBrowser, ABIEventBrowser, type ABIEventView } from '../../components/rbac/ContractPresentation'
import { abiChoices } from './executionABI'
import { Button } from '../../components/ui/button'
import { Textarea } from '../../components/ui/textarea'
import { Dialog, DialogContent, DialogHeader, DialogTitle } from '../../components/ui/dialog'
import { closedJSON } from '../auth/protocol'
import { SourceAuthoringScope } from './SourceAuthoringScope'
import { useAuthoringState, useClearAuthoring } from './sourceAuthoring'
import { browserNumbersSafe, object, type JSONObject } from './sourceProject'

export function parseAuthoringABI(raw: string): JSONObject[] {
  let parsed: unknown
  try { parsed = closedJSON(raw, 1 << 20, 32) } catch { throw Error('ABI JSON is malformed, has duplicate keys, or exceeds the 1 MiB / depth 32 limits.') }
  const value = Array.isArray(parsed) ? parsed : object(parsed).abi
  if (!Array.isArray(value) || value.length > 4096 || !browserNumbersSafe(value)) throw Error('Choose a raw ABI array or a compiled artifact with an abi array (at most 4096 entries).')
  let parameters = 0
  function parameter(v: unknown, depth: number): void {
    const p = object(v)
    if (++parameters > 4096 || depth > 32 || typeof p.type !== 'string' || !p.type || p.name !== undefined && typeof p.name !== 'string' || p.indexed !== undefined && typeof p.indexed !== 'boolean') throw Error('ABI parameters need a type, optional string name and boolean indexed flag, within bounded nesting/count limits.')
    if (p.components !== undefined) { if (!Array.isArray(p.components)) throw Error('Tuple components must be an array.'); p.components.forEach(c => parameter(c, depth + 1)) }
  }
  for (const entry of value) {
    const e = object(entry)
    if (!['function', 'event', 'constructor', 'error', 'fallback', 'receive'].includes(String(e.type))) throw Error('Every ABI entry needs a recognized ABI type.')
    if (['function', 'event', 'error'].includes(String(e.type)) && (typeof e.name !== 'string' || !e.name)) throw Error('Named ABI entries need a name.')
    for (const key of ['inputs', 'outputs']) if (e[key] !== undefined) { if (!Array.isArray(e[key])) throw Error(`ABI ${key} must be an array.`); (e[key] as unknown[]).forEach(p => parameter(p, 0)) }
    if (e.anonymous !== undefined && typeof e.anonymous !== 'boolean' || e.constant !== undefined && typeof e.constant !== 'boolean' || e.payable !== undefined && typeof e.payable !== 'boolean') throw Error('ABI boolean flags must be booleans.')
    if (e.stateMutability !== undefined && !['pure', 'view', 'nonpayable', 'payable'].includes(String(e.stateMutability))) throw Error('ABI stateMutability must be pure, view, nonpayable or payable.')
  }
  // Registry stores the ABI array only. Artifact compiler metadata is not a
  // source permission, and is intentionally excluded from this bounded import.
  if (new TextEncoder().encode(JSON.stringify(value)).length > 1 << 20) throw Error('The ABI exceeds 1 MiB.')
  return value.map(object)
}
export function abiSummary(abi: unknown) { const rows = Array.isArray(abi) ? abi : []; return { entries: rows.length, functions: rows.filter(e => e && typeof e === 'object' && (e as JSONObject).type === 'function').length, events: rows.filter(e => e && typeof e === 'object' && (e as JSONObject).type === 'event').length } }
export function SourceContractABI({ contract, identity, generation, editing, onSave }: { contract: JSONObject; identity: string; generation: number; editing: boolean; onSave(abi: JSONObject[]): void }) {
  return <SourceAuthoringScope id={'abi:' + identity}><ABIContent contract={contract} identity={identity} generation={generation} editing={editing} onSave={onSave} /></SourceAuthoringScope>
}
function ABIContent({ contract, identity, generation, editing, onSave }: Parameters<typeof SourceContractABI>[0]) {
  const [open, setOpen] = useAuthoringState('open', false), clear = useClearAuthoring(), summary = abiSummary(contract.abi)
  const close = () => { clear('form'); setOpen(false) }
  return <><Button type="button" variant="outline" size="sm" className={summary.entries ? "text-success" : "text-neutral-500"} onClick={() => setOpen(true)}>{summary.entries > 0 && <Check className="mr-1 h-3.5 w-3.5" />}ABI · {summary.functions} functions · {summary.events} events</Button><Dialog open={open} onOpenChange={v => { if (!v) close() }}><DialogContent className="max-w-3xl max-h-[85vh] overflow-y-auto"><DialogHeader><DialogTitle>{String(contract.name)} — public ABI</DialogTitle></DialogHeader>{editing ? <SourceAuthoringScope id="form"><ABIForm value={contract.abi} identity={identity} generation={generation} onClose={close} onSave={abi => { onSave(abi); close() }} /></SourceAuthoringScope> : <><StructuredABI value={contract.abi} /><details><summary className="cursor-pointer text-sm font-medium">Advanced public ABI JSON</summary><pre className="mt-2 text-xs overflow-auto whitespace-pre-wrap break-all">{JSON.stringify(contract.abi, null, 2)}</pre></details></>}</DialogContent></Dialog></>
}
export function ABIForm({ value, identity, generation, onClose, onSave }: { value: unknown; identity: string; generation: number; onClose(): void; onSave(abi: JSONObject[]): void }) {
  const [raw, setRaw] = useAuthoringState('abi', JSON.stringify(value, null, 2), { draft: true, base: value }), [filename, setFilename] = useAuthoringState('filename', '', { base: value }), [error, setError] = useState<string | null>(null), [busy, setBusy] = useState(false)
  const input = useRef<HTMLInputElement>(null), alive = useRef(true), request = useRef(0), latest = useRef({ identity, generation, raw })
  latest.current = { identity, generation, raw }
  useEffect(() => { alive.current = true; return () => { alive.current = false; request.current++ } }, [])
  useEffect(() => { request.current++; setBusy(false) }, [identity, generation])
  const changed = raw !== JSON.stringify(value, null, 2)
  let summary = null; try { summary = abiSummary(parseAuthoringABI(raw)) } catch { /* Incomplete paste remains editable, never replaces the current ABI. */ }
  async function upload(file: File) {
    const current = ++request.current, original = latest.current
    const active = () => alive.current && current === request.current && original.identity === latest.current.identity && original.generation === latest.current.generation && original.raw === latest.current.raw
    setBusy(true)
    try {
      if (file.size > 1 << 20) throw Error('ABI files must be at most 1 MiB.')
      const text = await file.text(); if (!active()) return
      const abi = parseAuthoringABI(text)
      setRaw(JSON.stringify(abi, null, 2)); setFilename(file.name); setError(null)
    } catch (e) { if (active()) setError(e instanceof Error ? e.message : 'Could not read ABI file. The previous ABI is retained.') }
    finally { if (alive.current && current === request.current) setBusy(false) }
  }
  return <form className="space-y-4" onSubmit={e => { e.preventDefault(); e.stopPropagation(); try { onSave(parseAuthoringABI(raw)) } catch (e) { setError(e instanceof Error ? e.message : 'Could not save ABI.') } }}>
    <p className="text-sm text-neutral-500">Upload a raw ABI array or the usual compiled artifact with an abi array. Browser parsing assists source authoring; the matching Go tool remains ABI authority.</p>
    <Button type="button" variant="outline" disabled={busy} onClick={() => input.current?.click()}><Upload className="mr-2 h-4 w-4" />{busy ? 'Reading local ABI…' : Array.isArray(value) && value.length ? 'Replace ABI file' : 'Upload ABI file'}</Button><input ref={input} className="sr-only" type="file" accept=".json,application/json" aria-label="Upload or replace ABI file" onChange={e => { const file = e.currentTarget.files?.[0]; e.currentTarget.value = ''; if (file) void upload(file) }} />
    <p role="status" className={`rounded-lg border p-3 text-sm ${summary ? 'border-success/20 bg-success-light text-success-dark' : 'border-warning/20 bg-warning-light text-warning-dark'}`}>{filename ? `Loaded file: ${filename}. ` : 'Current source ABI. '}{summary ? `${summary.entries} entries · ${summary.functions} functions · ${summary.events} events.` : 'Incomplete or invalid ABI paste.'} {changed ? 'Replacement pending local save.' : 'No replacement pending.'}</p>
    {summary && <StructuredABI value={parseAuthoringABI(raw)} />}
    <details><summary className="text-sm cursor-pointer">Paste or inspect ABI JSON</summary><label className="block text-sm font-medium mt-2">Public ABI JSON<Textarea variant="code" className="min-h-64" value={raw} onChange={e => { request.current++; setBusy(false); setRaw(e.target.value); setFilename('') }} /></label></details>
    {error && <p role="alert" className="text-sm text-error-dark">{error} The previous saved ABI remains unchanged.</p>}
    <div className="flex justify-end gap-2"><Button type="button" variant="ghost" onClick={onClose}>Cancel</Button><Button type="submit" disabled={busy || !summary}>Save ABI draft</Button></div>
  </form>
}

export function StructuredABI({ value }: { value: unknown }) {
  const summary = abiSummary(value)
  try {
    const choices = abiChoices(value), events: ABIEventView[] = []
    for (const entry of value as JSONObject[]) if (entry.type === 'event') {
      const event = abiChoices([entry]).events[0]
      events.push({ ...event, inputs: Array.isArray(entry.inputs) ? entry.inputs as unknown as ABIEventView['inputs'] : [] })
    }
    return <div className="space-y-4"><div className="rounded-lg bg-neutral-50 p-3 text-sm"><p className="font-medium">{summary.entries ? 'Public ABI loaded in source' : 'No ABI loaded'}</p><p className="mt-1 text-xs text-neutral-500">{summary.entries} entries · {summary.functions} functions · {summary.events} events. ABI assistance does not establish deployment or execution access.</p></div><ABIFunctionBrowser functions={choices.functions} /><ABIEventBrowser events={events} /></div>
  } catch (error) { return <p className="rounded-lg bg-warning-light p-3 text-sm text-warning-dark">This imported ABI cannot be presented safely: {(error as Error).message} It is retained in advanced JSON; use the matching Go tool to inspect it.</p> }
}
