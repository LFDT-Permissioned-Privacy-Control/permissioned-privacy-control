import { useState, type FormEvent } from 'react'
import { Pencil, Plus, Trash2, Search, X } from 'lucide-react'
import { Button } from '../../components/ui/button'
import { Input } from '../../components/ui/input'
import { Textarea } from '../../components/ui/textarea'
import { Checkbox } from '../../components/ui/checkbox'
import { Badge } from '../../components/ui/badge'
import Pagination from '../../components/ui/Pagination'
import { CopyValue } from '../../components/auth/AccountPresentation'
import { Dialog, DialogContent, DialogHeader, DialogTitle } from '../../components/ui/dialog'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '../../components/ui/table'
import { SourceAuthoringScope } from './SourceAuthoringScope'
import { useAuthoringState, useClearAuthoring } from './sourceAuthoring'
import { closedJSON } from '../auth/protocol'
import { browserNumbersSafe, object, type JSONObject } from './sourceProject'

export interface SourceField { key: string; label: string; kind?: 'text' | 'number' | 'boolean' | 'list' | 'json' | 'textarea'; optional?: boolean; options?: readonly string[]; help?: string; onlyFor?: readonly string[]; allowEmpty?: boolean }
function valueAt(value: JSONObject, path: string): unknown { return path.split('.').reduce<unknown>((v, key) => v && typeof v === 'object' ? (v as JSONObject)[key] : undefined, value) }
function put(value: JSONObject, path: string, replacement: unknown): void {
  const keys = path.split('.'); let current = value
  keys.slice(0, -1).forEach(key => { current[key] = { ...object(current[key] ?? {}) }; current = current[key] as JSONObject })
  const key = keys[keys.length - 1]; if (replacement === undefined) delete current[key]; else current[key] = replacement
}
export function SourceRecordForm({ value, fields, onSave, onClose, submit = 'Save draft' }: { value: JSONObject; fields: SourceField[]; onSave(value: JSONObject): void; onClose(): void; submit?: string }) {
  const [values, setValues] = useAuthoringState<Record<string, string | boolean>>('fields', () => Object.fromEntries(fields.map(f => {
    const v = valueAt(value, f.key)
    return [f.key, f.kind === 'boolean' ? v === true : v === undefined ? f.optional ? '' : f.options?.[0] ?? '' : f.kind === 'json' ? JSON.stringify(v, null, 2) : f.kind === 'list' ? (v as string[]).join('\n') : String(v)]
  })), { draft: true, base: value }), [error, setError] = useState<string | null>(null)
  function save(event: FormEvent) {
    event.preventDefault()
    try {
      if (!browserNumbersSafe(value)) throw Error('Use raw source editing to preserve this document’s numeric values exactly.')
      const result = { ...value }
      for (const f of fields) {
        if (f.onlyFor && !f.onlyFor.includes(String(values.kind))) { put(result, f.key, undefined); continue }
        const raw = values[f.key]
        if (f.kind === 'boolean') { put(result, f.key, f.optional && raw === false ? undefined : raw); continue }
        const text = String(raw).trim()
        if (f.optional && !text) { put(result, f.key, undefined); continue }
        if (f.kind === 'json') put(result, f.key, closedJSON(text, 1 << 20, 32))
        else if (f.kind === 'number') { const n = Number(text); if (!text || !Number.isFinite(n)) throw Error(`${f.label} needs a finite number.`); put(result, f.key, n) }
        else if (f.kind === 'list') put(result, f.key, [...new Set(text.split(/[\s,]+/).filter(Boolean))])
        else put(result, f.key, text)
      }
      if (!browserNumbersSafe(result)) throw Error('Use raw source editing for numeric values outside the browser’s exact integer range.')
      onSave(result)
    } catch (e) { setError(e instanceof Error ? e.message : 'Could not save this source draft.') }
  }
  return <form onSubmit={save} className="space-y-4">
    {fields.filter(f => !f.onlyFor || f.onlyFor.includes(String(values.kind))).map(f => <label key={f.key} className="block text-sm font-medium">{f.kind === 'boolean' ? <span className="inline-flex gap-2"><Checkbox aria-label={f.label} checked={values[f.key] === true} onCheckedChange={checked => setValues({ ...values, [f.key]: checked === true })} />{f.label}</span> : <>{f.label}
      {f.options ? <select className="block w-full rounded-lg border border-neutral-300 p-2 mt-1" value={String(values[f.key])} onChange={e => setValues({ ...values, [f.key]: e.target.value })}>{f.optional && <option value="">Not set</option>}{f.options.map(v => <option key={v}>{v}</option>)}</select>
        : ['json', 'textarea', 'list'].includes(f.kind ?? '') ? <Textarea aria-label={f.label} variant={f.kind === 'json' ? 'code' : 'default'} className={f.kind === 'json' ? 'min-h-36' : ''} required={!f.optional} value={String(values[f.key])} onChange={e => setValues({ ...values, [f.key]: e.target.value })} spellCheck={false} />
          : <Input aria-label={f.label} required={!f.optional && !f.allowEmpty} type={f.kind === 'number' ? 'number' : 'text'} step={f.kind === 'number' ? 'any' : undefined} value={String(values[f.key])} onChange={e => setValues({ ...values, [f.key]: e.target.value })} />}</>}
      {f.help && <span className="block mt-1 text-xs font-normal text-neutral-500">{f.help}</span>}
    </label>)}
    {error && <p role="alert" className="rounded-lg bg-error-light p-3 text-sm text-error-dark">{error}</p>}
    <p className="text-xs text-neutral-500">This edits a local proposal. The matching Go tool validates the complete document and its references.</p>
    <div className="flex justify-end gap-2"><Button type="button" variant="ghost" onClick={onClose}>Cancel</Button><Button type="submit">{submit}</Button></div>
  </form>
}
function SourceRecordsContent({ title, description, records, fields, defaults, editing, onChange, renderActions, dependencies }: {
  title: string; description?: string; records: unknown; fields: SourceField[]; defaults(): JSONObject; editing: boolean; onChange(values: JSONObject[]): void
  renderActions?(record: JSONObject, index: number): React.ReactNode; dependencies?(record: JSONObject): string[]
}) {
  const clear = useClearAuthoring()
  const [pendingModal, setModal] = useAuthoringState<{ kind: 'edit' | 'delete'; index: number; value?: JSONObject } | null>('modal', null), [search, setSearch] = useAuthoringState('search', ''), [pageOffset, setPageOffset] = useAuthoringState('page-offset', 0), [error, setError] = useState<string | null>(null)
  const [inspection, setInspection] = useState<{ kind: 'inspect'; index: number } | null>(null)
  const modal = inspection ?? (editing ? pendingModal : null)
  if (!Array.isArray(records)) throw Error(`${title} has an unsupported source shape. Open Review & export to repair it.`)
  const rows = records.map(object), selected = modal && modal.index >= 0 ? rows[modal.index] : undefined
  const matching = rows.map((r, index) => ({ r, index })).filter(({ r }) => !search || JSON.stringify(r).toLowerCase().includes(search.toLowerCase()))
  const limit = 50, offset = Math.min(pageOffset, Math.max(0, Math.floor((matching.length - 1) / limit) * limit))
  const searchRows = (value: string) => { setSearch(value); setPageOffset(0) }
  const close = () => { if (inspection) setInspection(null); else { clear('form'); setModal(null) } setError(null) }
  return <section className="space-y-4"><div className="flex flex-wrap items-start justify-between gap-3"><div><h3 className="text-sm font-medium text-neutral-700">{title}</h3>{description && <p className="text-xs text-neutral-500 mt-1 max-w-3xl">{description}</p>}</div>{editing && <Button size="sm" onClick={() => setModal({ kind: 'edit', index: -1, value: defaults() })}><Plus className="w-4 h-4 mr-2" />Add {title.toLowerCase().replace(/s$/, '')}</Button>}</div>
    <div className="flex items-center gap-3"><div className="relative flex-1 max-w-sm"><Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-neutral-400" /><Input className="pl-9" aria-label={`Search ${title.toLowerCase()}`} placeholder="Search..." value={search} onChange={e => searchRows(e.target.value)} /></div>{search && <Button size="sm" variant="ghost" onClick={() => searchRows('')}><X className="h-4 w-4 mr-1" />Clear search</Button>}</div>
    <div className="rounded-lg border border-neutral-200 overflow-x-auto"><Table><TableHeader><TableRow><TableHead>Name / ID</TableHead><TableHead>Details</TableHead><TableHead className="text-right">Actions</TableHead></TableRow></TableHeader><TableBody>
      {matching.slice(offset, offset + limit).map(({ r, index }) => <TableRow key={index}><TableCell className="font-medium"><button className="text-primary hover:underline text-left break-all" onClick={() => setInspection({ kind: 'inspect', index })}>{String(r.name ?? r.id ?? r.profileId ?? r.address ?? `Entry ${index + 1}`)}</button></TableCell><TableCell className="text-xs text-neutral-500 max-w-sm break-all">{fields.filter(f => !['json', 'boolean', 'textarea'].includes(f.kind ?? '')).slice(0, 4).map(f => valueAt(r, f.key) === undefined ? null : <p key={f.key}>{f.label}: {Array.isArray(valueAt(r, f.key)) ? (valueAt(r, f.key) as string[]).join(', ') : String(valueAt(r, f.key))}</p>)}</TableCell><TableCell><div className="flex justify-end gap-1">{renderActions?.(r, index)}{editing && <><Button size="sm" variant="ghost" title={`Edit ${title.toLowerCase()} draft`} onClick={() => setModal({ kind: 'edit', index })}><Pencil className="w-4 h-4" /></Button><Button size="sm" variant="ghost" title={`Remove ${title.toLowerCase()} draft`} onClick={() => setModal({ kind: 'delete', index })}><Trash2 className="w-4 h-4" /></Button></>}</div></TableCell></TableRow>)}
      {!matching.length && <TableRow><TableCell colSpan={3} className="text-center text-neutral-500 py-8">{search ? `No ${title.toLowerCase()} match this search.` : `No ${title.toLowerCase()} in this source.`}</TableCell></TableRow>}
    </TableBody></Table></div>
    <Pagination total={matching.length} limit={limit} offset={offset} onPageChange={setPageOffset} />
    <Dialog open={!!modal} onOpenChange={open => { if (!open) close() }}><DialogContent className="max-w-3xl max-h-[85vh] overflow-y-auto"><DialogHeader><DialogTitle>{modal?.kind === 'delete' ? 'Remove from local draft' : modal?.kind === 'inspect' ? title : `${selected ? 'Edit' : 'New'} ${title.toLowerCase()} draft`}</DialogTitle></DialogHeader>
      {modal?.kind === 'edit' && <SourceAuthoringScope id="form"><SourceAuthoringScope id={String(selected?.id ?? selected?.profileId ?? modal.index)}><SourceRecordForm key={modal.index} fields={fields} value={selected ?? modal.value!} onClose={close} onSave={value => { const next = [...rows]; if (modal.index < 0) next.push(value); else next[modal.index] = value; onChange(next); close() }} /></SourceAuthoringScope></SourceAuthoringScope>}
      {modal?.kind === 'inspect' && selected && <><dl className="grid gap-4 sm:grid-cols-2">{fields.filter(field => !field.onlyFor || field.onlyFor.includes(String(selected.kind))).map(field => <div key={field.key} className="min-w-0 rounded-lg border border-neutral-200 p-3"><dt className="mb-2 text-xs font-medium text-neutral-500">{field.label}</dt><dd><SourceFieldValue value={valueAt(selected, field.key)} label={field.label} /></dd></div>)}</dl><details className="rounded-lg border border-neutral-200 p-3"><summary className="cursor-pointer text-sm text-neutral-600">Raw JSON (advanced)</summary><pre className="mt-3 max-h-72 overflow-auto whitespace-pre-wrap break-all text-xs">{JSON.stringify(selected, null, 2)}</pre></details><div className="flex justify-end"><Button variant="outline" onClick={close}>Close</Button></div></>}
      {modal?.kind === 'delete' && selected && <div className="space-y-4"><p className="text-sm">Remove this entry from the proposal? Other policy references remain unchanged and must be reviewed.</p>{dependencies?.(selected).map(path => <p key={path} className="text-xs text-warning-dark break-all">Referenced by: {path}</p>)}{error && <p role="alert" className="text-error-dark">{error}</p>}<div className="flex justify-end gap-2"><Button variant="ghost" onClick={close}>Cancel</Button><Button variant="destructive" onClick={() => { try { onChange(rows.filter((_, i) => i !== modal.index)); close() } catch (e) { setError(e instanceof Error ? e.message : 'Could not remove this draft entry.') } }}>Remove from draft</Button></div></div>}
    </DialogContent></Dialog>
  </section>
}

export function SourceFieldValue({ value, label }: { value: unknown; label: string }) {
  if (value === undefined || value === null || value === '') return <span className="text-sm text-neutral-400">Not set</span>
  if (typeof value === 'boolean') return <Badge variant={value ? 'info' : 'outline'}>{value ? 'Enabled' : 'Disabled'}</Badge>
  if (Array.isArray(value) && value.every(item => typeof item === 'string')) return <div className="flex flex-wrap gap-1">{value.length ? value.map((item, index) => <Badge key={index} variant="outline">{item}</Badge>) : <span className="text-sm text-neutral-400">None</span>}</div>
  if (typeof value === 'object') return <details><summary className="cursor-pointer text-sm text-primary">Show {label.toLowerCase()}</summary><pre className="mt-2 max-h-64 overflow-auto whitespace-pre-wrap break-all text-xs">{JSON.stringify(value, null, 2)}</pre></details>
  const text = String(value)
  return <span className="flex min-w-0 items-start gap-1"><span className="break-all text-sm text-neutral-900">{text}</span><CopyValue value={text} label={'Copy ' + label.toLowerCase()} /></span>
}

export function SourceRecords(props: Parameters<typeof SourceRecordsContent>[0]) {
  return <SourceAuthoringScope id={'records:' + props.title}><SourceRecordsContent {...props} /></SourceAuthoringScope>
}
