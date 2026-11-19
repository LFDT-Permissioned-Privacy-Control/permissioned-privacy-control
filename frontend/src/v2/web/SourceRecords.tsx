import { useState, type FormEvent } from 'react'
import { Pencil, Plus, Trash2 } from 'lucide-react'
import { Button } from '../../components/ui/button'
import { Input } from '../../components/ui/input'
import { Textarea } from '../../components/ui/textarea'
import { Dialog, DialogContent, DialogHeader, DialogTitle } from '../../components/ui/dialog'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '../../components/ui/table'
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
  const [values, setValues] = useState<Record<string, string | boolean>>(() => Object.fromEntries(fields.map(f => {
    const v = valueAt(value, f.key)
    return [f.key, f.kind === 'boolean' ? v === true : v === undefined ? f.optional ? '' : f.options?.[0] ?? '' : f.kind === 'json' ? JSON.stringify(v, null, 2) : f.kind === 'list' ? (v as string[]).join('\n') : String(v)]
  }))), [error, setError] = useState<string | null>(null)
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
    {fields.filter(f => !f.onlyFor || f.onlyFor.includes(String(values.kind))).map(f => <label key={f.key} className="block text-sm font-medium">{f.kind === 'boolean' ? <span className="inline-flex gap-2"><input type="checkbox" checked={values[f.key] === true} onChange={e => setValues({ ...values, [f.key]: e.target.checked })} />{f.label}</span> : <>{f.label}
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
export function SourceRecords({ title, description, records, fields, defaults, editing, onChange, renderActions, dependencies }: {
  title: string; description?: string; records: unknown; fields: SourceField[]; defaults(): JSONObject; editing: boolean; onChange(values: JSONObject[]): void
  renderActions?(record: JSONObject, index: number): React.ReactNode; dependencies?(record: JSONObject): string[]
}) {
  const [modal, setModal] = useState<{ kind: 'edit' | 'delete' | 'inspect'; index: number } | null>(null), [search, setSearch] = useState(''), [error, setError] = useState<string | null>(null)
  if (!Array.isArray(records)) throw Error(`${title} has an unsupported source shape. Open Configuration source to repair it.`)
  const rows = records.map(object), selected = modal && modal.index >= 0 ? rows[modal.index] : undefined
  const close = () => { setModal(null); setError(null) }
  return <section className="space-y-4"><div className="flex flex-wrap items-start justify-between gap-3"><div><h3 className="text-sm font-medium text-neutral-700">{title}</h3>{description && <p className="text-xs text-neutral-500 mt-1 max-w-3xl">{description}</p>}</div>{editing && <Button size="sm" onClick={() => setModal({ kind: 'edit', index: -1 })}><Plus className="w-4 h-4 mr-2" />Add {title.toLowerCase().replace(/s$/, '')}</Button>}</div>
    <Input className="max-w-sm" aria-label={`Search ${title.toLowerCase()}`} placeholder="Search..." value={search} onChange={e => setSearch(e.target.value)} />
    <div className="rounded-lg border border-neutral-200 overflow-x-auto"><Table><TableHeader><TableRow><TableHead>Name / ID</TableHead><TableHead>Details</TableHead><TableHead className="text-right">Actions</TableHead></TableRow></TableHeader><TableBody>
      {rows.map((r, index) => ({ r, index })).filter(({ r }) => !search || JSON.stringify(r).toLowerCase().includes(search.toLowerCase())).map(({ r, index }) => <TableRow key={index}><TableCell className="font-medium"><button className="text-primary hover:underline text-left break-all" onClick={() => setModal({ kind: 'inspect', index })}>{String(r.name ?? r.id ?? r.profileId ?? r.address ?? `Entry ${index + 1}`)}</button></TableCell><TableCell className="text-xs text-neutral-500 max-w-sm break-all">{fields.filter(f => !['json', 'boolean', 'textarea'].includes(f.kind ?? '')).slice(0, 4).map(f => valueAt(r, f.key) === undefined ? null : <p key={f.key}>{f.label}: {Array.isArray(valueAt(r, f.key)) ? (valueAt(r, f.key) as string[]).join(', ') : String(valueAt(r, f.key))}</p>)}</TableCell><TableCell><div className="flex justify-end gap-1">{renderActions?.(r, index)}{editing && <><Button size="sm" variant="ghost" title={`Edit ${title.toLowerCase()} draft`} onClick={() => setModal({ kind: 'edit', index })}><Pencil className="w-4 h-4" /></Button><Button size="sm" variant="ghost" title={`Remove ${title.toLowerCase()} draft`} onClick={() => setModal({ kind: 'delete', index })}><Trash2 className="w-4 h-4" /></Button></>}</div></TableCell></TableRow>)}
      {!rows.length && <TableRow><TableCell colSpan={3} className="text-center text-neutral-500 py-8">No {title.toLowerCase()} in this source.</TableCell></TableRow>}
    </TableBody></Table></div>
    <Dialog open={!!modal} onOpenChange={open => { if (!open) close() }}><DialogContent className="max-w-3xl max-h-[85vh] overflow-y-auto"><DialogHeader><DialogTitle>{modal?.kind === 'delete' ? 'Remove from local draft' : modal?.kind === 'inspect' ? title : `${selected ? 'Edit' : 'New'} ${title.toLowerCase()} draft`}</DialogTitle></DialogHeader>
      {modal?.kind === 'edit' && <SourceRecordForm key={modal.index} fields={fields} value={selected ?? defaults()} onClose={close} onSave={value => { const next = [...rows]; if (modal.index < 0) next.push(value); else next[modal.index] = value; onChange(next); close() }} />}
      {modal?.kind === 'inspect' && <div className="space-y-3">{fields.map(f => <div key={f.key}><p className="text-xs font-medium text-neutral-500">{f.label}</p><pre className="text-sm whitespace-pre-wrap break-all max-h-60 overflow-auto">{typeof valueAt(selected ?? {}, f.key) === 'object' ? JSON.stringify(valueAt(selected ?? {}, f.key), null, 2) : String(valueAt(selected ?? {}, f.key) ?? 'Not set')}</pre></div>)}</div>}
      {modal?.kind === 'delete' && selected && <div className="space-y-4"><p className="text-sm">Remove this entry from the proposal? Other policy references remain unchanged and must be reviewed.</p>{dependencies?.(selected).map(path => <p key={path} className="text-xs text-warning-dark break-all">Referenced by: {path}</p>)}{error && <p role="alert" className="text-error-dark">{error}</p>}<div className="flex justify-end gap-2"><Button variant="ghost" onClick={close}>Cancel</Button><Button variant="destructive" onClick={() => { try { onChange(rows.filter((_, i) => i !== modal.index)); close() } catch (e) { setError(e instanceof Error ? e.message : 'Could not remove this draft entry.') } }}>Remove from draft</Button></div></div>}
    </DialogContent></Dialog>
  </section>
}
