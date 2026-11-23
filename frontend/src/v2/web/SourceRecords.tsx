import { useEffect, useState } from 'react'
import { Eye, Search } from 'lucide-react'
import { Badge } from '../../components/ui/badge'
import { Button } from '../../components/ui/button'
import { Input } from '../../components/ui/input'
import { Dialog, DialogContent, DialogHeader, DialogTitle } from '../../components/ui/dialog'
import { Table, TableHeader, TableBody, TableRow, TableHead, TableCell } from '../../components/ui/table'
import Pagination from '../../components/ui/Pagination'
import { CopyValue } from '../../components/ui/CopyValue'
import { SourceViewScope, useSourceObservation, useSourceViewState } from './sourceViewState'
import { browserNumbersSafe, object, type JSONObject } from './sourceProject'

export interface SourceField { key: string; label: string; kind?: 'text' | 'number' | 'boolean' | 'list' | 'json'; optional?: boolean; help?: string; options?: string[]; onlyFor?: string[] }
const valueAt = (value: JSONObject, path: string): unknown => path.split('.').reduce<unknown>((next, key) => next && typeof next === 'object' && !Array.isArray(next) ? (next as JSONObject)[key] : undefined, value)
interface Props { title: string; description?: string; records: unknown; fields: SourceField[] }
function SourceRecordsContent({ title, description, records, fields }: Props) {
  const [search, setSearch] = useSourceViewState('search', ''), [pageOffset, setPageOffset] = useSourceViewState('offset', 0)
  const observation = useSourceObservation(), [selection, setSelection] = useState<{ id?: string; index: number; observation: number } | null>(null)
  if (!Array.isArray(records) || records.length > 4096 || !browserNumbersSafe(records)) throw Error('This catalog cannot be displayed safely in structured views. Inspect its source file.')
  const rows = records.map(object), limit = 50
  const matching = rows.map((row, index) => ({ row, index })).filter(({ row }) => JSON.stringify(row).toLowerCase().includes(search.toLowerCase()))
  const offset = Math.min(pageOffset, Math.max(0, Math.ceil(matching.length / limit) - 1) * limit), visible = matching.slice(offset, offset + limit)
  const matches = selection?.id ? rows.filter(row => row.id === selection.id) : []
  const selected = selection?.id ? matches.length === 1 ? matches[0] : undefined : selection?.observation === observation ? rows[selection.index] : undefined
  useEffect(() => { if (selection && !selected) setSelection(null) }, [selection, selected])
  const close = () => setSelection(null)
  const inspect = (row: JSONObject, index: number) => setSelection({ ...(typeof row.id === 'string' && rows.filter(other => other.id === row.id).length === 1 ? { id: row.id } : {}), index, observation })
  return <section className="space-y-4"><div className="flex flex-wrap items-center justify-between gap-3"><div><h3 className="text-sm font-medium">{title}</h3>{description && <p className="mt-1 text-xs text-neutral-500">{description}</p>}</div><Badge variant="outline">{rows.length} entries</Badge></div>
    {rows.length > 0 && <div className="relative max-w-md"><Search className="absolute left-3 top-3 h-4 w-4 text-neutral-400" /><Input className="pl-9" aria-label={'Search ' + title.toLowerCase()} value={search} placeholder="Search..." onChange={event => { setSearch(event.target.value); setPageOffset(0) }} /></div>}
    <div className="overflow-x-auto rounded-lg border border-neutral-200"><Table><TableHeader><TableRow><TableHead>Name / ID</TableHead><TableHead>Details</TableHead><TableHead className="text-right">Actions</TableHead></TableRow></TableHeader><TableBody>{visible.map(({ row, index }) => <TableRow key={typeof row.id === 'string' ? row.id : index}><TableCell><button type="button" className="break-all text-left font-medium text-primary hover:underline" onClick={() => inspect(row, index)}>{String(row.name ?? row.id ?? row.profileId ?? row.organizationId ?? row.url ?? row.network ?? 'Entry ' + (index + 1))}</button></TableCell><TableCell><div className="flex max-w-lg flex-wrap gap-2 text-xs text-neutral-500">{fields.slice(0, 3).map(field => <span key={field.key}>{field.label}: {typeof valueAt(row, field.key) === 'object' ? 'Configured' : String(valueAt(row, field.key) ?? 'Not set')}</span>)}</div></TableCell><TableCell className="text-right"><Button size="sm" variant="ghost" aria-label={`Inspect ${title.toLowerCase()} ${String(row.name ?? row.id ?? index + 1)}`} onClick={() => inspect(row, index)}><Eye className="mr-1 h-4 w-4" />Inspect</Button></TableCell></TableRow>)}{!visible.length && <TableRow><TableCell colSpan={3} className="py-8 text-center text-neutral-500">{search ? `No ${title.toLowerCase()} match this search.` : `No ${title.toLowerCase()} in this source.`}</TableCell></TableRow>}</TableBody></Table></div>
    {search && !matching.length && <Button variant="outline" onClick={() => { setSearch(''); setPageOffset(0) }}>Clear search</Button>}
    <Pagination total={matching.length} limit={limit} offset={offset} onPageChange={setPageOffset} />
    <Dialog open={!!selected} onOpenChange={open => { if (!open) close() }}><DialogContent className="max-w-3xl max-h-[85vh] overflow-y-auto"><DialogHeader><DialogTitle>{title}</DialogTitle></DialogHeader>{selected && <><dl className="grid gap-4 sm:grid-cols-2">{fields.filter(field => !field.onlyFor || field.onlyFor.includes(String(selected.kind))).map(field => <div key={field.key} className="min-w-0 rounded-lg border border-neutral-200 p-3"><dt className="mb-2 text-xs font-medium text-neutral-500">{field.label}</dt><dd><SourceFieldValue value={valueAt(selected, field.key)} label={field.label} /></dd>{field.help && <p className="mt-2 text-xs text-neutral-500">{field.help}</p>}</div>)}</dl><details className="rounded-lg border border-neutral-200 p-3"><summary className="cursor-pointer text-sm text-neutral-600">Raw JSON (advanced)</summary><pre className="mt-3 max-h-72 overflow-auto whitespace-pre-wrap break-all text-xs">{JSON.stringify(selected, null, 2)}</pre></details><div className="flex justify-end"><Button variant="outline" onClick={close}>Close</Button></div></>}</DialogContent></Dialog>
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
export function SourceRecords(props: Props) { return <SourceViewScope id={'records:' + props.title}><SourceRecordsContent {...props} /></SourceViewScope> }
