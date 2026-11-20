import { useState } from 'react'
import { Button } from '../../components/ui/button'
import { actorID } from './operationsModels'
import { Field, Panel, SelectField, TaskError } from './operationsUI'

export interface CaseFilterValues { status: string; privacyLevel: string; recipientActorId: string; createdFrom: string; createdTo: string }
export const emptyCaseFilters: CaseFilterValues = { status: '', privacyLevel: '', recipientActorId: '', createdFrom: '', createdTo: '' }
export function caseFilterQuery(value: CaseFilterValues): Record<string, string> {
  const query: Record<string, string> = {}
  for (const key of ['status', 'privacyLevel', 'recipientActorId'] as const) if (value[key].trim()) query[key] = value[key].trim()
  if (query.recipientActorId && !actorID(query.recipientActorId)) throw Error('Enter a complete OPS actor ID.')
  for (const key of ['createdFrom', 'createdTo'] as const) if (value[key]) {
    const stamp = Date.parse(value[key] + 'Z') / 1000
    if (!Number.isSafeInteger(stamp) || stamp <= 0) throw Error('Enter a valid UTC creation time.')
    query[key] = String(stamp)
  }
  if (query.createdFrom && query.createdTo && Number(query.createdFrom) >= Number(query.createdTo)) throw Error('Created from must be earlier than Created before.')
  return query
}
export function CaseFilters({ value, onChange, onSearch }: { value: CaseFilterValues; onChange(value: CaseFilterValues): void; onSearch(query: Record<string, string>): void }) {
  const [error, setError] = useState<string | null>(null)
  const edit = (key: keyof CaseFilterValues, next: string) => { setError(null); onChange({ ...value, [key]: next }) }
  return <Panel title="Find disclosure cases"><form aria-label="Disclosure case filters" className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3" onSubmit={event => { event.preventDefault(); try { onSearch(caseFilterQuery(value)); setError(null) } catch (failure) { setError((failure as Error).message) } }}>
    <SelectField label="Case status" value={value.status} onChange={next => edit('status', next)} options={[{ value: '', label: 'All statuses' }, { value: 'active', label: 'Open (not expired)' }, { value: 'expired', label: 'Expired' }, { value: 'revoked', label: 'Revoked' }]} />
    <SelectField label="Case privacy level" value={value.privacyLevel} onChange={next => edit('privacyLevel', next)} options={[{ value: '', label: 'All privacy levels' }, { value: 'redacted', label: 'Redacted' }, { value: 'pseudonymous', label: 'Pseudonymous' }, { value: 'full', label: 'Full' }]} />
    <Field label="Recipient OPS actor ID filter" value={value.recipientActorId} onChange={next => edit('recipientActorId', next)} hint="Exact identity ID; this filter cannot add access to another recipient’s cases." />
    <Field label="Created from (UTC)" type="datetime-local" step={1} value={value.createdFrom} onChange={next => edit('createdFrom', next)} />
    <Field label="Created before (UTC)" type="datetime-local" step={1} value={value.createdTo} onChange={next => edit('createdTo', next)} />
    <div className="flex items-end gap-2"><Button type="submit">Search cases</Button><Button type="button" variant="outline" onClick={() => { onChange(emptyCaseFilters); onSearch({}); setError(null) }}>Reset case filters</Button></div>
    <div className="sm:col-span-2 lg:col-span-3"><TaskError message={error} /><p className="mt-2 text-xs text-neutral-500">Filters run on the server within your selected case view. Status is evaluated when each page is read. Results use the last submitted search.</p></div>
  </form></Panel>
}
