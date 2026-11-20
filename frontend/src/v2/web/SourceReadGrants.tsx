import { useMemo, useState, type FormEvent } from 'react'
import { toEventSelector, toEventSignature, type AbiEvent, type AbiParameter } from 'viem'
import { Pencil, Plus, Radio, Trash2, X } from 'lucide-react'
import { Button } from '../../components/ui/button'
import { Input } from '../../components/ui/input'
import { Dialog, DialogContent, DialogHeader, DialogTitle } from '../../components/ui/dialog'
import { SourceAuthoringScope } from './SourceAuthoringScope'
import { useAuthoringState, useClearAuthoring } from './sourceAuthoring'
import { SourceRecordForm } from './SourceRecords'
import { browserNumbersSafe, object, type JSONObject } from './sourceProject'
import type { DraftGroup } from './workspace'

interface EventDefinition { name: string; signature: string; topic: string; inputs: readonly AbiParameter[] }
type GroupChoice = Pick<DraftGroup, 'id' | 'name' | 'slug'>
const selectClass = 'block w-full rounded-lg border border-neutral-300 p-2 mt-1 text-sm'
const modes = { none: 'No events visible', all: 'All events visible', allowlist: 'Specific events only' }
const boolHex = (value: boolean) => '0x' + '0'.repeat(63) + (value ? '1' : '0')
function integerWidth(type: string): number | null {
  const match = /^(u?int)([0-9]+)?$/.exec(type)
  if (!match) return null
  const bits = Number(match[2] || 256)
  return bits >= 8 && bits <= 256 && bits % 8 === 0 ? bits : null
}
const staticType = (type: string) => type === 'address' || type === 'bool' || integerWidth(type) !== null || /^bytes([1-9]|[12][0-9]|3[0-2])$/.test(type)

function normalizedParameter(value: AbiParameter): AbiParameter {
  const type = value.type.replace(/^(uint|int)(?=\[|$)/, (_, base: string) => base + '256')
  return { ...value, type, ...('components' in value ? { components: value.components.map(normalizedParameter) } : {}) } as AbiParameter
}
function eventsFromABI(value: unknown): { events: EventDefinition[]; error: string | null } {
  try {
    if (!Array.isArray(value)) throw Error('The contract ABI must be a JSON array.')
    const events = value.filter(entry => object(entry).type === 'event' && object(entry).anonymous !== true).map(entry => {
      const event = object(entry)
      if (typeof event.name !== 'string' || !Array.isArray(event.inputs)) throw Error('An event in this ABI is incomplete.')
      const parsed = { ...event, inputs: event.inputs.map(input => normalizedParameter(object(input) as unknown as AbiParameter)) } as unknown as AbiEvent
      return { name: parsed.name, signature: toEventSignature(parsed), topic: toEventSelector(parsed).toLowerCase(), inputs: parsed.inputs }
    })
    if (new Set(events.map(event => event.topic)).size !== events.length) throw Error('The ABI has duplicate event signatures. Repair it before selecting events.')
    return { events: events.sort((a, b) => a.signature.localeCompare(b.signature)), error: null }
  } catch (error) { return { events: [], error: error instanceof Error ? error.message : 'The contract ABI could not be read.' } }
}

// A literal is stored in the native Go schema's exact scalar width. Never
// truncate an oversized address/value as the legacy form's padding helper did.
function nativeLiteral(raw: string, type: string): string {
  if (raw === 'self') {
    if (type !== 'address') throw Error('Self can be used only for an address parameter.')
    return raw
  }
  if (!staticType(type)) throw Error('This parameter type supports Any value only. Inspect advanced JSON to repair an existing rule.')
  const value = raw.trim().toLowerCase()
  if (!/^0x[0-9a-f]+$/.test(value)) throw Error('Enter a 0x-prefixed hex value for each custom parameter.')
  const width = type === 'address' ? 40 : type.startsWith('bytes') ? Number(type.slice(5)) * 2 : 64
  const hex = value.slice(2)
  if (type.startsWith('bytes') && hex.length % 2) throw Error('Fixed byte values need a whole number of bytes (two hex characters each).')
  if (hex.length > width) throw Error(`The ${type} value is too long; it will not be truncated.`)
  if (type === 'bool' && BigInt(value) > 1n) throw Error('A boolean constraint must be True or False.')
  if (type === 'address' && hex.length !== width) throw Error('A custom address needs exactly 40 hex characters after 0x.')
  const bits = integerWidth(type)
  if (bits !== null) {
    const numeric = BigInt(value), signed = type.startsWith('int')
    const limit = 1n << BigInt(bits - (signed ? 1 : 0))
    const negative = signed && hex.length === 64 && numeric >= (1n << 256n) - limit
    if (numeric >= limit && !negative) throw Error(`The value is outside the ${type} range.${signed ? ' Negative values need the full 32-byte sign-extended hex word.' : ''}`)
  }
  return '0x' + (type.startsWith('bytes') ? hex.padEnd(width, '0') : hex.padStart(width, '0'))
}
function rulesOf(value: JSONObject): JSONObject[] {
  const rules = object(value.eventRules).rules
  if (!Array.isArray(rules)) throw Error('Read grants need an eventRules.rules array. Repair this grant in Review & export.')
  return rules.map(object)
}
function paramsOf(value: JSONObject): JSONObject[] {
  if (!Array.isArray(value.paramRules)) throw Error('Each event rule needs a paramRules array. Repair this grant in advanced JSON.')
  return value.paramRules.map(object)
}

function SourceReadGrantsContent({ contract, groups, editing, onChange }: {
  contract: JSONObject; groups: GroupChoice[]; editing: boolean; onChange(values: JSONObject[]): void
}) {
  const clear = useClearAuthoring()
  const [pendingModal, setModal] = useAuthoringState<{ index: number; remove?: boolean; value?: JSONObject } | null>('modal', null)
  const [inspection, setInspection] = useState<{ index: number; remove?: boolean; value?: JSONObject } | null>(null)
  const modal = inspection ?? (editing ? pendingModal : null), activeEditing = editing && !inspection
  const [search, setSearch] = useAuthoringState('search', ''), [error, setError] = useState<string | null>(null)
  if (!Array.isArray(contract.readGrants)) throw Error('Read grants must be an array. Repair the contract in Review & export.')
  const grants = contract.readGrants.map(object), parsed = useMemo(() => eventsFromABI(contract.abi), [contract.abi])
  const groupName = (id: unknown) => groups.find(group => group.id === id)?.name ?? `Unknown group (${String(id)})`
  const close = () => { if (inspection) setInspection(null); else { clear('form'); setModal(null) } setError(null) }
  const current = modal && (modal.index < 0 ? modal.value : grants[modal.index])
  const availableGroups = groups.filter(group => !grants.some((grant, index) => grant.groupId === group.id && index !== modal?.index))
  return <section className="space-y-4">
    <div className="flex flex-wrap items-start justify-between gap-3"><div><h3 className="text-sm font-medium text-neutral-700">Read grants</h3><p className="mt-1 text-xs text-neutral-500">Choose the group and the events its members may read. Execution permissions are separate.</p></div>{editing && <Button size="sm" disabled={!groups.some(group => !grants.some(grant => grant.groupId === group.id))} onClick={() => setModal({ index: -1, value: { id: crypto.randomUUID(), groupId: '', eventRules: { mode: 'none', rules: [] } } })}><Plus className="mr-2 h-4 w-4" />Add read grant</Button>}</div>
    <Input aria-label="Search read grants" placeholder="Search groups..." value={search} onChange={event => setSearch(event.target.value)} />
    <div className="divide-y divide-neutral-200 rounded-lg border border-neutral-200">{grants.map((grant, index) => ({ grant, index })).filter(({ grant }) => groupName(grant.groupId).toLowerCase().includes(search.toLowerCase())).map(({ grant, index }) => <div key={index} className="flex flex-wrap items-center justify-between gap-3 p-3"><div className="min-w-0"><button className="text-sm font-medium text-primary hover:underline" onClick={() => { if (editing) setModal({ index }); else setInspection({ index }) }}>{groupName(grant.groupId)}</button><p className="mt-1 text-xs text-neutral-500">{modes[object(grant.eventRules).mode as keyof typeof modes] ?? 'Unknown event mode'}{object(grant.eventRules).mode === 'allowlist' && ` · ${rulesOf(grant).length} selected`}</p></div>{editing && <div className="flex gap-1"><Button size="sm" variant="ghost" aria-label={`Edit read grant for ${groupName(grant.groupId)}`} onClick={() => setModal({ index })}><Pencil className="h-4 w-4" /></Button><Button size="sm" variant="ghost" aria-label={`Remove read grant for ${groupName(grant.groupId)}`} onClick={() => setModal({ index, remove: true })}><Trash2 className="h-4 w-4" /></Button></div>}</div>)}</div>
    {!grants.length && <p className="text-sm text-neutral-500">No group has a read grant for this contract.</p>}
    <Dialog open={modal !== null} onOpenChange={open => { if (!open) close() }}><DialogContent className="max-w-3xl max-h-[85vh] overflow-y-auto"><DialogHeader><DialogTitle>{modal?.remove ? 'Remove read grant' : `${activeEditing ? 'Edit' : 'Inspect'} read grant`}</DialogTitle></DialogHeader>
      {modal?.remove ? <div className="space-y-4"><p>Remove {groupName(current?.groupId)} from this contract’s local read grants?</p>{error && <p role="alert" className="text-error-dark">{error}</p>}<div className="flex justify-end gap-2"><Button variant="ghost" onClick={close}>Cancel</Button><Button variant="destructive" onClick={() => { try { onChange(grants.filter((_, index) => index !== modal.index)); close() } catch (error) { setError(error instanceof Error ? error.message : 'Could not remove the grant.') } }}>Remove from draft</Button></div></div>
        : current && <SourceAuthoringScope id={inspection ? "inspection" : "form"}><SourceAuthoringScope id={String(current.id ?? modal?.index)}><ReadGrantForm key={modal?.index} value={current} groups={availableGroups} events={parsed.events} abiError={parsed.error} editing={activeEditing} onClose={close} onSave={value => { if (!groups.some(group => group.id === value.groupId)) throw Error('Choose a group from this organization.'); if (grants.some((grant, index) => index !== modal!.index && grant.groupId === value.groupId)) throw Error('This group already has a read grant. Edit its existing grant instead.'); onChange(modal!.index < 0 ? [...grants, value] : grants.map((grant, index) => index === modal!.index ? value : grant)); close() }} /></SourceAuthoringScope></SourceAuthoringScope>}
    </DialogContent></Dialog>
  </section>
}

function ReadGrantForm({ value, groups, events, abiError, editing, onSave, onClose }: {
  value: JSONObject; groups: GroupChoice[]; events: EventDefinition[]; abiError: string | null; editing: boolean; onSave(value: JSONObject): void; onClose(): void
}) {
  const clear = useClearAuthoring()
  const [group, setGroup] = useAuthoringState('group', String(value.groupId), { draft: true, base: value }), [mode, setMode] = useAuthoringState('mode', String(object(value.eventRules).mode), { draft: true, base: value })
  const [rules, setRules] = useAuthoringState('rules', () => rulesOf(value), { draft: true, base: value }), [advanced, setAdvanced] = useAuthoringState('advanced', false), [error, setError] = useState<string | null>(null)
  const proposed = { ...value, groupId: group, eventRules: { ...object(value.eventRules), mode, rules: mode === 'allowlist' ? rules : [] } }
  function save(event: FormEvent) {
    event.preventDefault()
    try {
      if (!browserNumbersSafe(value)) throw Error('Use Configuration source to preserve this document’s numeric values exactly.')
      if (!groups.some(choice => choice.id === group)) throw Error('Choose a group from this organization.')
      if (!Object.keys(modes).includes(mode)) throw Error('Choose an event visibility mode.')
      if (mode === 'allowlist' && !rules.length) throw Error('Choose at least one event, or select No events visible.')
      const normalized = rules.map(rule => {
        const definition = events.find(event => event.topic === String(rule.topic0).toLowerCase())
        // Preserve unresolved existing rules rather than silently dropping or
        // replacing them. The Go checker remains the final ABI authority.
        if (!definition) return rule
        return { ...rule, paramRules: paramsOf(rule).map(param => {
          if (!Number.isSafeInteger(param.index) || Number(param.index) < 0 || Number(param.index) >= definition.inputs.length) throw Error('An event parameter index does not match this ABI.')
          return { ...param, must_be: nativeLiteral(String(param.must_be), definition.inputs[Number(param.index)].type) }
        }) }
      })
      const result = { ...proposed, eventRules: { ...proposed.eventRules, rules: mode === 'allowlist' ? normalized : [] } }
      if (!browserNumbersSafe(result)) throw Error('Use Configuration source to preserve numeric values exactly.')
      onSave(result)
    } catch (error) { setError(error instanceof Error ? error.message : 'Could not save this grant.') }
  }
  function setParam(topic: unknown, index: number, mustBe: string | null) {
    setRules(rules.map(rule => rule.topic0 !== topic ? rule : { ...rule, paramRules: mustBe === null ? paramsOf(rule).filter(param => param.index !== index) : paramsOf(rule).some(param => param.index === index) ? paramsOf(rule).map(param => param.index === index ? { ...param, must_be: mustBe } : param) : [...paramsOf(rule), { index, must_be: mustBe }] }))
  }
  if (advanced && editing) return <div className="space-y-4"><Button variant="ghost" onClick={() => { clear('advanced'); setAdvanced(false) }}>Cancel advanced edits</Button><SourceAuthoringScope id="advanced"><SourceRecordForm value={proposed} fields={[{ key: 'id', label: 'Grant ID' }, { key: 'groupId', label: 'Group ID' }, { key: 'eventRules.mode', label: 'Event visibility mode', options: Object.keys(modes) }, { key: 'eventRules.rules', label: 'Custom event rules', kind: 'json' }]} onClose={onClose} onSave={onSave} /></SourceAuthoringScope></div>
  return <form onSubmit={save} className="space-y-5">
    <fieldset disabled={!editing} className="space-y-5">
      <label className="block text-sm font-medium">Group<select className={selectClass} value={group} onChange={event => setGroup(event.target.value)}><option value="">Select a group...</option>{!groups.some(choice => choice.id === group) && group && <option value={group}>Unknown group ({group})</option>}{groups.map(choice => <option key={choice.id} value={choice.id}>{choice.name} ({choice.slug})</option>)}</select></label>
      <fieldset className="space-y-2"><legend className="mb-2 text-sm font-medium">Event visibility</legend>{Object.entries(modes).map(([id, label]) => <label key={id} className="flex cursor-pointer items-center gap-3 rounded-lg border border-neutral-200 p-3 hover:bg-neutral-100"><input type="radio" name="event-visibility" value={id} checked={mode === id} onChange={() => setMode(id)} /><span className="text-sm">{label}</span></label>)}</fieldset>
      {mode === 'allowlist' && <div className="space-y-4">
        <p className="text-xs text-neutral-500">An event is visible when any one of its parameter constraints matches (OR). With no constraints, every event with that signature is visible. Self means one of the viewer’s linked addresses.</p>
        {rules.map((rule, index) => {
          const event = events.find(event => event.topic === String(rule.topic0).toLowerCase())
          return <div key={index} className="space-y-3 rounded-lg border border-primary-50 bg-neutral-50 p-3"><div className="flex items-start justify-between gap-2"><div className="min-w-0"><span className="inline-flex items-center gap-2 text-sm font-medium text-primary"><Radio className="h-4 w-4 shrink-0" />{String(rule.name)}</span><p className="break-all font-mono text-xs text-neutral-500">{event?.signature ?? String(rule.topic0)}</p></div><Button type="button" variant="ghost" size="sm" aria-label={`Remove event ${String(rule.name)}`} onClick={() => setRules(rules.filter((_, selected) => selected !== index))}><X className="h-4 w-4" /></Button></div>
            {!event && <p className="text-xs text-warning-dark">This rule does not match an event in the current ABI. It is preserved; inspect advanced JSON or repair the ABI before Go validation.</p>}
            {event?.inputs.map((param, inputIndex) => <ParameterConstraint key={inputIndex} parameter={param} index={inputIndex} value={paramsOf(rule).find(constraint => constraint.index === inputIndex)?.must_be} onChange={next => setParam(rule.topic0, inputIndex, next)} />)}
          </div>
        })}
        <div className="space-y-2"><p className="text-sm font-medium">Contract events</p>{abiError && <p className="text-sm text-warning-dark">{abiError} Repair the contract ABI to use event choices. Existing rules are preserved.</p>}{!abiError && !events.length && <p className="text-sm text-neutral-500">The ABI contains no non-anonymous events. Add or repair it in Contracts to choose events.</p>}
          <div className="max-h-48 space-y-1 overflow-y-auto rounded-lg border border-neutral-200 p-2">{events.map(event => <Button key={event.topic} type="button" variant="ghost" size="sm" className="h-auto w-full justify-start whitespace-normal text-left" disabled={rules.some(rule => String(rule.topic0).toLowerCase() === event.topic)} onClick={() => setRules([...rules, { topic0: event.topic, name: event.name, paramRules: event.inputs.flatMap((param, index) => param.type === 'address' ? [{ index, must_be: 'self' }] : []) }])}><Plus className="mr-2 h-3 w-3 shrink-0" /><span className="break-all font-mono text-xs">{event.signature}</span></Button>)}</div>
        </div>
      </div>}
    </fieldset>
    {error && <p role="alert" className="rounded-lg bg-error-light p-3 text-sm text-error-dark">{error}</p>}
    <p className="text-xs text-neutral-500">This saves a local proposal. Go validates the complete source; Git approval and deployment make it effective.</p>
    <div className="flex flex-wrap justify-between gap-2">{editing ? <Button type="button" variant="ghost" onClick={() => setAdvanced(true)}>Advanced grant JSON</Button> : <span />}<div className="flex gap-2"><Button type="button" variant="ghost" onClick={onClose}>{editing ? 'Cancel' : 'Close'}</Button>{editing && <Button type="submit">Save grant draft</Button>}</div></div>
  </form>
}

function ParameterConstraint({ parameter, index, value, onChange }: { parameter: AbiParameter; index: number; value: unknown; onChange(value: string | null): void }) {
  const name = parameter.name || `Parameter ${index + 1}`, type = parameter.type
  const mode = value === undefined ? 'any' : value === 'self' ? 'self' : type === 'bool' && value === boolHex(true) ? 'true' : type === 'bool' && value === boolHex(false) ? 'false' : 'custom'
  return <div className="space-y-2 rounded-lg border border-neutral-200 bg-white p-3"><label className="flex flex-wrap items-center gap-2 text-sm"><code className="break-all text-xs">{name}</code><span className="text-xs text-neutral-500">{type}{'indexed' in parameter && parameter.indexed ? ' · indexed' : ''}</span><select aria-label={`${name} constraint`} className="ml-auto max-w-full rounded-lg border border-neutral-300 p-1 text-xs" value={mode} onChange={event => onChange(event.target.value === 'any' ? null : event.target.value === 'self' ? 'self' : event.target.value === 'true' ? boolHex(true) : event.target.value === 'false' ? boolHex(false) : '')}><option value="any">Any value</option>{type === 'address' && <option value="self">Viewer’s linked address (self)</option>}{type === 'bool' && <><option value="true">True</option><option value="false">False</option></>}{(type !== 'bool' && staticType(type) || mode === 'custom') && <option value="custom">Custom hex value</option>}</select></label>
    {mode === 'custom' && <label className="block text-xs text-neutral-500">{name} custom value<Input aria-label={`${name} custom value`} className="mt-1 font-mono text-xs" value={String(value ?? '')} onChange={event => onChange(event.target.value)} placeholder={type === 'address' ? '0x plus 40 hex characters' : '0x hex value'} /></label>}
    {mode === 'custom' && type.startsWith('int') && integerWidth(type) !== null && <p className="text-xs text-neutral-500">For a negative value, enter its full 32-byte sign-extended hex word.</p>}
    {!staticType(type) && <p className="text-xs text-neutral-500">This type cannot have a native scalar constraint.</p>}
  </div>
}

export function SourceReadGrants(props: Parameters<typeof SourceReadGrantsContent>[0]) {
  return <SourceAuthoringScope id={'grants:' + String(props.contract.id)}><SourceReadGrantsContent {...props} /></SourceAuthoringScope>
}
