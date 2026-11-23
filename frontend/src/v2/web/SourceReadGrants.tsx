import { useEffect, useMemo, useState } from 'react'
import { toEventSelector, toEventSignature, type AbiEvent, type AbiParameter } from 'viem'
import { Radio, Shield, Users } from 'lucide-react'
import { ABIEventBrowser, ContractEmpty, PermissionPill } from '../../components/rbac/ContractPresentation'
import { Button } from '../../components/ui/button'
import { Input } from '../../components/ui/input'
import { Dialog, DialogContent, DialogHeader, DialogTitle } from '../../components/ui/dialog'
import { SourceViewScope, useSourceViewState } from './sourceViewState'
import { object, type JSONObject } from './sourceProject'
import type { DraftGroup } from './workspace'
interface EventDefinition { name: string; signature: string; topic: string; inputs: readonly AbiParameter[] }
type GroupChoice = Pick<DraftGroup, 'id' | 'name' | 'slug'> & Partial<Pick<DraftGroup, 'isOrgAdmin' | 'isOrgReadonlyAdmin' | 'allowedMethods' | 'claims'>>
const modes = { none: 'No events visible', all: 'All events visible', allowlist: 'Specific events only' }
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
    if (new Set(events.map(event => event.topic)).size !== events.length) throw Error('The ABI has duplicate event signatures.')
    return { events: events.sort((a, b) => a.signature.localeCompare(b.signature)), error: null }
  } catch (error) { return { events: [], error: error instanceof Error ? error.message : 'The contract ABI could not be read.' } }
}
function rulesOf(value: JSONObject): JSONObject[] {
  const rules = object(value.eventRules).rules
  if (!Array.isArray(rules)) throw Error('Read grants need an eventRules.rules array. Inspect the source file.')
  return rules.map(object)
}
function paramsOf(value: JSONObject): JSONObject[] {
  if (!Array.isArray(value.paramRules)) throw Error('Each event rule needs a paramRules array. Inspect the source file.')
  return value.paramRules.map(object)
}
function EventConstraintSummary({ rule, events }: { rule: JSONObject; events: EventDefinition[] }) {
  const event = events.find(event => event.topic === String(rule.topic0).toLowerCase()), params = paramsOf(rule)
  return <p className="break-all text-xs text-neutral-500">{!params.length ? 'No constraints · every event with this signature' : params.map(param => `${event?.inputs[Number(param.index)]?.name || 'Parameter ' + (Number(param.index) + 1)} = ${param.must_be === 'self' ? 'viewer’s linked address (self)' : String(param.must_be)}`).join(' OR ')}</p>
}
interface Props { contract: JSONObject; groups: GroupChoice[] }
function ReadGrants({ contract, groups }: Props) {
  const [inspection, setInspection] = useState<string | null>(null), [search, setSearch] = useSourceViewState('search', '')
  if (!Array.isArray(contract.readGrants)) throw Error('Read grants must be an array. Inspect the source file.')
  const grants = contract.readGrants.map(object)
  const ids = new Set<string>()
  for (const grant of grants) {
    const mode = object(grant.eventRules).mode
    if (typeof grant.id !== 'string' || !grant.id || ids.has(grant.id) || typeof grant.groupId !== 'string' || typeof mode !== 'string' || !Object.keys(modes).includes(String(mode))) throw Error('Unsupported read grant fields. Inspect the source file.')
    ids.add(grant.id)
    for (const rule of rulesOf(grant)) {
      if (typeof rule.topic0 !== 'string' || typeof rule.name !== 'string') throw Error('Unsupported event rule fields. Inspect the source file.')
      for (const param of paramsOf(rule)) if (!Number.isSafeInteger(param.index) || Number(param.index) < 0 || typeof param.must_be !== 'string') throw Error('Unsupported event parameter fields. Inspect the source file.')
    }
  }
  const parsed = useMemo(() => eventsFromABI(contract.abi), [contract.abi])
  const current = grants.find(grant => grant.id === inspection)
  useEffect(() => { if (inspection && !grants.some(grant => grant.id === inspection)) setInspection(null) }, [contract.readGrants, inspection])
  const groupName = (id: unknown) => groups.find(group => group.id === id)?.name ?? `Unknown group (${String(id)})`
  const visible = grants.filter(grant => groupName(grant.groupId).toLowerCase().includes(search.toLowerCase()))
  return <section className="space-y-4"><div><h3 className="flex items-center gap-2 font-medium text-neutral-900"><Users className="h-4 w-4 text-primary" />Groups with read access</h3><p className="mt-1 text-xs text-neutral-500">Groups and events declared by this configuration. Execution permissions are separate.</p></div>
    {grants.length > 0 && <Input aria-label="Search read grants" placeholder="Search groups..." value={search} onChange={event => setSearch(event.target.value)} />}
    <div className="space-y-3">{visible.map(grant => { const group = groups.find(g => g.id === grant.groupId), rules = rulesOf(grant), mode = object(grant.eventRules).mode; return <article key={String(grant.id)} className="space-y-3 rounded-xl border border-neutral-200 bg-white p-4"><div><button type="button" className="flex items-center gap-2 text-sm font-semibold text-primary hover:underline" onClick={() => setInspection(String(grant.id))}><Shield className="h-4 w-4" />{groupName(grant.groupId)}</button><p className="mt-1 text-xs text-neutral-500">{group?.slug ?? String(grant.groupId)} · Declared source group</p>{group && <div className="mt-2 flex flex-wrap gap-2 text-xs"><span className="rounded bg-neutral-100 px-2 py-0.5">{group.isOrgAdmin ? 'Organization admin role' : group.isOrgReadonlyAdmin ? 'Organization readonly admin role' : 'Group role'}</span>{group.allowedMethods && <span>{group.allowedMethods.length} declared RPC methods</span>}{group.claims && <span>Execution claims: {group.claims.join(', ') || 'none declared'}</span>}</div>}</div><div className="space-y-2 rounded-lg bg-neutral-50 p-3"><p className="text-xs font-medium text-neutral-600">Events · {modes[mode as keyof typeof modes] ?? 'Unknown source event mode'}{mode === 'allowlist' && ` · ${rules.length} selected`}</p>{mode === 'allowlist' && rules.map((rule, index) => <div key={index} className="space-y-1"><PermissionPill kind="event">{parsed.events.find(event => event.topic === String(rule.topic0).toLowerCase())?.signature ?? String(rule.name || rule.topic0)}</PermissionPill><EventConstraintSummary rule={rule} events={parsed.events} /></div>)}{mode === 'all' && <p className="text-xs text-neutral-500">All supported matched ABI events, subject to read and event-privacy gates.</p>}{mode === 'none' && <p className="text-xs text-neutral-500">This grant exposes no event signatures.</p>}</div></article> })}</div>
    {!grants.length && <ContractEmpty title="No group has a read grant for this contract" description="This configuration declares no group read grants. Execution permissions remain separate." />}
    {grants.length > 0 && !visible.length && <ContractEmpty title="No matching read groups" description="Try a different group name." action={<Button variant="outline" onClick={() => setSearch('')}>Clear search</Button>} />}
    <Dialog open={!!current} onOpenChange={open => { if (!open) setInspection(null) }}><DialogContent className="max-w-4xl max-h-[85vh] overflow-y-auto"><DialogHeader><DialogTitle>Inspect read grant</DialogTitle></DialogHeader>{current && <div className="space-y-5"><div className="rounded-lg border border-primary-100 bg-primary-50 p-3"><p className="text-sm font-medium text-primary">{groupName(current.groupId)}</p><p className="mt-1 break-all text-xs text-neutral-500">{String(current.groupId)} · {String(current.id)}</p></div><div role="group" aria-label="Event visibility" className="grid gap-2 sm:grid-cols-3">{Object.entries(modes).map(([id, label]) => <div key={id} className={'rounded-lg border p-3 text-sm ' + (object(current.eventRules).mode === id ? 'border-primary-200 bg-primary-50 font-medium text-primary' : 'border-neutral-200 text-neutral-500')}><span>{label}</span>{object(current.eventRules).mode === id && <span className="ml-2 text-xs">Selected</span>}</div>)}</div>
      {object(current.eventRules).mode === 'allowlist' && <div className="space-y-4"><h4 className="text-sm font-medium">Selected events · {rulesOf(current).length}</h4><p className="text-xs text-neutral-500">An event is visible when any one of its parameter constraints matches (OR). With no constraints, every event with that signature is visible. Self means one of the viewer’s linked addresses.</p>{rulesOf(current).map((rule, index) => { const event = parsed.events.find(event => event.topic === String(rule.topic0).toLowerCase()); return <div key={String(rule.topic0) + index} className="space-y-3 rounded-lg border border-violet-200 bg-violet-50/30 p-3"><div><span className="inline-flex items-center gap-2 text-sm font-medium text-violet-700"><Radio className="h-4 w-4" />{String(rule.name)}</span><p className="break-all font-mono text-xs text-neutral-500">{event?.signature ?? String(rule.topic0)}</p></div>{!event && <p className="text-xs text-warning-dark">This rule does not match an event in the current ABI. Inspect its source declaration.</p>}<EventConstraintSummary rule={rule} events={parsed.events} />{event?.inputs.map((parameter, inputIndex) => { const value = paramsOf(rule).find(param => param.index === inputIndex)?.must_be; return <div key={inputIndex} className="rounded-lg border border-neutral-200 bg-white p-3 text-xs"><p className="font-medium">{parameter.name || `Parameter ${inputIndex + 1}`} · {parameter.type}{'indexed' in parameter && parameter.indexed ? ' · indexed' : ''}</p><p className="mt-2 break-all">{value === undefined ? 'Any value' : value === 'self' ? 'Viewer’s linked address (self)' : String(value)}</p></div> })}</div> })}{parsed.error && <p className="text-sm text-warning-dark">{parsed.error}</p>}<ABIEventBrowser events={parsed.events.map(event => ({ ...event, topic0: event.topic }))} selected={rulesOf(current).map(rule => String(rule.topic0).toLowerCase())} editing={false} /></div>}
      <details><summary className="cursor-pointer text-sm">Advanced native read grant JSON</summary><pre className="mt-2 whitespace-pre-wrap break-all text-xs">{JSON.stringify(current, null, 2)}</pre></details><div className="flex justify-end"><Button variant="outline" onClick={() => setInspection(null)}>Close</Button></div></div>}</DialogContent></Dialog>
  </section>
}
export function SourceReadGrants(props: Props) { return <SourceViewScope id={'grants:' + String(props.contract.id)}><ReadGrants {...props} /></SourceViewScope> }
