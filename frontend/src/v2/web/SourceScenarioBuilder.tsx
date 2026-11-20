import { Button } from '../../components/ui/button'
import { Input } from '../../components/ui/input'
import { Textarea } from '../../components/ui/textarea'
import { closedJSON } from '../auth/protocol'
import { browserNumbersSafe, object, type JSONObject } from './sourceProject'
import { EXECUTION_CLAIMS } from './SourcePermissions'

const address = /^0x[0-9a-fA-F]{40}$/
const callTypes = ['call', 'staticcall', 'delegatecall', 'callcode', 'create', 'create2']
const selectClass = 'mt-1 block w-full rounded-lg border border-neutral-300 p-2'
export const initialScenarioFrame = (): JSONObject => ({ callType: 'call', storageAddress: '0x' + '0'.repeat(40), codeAddress: '', calldata: '0x', value: '0', depth: 0, facts: {} })
export function scenarioFrames(raw: string): JSONObject[] { const value = closedJSON(raw, 1 << 20, 24); if (!Array.isArray(value)) throw Error('Frames must be an array.'); return value.map(v => { const frame = object(v); object(frame.facts); return frame }) }
function mask(value: unknown): boolean { return typeof value === 'number' && Number.isInteger(value) && value >= 0 && value <= 255 }
function claimsMap(value: unknown): boolean { const map = object(value); return Object.keys(map).length <= 256 && Object.values(map).every(mask) }
export function validateScenario(context: JSONObject, input: JSONObject[]): JSONObject[] {
  if (!browserNumbersSafe(context) || !browserNumbersSafe(input)) throw Error('Scenario numeric facts must fit the browser’s exact numeric range.')
  if (!input.length || input.length > 256) throw Error('Provide one to 256 hypothetical frames.')
  if (!address.test(String(context.Signer))) throw Error('Provide the hypothetical signer address.')
  if (!Array.isArray(context.Groups) || context.Groups.length > 256 || context.Groups.some(g => typeof g !== 'string' || !g)) throw Error('Provide at most 256 hypothetical group IDs.')
  if (context.LinkedAddresses !== undefined && (!Array.isArray(context.LinkedAddresses) || context.LinkedAddresses.length > 1024 || context.LinkedAddresses.some(a => !address.test(String(a))))) throw Error('Linked addresses must contain at most 1024 valid addresses.')
  if (context.Claims !== undefined && !mask(context.Claims) || context.GroupSourceClaims !== undefined && !claimsMap(context.GroupSourceClaims)) throw Error('Context claim masks must fit uint8; use at most 256 group source masks.')
  let inputBytes = 0
  return input.map((f, index) => {
    const label = `Frame ${index + 1}`, facts = object(f.facts)
    if (!callTypes.includes(String(f.callType))) throw Error(`${label}: select a native call type.`)
    if (!address.test(String(f.storageAddress)) || f.codeAddress !== '' && !address.test(String(f.codeAddress))) throw Error(`${label}: storage and explicit code addresses must be valid 0x addresses.`)
    if (typeof f.calldata !== 'string' || !/^0x(?:[0-9a-fA-F]{2})*$/.test(f.calldata)) throw Error(`${label}: calldata must be 0x-prefixed complete hex bytes.`)
    inputBytes += (f.calldata.length - 2) / 2
    if (inputBytes > 256 << 10) throw Error('Scenario calldata exceeds 256 KiB across all frames.')
    if (typeof f.value !== 'string' || !/^(0|[1-9][0-9]*)$/.test(f.value) || f.value.length > 78 || BigInt(f.value) > (1n << 256n) - 1n) throw Error(`${label}: native value must be an exact canonical uint256 wei string.`)
    if (typeof f.depth !== 'number' || !Number.isSafeInteger(f.depth) || f.depth < 0) throw Error(`${label}: depth must be a nonnegative exact integer (up to ${Number.MAX_SAFE_INTEGER}).`)
    if (facts.CodeKind !== undefined && (!Number.isInteger(facts.CodeKind) || Number(facts.CodeKind) < 0 || Number(facts.CodeKind) > 3)) throw Error(`${label}: code kind must be unknown, EOA, contract or precompile.`)
    if (facts.CallerAddress !== undefined && !address.test(String(facts.CallerAddress))) throw Error(`${label}: caller assumption must be a valid address.`)
    if (facts.GroupClaims !== undefined && !claimsMap(facts.GroupClaims)) throw Error(`${label}: group claim masks must fit uint8 with at most 256 groups.`)
    for (const key of ['StorageOrg', 'CodeOrg', 'CallerOrg', 'UpgradeTargetOrg', 'CreationNamespace', 'StorageDeploymentNamespace', 'CodeDeploymentNamespace']) if (facts[key] !== undefined && typeof facts[key] !== 'string') throw Error(`${label}: ${key} must be exact text.`)
    for (const key of ['CodeShared', 'CodeAccessible', 'StorageShared', 'StorageDeployer', 'StoragePending', 'CreationUnresolved', 'StorageRuntimeHasCode']) if (facts[key] !== undefined && typeof facts[key] !== 'boolean') throw Error(`${label}: ${key} must be a boolean.`)
    return { ...f, codeAddress: f.codeAddress || f.storageAddress, facts }
  })
}
export function scenarioDocument({ context, frames, organization, signer, groups }: { context: string; frames: string; organization: string; signer: string; groups: string[] }): JSONObject {
  const facts = { ...object(closedJSON(context, 1 << 20, 24)), Org: organization, Groups: groups, Signer: signer }
  const value = { apiVersion: 'ops.policy-scenario/v1', context: facts, frames: validateScenario(facts, scenarioFrames(frames)) }
  if (new TextEncoder().encode(JSON.stringify(value, null, 2)).length > 1 << 20) throw Error('Scenario export exceeds 1 MiB.')
  return value
}
export function parseScenarioImport(raw: string, organization: string) {
  const value = object(closedJSON(raw, 1 << 20, 24)), context = object(value.context)
  if (value.apiVersion !== 'ops.policy-scenario/v1' || Object.keys(value).some(k => !['apiVersion', 'context', 'frames'].includes(k)) || context.Org !== organization || !Array.isArray(value.frames)) throw Error('Choose a native scenario for the selected organization.')
  const frames = value.frames.map(object); validateScenario(context, frames)
  return { signer: String(context.Signer), groups: context.Groups as string[], context: JSON.stringify(context, null, 2), frames: JSON.stringify(frames, null, 2) }
}
export function SourceScenarioBuilder({ context, frames, organizations, onContext, onFrames }: { context: string; frames: string; organizations: { id: string; name: string }[]; onContext(raw: string): void; onFrames(raw: string): void }) {
  let facts: JSONObject = {}, rows: JSONObject[] = [], contextValid = true, framesValid = true
  try { facts = object(closedJSON(context, 1 << 20, 24)) } catch { contextValid = false }
  try { rows = scenarioFrames(frames) } catch { framesValid = false }
  const linked = Array.isArray(facts.LinkedAddresses) ? facts.LinkedAddresses as string[] : [], claims = typeof facts.Claims === 'number' ? facts.Claims : 0
  const setFacts = (patch: JSONObject) => onContext(JSON.stringify({ ...facts, ...patch }, null, 2))
  const update = (index: number, patch: JSONObject) => onFrames(JSON.stringify(rows.map((f, i) => i === index ? { ...f, ...patch } : f), null, 2))
  const updateFact = (index: number, key: string, value: unknown) => { const next = { ...object(rows[index].facts), [key]: value }; if (value === undefined) delete next[key]; update(index, { facts: next }) }
  return <div className="space-y-5">
    {contextValid ? <div className="rounded-lg border border-neutral-200 p-4 space-y-4"><fieldset className="space-y-2"><legend className="text-sm font-medium">Hypothetical linked addresses · {linked.length}/1024</legend><p className="text-xs text-neutral-500">Operator assumptions about principal-linked addresses for this offline scenario.</p>{linked.map((a, i) => <div key={i} className="flex gap-2"><label className="text-sm flex-1">Linked address {i + 1}<Input value={a} onChange={e => setFacts({ LinkedAddresses: linked.map((a, j) => i === j ? e.target.value : a) })} /></label><Button type="button" variant="ghost" onClick={() => setFacts({ LinkedAddresses: linked.filter((_, j) => j !== i) })}>Remove linked address {i + 1}</Button></div>)}<Button type="button" size="sm" variant="outline" disabled={linked.length >= 1024} onClick={() => setFacts({ LinkedAddresses: [...linked, ''] })}>Add linked address</Button></fieldset>
      <fieldset className="space-y-2"><legend className="text-sm font-medium">Hypothetical context claims</legend>{EXECUTION_CLAIMS.map((c, i) => <label key={c.id} className="inline-flex items-center gap-2 text-sm mr-4"><input type="checkbox" checked={(claims & 1 << i) !== 0} onChange={e => setFacts({ Claims: e.target.checked ? claims | 1 << i : claims & ~(1 << i) })} />{c.name}</label>)}<p className="text-xs text-neutral-500">Assumed context flags, never verified authority. Native-v4 source claim masks and target-specific claims can be supplied in advanced facts.</p></fieldset>
    </div> : <p className="text-sm text-warning-dark">Repair the advanced context JSON to resume guided context editing.</p>}
    <div className="flex justify-between items-center"><h4 className="text-sm font-medium">Hypothetical frames · {rows.length}/256</h4><Button type="button" size="sm" variant="outline" disabled={!framesValid || rows.length >= 256} onClick={() => onFrames(JSON.stringify([...rows, initialScenarioFrame()], null, 2))}>Add frame</Button></div>
    {!framesValid && <p className="text-sm text-warning-dark">Repair the advanced frames JSON to resume guided frame editing.</p>}
    {rows.map((f, i) => { const ff = object(f.facts); return <article key={i} className="rounded-lg border border-neutral-200 p-4 space-y-4"><div className="flex justify-between"><h4 className="text-sm font-medium">Frame {i + 1}</h4><Button type="button" variant="ghost" size="sm" disabled={rows.length <= 1} onClick={() => onFrames(JSON.stringify(rows.filter((_, j) => j !== i), null, 2))}>Remove frame {i + 1}</Button></div><div className="grid gap-3 sm:grid-cols-2">
      <label className="block text-sm font-medium">Frame {i + 1} call type<select className={selectClass} value={String(f.callType)} onChange={e => update(i, { callType: e.target.value })}>{callTypes.map(t => <option key={t}>{t}</option>)}</select></label>
      <label className="block text-sm font-medium">Frame {i + 1} depth<Input value={String(f.depth ?? '')} onChange={e => update(i, { depth: /^(0|[1-9][0-9]*)$/.test(e.target.value) && Number.isSafeInteger(Number(e.target.value)) ? Number(e.target.value) : e.target.value })} /></label>
      <label className="block text-sm font-medium">Frame {i + 1} storage address<Input value={String(f.storageAddress ?? '')} onChange={e => update(i, { storageAddress: e.target.value })} /></label>
      <label className="block text-sm font-medium">Frame {i + 1} code address (optional)<Input value={String(f.codeAddress ?? '')} onChange={e => update(i, { codeAddress: e.target.value })} placeholder="Defaults to storage address on export" /></label>
    </div><p className="text-xs text-neutral-500">An empty code address exports the storage address. Delegatecall and callcode can use separate explicit code and storage addresses. These address choices do not infer ownership.</p>
      <label className="block text-sm font-medium">Frame {i + 1} calldata<Textarea value={String(f.calldata ?? '')} onChange={e => update(i, { calldata: e.target.value })} placeholder="0x..." /></label>
      <label className="block text-sm font-medium">Frame {i + 1} native value (exact wei)<Input value={String(f.value ?? '')} onChange={e => update(i, { value: e.target.value })} /></label>
      <fieldset className="rounded-lg bg-neutral-50 p-3 space-y-3"><legend className="text-sm font-medium">Frame {i + 1} hypothetical code, owner and caller facts</legend><p className="text-xs text-neutral-500">Every fact here is an operator-supplied assumption. Registry entries do not establish owner facts.</p><div className="grid gap-3 sm:grid-cols-2">
        <label className="block text-sm">Frame {i + 1} code kind<select className={selectClass} value={String(ff.CodeKind ?? 0)} onChange={e => updateFact(i, 'CodeKind', Number(e.target.value))}><option value="0">Unknown / not supplied</option><option value="1">EOA</option><option value="2">Contract</option><option value="3">Precompile</option></select></label>
        {(['StorageOrg', 'CodeOrg'] as const).map(key => <label key={key} className="block text-sm">Frame {i + 1} {key === 'StorageOrg' ? 'storage organization' : 'code organization'} assumption<select className={selectClass} value={String(ff[key] ?? '')} onChange={e => updateFact(i, key, e.target.value)}><option value="">No organization assumed</option>{!!ff[key] && !organizations.some(o => o.id === ff[key]) && <option value={String(ff[key])}>Imported assumption · {String(ff[key])}</option>}{organizations.map(o => <option key={o.id} value={o.id}>{o.name} · {o.id}</option>)}</select></label>)}
        <label className="block text-sm">Frame {i + 1} caller address assumption<Input value={String(ff.CallerAddress ?? '')} onChange={e => updateFact(i, 'CallerAddress', e.target.value || undefined)} placeholder="Optional 0x address" /></label>
      </div></fieldset>
    </article> })}
    <details><summary className="text-sm cursor-pointer">Advanced context and frame JSON</summary><p className="text-xs text-neutral-500 my-2">Use for uncommon creation, target-group and source-group facts. Guided edits retain other fields. Native facts use Go names, such as CodeOrg, StorageOrg, GroupClaims and CallerAddress.</p><label className="block text-sm font-medium">Hypothetical context facts<Textarea variant="code" value={context} onChange={e => onContext(e.target.value)} className="min-h-28" /></label><label className="block text-sm font-medium mt-3">Hypothetical frames<Textarea variant="code" value={frames} onChange={e => onFrames(e.target.value)} className="min-h-48" /></label></details>
  </div>
}
