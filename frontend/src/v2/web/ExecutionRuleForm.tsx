import { useEffect, useMemo, useRef, useState, type FormEvent } from 'react'
import { Button } from '../../components/ui/button'
import { Textarea } from '../../components/ui/textarea'
import { Field, SelectField } from './operationsUI'
import { useAuthoringState } from './sourceAuthoring'
import { browserNumbersSafe, object, type JSONObject, type SourceProject } from './sourceProject'
import { closedJSON } from '../auth/protocol'
import { download } from './SourceReview'
import { abiChoices, deriveCommonABI, selectedABIBytes, validateABIReport, type ABIReport } from './executionABI'
import { registryABIText } from './registryABIText'
import { constraintFor, guidedConstraint, saveGuidedRule } from './executionRules'

export function ExecutionRuleForm({ value, contracts, project, root, organization, check, onSave, onClose, abiBytesByAddress, registryText }: { value: JSONObject; contracts: JSONObject[]; project: SourceProject; root: string; organization: string; check(): void; onSave(value: JSONObject): void; onClose(): void; abiBytesByAddress?: Record<string, string>; registryText?: string }) {
  const [draft, setDraft] = useAuthoringState('rule', value, { draft: true, base: value }), [advanced, setAdvanced] = useAuthoringState('advanced-mode', false), [raw, setRaw] = useAuthoringState('advanced-json', JSON.stringify(value, null, 2), { draft: true, base: value }), [error, setError] = useState<string | null>(null)
  const [assistance, setAssistance] = useState<{ key: string; report: ABIReport; imported: boolean }>(), [abiError, setABIError] = useState<string | null>(null), picker = useRef<HTMLInputElement>(null), live = useRef(true)
  const codeAddress = String(draft.codeAddress || draft.storageAddress || ''), code = contracts.find(c => c.address === codeAddress), abi = code?.abi
  const abiRaw = useMemo(() => abi === undefined ? '' : abiBytesByAddress?.[codeAddress] ?? (registryText && code ? registryABIText(registryText, contracts.indexOf(code)) : selectedABIBytes(abi)), [abi, abiBytesByAddress, codeAddress, registryText, code, contracts])
  const key = useMemo(() => JSON.stringify([root, organization, project.generation, code?.id, codeAddress, abiRaw, registryText]), [root, organization, project.generation, code?.id, codeAddress, abiRaw, registryText]), latest = useRef(key)
  latest.current = key
  useEffect(() => { live.current = true; return () => { live.current = false } }, [])
  useEffect(() => {
    let current = true
    setABIError(null)
    if (abi !== undefined) void deriveCommonABI(abi, abiRaw).then(report => { check(); if (current && live.current && latest.current === key) setAssistance({ key, report, imported: false }) }).catch(e => { if (current && live.current && latest.current === key) setABIError((e as Error).message) })
    return () => { current = false }
  }, [key])
  const inspection = assistance?.key === key ? assistance.report : null
  let choices: ReturnType<typeof abiChoices> = { functions: [], events: [] }
  try { if (abi !== undefined) choices = abiChoices(abi) } catch { /* advanced source remains available */ }
  const fn = choices.functions.find(f => f.selector === draft.selector), argsValid = draft.args === undefined || Array.isArray(draft.args) && draft.args.every(arg => arg && typeof arg === 'object' && !Array.isArray(arg)), args = argsValid && Array.isArray(draft.args) ? draft.args.map(object) : []
  const patch = (key: string, replacement: unknown) => { const next = { ...draft }; if (replacement === undefined) delete next[key]; else next[key] = replacement; setDraft(next) }
  function selectFunction(selector: string) {
    const next: JSONObject = { ...draft, selector }
    if (selector === '*' || selector === '0x') { next.abiDigest = ''; delete next.args }
    else { next.abiDigest = inspection?.abiDigest ?? ''; next.args = [] }
    setDraft(next)
  }
  async function importReport(file: File) {
    const captured = key
    try {
      check(); if (file.size > 1 << 20) throw Error('The ABI report exceeds 1 MiB.')
      const raw = await file.text(); check()
      if (!live.current || latest.current !== captured) return
      const report = await validateABIReport(raw, abi, abiRaw); check()
      if (live.current && latest.current === captured) { setAssistance({ key: captured, report, imported: true }); setError(null) }
    } catch (e) { if (live.current && latest.current === captured) setError((e as Error).message) }
  }
  function save(e: FormEvent) {
    e.preventDefault()
    try {
      check()
      const result = advanced ? object(closedJSON(raw, 1 << 20, 32)) : saveGuidedRule(draft, inspection)
      if (!browserNumbersSafe(result)) throw Error('Use raw source editing for numeric values the browser cannot preserve.')
      onSave(result)
    } catch (e) { setError((e as Error).message) }
  }
  const options = (includeSame: boolean) => [{ value: '', label: includeSame ? 'Same as storage contract' : 'Select a registered contract' }, ...contracts.map(c => ({ value: String(c.address), label: `${String(c.name || c.id)} · ${String(c.address)}` })), ...(!contracts.some(c => c.address === (includeSame ? draft.codeAddress : draft.storageAddress)) && (includeSame ? draft.codeAddress : draft.storageAddress) ? [{ value: String(includeSame ? draft.codeAddress : draft.storageAddress), label: 'Unresolved imported address — use advanced source to repair' }] : [])]
  const calls = Array.isArray(draft.callTypes) ? draft.callTypes as string[] : [], creation = project.roots.find(r => r.id === root)?.draft.profile === 'catalog-runtime-creation-observed/v1'
  return <form className="space-y-4" onSubmit={save}>
    <div className="flex gap-2"><Button type="button" variant={advanced ? 'outline' : 'secondary'} onClick={() => { if (!advanced) return; try { const parsed = object(closedJSON(raw, 1 << 20, 32)); if (parsed.args !== undefined && (!Array.isArray(parsed.args) || parsed.args.some(arg => !arg || typeof arg !== 'object' || Array.isArray(arg)))) throw Error('Keep unsupported argument shapes in advanced JSON.'); setDraft(parsed); setAdvanced(false); setError(null) } catch (e) { setError((e as Error).message) } }}>Guided native rule</Button><Button type="button" variant={advanced ? 'secondary' : 'outline'} onClick={() => { if (!advanced) { setRaw(JSON.stringify(draft, null, 2)); setAdvanced(true) } }}>Advanced native JSON</Button></div>
    {advanced ? <label className="block text-sm font-medium">Advanced frame rule JSON<Textarea aria-label="Advanced frame rule JSON" variant="code" className="min-h-72" value={raw} onChange={e => setRaw(e.target.value)} /><span className="text-xs font-normal text-neutral-500">Retain except, recordParty and other imported native constraints here. Go checks all native semantics; this is a local proposal.</span></label> : <>
      <SelectField label="Target" value={String(draft.targetClass ?? '')} onChange={targetClass => { const next = { ...draft }; if (targetClass) { next.targetClass = targetClass; next.storageAddress = ''; delete next.codeAddress; next.selector = targetClass === 'eoa' ? '0x' : '*'; next.abiDigest = ''; delete next.args } else delete next.targetClass; setDraft(next) }} options={[{ value: '', label: 'Literal registered contract' }, ...['org', 'shared', 'eoa', 'precompile', ...(creation ? ['create'] : [])].map(value => ({ value, label: 'Runtime resolved: ' + value }))]} />
      {!draft.targetClass && <div className="grid gap-3 sm:grid-cols-2"><SelectField label="Storage contract" value={String(draft.storageAddress ?? '')} onChange={storageAddress => { setDraft({ ...draft, storageAddress, selector: '*', abiDigest: '', args: [] }) }} options={options(false)} /><SelectField label="Separate code contract" value={String(draft.codeAddress ?? '')} onChange={codeAddress => { const next: JSONObject = { ...draft, selector: '*', abiDigest: '', args: [] }; if (codeAddress) next.codeAddress = codeAddress; else delete next.codeAddress; setDraft(next) }} options={options(true)} /></div>}
      <SelectField label="ABI function / input" value={String(draft.selector ?? '')} onChange={selectFunction} options={[{ value: '', label: 'Choose a function or input scope' }, { value: '*', label: 'Any input (*) — clears digest and argument constraints' }, { value: '0x', label: 'Empty input only (0x) — clears digest and argument constraints' }, ...choices.functions.map(f => ({ value: f.selector, label: f.signature + ' · ' + f.selector })), ...(!['', '*', '0x'].includes(String(draft.selector)) && !fn ? [{ value: String(draft.selector), label: 'Unresolved imported selector — inspect advanced JSON' }] : [])]} />
      {code && <section className="space-y-2 rounded-lg border p-3"><p className="text-xs break-all">{inspection ? `${assistance?.imported ? 'Imported operator report' : 'Common ABI derived digest'}: ${inspection.abiDigest}` : abiError ?? 'Deriving current ABI assistance…'}</p><div className="flex flex-wrap gap-2"><Button type="button" size="sm" variant="outline" onClick={() => { check(); download('selected-ABI.json', abiRaw) }}>Export selected ABI</Button><Button type="button" size="sm" variant="outline" onClick={() => picker.current?.click()}>Import Go ABI inspection</Button></div><input ref={picker} type="file" accept=".json" aria-label="Go ABI inspection" className="sr-only" onChange={e => { const file = e.currentTarget.files?.[0]; e.currentTarget.value = ''; if (file) void importReport(file) }} /><code className="block text-xs">ops-v2 policy abi --file selected-ABI.json</code><p className="text-xs text-neutral-500">Assistance is bound to these ABI bytes and the current source generation. An imported report does not establish Go provenance, deployment or approval.</p></section>}
      {!argsValid && <p className="text-xs text-neutral-500">Unsupported imported argument shape is retained. Use advanced native JSON to inspect or repair it.</p>}
      {fn && argsValid && <fieldset className="space-y-3"><legend className="text-sm font-medium">Typed argument constraints</legend>{fn.inputs.map((input, index) => {
        const existing = args.filter(arg => arg.index === index), guided = existing.length > 1 ? null : guidedConstraint(existing[0], input.type), supported = input.type === 'address' || /^uint([0-9]+)?$/.test(input.type)
        if (!supported || !guided) return <p key={index} className="text-xs text-neutral-500">{index}: {input.name || 'Argument'} ({input.type}) — {existing.length ? 'advanced constraint retained; inspect advanced JSON' : 'guided constraints unavailable for this type'}</p>
        const update = (operator: string, rawValue: string) => { try { const constraint = constraintFor(input.type, index, operator, rawValue); patch('args', [...args.filter(a => a.index !== index), ...(constraint ? [constraint] : [])].sort((a, b) => Number(a.index) - Number(b.index))); setError(null) } catch (e) { setError((e as Error).message) } }
        return <div key={index} className="rounded-lg border p-3 space-y-2"><p className="text-sm">{index}: {input.name || 'Argument'} · {input.type}</p><SelectField label={`Argument ${index} constraint`} value={guided.operator} onChange={operator => { if (operator === 'literal' || operator === 'uintAtMost') patch('args', [...args.filter(a => a.index !== index), { index, ...(operator === 'literal' ? { addressEquals: { source: 'literal', value: '' } } : { uintAtMost: '' }) }]); else update(operator, '') }} options={[{ value: '', label: 'Any value' }, ...(input.type === 'address' ? [{ value: 'signer', label: 'Equals signer' }, { value: 'principal.linked', label: 'Equals a principal linked address' }, { value: 'literal', label: 'Equals literal address' }] : [{ value: 'uintAtMost', label: 'At most (inclusive exact integer)' }])]} />{(guided.operator === 'literal' || guided.operator === 'uintAtMost') && <Field label={`Argument ${index} exact value`} value={guided.value} onChange={text => { const replacement = guided.operator === 'literal' ? { index, addressEquals: { source: 'literal', value: text } } : { index, uintAtMost: text }; patch('args', [...args.filter(a => a.index !== index), replacement]) }} />}</div>
      })}</fieldset>}
      {!!args.length && !fn && <p className="text-xs text-neutral-500">Imported argument constraints remain in advanced JSON until a new function/input scope is selected.</p>}
      <fieldset><legend className="text-sm font-medium mb-2">Call types</legend><div className="flex flex-wrap gap-3">{['call', 'staticcall', 'delegatecall', 'callcode', ...(creation ? ['create', 'create2'] : [])].map(call => <label key={call} className="text-sm flex gap-2"><input type="checkbox" checked={calls.includes(call)} onChange={e => { const selected = e.target.checked ? [...calls, call] : calls.filter(c => c !== call); patch('callTypes', selected.length ? selected : undefined) }} />{call}</label>)}</div><p className="text-xs text-neutral-500 mt-2">Omitted call types permit call and staticcall only. Literal delegatecall/callcode rules require an explicit executing code contract. Different code/storage selections cannot include call/staticcall. Creation support is checked by the selected profile and Go.</p></fieldset>
      <div className="grid gap-3 sm:grid-cols-2"><Field label="Maximum native value (wei)" value={String(draft.maxValue ?? '')} onChange={v => patch('maxValue', v || undefined)} /><Field label="Required immediate caller" value={String(draft.callerAddress ?? '')} onChange={v => patch('callerAddress', v || undefined)} />{['minDepth', 'maxDepth'].map((k, i) => <Field key={k} label={i ? 'Maximum depth' : 'Minimum depth'} value={String(draft[k] ?? '')} onChange={v => patch(k, v === '' ? undefined : /^\d+$/.test(v) && Number.isSafeInteger(Number(v)) ? Number(v) : v)} />)}</div>
      <label className="flex gap-2 text-sm"><input type="checkbox" checked={draft.allowUpgrade === true} onChange={e => patch('allowUpgrade', e.target.checked ? true : undefined)} />Allow recognized upgrade with current upgrade claim</label>
      {draft.except !== undefined && <p className="text-xs text-neutral-500">Existing native deployer exceptions are retained. Inspect advanced JSON to edit them.</p>}
    </>}
    {error && <p role="alert" className="text-sm text-error-dark">{error}</p>}<div className="flex justify-end gap-2"><Button type="button" variant="outline" onClick={onClose}>Cancel</Button><Button type="submit">Save rule draft</Button></div>
  </form>
}
