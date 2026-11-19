import { useEffect, useRef, useState } from 'react'
import { Button } from '../../components/ui/button'
import { Input } from '../../components/ui/input'
import { Textarea } from '../../components/ui/textarea'
import { Badge } from '../../components/ui/badge'
import { download } from './SourceReview'
import { groupsOf, object, rootOf, type SourceProject } from './sourceProject'
import { closedJSON } from '../auth/protocol'

export async function scenarioDigest(raw: string): Promise<string> {
  const bytes = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(raw))
  return 'sha256:' + Array.from(new Uint8Array(bytes), v => v.toString(16).padStart(2, '0')).join('')
}
export function SourceScenario({ project, root, organization, check }: { project: SourceProject; root: string; organization: string; check(): void }) {
  const selected = rootOf(project, root), groups = groupsOf(project, root, organization)
  const [signer, setSigner] = useState(''), [memberships, setMemberships] = useState<string[]>([]), [frames, setFrames] = useState('[\n  {"callType":"call","storageAddress":"0x0000000000000000000000000000000000000000","codeAddress":"0x0000000000000000000000000000000000000000","calldata":"0x","value":"0","depth":0,"facts":{}}\n]')
  const [context, setContext] = useState('{"LinkedAddresses":[],"Claims":0,"GroupSourceClaims":{}}'), [error, setError] = useState<string | null>(null), [expectedManifest, setExpectedManifest] = useState('')
  const [exported, setExported] = useState<{ raw: string; digest: string; generation: number } | null>(null), [result, setResult] = useState<{ raw: string; manifest: string; generation: number; allowed: boolean; code: string; reason: string } | null>(null)
  const picker = useRef<HTMLInputElement>(null), alive = useRef(true), latest = useRef({ raw: '', generation: project.generation, manifest: expectedManifest })
  useEffect(() => { alive.current = true; return () => { alive.current = false } }, [])
  function build(): string {
    const facts = object(closedJSON(context, 1 << 20, 32)), input = closedJSON(frames, 1 << 20, 32)
    if (!Array.isArray(input) || !input.length || input.length > 256) throw Error('Provide one to 256 hypothetical frames.')
    for (const frame of input) {
      const f = object(frame)
      if (!Number.isSafeInteger(f.depth) || Number(f.depth) < 0 || typeof f.value !== 'string' || !/^(0|[1-9][0-9]*)$/.test(f.value)) throw Error('Frame depth must be a safe nonnegative integer and value an exact decimal string.')
    }
    if (!/^0x[0-9a-fA-F]{40}$/.test(signer)) throw Error('Provide the hypothetical signer address.')
    return JSON.stringify({ apiVersion: 'ops.policy-scenario/v1', context: { ...facts, Org: organization, Groups: memberships, Signer: signer }, frames: input }, null, 2)
  }
  let currentRaw = ''; try { currentRaw = build() } catch { /* An incomplete scenario is editable, never evaluated in JS. */ }
  latest.current = { raw: currentRaw, generation: project.generation, manifest: expectedManifest }
  async function exportScenario() {
    const generation = project.generation
    try {
      check(); const raw = build(), digest = await scenarioDigest(raw); check()
      if (!alive.current || latest.current.generation !== generation || latest.current.raw !== raw) return
      download('ops-policy-scenario.json', raw); setExported({ raw, digest, generation }); setResult(null); setError(null)
    } catch (e) { if (alive.current) setError(e instanceof Error ? e.message : 'Could not export scenario.') }
  }
  async function importResult(file: File) {
    const generation = project.generation, manifest = expectedManifest, original = exported
    try {
      check()
      if (!original || original.generation !== generation || original.raw !== currentRaw) throw Error('Export the current scenario first.')
      if (!/^sha256:[0-9a-f]{64}$/.test(manifest)) throw Error('Select the manifest digest you used with the Go command.')
      if (file.size > 1 << 20) throw Error('The local scenario report is too large.')
      const raw = await file.text(); check()
      if (!alive.current || latest.current.generation !== generation || latest.current.raw !== original.raw || latest.current.manifest !== manifest) return
      const value = object(closedJSON(raw, 1 << 20, 32)), decision = object(value.decision)
      if (value.action !== 'simulate' || value.approved !== false || value.hypothetical !== true || value.deploymentVerified !== false || value.manifestDigest !== manifest || value.scenarioDigest !== original.digest || value.profile !== selected.draft.profile || value.evaluatorVersion !== selected.draft.evaluatorVersion || typeof decision.Allowed !== 'boolean' || typeof decision.Code !== 'string' || typeof decision.Reason !== 'string') throw Error('This report does not match the exported scenario, selected artifact and evaluator.')
      setResult({ raw: original.raw, manifest, generation, allowed: decision.Allowed, code: decision.Code, reason: decision.Reason }); setError(null)
    } catch (e) { if (alive.current) setError(e instanceof Error ? e.message : 'Could not read scenario report.') }
  }
  const currentResult = result && result.raw === currentRaw && result.generation === project.generation && result.manifest === expectedManifest
  const shell = (value: string) => "'" + value.replace(/'/g, "'\"'\"'") + "'"
  return <section className="space-y-4"><h3 className="text-sm font-medium">Policy scenario</h3>
    <p className="text-sm text-neutral-500">Evaluate hypothetical facts using the matching Go reference evaluator. This does not execute an EVM call, prove a current identity or node trace, establish owner facts, or verify deployed Guard equivalence.</p>
    <label className="block text-sm font-medium">Hypothetical signer<Input value={signer} onChange={e => setSigner(e.target.value)} placeholder="0x..." /></label>
    <fieldset><legend className="text-sm font-medium mb-2">Hypothetical groups</legend><div className="flex flex-wrap gap-4">{groups.map(g => <label key={g.id} className="inline-flex items-center gap-2 text-sm"><input type="checkbox" checked={memberships.includes(g.id)} onChange={e => setMemberships(e.target.checked ? [...memberships, g.id] : memberships.filter(id => id !== g.id))} />{g.name}</label>)}</div></fieldset>
    <label className="block text-sm font-medium">Hypothetical context facts<Textarea variant="code" value={context} onChange={e => setContext(e.target.value)} className="min-h-28" /></label>
    <label className="block text-sm font-medium">Hypothetical frames<Textarea variant="code" value={frames} onChange={e => setFrames(e.target.value)} className="min-h-48" /></label>
    <p className="text-xs text-neutral-500">Calldata is 0x hex; value is an exact decimal string. Native facts use Go Frame names, such as CodeOrg, StorageOrg, GroupClaims and CallerAddress. They are operator-supplied assumptions, never imported identity authority.</p>
    <Button onClick={() => void exportScenario()}>Export policy scenario</Button>{exported && <p className="text-xs text-neutral-500 break-all">{exported.raw === currentRaw && exported.generation === project.generation ? 'Exported scenario' : 'Scenario or source changed; export again'}: <code>{exported.digest}</code></p>}
    <pre className="text-xs rounded-lg bg-neutral-100 p-3 whitespace-pre-wrap break-all">{`ops-v2 policy simulate --bundle ./artifact-NEW --expected-digest REVIEWED_MANIFEST_DIGEST --environment ${shell(selected.draft.environment)} --chain-id ${shell(selected.draft.chainId)} --profile ${shell(selected.draft.profile)}${selected.draft.profile === 'catalog-runtime-creation-observed/v1' ? ' --consumer delivery' : ''} --scenario ./ops-policy-scenario.json`}</pre>
    <label className="block text-sm font-medium">Selected prepared manifest digest<Input value={expectedManifest} onChange={e => setExpectedManifest(e.target.value)} placeholder="sha256:..." /></label>
    <Button variant="outline" onClick={() => picker.current?.click()}>Import Go scenario result</Button><input ref={picker} type="file" accept=".json" className="sr-only" aria-label="Go scenario result" onChange={e => { const file = e.currentTarget.files?.[0]; e.currentTarget.value = ''; if (file) void importResult(file) }} />
    {result && <div className="rounded-lg border border-neutral-200 p-4 space-y-2"><Badge variant="outline">{currentResult ? 'Imported local result' : 'Scenario, source or selected artifact changed'}</Badge>{currentResult && <><p className="text-sm font-medium">Conditional {result.allowed ? 'allow' : 'deny'}{result.code ? ': ' + result.code : ''}</p><p className="text-sm break-words">{result.reason}</p></>}<p className="text-xs text-neutral-500">This operator-provided report matches the exported scenario digest and selected artifact/evaluator fields. Its provenance and the running deployment are not established.</p></div>}
    {error && <p role="alert" className="text-sm text-error-dark">{error}</p>}
  </section>
}
