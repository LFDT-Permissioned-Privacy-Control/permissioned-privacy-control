import { useEffect, useRef, useState } from 'react'
import { Button } from '../../components/ui/button'
import { Input } from '../../components/ui/input'
import { Badge } from '../../components/ui/badge'
import { download } from './SourceReview'
import { groupsOf, object, rootOf, type SourceProject } from './sourceProject'
import { useAuthoringState } from './sourceAuthoring'
import { closedJSON } from '../auth/protocol'
import { initialScenarioFrame, parseScenarioImport, scenarioDocument, SourceScenarioBuilder } from './SourceScenarioBuilder'

export async function scenarioDigest(raw: string): Promise<string> {
  const bytes = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(raw))
  return 'sha256:' + Array.from(new Uint8Array(bytes), v => v.toString(16).padStart(2, '0')).join('')
}
export function SourceScenario({ project, root, organization, check }: { project: SourceProject; root: string; organization: string; check(): void }) {
  const selected = rootOf(project, root), groups = groupsOf(project, root, organization)
  const [signer, setSigner] = useAuthoringState('signer', ''), [memberships, setMemberships] = useAuthoringState<string[]>('memberships', []), [frames, setFrames] = useAuthoringState('frames', JSON.stringify([initialScenarioFrame()], null, 2))
  const [context, setContext] = useAuthoringState('context', '{"LinkedAddresses":[],"Claims":0,"GroupSourceClaims":{}}'), [error, setError] = useState<string | null>(null), [expectedManifest, setExpectedManifest] = useAuthoringState('manifest', '')
  const [exported, setExported] = useState<{ raw: string; digest: string; generation: number } | null>(null), [result, setResult] = useState<{ raw: string; manifest: string; generation: number; allowed: boolean; code: string; reason: string } | null>(null)
  const scenarioPicker = useRef<HTMLInputElement>(null), picker = useRef<HTMLInputElement>(null), alive = useRef(true), latest = useRef({ raw: '', generation: project.generation, manifest: expectedManifest, input: '', selection: root + ':' + organization })
  useEffect(() => { alive.current = true; return () => { alive.current = false } }, [])
  function build(): string {
    return JSON.stringify(scenarioDocument({ context, frames, organization, signer, groups: memberships }), null, 2)
  }
  let currentRaw = ''; try { currentRaw = build() } catch { /* An incomplete scenario is editable, never evaluated in JS. */ }
  useEffect(() => { setResult(null) }, [currentRaw, project.generation, expectedManifest])
  latest.current = { raw: currentRaw, generation: project.generation, manifest: expectedManifest, input: JSON.stringify({ signer, memberships, frames, context }), selection: root + ':' + organization }
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
  async function importScenario(file: File) {
    const original = latest.current
    try {
      check(); if (file.size > 1 << 20) throw Error('The local scenario is too large.')
      const raw = await file.text(); check()
      if (!alive.current || latest.current.input !== original.input || latest.current.generation !== original.generation || latest.current.selection !== original.selection) return
      const value = parseScenarioImport(raw, organization)
      setSigner(value.signer); setMemberships(value.groups); setContext(value.context); setFrames(value.frames); setExported(null); setResult(null); setError(null)
    } catch (e) { if (alive.current && latest.current.input === original.input && latest.current.generation === original.generation && latest.current.selection === original.selection) setError(e instanceof Error ? e.message : 'Could not import scenario.') }
  }
  const currentResult = result && result.raw === currentRaw && result.generation === project.generation && result.manifest === expectedManifest
  const shell = (value: string) => "'" + value.replace(/'/g, "'\"'\"'") + "'"
  return <section className="space-y-4"><h3 className="text-sm font-medium">Policy scenario</h3>
    <p className="text-sm text-neutral-500">Evaluate hypothetical facts using the matching Go reference evaluator. This does not execute an EVM call, prove a current identity or node trace, establish owner facts, or verify deployed Guard equivalence.</p>
    <label className="block text-sm font-medium">Hypothetical signer<Input value={signer} onChange={e => setSigner(e.target.value)} placeholder="0x..." /></label>
    <fieldset><legend className="text-sm font-medium mb-2">Hypothetical groups</legend><div className="flex flex-wrap gap-4">{groups.map(g => <label key={g.id} className="inline-flex items-center gap-2 text-sm"><input type="checkbox" checked={memberships.includes(g.id)} onChange={e => setMemberships(e.target.checked ? [...memberships, g.id] : memberships.filter(id => id !== g.id))} />{g.name}</label>)}</div></fieldset>
    <SourceScenarioBuilder context={context} frames={frames} organizations={selected.draft.organizations} onContext={setContext} onFrames={setFrames} />
    <Button variant="outline" onClick={() => scenarioPicker.current?.click()}>Import scenario JSON</Button><input ref={scenarioPicker} type="file" accept=".json" className="sr-only" aria-label="Import hypothetical scenario" onChange={e => { const file = e.currentTarget.files?.[0]; e.currentTarget.value = ''; if (file) void importScenario(file) }} />
    <Button onClick={() => void exportScenario()}>Export policy scenario</Button>{exported && <p className="text-xs text-neutral-500 break-all">{exported.raw === currentRaw && exported.generation === project.generation ? 'Exported scenario' : 'Scenario or source changed; export again'}: <code>{exported.digest}</code></p>}
    <pre className="text-xs rounded-lg bg-neutral-100 p-3 whitespace-pre-wrap break-all">{`ops-v2 policy simulate --bundle ./artifact-NEW --expected-digest REVIEWED_MANIFEST_DIGEST --environment ${shell(selected.draft.environment)} --chain-id ${shell(selected.draft.chainId)} --profile ${shell(selected.draft.profile)}${selected.draft.profile === 'catalog-runtime-creation-observed/v1' ? ' --consumer delivery' : ''} --scenario ./ops-policy-scenario.json`}</pre>
    <label className="block text-sm font-medium">Selected prepared manifest digest<Input value={expectedManifest} onChange={e => setExpectedManifest(e.target.value)} placeholder="sha256:..." /></label>
    <Button variant="outline" onClick={() => picker.current?.click()}>Import Go scenario result</Button><input ref={picker} type="file" accept=".json" className="sr-only" aria-label="Go scenario result" onChange={e => { const file = e.currentTarget.files?.[0]; e.currentTarget.value = ''; if (file) void importResult(file) }} />
    {result && <div className="rounded-lg border border-neutral-200 p-4 space-y-2"><Badge variant="outline">{currentResult ? 'Imported local result' : 'Scenario, source or selected artifact changed'}</Badge>{currentResult && <><p className="text-sm font-medium">Conditional {result.allowed ? 'allow' : 'deny'}{result.code ? ': ' + result.code : ''}</p><p className="text-sm break-words">{result.reason}</p></>}<p className="text-xs text-neutral-500">This operator-provided report matches the exported scenario digest and selected artifact/evaluator fields. Its provenance and the running deployment are not established.</p></div>}
    {error && <p role="alert" className="text-sm text-error-dark">{error}</p>}
  </section>
}
