import { useEffect, useRef, useState } from 'react'
import { Download, FileCheck } from 'lucide-react'
import { Button } from '../../components/ui/button'
import { Textarea } from '../../components/ui/textarea'
import { Badge } from '../../components/ui/badge'
import { closedJSON } from '../auth/protocol'
import { documentText, importReferencedDocument, object, rootOf, sourcePackage, sourceText, updateSourceText, type SourceProject } from './sourceProject'

export function download(name: string, text: string, type = 'application/json') {
  const url = URL.createObjectURL(new Blob([text], { type })), link = document.createElement('a')
  link.href = url; link.download = name; link.click()
  // Keep the object alive long enough for the browser to start the download,
  // then retire it. The source never enters a network request or browser store.
  setTimeout(() => URL.revokeObjectURL(url), 30000)
}
const shell = (v: string) => "'" + v.replace(/'/g, "'\"'\"'") + "'"
export function SourceReview({ project, root, editing, onChange, check, initialPath = 'draft.json' }: { project: SourceProject; root: string; editing: boolean; onChange(p: SourceProject): void; check(): void; initialPath?: string }) {
  const selected = rootOf(project, root), [path, setPath] = useState(initialPath), [report, setReport] = useState<{ generation: number; digest: string; text: string } | null>(null)
  const reportPicker = useRef<HTMLInputElement>(null), sourcePicker = useRef<HTMLInputElement>(null), alive = useRef(true), latest = useRef(project.generation); latest.current = project.generation
  useEffect(() => { alive.current = true; return () => { alive.current = false } }, [])
  const [error, setError] = useState<string | null>(null)
  const file = selected.files.find(f => f.path === path) ?? selected.files[0]
  const consumer = selected.draft.profile === 'catalog-runtime-creation-observed/v1' ? ' --consumer delivery' : ''
  const artifact = `./artifact-${selected.id}-NEW`
  const commands = `ops-v2 policy unpack --file ./ops-source-package.json --output ./source-NEW\nops-v2 policy prepare --source ${shell('./source-NEW/' + selected.id)} --output ${shell(artifact)} --profile ${shell(selected.draft.profile)}${consumer}\nops-v2 policy check --bundle ${shell(artifact)} --expected-digest REVIEWED_MANIFEST_DIGEST --environment ${shell(selected.draft.environment)} --chain-id ${shell(selected.draft.chainId)} --profile ${shell(selected.draft.profile)}${consumer}`
  async function importReport(file: File) {
    const generation = project.generation
    try {
      check(); if (file.size > 2 << 20) throw Error('The local report is too large.')
      const raw = await file.text(); check()
      if (!alive.current || latest.current !== generation) throw Error('Source changed while the report was read.')
      const value = object(closedJSON(raw, 2 << 20, 32)), metadata = object(value.metadata)
      if (!['prepare', 'check', 'inspect'].includes(String(value.action)) || value.approved !== false || typeof value.manifestDigest !== 'string' || !/^sha256:[0-9a-f]{64}$/.test(value.manifestDigest) ||
        metadata.Environment !== selected.draft.environment || metadata.ChainID !== selected.draft.chainId || metadata.Profile !== selected.draft.profile || metadata.SourceRevision !== selected.draft.sourceRevision) throw Error('This report does not describe this draft selection.')
      setReport({ generation, digest: value.manifestDigest, text: raw }); setError(null)
    } catch (e) { try { check(); if (alive.current && latest.current === generation) setError(e instanceof Error ? e.message : 'Could not read the local report.') } catch { /* retired document */ } }
  }
  async function importSource(file: File) {
    const generation = project.generation
    try {
      check(); if (file.size > 1 << 20) throw Error('Each referenced document must be at most 1 MiB.')
      const raw = await file.text(); check()
      if (!alive.current || latest.current !== generation) return
      onChange(importReferencedDocument(project, root, file.name, raw)); setError(null)
    } catch (e) { if (alive.current) setError(e instanceof Error ? e.message : 'Could not import this referenced document.') }
  }
  return <div className="space-y-5">
    <div className="flex flex-wrap items-center justify-between gap-3"><div><h3 className="text-sm font-medium text-neutral-700">Configuration source and review</h3><p className="text-xs text-neutral-500">Complete files, dependencies, local checks and deployment handoff</p></div>
      <Button onClick={() => { check(); download('ops-source-package.json', JSON.stringify(sourcePackage(project))) }}><Download className="w-4 h-4 mr-2" />Export complete source package</Button></div>
    <div className="rounded-lg border border-warning/30 bg-warning-light p-4 text-sm text-warning-dark"><strong>Go validation has not run in this browser.</strong><p className="mt-1">Export and run the matching release's Go tool. Browser syntax hints and imported reports do not approve a change or establish the serving configuration.</p></div>
    {editing && <div className="space-y-2"><Button variant="outline" size="sm" onClick={() => sourcePicker.current?.click()}>Import missing referenced document</Button><input ref={sourcePicker} type="file" accept=".json" className="sr-only" aria-label="Missing referenced source document" onChange={e => { const file = e.currentTarget.files?.[0]; e.currentTarget.value = ''; if (file) void importSource(file) }} /><p className="text-xs text-neutral-500">Add a reference in the draft or broker public-document pins first, then select that exact flat filename. Adjacent files and credentials are never added automatically.</p></div>}
    <div className="grid gap-4 lg:grid-cols-[15rem_1fr]">
      <nav className="space-y-1" aria-label="Source files">{selected.files.map(f => <Button key={f.path} variant={f.path === file.path ? 'secondary' : 'ghost'} size="sm" className="w-full justify-start break-all whitespace-normal text-left" onClick={() => { setPath(f.path); setError(null) }}>{f.path}{f.editedText !== null && <Badge variant="outline" className="ml-2">Changed</Badge>}</Button>)}</nav>
      <div className="space-y-3"><h4 className="text-sm font-medium break-all">{file.path}</h4><SourceTextEditor key={`${root}:${file.path}`} text={documentText(project, root, file.path)} editing={editing} onEdit={raw => { check(); onChange(updateSourceText(project, root, file.path, raw)) }} />
        <details><summary className="text-sm cursor-pointer">Compare original and proposed source</summary><div className="grid gap-3 mt-3 lg:grid-cols-2"><div><p className="text-xs text-neutral-500">Original</p><pre className="overflow-auto max-h-80 rounded-lg bg-neutral-100 p-3 text-xs whitespace-pre-wrap break-all">{file.originalText || 'New document'}</pre></div><div><p className="text-xs text-neutral-500">Proposed</p><pre className="overflow-auto max-h-80 rounded-lg bg-neutral-100 p-3 text-xs whitespace-pre-wrap break-all">{sourceText(file)}</pre></div></div></details>
      </div>
    </div>
    <section className="rounded-lg border border-neutral-200 p-4 space-y-3"><h4 className="text-sm font-medium">Prepare and check with Go</h4><p className="text-sm text-neutral-500">Use a new output directory for each attempt. Repeat for every changed Core/broker root. The profile and any consumer selection must match the intended deployment.</p><pre className="rounded-lg bg-neutral-100 p-3 text-xs whitespace-pre-wrap break-all">{commands}</pre>
      <Button variant="outline" size="sm" onClick={() => reportPicker.current?.click()}><FileCheck className="w-4 h-4 mr-2" />Import local Go report</Button><input ref={reportPicker} className="sr-only" type="file" accept=".json" aria-label="Local Go validation report" onChange={e => { const file = e.currentTarget.files?.[0]; e.currentTarget.value = ''; if (file) void importReport(file) }} />
      {report && <div className="text-sm text-neutral-600"><p><Badge variant="outline">{report.generation === project.generation ? 'Local report imported' : 'Source changed since report'}</Badge></p><p className="mt-2 break-all">Reported manifest: <code>{report.digest}</code></p><p className="text-xs mt-1">The imported JSON is an operator-provided report. It does not prove who ran the tool or that every file still matches; run Go check again before review/deployment.</p><details><summary className="cursor-pointer mt-2">Report details</summary><pre className="max-h-64 overflow-auto text-xs whitespace-pre-wrap break-all">{report.text}</pre></details></div>}
      {error && <p role="alert" className="text-sm text-error-dark">{error}</p>}
    </section>
    <section className="space-y-2 text-sm"><h4 className="font-medium">Operator handoff</h4><ol className="list-decimal ml-5 space-y-2"><li>Review the source changes and exact generated artifact/digest through your organization's approved process.</li><li>Coordinate matching Core, broker, SSO client/runtime and read-policy pins. A new organization also needs its configured node and environment credential references.</li><li>Materialize reviewed files read-only and deliberately drain/restart the selected deployment. A draft export or local check does not activate it.</li><li>For rollback, select the previous approved compatible image and complete bundle set. Recheck readiness and current identities.</li></ol></section>
  </div>
}
function SourceTextEditor({ text, editing, onEdit }: { text: string; editing: boolean; onEdit(raw: string): void }) {
  const [error, setError] = useState<string | null>(null)
  return <div className="space-y-2"><Textarea aria-label="Proposed source" variant="code" className="min-h-64" value={text} readOnly={!editing} onChange={e => { try { onEdit(e.target.value); setError(null) } catch (e) { setError(e instanceof Error ? e.message : 'Could not retain this draft text.') } }} spellCheck={false} />
    {error && <p role="alert" className="text-sm text-error-dark">{error}</p>}
    <p className="text-xs text-neutral-500">Text changes immediately join this local proposal and its export, including unfinished JSON. Repair draft syntax before Go preparation or semantic editing. The matching Go tool checks schemas, references, capabilities and native execution semantics.</p>
  </div>
}
