import { useState } from 'react'
import { Button } from '../../components/ui/button'
import { Badge } from '../../components/ui/badge'
import { Dialog, DialogContent, DialogHeader, DialogTitle } from '../../components/ui/dialog'
import { SourceRecords } from './SourceRecords'
import { SourceScenario } from './SourceScenario'
import { documentFor, documentValue, groupsOf, object, rootOf, updateDocument, type SourceProject } from './sourceProject'

const ruleFields: import('./SourceRecords').SourceField[] = [
  { key: 'targetClass', label: 'Resolved target class', optional: true, options: ['org', 'shared', 'eoa', 'precompile', 'create'], help: 'Leave unset for literal addresses. Ownership and code kind are acquired by the runtime.' },
  { key: 'storageAddress', label: 'Storage address', allowEmpty: true }, { key: 'codeAddress', label: 'Separate code address', optional: true, help: 'For delegatecall/callcode; omitted means storage and code coincide.' },
  { key: 'selector', label: 'Selector', help: '0x plus four selector bytes, * for any input, or 0x for exactly empty input.' },
  { key: 'abiDigest', label: 'Go canonical ABI digest', allowEmpty: true, help: 'Exact selectors require the Go inspector digest; wildcard/empty-input rules use an empty string.' },
  { key: 'callTypes', label: 'Call types', kind: 'list', optional: true, help: 'call, staticcall, delegatecall, callcode, create or create2. Omitted permits only call and staticcall.' },
  { key: 'args', label: 'Argument constraints', kind: 'json', optional: true }, { key: 'maxValue', label: 'Maximum native value (exact decimal wei)', optional: true },
  { key: 'minDepth', label: 'Minimum depth', kind: 'number', optional: true }, { key: 'maxDepth', label: 'Maximum depth', kind: 'number', optional: true },
  { key: 'callerAddress', label: 'Required immediate caller', optional: true }, { key: 'allowUpgrade', label: 'Allow recognized upgrade with a current upgrade claim', kind: 'boolean', optional: true },
  { key: 'except', label: 'Native deployer exceptions', kind: 'json', optional: true },
]
export function SourceExecution({ project, root, organization, editing, onChange, check, onOpenSource }: { project: SourceProject; root: string; organization: string; editing: boolean; onChange(project: SourceProject): void; check(): void; onOpenSource(path: string): void }) {
  const [mode, setMode] = useState('rules'), [bindingIndex, setBindingIndex] = useState<number | null>(null)
  if (!organization) return <p className="text-sm text-neutral-500 text-center py-12">Select an organization from the imported source</p>
  const selected = rootOf(project, root), path = documentFor(selected, organization, 'execution-rules'), doc = documentValue(project, root, path), spec = object(doc.spec), policy = object(spec.policy), groups = groupsOf(project, root, organization), bindings = policy.bindings as Record<string, unknown>[], binding = bindingIndex === null ? null : object(bindings[bindingIndex])
  function savePolicy(value: unknown) { check(); onChange(updateDocument(project, root, path, { ...doc, spec: { ...spec, policy: object(value) } })) }
  return <div className="space-y-5"><div className="flex flex-wrap gap-2"><Button variant={mode === 'rules' ? 'secondary' : 'outline'} onClick={() => setMode('rules')}>Execution rules</Button><Button variant={mode === 'scenario' ? 'secondary' : 'outline'} onClick={() => setMode('scenario')}>Policy scenario</Button><Button variant="outline" onClick={() => onOpenSource(path)}>Candidate source</Button></div>
    <div className="flex flex-wrap gap-2 text-xs"><Badge variant="outline">{String(policy.apiVersion)}</Badge><Badge variant="outline">Nested calls require their own rule</Badge><Badge variant="outline">Local proposal</Badge></div>
    {mode === 'rules' ? <><SourceRecords title="Group bindings" description="Every observed frame needs its own matching allow rule. The group and contract IDs below come from this local source; Go validates references, ABI selectors and native execution semantics." records={policy.bindings} editing={editing}
      fields={[{ key: 'group', label: 'Group ID', help: groups.map(g => `${g.name}: ${g.id}`).join('; ') }, { key: 'allow', label: 'Advanced allow rule JSON', kind: 'json', help: 'Use Frame rules for individual rule fields. Empty allow denies. Partior recordParty is deferred.' }]}
      defaults={() => ({ group: '', allow: [] })} onChange={bindings => savePolicy({ ...policy, bindings })} renderActions={(_, index) => <Button variant="outline" size="sm" onClick={() => setBindingIndex(index)}>Frame rules</Button>} />
      <Dialog open={binding !== null} onOpenChange={open => { if (!open) setBindingIndex(null) }}><DialogContent className="max-w-4xl max-h-[85vh] overflow-y-auto"><DialogHeader><DialogTitle>Execution frame rules</DialogTitle></DialogHeader>{binding && <SourceRecords title="Frame rules" description="Literal or resolved targets, exact ABI selection and explicit bounds. Each nested frame needs its own rule." records={binding.allow} fields={ruleFields} defaults={() => ({ storageAddress: '', selector: '', abiDigest: '', args: [] })} editing={editing} onChange={allow => savePolicy({ ...policy, bindings: bindings.map((b, i) => i === bindingIndex ? { ...b, allow } : b) })} />}</DialogContent></Dialog>
      <details className="text-sm"><summary className="cursor-pointer font-medium">Registered ABI and address references</summary><pre className="mt-3 rounded-lg bg-neutral-100 p-3 text-xs whitespace-pre-wrap break-all max-h-72 overflow-auto">{JSON.stringify(documentValue(project, root, documentFor(selected, organization, 'contract-registry')), null, 2)}</pre><p className="text-xs text-neutral-500 mt-2">Use <code>ops-v2 policy abi --file ABI.json</code> to obtain the Go tool's normalized ABI digest and selectors. Browser labels do not establish deployment or owner facts.</p></details>
    </>      : <SourceScenario key={`${root}:${organization}`} project={project} root={root} organization={organization} check={check} />}
  </div>
}
