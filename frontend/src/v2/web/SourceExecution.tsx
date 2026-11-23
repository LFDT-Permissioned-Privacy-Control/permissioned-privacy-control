import { useState } from 'react'
import { FileCode2, Shield } from 'lucide-react'
import { ContractEmpty, PermissionPill } from '../../components/rbac/ContractPresentation'
import { SourcePolicyLink } from './SourceContracts'
import { Button } from '../../components/ui/button'
import { Badge } from '../../components/ui/badge'
import { Dialog, DialogContent, DialogHeader, DialogTitle } from '../../components/ui/dialog'
import { SourceRecords } from './SourceRecords'
import { ExecutionRuleDetails, ExecutionRuleSummary, ruleFunctionLabel, assertRuleDisplay } from './ExecutionRuleDetails'
import { documentFor, documentValue, groupsOf, object, rootOf, type JSONObject, type SourceProject } from './sourceProject'
import { SourceViewScope, useSourceObservation } from './sourceViewState'
interface Props { project: SourceProject; root: string; organization: string; onOpenSource(path: string): void }
export function SourceExecution(props: Props) {
  if (!props.organization) return <p className="py-12 text-center text-sm text-neutral-500">Select an organization from the configuration</p>
  return <SourceViewScope id="execution"><SourceExecutionContent {...props} /></SourceViewScope>
}
function SourceExecutionContent({ project, root, organization, onOpenSource }: Props) {
  const selected = rootOf(project, root), path = documentFor(selected, organization, 'execution-rules'), policy = object(object(documentValue(project, root, path).spec).policy)
  if (!Array.isArray(policy.bindings)) throw Error('Execution bindings must be an array. Inspect the source file.')
  const groups = groupsOf(project, root, organization), bindings = policy.bindings.map(object)
  for (const binding of bindings) {
    if (typeof binding.group !== 'string' || !Array.isArray(binding.allow)) throw Error('Execution bindings need a group ID and an allow array. Inspect the source file.')
    binding.allow.map(object).forEach(assertRuleDisplay)
  }
  const registry = documentValue(project, root, documentFor(selected, organization, 'contract-registry')), contracts = (object(registry.spec).contracts as unknown[]).map(object)
  const observation = useSourceObservation(), [inspection, setInspection] = useState<{ value: JSONObject; observation: number } | null>(null)
  const current = inspection?.observation === observation ? inspection.value : null
  return <div className="space-y-5"><div className="flex flex-wrap gap-2"><Button variant="outline" onClick={() => onOpenSource(path)}><FileCode2 className="mr-2 h-4 w-4" />View execution source</Button></div>
    <div className="flex flex-wrap gap-2 text-xs"><Badge variant="outline">{String(policy.apiVersion)}</Badge><Badge variant="outline">Nested calls require their own rule</Badge></div>
    <h3 className="flex items-center gap-2 text-lg font-semibold"><Shield className="h-5 w-5 text-primary" />Execution permissions</h3>
    <p className="text-sm text-neutral-500">Every observed frame needs its own matching rule. Groups and registered contracts below come from the selected configuration; registry entries do not establish deployed code or runtime owner facts.</p>
    {!bindings.length && <ContractEmpty title="No group bindings" description="An empty allow list denies execution." />}
    {bindings.map((binding, index) => { const group = groups.find(g => g.id === binding.group), allow = Array.isArray(binding.allow) ? binding.allow.map(object) : []; return <section key={String(binding.group) + index} className="space-y-3 rounded-lg border border-neutral-200 p-4"><div className="flex items-start justify-between gap-3"><div><h3 className="font-medium">{group?.name ?? 'Unresolved source group'}</h3><p className="break-all text-xs text-neutral-500">{String(binding.group)}</p><SourcePolicyLink page="groups" organization={organization}>View group permissions</SourcePolicyLink></div><Button variant="outline" size="sm" onClick={() => setInspection({ value: binding, observation })}>Inspect binding</Button></div>
      {allow.map((rule, ruleIndex) => { const storage = contracts.find(c => c.address === rule.storageAddress), code = contracts.find(c => c.address === (rule.codeAddress || rule.storageAddress)); return <div key={ruleIndex} className="flex flex-wrap justify-between gap-3 rounded-lg bg-neutral-50 p-3"><div className="min-w-0"><p className="break-all text-sm font-medium">{rule.targetClass ? 'Target class: ' + rule.targetClass : String(storage?.name ?? rule.storageAddress)}</p><p className="break-all text-xs"><PermissionPill>{ruleFunctionLabel(rule, contracts)}</PermissionPill> · {String(rule.selector)}{rule.codeAddress ? ' · code: ' + String(code?.name ?? rule.codeAddress) : ''}</p><p className="text-xs text-neutral-500">{Array.isArray(rule.args) ? rule.args.length : 0} argument constraints (AND) · {Array.isArray(rule.callTypes) && rule.callTypes.length ? rule.callTypes.join(', ') : 'call, staticcall (native default)'}</p><ExecutionRuleSummary rule={rule} /></div><Button size="sm" variant="outline" onClick={() => setInspection({ value: rule, observation })}>Inspect rule</Button></div> })}
      {!allow.length && <p className="text-sm text-neutral-500">No allowed frames for this group.</p>}
    </section> })}
    <details className="text-sm"><summary className="cursor-pointer font-medium">Advanced binding JSON</summary><SourceRecords title="Advanced group bindings" records={policy.bindings} fields={[{ key: 'group', label: 'Group ID' }, { key: 'allow', label: 'Native allow rules', kind: 'json' }]} /></details>
    <Dialog open={!!current} onOpenChange={open => { if (!open) setInspection(null) }}><DialogContent className="max-w-3xl max-h-[85vh] overflow-y-auto"><DialogHeader><DialogTitle>Native execution inspection</DialogTitle></DialogHeader>{current && (Array.isArray(current.allow) ? <div className="space-y-4"><h3 className="font-medium">{groups.find(g => g.id === current.group)?.name ?? 'Unresolved source group'}</h3><p className="break-all text-xs text-neutral-500">{String(current.group)} · Every nested frame requires its own matching rule.</p>{!current.allow.length && <p className="text-sm text-neutral-500">Empty allow list — no allowed frames.</p>}{current.allow.map((rule, index) => <ExecutionRuleDetails key={index} rule={object(rule)} contracts={contracts} />)}<details><summary className="cursor-pointer text-sm">Advanced native binding JSON</summary><pre className="whitespace-pre-wrap break-all text-xs">{JSON.stringify(current, null, 2)}</pre></details></div> : <ExecutionRuleDetails rule={current} contracts={contracts} />)}</DialogContent></Dialog>
  </div>
}
