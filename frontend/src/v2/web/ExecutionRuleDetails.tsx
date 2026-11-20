import { PermissionPill } from '../../components/rbac/ContractPresentation'
import { abiChoices } from './executionABI'
import { object, type JSONObject } from './sourceProject'
export function ruleFunctionLabel(rule: JSONObject, contracts: JSONObject[]): string {
  const code = contracts.find(c => c.address === (rule.codeAddress || rule.storageAddress))
  if (rule.selector === '*') return 'Any input'
  if (rule.selector === '0x') return 'Empty input only'
  try { return abiChoices(code?.abi).functions.find(f => f.selector === rule.selector)?.signature ?? 'Unresolved ABI function' } catch { return 'Unresolved ABI function' }
}
export function ExecutionRuleDetails({ rule, contracts }: { rule: JSONObject; contracts: JSONObject[] }) {
  const name = (address: unknown) => { const contract = contracts.find(c => c.address === address); return contract ? `${String(contract.name || contract.id)} · ${String(address)}` : String(address || 'Same as storage contract') }
  const argsValid = rule.args === undefined || Array.isArray(rule.args) && rule.args.every(arg => arg && typeof arg === 'object' && !Array.isArray(arg)), args = argsValid && Array.isArray(rule.args) ? rule.args.map(object) : [], code = contracts.find(c => c.address === (rule.codeAddress || rule.storageAddress))
  let inputs: ReturnType<typeof abiChoices>['functions'][number]['inputs'] = []
  try { inputs = abiChoices(code?.abi).functions.find(f => f.selector === rule.selector)?.inputs ?? [] } catch { /* unresolved source stays visible */ }
  const rows = [
    ['Target', rule.targetClass ? `Runtime resolved class: ${String(rule.targetClass)}` : name(rule.storageAddress)],
    ['Executing code', rule.targetClass ? 'Resolved by runtime' : name(rule.codeAddress || rule.storageAddress)],
    ['Function / input', ruleFunctionLabel(rule, contracts)], ['Selector', String(rule.selector)], ['Pinned ABI digest', String(rule.abiDigest || 'None for wildcard / empty input')],
    ['Call types', Array.isArray(rule.callTypes) && rule.callTypes.length ? rule.callTypes.join(', ') : 'call, staticcall (native default)'],
    ['Maximum native value', rule.maxValue === undefined ? 'Unbounded' : String(rule.maxValue) + ' wei'], ['Minimum depth', rule.minDepth === undefined ? 'Unbounded' : String(rule.minDepth)], ['Maximum depth', rule.maxDepth === undefined ? 'Unbounded' : String(rule.maxDepth)], ['Immediate caller', rule.callerAddress === undefined ? 'Any immediate caller' : String(rule.callerAddress)], ['Recognized upgrades', rule.allowUpgrade === true ? 'Requires current target-specific upgrade claim' : 'No upgrade exception'],
  ]
  return <section className="space-y-4 rounded-lg border p-4"><h4 className="font-medium break-all"><PermissionPill>{ruleFunctionLabel(rule, contracts)}</PermissionPill></h4><dl className="grid gap-3 sm:grid-cols-2">{rows.map(([label, value]) => <div key={label}><dt className="text-xs text-neutral-500">{label}</dt><dd className="text-sm break-all">{value}</dd></div>)}</dl>
    <div className="space-y-2"><h5 className="text-sm font-medium">Argument constraints · all must match (AND)</h5>{!argsValid ? <p className="text-sm text-warning-dark">Unsupported imported argument shape is retained; inspect advanced native JSON.</p> : !args.length ? <p className="text-sm text-neutral-500">No argument constraints.</p> : args.map((arg, i) => { const input = inputs[Number(arg.index)], match = arg.addressEquals && typeof arg.addressEquals === 'object' && !Array.isArray(arg.addressEquals) ? object(arg.addressEquals) : null; return <div key={i} className="rounded-lg bg-neutral-50 p-3 text-sm break-all"><p className="font-medium">Argument {String(arg.index)}{input ? ` · ${input.name || 'Unnamed'} (${input.type})` : ''}</p><p>{match ? match.source === 'literal' ? 'Equals literal address: ' + String(match.value) : match.source === 'signer' ? 'Equals the transaction signer' : match.source === 'principal.linked' ? 'Equals an address linked to the verified principal' : 'Advanced address source: ' + String(match.source) : arg.uintAtMost !== undefined ? 'At most (inclusive): ' + String(arg.uintAtMost) : arg.recordParty !== undefined ? 'Advanced record-party constraint (deferred); inspect native JSON' : 'Advanced native constraint; inspect native JSON'}</p></div> })}</div>
    {rule.except !== undefined && <p className="text-xs text-neutral-500">Native deployer exceptions are present; inspect advanced JSON for exact group/target references.</p>}
    <details><summary className="cursor-pointer text-sm font-medium">Advanced native rule JSON</summary><pre className="mt-2 whitespace-pre-wrap break-all text-xs">{JSON.stringify(rule, null, 2)}</pre></details>
  </section>
}

export function ExecutionRuleSummary({ rule }: { rule: JSONObject }) {
  const valid = rule.args === undefined || Array.isArray(rule.args) && rule.args.every(arg => arg && typeof arg === 'object' && !Array.isArray(arg))
  const args = valid && Array.isArray(rule.args) ? rule.args.map(object) : []
  return <div className="mt-2 flex flex-wrap gap-1 text-xs">{!valid && <span className="text-warning-dark">Unsupported arguments retained in advanced JSON</span>}{args.map((arg, i) => { const match = arg.addressEquals && typeof arg.addressEquals === 'object' && !Array.isArray(arg.addressEquals) ? object(arg.addressEquals) : null; return <span key={i} className="rounded bg-white px-2 py-1 text-neutral-600">Argument {String(arg.index)}: {match ? 'equals ' + (match.source === 'literal' ? String(match.value) : match.source === 'principal.linked' ? 'principal linked address' : String(match.source)) : arg.uintAtMost !== undefined ? '≤ ' + String(arg.uintAtMost) : 'advanced constraint retained'}{i < args.length - 1 ? ' AND' : ''}</span> })}{rule.maxValue !== undefined && <span className="rounded bg-white px-2 py-1 text-neutral-600">≤ {String(rule.maxValue)} wei</span>}{(rule.minDepth !== undefined || rule.maxDepth !== undefined) && <span className="rounded bg-white px-2 py-1 text-neutral-600">Depth {String(rule.minDepth ?? 'any')}–{String(rule.maxDepth ?? 'any')}</span>}{rule.callerAddress !== undefined && <span className="break-all rounded bg-white px-2 py-1 text-neutral-600">Caller: {String(rule.callerAddress)}</span>}{rule.allowUpgrade === true && <span className="rounded bg-warning-light px-2 py-1 text-warning-dark">Current upgrade claim required</span>}</div>
}
