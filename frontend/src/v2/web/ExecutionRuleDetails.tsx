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
  const args = Array.isArray(rule.args) ? rule.args.map(object) : [], code = contracts.find(c => c.address === (rule.codeAddress || rule.storageAddress))
  let inputs: ReturnType<typeof abiChoices>['functions'][number]['inputs'] = []
  try { inputs = abiChoices(code?.abi).functions.find(f => f.selector === rule.selector)?.inputs ?? [] } catch { /* unresolved source stays visible */ }
  const rows = [
    ['Target', rule.targetClass ? `Runtime resolved class: ${String(rule.targetClass)}` : name(rule.storageAddress)],
    ['Executing code', rule.targetClass ? 'Resolved by runtime' : name(rule.codeAddress || rule.storageAddress)],
    ['Function / input', ruleFunctionLabel(rule, contracts)], ['Selector', String(rule.selector)], ['Pinned ABI digest', String(rule.abiDigest || 'None for wildcard / empty input')],
    ['Call types', Array.isArray(rule.callTypes) && rule.callTypes.length ? rule.callTypes.join(', ') : 'call, staticcall (native default)'],
    ['Maximum native value', rule.maxValue === undefined ? 'Unbounded' : String(rule.maxValue) + ' wei'], ['Minimum depth', rule.minDepth === undefined ? 'Unbounded' : String(rule.minDepth)], ['Maximum depth', rule.maxDepth === undefined ? 'Unbounded' : String(rule.maxDepth)], ['Immediate caller', rule.callerAddress === undefined ? 'Any immediate caller' : String(rule.callerAddress)], ['Recognized upgrades', rule.allowUpgrade === true ? 'Requires current target-specific upgrade claim' : 'No upgrade exception'],
  ]
  return <section className="space-y-4 rounded-lg border p-4"><h4 className="font-medium break-all">{ruleFunctionLabel(rule, contracts)}</h4><dl className="grid gap-3 sm:grid-cols-2">{rows.map(([label, value]) => <div key={label}><dt className="text-xs text-neutral-500">{label}</dt><dd className="text-sm break-all">{value}</dd></div>)}</dl>
    <div className="space-y-2"><h5 className="text-sm font-medium">Argument constraints</h5>{!args.length ? <p className="text-sm text-neutral-500">No argument constraints.</p> : args.map((arg, i) => { const input = inputs[Number(arg.index)], match = arg.addressEquals ? object(arg.addressEquals) : null; return <div key={i} className="rounded-lg bg-neutral-50 p-3 text-sm break-all"><p className="font-medium">Argument {String(arg.index)}{input ? ` · ${input.name || 'Unnamed'} (${input.type})` : ''}</p><p>{match ? match.source === 'literal' ? 'Equals literal address: ' + String(match.value) : match.source === 'signer' ? 'Equals the transaction signer' : match.source === 'principal.linked' ? 'Equals an address linked to the verified principal' : 'Advanced address source: ' + String(match.source) : arg.uintAtMost !== undefined ? 'At most (inclusive): ' + String(arg.uintAtMost) : arg.recordParty !== undefined ? 'Advanced record-party constraint (deferred); inspect native JSON' : 'Advanced native constraint; inspect native JSON'}</p></div> })}</div>
    {rule.except !== undefined && <p className="text-xs text-neutral-500">Native deployer exceptions are present; inspect advanced JSON for exact group/target references.</p>}
    <details><summary className="cursor-pointer text-sm font-medium">Advanced native rule JSON</summary><pre className="mt-2 whitespace-pre-wrap break-all text-xs">{JSON.stringify(rule, null, 2)}</pre></details>
  </section>
}
