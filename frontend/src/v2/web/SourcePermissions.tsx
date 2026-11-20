import { useId } from 'react'
import { Check, Code, Server, ShieldCheck, Wallet } from 'lucide-react'
import { PermissionCheck, PermissionCount, permissionClaimClasses, permissionMethodClasses, permissionPresetClasses } from '../../components/rbac/PermissionSelectionView'
import { Button } from '../../components/ui/button'
import { Badge } from '../../components/ui/badge'

// Names verified against rpcexecution metadata/state/history handlers and
// rpcengine call/client_trace/utility/raw dispatch. These choices are assistance,
// not a claim that the selected runtime has enabled an operation.
export const NATIVE_METHOD_SECTIONS = [
  { name: 'Network and fees', description: 'Network metadata, node accounts, sync status and fee estimates. Accounts do not grant signing authority.', methods: ['eth_accounts', 'eth_blockNumber', 'eth_chainId', 'eth_feeHistory', 'eth_gasPrice', 'eth_maxPriorityFeePerGas', 'eth_syncing', 'net_listening', 'net_peerCount', 'net_version', 'web3_clientVersion', 'web3_sha3'] },
  { name: 'Account state', description: 'Authorized account state reads under the native read policy.', methods: ['eth_getBalance', 'eth_getCode', 'eth_getStorageAt', 'eth_getProof', 'eth_getTransactionCount'] },
  { name: 'Blocks and history', description: 'Native filtered block, transaction, receipt and log reads.', methods: ['eth_getTransactionByHash', 'eth_getTransactionReceipt', 'eth_getBlockByHash', 'eth_getBlockByNumber', 'eth_getBlockTransactionCountByHash', 'eth_getBlockTransactionCountByNumber', 'eth_getTransactionByBlockHashAndIndex', 'eth_getTransactionByBlockNumberAndIndex', 'eth_getLogs', 'eth_getBlockReceipts'] },
  { name: 'Execution', description: 'Calls, traces, estimates and signed submission still require the configured native runtime and execution rules.', methods: ['eth_call', 'debug_traceCall', 'eth_estimateGas', 'eth_createAccessList', 'eth_sendRawTransaction'] },
] as const
export const NATIVE_METHODS: readonly string[] = NATIVE_METHOD_SECTIONS.flatMap(s => [...s.methods])
export const NATIVE_PRESETS = [
  { name: 'Network reader', description: 'Network identity and fee information.', methods: ['eth_chainId', 'eth_blockNumber', 'net_version', 'net_listening', 'eth_gasPrice', 'eth_feeHistory'] },
  { name: 'Application reader', description: 'Network, account and filtered history reads with eth_call.', methods: [...NATIVE_METHOD_SECTIONS[0].methods, ...NATIVE_METHOD_SECTIONS[1].methods, ...NATIVE_METHOD_SECTIONS[2].methods, 'eth_call'] },
  { name: 'Transaction application', description: 'Application reads, gas estimation, access lists and already signed submission.', methods: NATIVE_METHODS.filter(m => m !== 'debug_traceCall') },
  { name: 'Trace developer', description: 'Native supported read and execution choices, including debug_traceCall.', methods: [...NATIVE_METHODS] },
] as const
export const EXECUTION_CLAIMS = [
  { id: 'admin', name: 'Execution administrator', description: 'Expands to admin, deploy and upgrade execution flags in the native compiler. It does not grant organization administration or bypass frame rules.' },
  { id: 'deploy', name: 'Deploy contracts', description: 'Deployment authority where the selected native profile and qualified source facts support it; creation still needs an execution rule.' },
  { id: 'upgrade', name: 'Upgrade contracts', description: 'Upgrade authority where the native evaluator requires it. The matching execution rule must also allow upgrades.' },
] as const
export function presetMethods(current: string[], methods: readonly string[]): string[] { return [...new Set([...current.filter(m => !NATIVE_METHODS.includes(m)), ...methods])].sort() }
// Imported custom names are preserved separately. A preset describes only the
// exact set of guided choices; toggling any guided method recomputes the match.
export function matchingNativePreset(methods: readonly string[]) {
  const selected = new Set(methods.filter(m => NATIVE_METHODS.includes(m)))
  return NATIVE_PRESETS.find(p => p.methods.length === selected.size && p.methods.every(m => selected.has(m)))?.name ?? null
}
const presetIcons = [Server, Wallet, Code, ShieldCheck]
export function SourcePermissionChoices({ methods, claims, isAdmin, onMethods, onClaims, pendingAdditionalMethods = false }: { methods: string[]; claims: string[]; isAdmin: boolean; pendingAdditionalMethods?: boolean; onMethods?(value: string[]): void; onClaims?(value: string[]): void }) {
  const id = useId()
  const unknown = methods.filter(m => !NATIVE_METHODS.includes(m)), customClaims = claims.filter(c => !EXECUTION_CLAIMS.some(v => v.id === c))
  const matchingPreset = pendingAdditionalMethods ? null : matchingNativePreset(methods), adminDeclared = claims.includes('admin')
  const toggle = (items: string[], item: string) => items.includes(item) ? items.filter(v => v !== item) : [...items, item]
  return <div className="space-y-5">
    <fieldset className="space-y-2">
      <legend className="text-sm font-medium text-neutral-700">Permission presets</legend>
      <p className="text-xs text-neutral-500">{onMethods ? 'Select a preset or choose methods individually below.' : 'Matching preset for the declared guided methods.'} Imported additional methods are shown separately.</p>
      {pendingAdditionalMethods && <p className="text-xs text-neutral-500">Additional method names are pending; preset matching resumes after they are saved or cleared.</p>}
      <div className="grid gap-3 sm:grid-cols-2">
        {NATIVE_PRESETS.map((p, i) => {
          const selected = matchingPreset === p.name, Icon = presetIcons[i]
          return <button key={p.name} type="button" aria-label={p.name} aria-pressed={selected} disabled={!onMethods}
            data-state={selected ? 'selected' : 'unselected'} className={permissionPresetClasses(selected, !!onMethods)}
            onClick={() => onMethods?.(presetMethods(methods, p.methods))}>
            <span className="flex w-full items-center justify-between"><Icon className="w-5 h-5 text-primary" aria-hidden="true" />{selected && <Check className="w-4 h-4 text-primary stroke-[3]" aria-hidden="true" />}</span>
            <span className="text-sm font-semibold text-neutral-900">{p.name}</span>
            <span className="text-[11px] text-neutral-500">{p.description}</span>
            <span className="text-[10px] text-neutral-500">{p.methods.length} guided methods{selected ? ' · Matches selection' : ''}</span>
          </button>
        })}
      </div>
      <p className="text-xs text-neutral-500">{onMethods ? 'Presets replace the displayed choices and retain imported additional methods. ' : ''}They are conservative convenience selections; Go validation and the running runtime remain authoritative. Node-owned eth_sendTransaction requires NodeSigning and is only available as an explicit additional name.</p>
    </fieldset>
    <fieldset className="space-y-3 bg-neutral-50 border border-neutral-200 rounded-lg p-4">
      <legend className="text-sm font-semibold text-neutral-900">Execution claims · {isAdmin ? 0 : claims.length} declared</legend>
      {isAdmin ? <div className="flex items-start gap-3 bg-primary-50 border border-primary-200 rounded-lg p-4">
        <ShieldCheck className="w-5 h-5 text-primary-700 flex-shrink-0 mt-0.5" aria-hidden="true" />
        <p className="text-xs text-neutral-600">Organization admin groups save an empty claims list. Their organization role and explicit RPC methods remain separate from these source claim flags.</p>
      </div> : <>
        <p className="text-xs text-neutral-500">Execution administrator implies deploy and upgrade in the native compiler. Implied checks describe that relationship; the saved source keeps only the explicitly declared flags.</p>
        <div className="grid gap-3 sm:grid-cols-3">
          {EXECUTION_CLAIMS.map(c => {
            const declared = claims.includes(c.id), implied = c.id !== 'admin' && adminDeclared, selected = declared || implied
            const status = declared ? implied ? 'Declared · also implied by admin' : 'Declared' : implied ? 'Implied by admin' : 'Not declared'
            return <label key={c.id} className={permissionClaimClasses(selected, !!onClaims && !implied, implied)} data-state={selected ? 'selected' : 'unselected'}>
              <input className="sr-only" type="checkbox" aria-label={c.name} aria-describedby={`${id}-${c.id}`} checked={selected} disabled={!onClaims || implied} onChange={() => onClaims?.(toggle(claims, c.id))} />
              <PermissionCheck checked={selected} size="claim" />
              <span>
                <span className="block text-sm font-semibold text-neutral-900">{c.name}</span>
                <span className="block text-[11px] text-neutral-500 leading-tight mt-0.5">{c.description}</span>
                <span id={`${id}-${c.id}`} className={`block text-[11px] mt-2 font-medium ${selected ? 'text-primary-700' : 'text-neutral-500'}`}>{status}</span>
              </span>
            </label>
          })}
        </div>
        {!!customClaims.length && <div className="space-y-2"><p className="text-xs text-neutral-500">Imported additional claims — preserved for Go validation.</p><div className="flex flex-wrap gap-2">{customClaims.map(c => onClaims ? <Button key={c} type="button" size="sm" variant="outline" className="border-primary-200 bg-primary-50 text-primary" onClick={() => onClaims(claims.filter(v => v !== c))}>Remove claim {c}</Button> : <Badge key={c} variant="outline" className="border-primary-200 bg-primary-50 text-primary">{c}</Badge>)}</div></div>}
      </>}
    </fieldset>
    <fieldset className="space-y-4">
      <legend className="text-sm font-medium text-neutral-700">RPC methods · <span className="text-xs px-2 py-0.5 rounded-full bg-primary-50 text-primary">{methods.length} selected</span> · {NATIVE_METHODS.length} available choices</legend>
      {NATIVE_METHOD_SECTIONS.map(s => {
        const selected = s.methods.filter(m => methods.includes(m)).length
        return <details key={s.name} open className="rounded-lg border border-neutral-200">
          <summary className="p-3 text-sm font-medium text-neutral-700 cursor-pointer focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary/40 rounded-lg">
            <span className="inline-flex items-center gap-2"><span>{s.name}</span><PermissionCount selected={selected} total={s.methods.length} label={`${s.name}: ${selected} of ${s.methods.length} selected`} /></span>
          </summary>
          <div className="px-3 pb-2"><p className="text-xs text-neutral-500">{s.description}</p></div>
          {onMethods && <div className="flex items-center gap-2 px-3 pb-3">
            <button type="button" aria-label={`Select all ${s.name.toLowerCase()}`} className="text-xs text-primary hover:text-primary-600 font-medium focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary/40 rounded" onClick={() => onMethods([...new Set([...methods, ...s.methods])])}>Select All</button>
            <span className="text-neutral-200">|</span>
            <button type="button" aria-label={`Clear ${s.name.toLowerCase()}`} className="text-xs text-neutral-500 hover:text-neutral-700 font-medium focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary/40 rounded" onClick={() => onMethods(methods.filter(m => !(s.methods as readonly string[]).includes(m)))}>Clear</button>
          </div>}
          <div className="grid gap-1.5 p-3 border-t border-neutral-200 sm:grid-cols-2">
            {s.methods.map(m => <label key={m} className={permissionMethodClasses(!!onMethods)}>
              <input className="sr-only" type="checkbox" aria-label={m} checked={methods.includes(m)} disabled={!onMethods} onChange={() => onMethods?.(toggle(methods, m))} />
              <PermissionCheck checked={methods.includes(m)} />
              <span className="text-xs font-mono text-neutral-700 truncate" title={m}>{m}</span>
            </label>)}
          </div>
        </details>
      })}
      {!!unknown.length && <div className="rounded-lg border border-warning-light p-3 space-y-2"><h4 className="text-sm font-medium">Imported additional methods · {unknown.length}</h4><p className="text-xs text-neutral-500">These names are outside the native guided choices. They remain unchanged until explicitly removed; the matching Go tool and runtime decide support. Guided controls never expand or add wildcards.</p><div className="flex flex-wrap gap-2">{unknown.map(m => onMethods ? <Button key={m} type="button" size="sm" variant="outline" className="border-primary-200 bg-primary-50 text-primary" onClick={() => onMethods(methods.filter(v => v !== m))}>Remove method {m}</Button> : <Badge key={m} variant="outline" className="border-primary-200 bg-primary-50 text-primary">{m}</Badge>)}</div></div>}
    </fieldset>
  </div>
}
