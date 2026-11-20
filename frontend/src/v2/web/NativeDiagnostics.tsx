import { useEffect, useRef, useState } from 'react'
import { Link } from 'react-router-dom'
import { Button } from '../../components/ui/button'
import type { OperationScope } from './controller'
import { record, type ObjectValue } from './operationsModels'
import { useApprovedTokens } from './approvedTokens'
import { ExactAmount, TokenChoice, useExactAmountState } from './ExactTokenAmount'
import { diagnosticRequest, diagnosticResult, diagnosticTemplates, type DiagnosticTemplate } from './diagnosticTemplates'
import { Field, Panel, SelectField, TaskError, useNativeTask } from './operationsUI'
import { NativeHealth } from './NativeHealth'

export function NativeDiagnostics({ scope }: { scope: OperationScope }) {
  const task = useNativeTask(scope),
    [org, setOrg] = useState(
      scope.self.organizations.length === 1 ? scope.self.organizations[0].id : '',
    ),
    [method, setMethod] = useState('eth_chainId'),
    [params, setParams] = useState('[]'),
    [result, setResult] = useState<{ scope: OperationScope; key: string; value: ObjectValue; decoded?: string }>(),
    [mode, setMode] = useState('guided'),
    [template, setTemplate] = useState<DiagnosticTemplate>('balanceOf'),
    [token, setToken] = useState(''), [owner, setOwner] = useState(''), [spender, setSpender] = useState(''), [recipient, setRecipient] = useState('')
  const catalog = useApprovedTokens(scope, org), selectedToken = catalog.tokens.find(t => t.address === token)
  const amountState = useExactAmountState(`${org}:${token}:${selectedToken?.decimals ?? 'unknown'}`, selectedToken?.decimals), { amount, mode: amountMode, setAmount, setMode: setAmountMode } = amountState
  const requestKey = JSON.stringify([org, mode, method, params, template, token, owner, spender, recipient, amount, amountMode, selectedToken?.decimals]), latest = useRef(requestKey), latestScope = useRef(scope), live = useRef(true)
  latest.current = requestKey; latestScope.current = scope
  useEffect(() => { live.current = true; return () => { live.current = false } }, [])
  return (
    <section className="space-y-6">
      <NativeHealth scope={scope} />
      <TaskError message={task.error} />
      <Panel title="Test request">
        <p className="mb-4 text-sm text-neutral-500">For a signed transaction, <Link to="/admin/account" className="font-medium text-primary hover:underline">set up your wallet and RPC connection</Link>. This tester checks reads and estimates with your own verified identity.</p>
        <form
          className="space-y-4"
          onSubmit={(e) => {
            e.preventDefault()
            void task.run(async () => {
              setResult(undefined)
              if (!scope.self.organizations.some(o => o.id === org)) throw Error('Select a verified organization.')
              const key = requestKey
              let request: { method: string; params: unknown[] }
              if (mode === 'guided') request = diagnosticRequest({ template, token, owner, spender, recipient, amount, mode: amountMode, decimals: selectedToken?.decimals })
              else {
                const parsed: unknown = JSON.parse(params)
                if (!Array.isArray(parsed)) throw Error('Parameters must be a JSON array.')
                request = { method, params: parsed }
              }
              const value = record(
                await scope.request('/rpc/' + org, {
                  method: 'POST',
                  body: JSON.stringify({
                    jsonrpc: '2.0',
                    id: crypto.randomUUID(),
                    ...request,
                  }),
                }),
              )
              scope.check()
              let decoded: string | undefined
              if (mode === 'guided' && !value.error) { try { decoded = diagnosticResult(template, value.result) } catch (e) { decoded = 'Unable to decode response: ' + (e as Error).message } }
              if (live.current && latest.current === key && latestScope.current === scope) setResult({ scope, key, value, decoded })
            })
          }}
        >
          <SelectField
            label="Organization"
            value={org}
            disabled={task.busy}
            onChange={(value) => {
              setOrg(value)
              setResult(undefined)
            }}
            options={[
              { value: '', label: 'Select an organization' },
              ...scope.self.organizations.map((o) => ({ value: o.id, label: o.name })),
            ]}
          />
          <SelectField label="Request mode" value={mode} onChange={setMode} disabled={task.busy} options={[{ value: 'guided', label: 'Guided ERC-20 request' }, { value: 'advanced', label: 'Advanced JSON request' }]} />
          {mode === 'guided' ? <div className="space-y-4">
            <SelectField label="ERC-20 template" value={template} onChange={value => setTemplate(value as DiagnosticTemplate)} disabled={task.busy} options={diagnosticTemplates.map(value => ({ value, label: value }))} />
            <TokenChoice tokens={catalog.tokens} token={token} onChange={setToken} disabled={task.busy} />
            {catalog.error && <p className="text-xs text-neutral-500">{catalog.error}</p>}
            {(template === 'balanceOf' || template === 'allowance' || template.startsWith('estimate ')) && <Field label="Owner / account" value={owner} onChange={setOwner} disabled={task.busy} required hint="Owner/account is an explicit calldata argument; transfer/approve estimates also use it as from. TransferFrom estimates use the spender as from. These inputs grant no identity authority." />}
            {(template === 'allowance' || template === 'estimate approve' || template === 'estimate transferFrom') && <Field label="Spender" value={spender} onChange={setSpender} disabled={task.busy} required />}
            {(template === 'estimate transfer' || template === 'estimate transferFrom') && <Field label="Recipient" value={recipient} onChange={setRecipient} disabled={task.busy} required />}
            {template.startsWith('estimate ') && <ExactAmount amount={amount} mode={amountMode} decimals={selectedToken?.decimals} unit={selectedToken?.symbol ?? 'Token base units'} onAmount={setAmount} onMode={setAmountMode} notice={amountState.notice} disabled={task.busy} />}
            <p className="text-xs text-neutral-500">Calldata is encoded locally. Reads and estimates use your current verified identity and selected organization; an estimate never submits a transaction.</p>
          </div> : <>
          <SelectField
            label="RPC method"
            value={method}
            disabled={task.busy}
            onChange={(value) => {
              setMethod(value)
              setResult(undefined)
            }}
            options={[
              'eth_chainId',
              'net_version',
              'eth_syncing',
              'eth_blockNumber',
              'eth_getBalance',
              'web3_clientVersion',
              'eth_call',
              'eth_estimateGas',
              'eth_getTransactionReceipt',
            ].map((value) => ({ value, label: value }))}
          />
          <Field
            label="JSON parameters"
            multiline
            value={params}
            disabled={task.busy}
            onChange={(value) => {
              setParams(value)
              setResult(undefined)
            }}
            required
            hint="The request uses your own identity and the selected organization. Permissions still apply."
          />
          </>}
          <Button type="submit" disabled={task.busy || !org}>
            {task.busy ? 'Checking…' : 'Send test request'}
          </Button>
        </form>
        {result?.scope === scope && result.key === requestKey && (
          <div className="mt-4 rounded-lg border border-neutral-200 bg-neutral-50 p-4">
            <p className="mb-2 text-sm font-medium">{result.value.error ? 'RPC error / denial' : 'RPC response'}</p>
            {result.decoded && <p className="mb-3 break-all text-sm">{template}: {result.decoded}</p>}
            <pre className="max-h-72 overflow-auto whitespace-pre-wrap break-all font-mono text-xs">
              {JSON.stringify(result.value, null, 2)}
            </pre>
          </div>
        )}
      </Panel>
    </section>
  )
}
