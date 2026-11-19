import { useEffect, useState } from 'react'
import { StatusCard } from '../../components/dashboard/StatusCard'
import { Button } from '../../components/ui/button'
import type { OperationScope } from './controller'
import { record, type ObjectValue } from './operationsModels'
import { Field, Panel, SelectField, TaskError, useNativeTask } from './operationsUI'

export function NativeDiagnostics({ scope }: { scope: OperationScope }) {
  const task = useNativeTask(scope),
    [health, setHealth] = useState<{ live: boolean; ready: boolean }>(),
    [org, setOrg] = useState(
      scope.self.organizations.length === 1 ? scope.self.organizations[0].id : '',
    ),
    [method, setMethod] = useState('eth_chainId'),
    [params, setParams] = useState('[]'),
    [result, setResult] = useState<ObjectValue>()
  const load = async () => {
    const live = record(await scope.request('/health/live')),
      ready = record(await scope.request('/health/ready'))
    scope.check()
    setHealth({ live: live.ready === true, ready: ready.ready === true })
  }
  useEffect(() => {
    void task.run(load)
  }, [])
  return (
    <section className="space-y-6">
      <div className="flex items-start justify-between gap-3">
        <div>
          <h2 className="text-2xl font-semibold">Diagnostics</h2>
          <p className="mt-1 text-sm text-neutral-500">
            Current OPS health and requests under your verified permissions
          </p>
        </div>
        <Button variant="outline" disabled={task.busy} onClick={() => void task.run(load)}>
          Refresh
        </Button>
      </div>
      <TaskError message={task.error} />
      <div className="grid gap-4 md:grid-cols-2">
        <StatusCard
          title="OPS process"
          status={!health ? 'Checking' : health.live ? 'Running' : 'Error'}
        />
        <StatusCard
          title="Operational readiness"
          status={!health ? 'Checking' : health.ready ? 'Connected' : 'Error'}
        />
      </div>
      <p className="text-xs text-neutral-500">
        Readiness covers configured operational dependencies. Explorer and disclosure reads check
        Indexer availability separately. No internal endpoints, credentials or cache statistics are
        exposed here.
      </p>
      <Panel title="Test request">
        <form
          className="space-y-4"
          onSubmit={(e) => {
            e.preventDefault()
            void task.run(async () => {
              setResult(undefined)
              const parsed: unknown = JSON.parse(params)
              if (!Array.isArray(parsed)) throw Error('Parameters must be a JSON array.')
              const value = record(
                await scope.request('/rpc/' + org, {
                  method: 'POST',
                  body: JSON.stringify({
                    jsonrpc: '2.0',
                    id: crypto.randomUUID(),
                    method,
                    params: parsed,
                  }),
                }),
              )
              scope.check()
              setResult(value)
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
              'eth_call',
              'eth_estimateGas',
              'eth_getTransactionReceipt',
            ].map((value) => ({ value, label: value }))}
          />
          <Field
            label="JSON parameters"
            value={params}
            disabled={task.busy}
            onChange={(value) => {
              setParams(value)
              setResult(undefined)
            }}
            required
            hint="The request uses your own identity and the selected organization. Permissions still apply."
          />
          <Button type="submit" disabled={task.busy || !org}>
            {task.busy ? 'Checking…' : 'Send test request'}
          </Button>
        </form>
        {result && (
          <div className="mt-4 rounded-lg border border-neutral-200 bg-neutral-50 p-4">
            <p className="mb-2 text-sm font-medium">RPC response</p>
            <pre className="max-h-72 overflow-auto whitespace-pre-wrap break-all font-mono text-xs">
              {JSON.stringify(result, null, 2)}
            </pre>
          </div>
        )}
      </Panel>
    </section>
  )
}
