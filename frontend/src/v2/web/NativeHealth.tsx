import { useEffect, useState } from 'react'
import { StatusCard } from '../../components/dashboard/StatusCard'
import { Button } from '../../components/ui/button'
import type { OperationScope } from './controller'
import { useLiveOrganizationScope } from './useLiveOrganizationScope'
import { useOperationContext } from './useOperationContext'
import { Panel, SelectField, TaskError, useNativeTask } from './operationsUI'
import { record } from './operationsModels'

interface Observation { state: string; sampledAt?: string; latencyMs?: number }
interface Health { organizationId: string; build: { version: string; commit: string; builtAt: string }; process: 'running'; observedAt: string; readiness: Observation; node: Observation }
const exact = (value: unknown, allowed: string[], required = allowed) => { const out = record(value); if (Object.keys(out).some(key => !allowed.includes(key)) || required.some(key => !(key in out))) throw Error('Invalid diagnostics response.'); return out }
const timestamp = (value: unknown): value is string => typeof value === 'string' && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$/.test(value) && Number.isFinite(Date.parse(value))
function observation(value: unknown, node: boolean, at: number): Observation {
  const out = exact(value, ['state', 'sampledAt', 'latencyMs'], ['state'])
  if (!['unknown', 'unavailable', node ? 'connected' : 'ready'].includes(String(out.state))) throw Error('Invalid diagnostics state.')
  if (out.state === 'unknown') { if ('sampledAt' in out || 'latencyMs' in out) throw Error('Unknown status cannot claim a sample.'); return { state: 'unknown' } }
  if (!timestamp(out.sampledAt) || Date.parse(out.sampledAt) > at || at - Date.parse(out.sampledAt) > 1000 || out.latencyMs !== undefined && (!node || !Number.isSafeInteger(out.latencyMs) || Number(out.latencyMs) < 0 || Number(out.latencyMs) > 3000)) throw Error('Invalid diagnostics observation.')
  return out as unknown as Observation
}
export function parseHealth(value: unknown, org: string): Health {
  const out = exact(value, ['organizationId', 'build', 'process', 'observedAt', 'readiness', 'node']), build = exact(out.build, ['version', 'commit', 'builtAt'])
  if (out.organizationId !== org || out.process !== 'running' || !timestamp(out.observedAt) || typeof build.version !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$/.test(build.version) || typeof build.commit !== 'string' || !/^(?:[0-9a-f]{7,64}|none|unknown)$/.test(build.commit) || build.builtAt !== 'unknown' && !timestamp(build.builtAt)) throw Error('Invalid diagnostics identity.')
  return { organizationId: org, build: build as unknown as Health['build'], process: 'running', observedAt: out.observedAt, readiness: observation(out.readiness, false, Date.parse(out.observedAt)), node: observation(out.node, true, Date.parse(out.observedAt)) }
}
export function NativeHealth({ scope }: { scope: OperationScope }) {
  const orgs = scope.self.organizations.filter(value => value.isOrgAdmin || value.isOrgReadonlyAdmin)
  const [org, setOrg] = useLiveOrganizationScope(orgs)
  return <><div><h2 className="text-2xl font-semibold">Diagnostics</h2><p className="mt-1 text-sm text-neutral-500">OPS build, operational readiness and a separate sample of your organization’s configured node checks</p></div>
    <div className="max-w-md"><SelectField label="Health organization" value={org} onChange={setOrg} disabled={orgs.length === 1 && !!org} options={[{ value: '', label: 'Select an organization' }, ...orgs.map(value => ({ value: value.id, label: value.name }))]} /></div>
    {org ? <HealthContext key={`${scope.identity.actor}:${scope.identity.expires}:${org}`} scope={scope} org={org} /> : <p className="text-sm text-neutral-500">Select a verified administrative organization to inspect its node health.</p>}</>
}
function HealthContext({ scope: parent, org }: { scope: OperationScope; org: string }) {
  const scope = useOperationContext(parent)
  return scope ? <HealthSample scope={scope} org={org} /> : <p role="status">Preparing the selected health view…</p>
}
function HealthSample({ scope, org }: { scope: OperationScope; org: string }) {
  const task = useNativeTask(scope), [health, setHealth] = useState<Health>(), [now, setNow] = useState(Date.now()), [ended, setEnded] = useState(false)
  const requireScope = () => { scope.check(); if (scope.signal.aborted || scope.identity.expires * 1000 <= Date.now()) throw Error('The original session expired. Renew your session before reading diagnostics.') }
  const load = async () => { requireScope(); const result = parseHealth(await scope.request(`/api/v2/orgs/${org}/diagnostics`), org); requireScope(); setHealth(result); setNow(Date.now()) }
  useEffect(() => {
    let stopped = false
    const poll = () => { if (!stopped && !document.hidden && !scope.signal.aborted && scope.identity.expires * 1000 > Date.now()) void task.run(load) }
    const timer = setInterval(poll, 5000), age = setInterval(() => setNow(Date.now()), 1000)
    const stop = () => { if (stopped) return; stopped = true; clearInterval(timer); clearInterval(age); clearTimeout(expiry); setEnded(true); setHealth(undefined); scope.dispose() }
    const expiry = setTimeout(stop, Math.max(0, scope.identity.expires * 1000 - Date.now()))
    document.addEventListener('visibilitychange', poll); scope.signal.addEventListener('abort', stop, { once: true })
    if (scope.signal.aborted || scope.identity.expires * 1000 <= Date.now()) stop()
    else poll()
    return () => { stopped = true; clearInterval(timer); clearInterval(age); clearTimeout(expiry); document.removeEventListener('visibilitychange', poll); scope.signal.removeEventListener('abort', stop) }
  }, [])
  const state = (value: Observation | undefined, ready = false) => !value ? task.busy ? 'Checking' : 'Unknown' : value.state === 'unknown' ? 'Unknown' : value.state === 'unavailable' ? 'Unavailable' : ready ? 'Ready' : 'Connected'
  const age = (value: Observation | undefined) => value?.sampledAt ? `Sampled ${Math.max(0, Math.floor((now - Date.parse(value.sampledAt)) / 1000))}s ago (${new Date(value.sampledAt).toLocaleString()}).` : 'No completed sample is available.'
  return <div className="space-y-4"><div className="flex justify-end"><Button variant="outline" disabled={task.busy || ended} onClick={() => void task.run(load)}>Refresh health</Button></div><TaskError message={task.error} />
    {ended && <p role="status" className="text-sm text-neutral-500">The original session ended. Renew your session before reading diagnostics.</p>}
    <div className="grid gap-4 md:grid-cols-3"><StatusCard title="OPS process" status={health ? 'Running' : task.busy ? 'Checking' : 'Unknown'} /><StatusCard title="Operational readiness (sampled)" status={state(health?.readiness, true)} /><StatusCard title="Blockchain node (sampled)" status={state(health?.node)} latency={health?.node.latencyMs} /></div>
    <div className="grid gap-3 text-xs text-neutral-500 md:grid-cols-2"><p>Operational readiness: {age(health?.readiness)}</p><p>Organization node: {age(health?.node)} Latency is the maximum measured check time across this organization’s configured bindings.</p></div>
    <p className="text-xs text-neutral-500">Readiness and node checks are separate observations, not authorization or a guarantee of current availability. Samples refresh every 5 seconds while this page is visible. Endpoints, credentials and raw node errors are not exposed.</p>
    <Panel title="OPS build"><dl className="grid gap-4 text-sm sm:grid-cols-3">{[['Version', health?.build.version], ['Commit', health?.build.commit], ['Built at', health?.build.builtAt]].map(([label, value]) => <div key={label}><dt className="text-xs text-neutral-500">{label}</dt><dd className="mt-1 break-all font-mono">{value ?? (task.busy ? 'Checking…' : 'Unavailable')}</dd></div>)}</dl></Panel>
  </div>
}
