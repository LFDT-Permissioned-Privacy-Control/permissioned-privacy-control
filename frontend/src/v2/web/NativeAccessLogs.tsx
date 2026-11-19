import { useEffect, useRef, useState, type FormEvent } from 'react'
import { useLocation } from 'react-router-dom'
import { Loader2, RefreshCw, ScrollText } from 'lucide-react'
import { Badge } from '../../components/ui/badge'
import { Button } from '../../components/ui/button'
import { Input } from '../../components/ui/input'
import { CopyValue } from '../../components/auth/AccountPresentation'
import type { OperationScope } from './controller'
import { accessLogOutcomes, accessLogPage, accessLogsEndpoint, logTime, outcomeLabels, sameLogSource, type AccessLogPage, type AccessLogQuery, type AccessLogSource } from './accessLogsModels'
import { DataTable, Field, Panel, SelectField, TaskError } from './operationsUI'
import type { ObjectValue } from './operationsModels'
import { logReasonLabel, type AccessLogReason } from './accessLogReasons'

interface Filters { actorId: string; method: string; outcome: string; requestReference: string; from: string; to: string }
const pageSize = 50
const historySize = 10
interface VisitedPage { number: number; cursor: string; query: string; scope: OperationScope; expires: number; result: AccessLogPage }
function defaultFilters(): Filters {
  const now = Date.now()
  return { actorId: '', method: '', outcome: '', requestReference: '', from: new Date(now - 86400000).toISOString().slice(0, 19), to: new Date(now).toISOString().slice(0, 19) }
}
function queryOf(filters: Filters): AccessLogQuery {
  const wireTime = (value: string) => value + (/T\d{2}:\d{2}$/.test(value) ? ':00Z' : 'Z')
  const from = wireTime(filters.from), to = wireTime(filters.to)
  if (logTime(from) >= logTime(to)) throw Error('From must be earlier than To. The end time is excluded.')
  return { from, to, limit: pageSize, ...Object.fromEntries(['actorId', 'method', 'outcome', 'requestReference'].filter(key => filters[key as keyof Filters].trim()).map(key => [key, filters[key as keyof Filters].trim()])) }
}
const utc = (value: string) => value.replace('T', ' ').replace(/Z$/, ' UTC')

function LogIdentifier({ value, label }: { value: string; label: string }) {
  return <div className="flex w-56 min-w-56 items-center gap-1"><code className="min-w-0 flex-1 truncate whitespace-nowrap text-xs" title={value}>{value}</code><CopyValue value={value} label={label} /></div>
}

export function NativeAccessLogs({ scope }: { scope: OperationScope }) {
  const location = useLocation(), orgs = scope.self.organizations.filter(org => org.isOrgAdmin || org.isOrgReadonlyAdmin)
  const selected = new URLSearchParams(location.search).get('org')
  const [chosen, setChosen] = useState(orgs.find(org => org.id === selected)?.id ?? (orgs.length === 1 ? orgs[0].id : ''))
  const org = orgs.some(org => org.id === chosen) ? chosen : ''
  const owner = `${scope.self.actorId}:${scope.self.expiresAt}:${scope.self.sourceProfileDigest}:${org}`
  return <section className="space-y-6">
    <div className="flex items-center gap-3"><div className="flex h-10 w-10 items-center justify-center rounded-lg bg-primary-50"><ScrollText className="h-5 w-5 text-primary" /></div><div><h2 className="text-2xl font-semibold">Access Logs</h2><p className="mt-1 text-sm text-neutral-500">Investigate your organization’s recorded requests</p></div></div>
    {!orgs.length ? <p className="py-8 text-neutral-500">Your identity has no organization access-log administration role.</p> : <>
      <div className="max-w-md"><SelectField label="Organization" value={org} onChange={setChosen} disabled={orgs.length === 1} options={[{ value: '', label: 'Select an organization' }, ...orgs.map(value => ({ value: value.id, label: value.name }))]} /></div>
      {org && <AccessLogSearch key={owner} scope={scope} org={org} />}
    </>}
  </section>
}
function AccessLogSearch({ scope, org }: { scope: OperationScope; org: string }) {
  const [filters, setFilters] = useState(defaultFilters), [result, setResult] = useState<AccessLogPage | null>(null), [active, setActive] = useState<AccessLogQuery | null>(null)
  const [busy, setBusy] = useState(false), [error, setError] = useState<string | null>(null), [page, setPage] = useState(1)
  const owner = useRef({ live: true, serial: 0 }), seenCursors = useRef(new Set<string>()), history = useRef<VisitedPage[]>([])
  function clear() { owner.current.serial++; setResult(null); setActive(null); setPage(1); setError(null); setBusy(false); seenCursors.current.clear(); history.current = [] }
  function requireScope() {
    scope.check()
    if (!owner.current.live || scope.signal.aborted || scope.identity.expires * 1000 <= Date.now()) throw Error('The original session is no longer current. Sign in again before reading access logs.')
  }
  function edit(key: keyof Filters, value: string) { clear(); setFilters(previous => ({ ...previous, [key]: value })) }
  async function load(query: AccessLogQuery, cursor = '', number = 1, pinned?: AccessLogSource) {
    const serial = ++owner.current.serial
    const current = () => owner.current.live && serial === owner.current.serial && !scope.signal.aborted
    setResult(null); setError(null); setBusy(true)
    try {
      requireScope()
      const value = await scope.request(accessLogsEndpoint(org, query, cursor))
      if (!current()) return
      requireScope()
      const next = accessLogPage(value, org, query, pinned)
      if (next.next && (next.next === cursor || seenCursors.current.has(next.next))) throw Error('The access-log continuation repeated. Search again for a fresh snapshot.')
      if (!current()) return
      if (cursor) {
        seenCursors.current.add(cursor)
        if (seenCursors.current.size > 16) seenCursors.current.delete(seenCursors.current.values().next().value!)
      }
      history.current.push({ number, cursor, query: accessLogsEndpoint(org, query), scope, expires: scope.identity.expires, result: next })
      if (history.current.length > historySize) history.current.shift()
      setResult(next); setActive(query); setPage(number)
    } catch (failure) {
      if (!current()) return
      clear()
      try { requireScope(); setError(failure instanceof Error ? failure.message : 'Access logs could not be read.') }
      catch { setError('The original session is no longer current. Sign in again before reading access logs.') }
    } finally { if (current()) setBusy(false) }
  }
  function visit(number: number) {
    const saved = history.current.find(value => value.number === number)
    if (!saved || !result || !active || busy) return
    try {
      requireScope()
      if (saved.scope !== scope || saved.expires !== scope.identity.expires || saved.query !== accessLogsEndpoint(org, active) || !sameLogSource(saved.result.source, result.source)) throw Error('The cached page no longer matches this investigation. Search again for a fresh snapshot.')
      requireScope()
      owner.current.serial++
      setResult(saved.result); setPage(saved.number); setError(null)
    } catch (failure) {
      clear()
      try { requireScope(); setError(failure instanceof Error && failure.message ? failure.message : 'The original investigation is no longer current.') }
      catch { setError('The original session is no longer current. Sign in again before reading access logs.') }
    }
  }
  function nextPage() {
    if (!active || !result?.next) return
    const saved = history.current.find(value => value.number === page + 1)
    if (saved) {
      if (saved.cursor !== result.next) { clear(); setError('The cached continuation changed. Search again for a fresh snapshot.'); return }
      visit(page + 1)
    } else void load(active, result.next, page + 1, result.source)
  }
  function search(value = filters) {
    clear()
    try { void load(queryOf(value)) } catch (failure) { setError(failure instanceof Error ? failure.message : 'Check the filter fields.') }
  }
  useEffect(() => {
    owner.current.live = true
    const abort = () => { clear(); setError('The original session is no longer current. Sign in again before reading access logs.') }
    scope.signal.addEventListener('abort', abort, { once: true })
    const expiry = setTimeout(abort, Math.max(0, scope.identity.expires * 1000 - Date.now()))
    if (scope.signal.aborted) abort()
    else search()
    return () => { owner.current.live = false; owner.current.serial++; history.current = []; clearTimeout(expiry); scope.signal.removeEventListener('abort', abort) }
  }, [scope])
  function apply(event: FormEvent) { event.preventDefault(); search() }
  return <div className="space-y-4">
    <Panel title="Recorded requests" actions={<Button variant="outline" size="sm" disabled={busy} onClick={() => search()}><RefreshCw className="mr-2 h-4 w-4" />Refresh results</Button>}>
      <form onSubmit={apply} aria-label="Access log filters" className="mb-5 grid grid-cols-1 gap-3 md:grid-cols-2 xl:grid-cols-3">
        <Field label="OPS actor ID" value={filters.actorId} onChange={value => edit('actorId', value)} hint="Exact OPS actor ID; leave blank for all actors in this organization." />
        <Field label="Method" value={filters.method} onChange={value => edit('method', value)} hint="Exact recorded method, such as eth_call or explorer.transactions." />
        <SelectField label="Outcome" value={filters.outcome} onChange={value => edit('outcome', value)} options={[{ value: '', label: 'All outcomes' }, ...accessLogOutcomes.map(value => ({ value, label: outcomeLabels[value] }))]} />
        <Field label="Request reference" value={filters.requestReference} onChange={value => edit('requestReference', value)} hint="The recorded request UUID, not a user-supplied correlation label." />
        {(['from', 'to'] as const).map(key => <label key={key} className="block space-y-1 text-sm font-medium text-neutral-700">{key === 'from' ? 'From (UTC)' : 'To (UTC, excluded)'}<Input aria-label={key === 'from' ? 'From (UTC)' : 'To (UTC, excluded)'} type="datetime-local" step="1" required value={filters[key]} onChange={event => edit(key, event.target.value)} /></label>)}
        <div className="flex flex-wrap items-center gap-2 md:col-span-2 xl:col-span-3"><Button type="submit" disabled={busy}><Loader2 className={busy ? 'mr-2 h-4 w-4 animate-spin' : 'hidden'} />Search</Button><Button type="button" variant="outline" onClick={() => { const value = defaultFilters(); setFilters(value); search(value) }}>Last 24 hours / reset filters</Button><p className="text-xs text-neutral-500">All filters run on the server. Times use UTC; From is included and To is excluded.</p></div>
      </form>
      <TaskError message={error} />
      {busy && <p role="status" className="py-8 text-center text-sm text-neutral-500">Loading recorded requests…</p>}
      {!busy && !error && !result && <p className="py-8 text-center text-sm text-neutral-500">Search to load records for the selected filters.</p>}
      {result && <>
        <div className="mb-4 space-y-2 rounded-lg border border-warning/30 bg-warning-light p-3 text-xs text-neutral-700" role="note"><p className="font-medium">Sealed records only — this is not a complete live traffic history.</p><p>Requests not yet sealed, outside this source, or without this organization’s recorded attribution are not included.</p><p>Source as of <time dateTime={result.source.sourceAsOf}>{utc(result.source.sourceAsOf)}</time>. Retained from <time dateTime={result.source.retainedFrom}>{utc(result.source.retainedFrom)}</time>.</p>{active && logTime(active.to) > logTime(result.source.sourceAsOf) && <p>The selected time window extends beyond this source snapshot. Newer requests may be missing.</p>}</div>
        <DataTable items={result.items as unknown as ObjectValue[]} empty="No sealed records match these filters in this organization." columns={[
          { key: 'observedAt', label: 'Observed (UTC)', render: row => <time dateTime={String(row.observedAt)} className="whitespace-nowrap text-xs">{utc(String(row.observedAt))}</time> },
          { key: 'method', label: 'Method', render: row => <code className="whitespace-nowrap text-xs">{String(row.method)}</code> },
          { key: 'actorId', label: 'OPS actor ID', render: row => row.actorId ? <LogIdentifier value={String(row.actorId)} label="Copy actor ID" /> : 'Not recorded' },
          { key: 'requestReference', label: 'Request reference', render: row => <LogIdentifier value={String(row.requestReference)} label="Copy request reference" /> },
          { key: 'outcome', label: 'Recorded outcome', render: row => <Badge variant={row.outcome === 'success' ? 'success' : row.outcome === 'denied' ? 'warning' : 'destructive'}>{outcomeLabels[row.outcome as keyof typeof outcomeLabels]}</Badge> },
          { key: 'httpStatus', label: 'Recorded HTTP', render: row => String(row.httpStatus) },
          { key: 'rpcErrorCode', label: 'RPC error', render: row => row.rpcErrorCode === null ? 'None recorded' : String(row.rpcErrorCode) },
          { key: 'recordedStatus', label: 'Recorded status', render: row => String(row.recordedStatus) },
          { key: 'trustedIP', label: 'Recorded IP', render: row => row.trustedIP === null ? 'Not recorded' : String(row.trustedIP) },
          { key: 'reason', label: 'Reason', render: row => <span title={String(row.reason)}>{logReasonLabel(row.reason as AccessLogReason)}</span> },
          { key: 'policyDigest', label: 'Policy details', render: row => <details className="text-xs"><summary className="cursor-pointer text-primary">Digests</summary><p className="mt-2">Policy: <code className="break-all">{row.policyDigest === null ? 'Not recorded' : String(row.policyDigest)}</code></p><p className="mt-2">Recorded configuration: <code className="break-all">{String(row.configurationDigest)}</code></p></details> },
        ]} />
        <p className="mt-3 text-xs text-neutral-500">Recorded status summarizes the outcome; Recorded HTTP is the selected response status. Final delivery may still fail or change. Older or unclassified operations show Not recorded for their reason. IP identifies the recorded direct peer.</p>
        <div className="mt-4 flex flex-wrap items-center justify-between gap-3"><p className="text-xs text-neutral-500">Page {page} · {result.items.length} records on this page{result.next ? ' · More records available' : ' · End of this snapshot'}</p><div className="flex gap-2"><Button variant="outline" disabled={busy || !history.current.some(value => value.number === page - 1)} onClick={() => visit(page - 1)}>Previous page</Button>{result.next && active && <Button variant="outline" disabled={busy} onClick={nextPage}>Next page</Button>}</div></div>
        {history.current[0]?.number > 1 && <p className="mt-3 text-xs text-neutral-500">Up to {historySize} visited pages are kept in this tab. Pages before {history.current[0].number} are no longer available here. Search starts a new snapshot.</p>}
        <details className="mt-4 text-xs text-neutral-500"><summary className="cursor-pointer">Recorded source details</summary><dl className="mt-2 space-y-2 break-all">{Object.entries(result.source).map(([key, value]) => <div key={key}><dt className="font-medium">{key}</dt><dd><code>{value}</code></dd></div>)}</dl></details>
      </>}
    </Panel>
  </div>
}
