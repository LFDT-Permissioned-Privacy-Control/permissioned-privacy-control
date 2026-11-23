import { useEffect, useRef, useState } from 'react'
import { Link } from 'react-router-dom'
import { useLiveOrganizationScope } from './useLiveOrganizationScope'
import { useOperationContext } from './useOperationContext'
import { CopyValue } from '../../components/auth/AccountPresentation'
import { Badge } from '../../components/ui/badge'
import { Button } from '../../components/ui/button'
import { Dialog, DialogContent, DialogHeader, DialogTitle } from '../../components/ui/dialog'
import { ConfirmDialog } from '../../components/ui/ConfirmDialog'
import type { OperationScope } from './controller'
import { ComplianceEventDetails, TravelRecordDetails } from './ComplianceDetails'
import { useApprovedTokens } from './approvedTokens'
import { ExactAmount, TokenChoice, amountInBaseUnits, useExactAmountState } from './ExactTokenAmount'
import {
  actorID,
  address,
  instant,
  optionalText,
  quantity,
  record,
  rows,
  text,
  type ObjectValue,
} from './operationsModels'
import {
  DataTable,
  Field,
  Panel,
  SelectField,
  TaskError,
  useNativeTask,
} from './operationsUI'

const tabs = [
  ['config', 'Settings'],
  ['tokens', 'Token prices'],
  ['travel-rule-records', 'Travel rules'],
  ['address-thresholds', 'Address thresholds'],
  ['sanctions', 'Sanctions'],
  ['quotes', 'Observed quotes'],
  ['events', 'Compliance logs'],
  ['preview', 'Preview'],
] as const
export function NativeCompliance({ scope }: { scope: OperationScope }) {
  const orgs = scope.self.organizations.filter((o) => o.isOrgAdmin || o.isOrgReadonlyAdmin)
  const [org, setOrg] = useLiveOrganizationScope(orgs), [tab, setTab] = useState('config')
  return (
    <section className="space-y-6">
      <div>
        <h2 className="text-2xl font-semibold">Compliance</h2>
        <p className="mt-1 text-sm text-neutral-500">
          Approved rules, observed prices and operational travel-rule records
        </p>
      </div>
      {!orgs.length ? (
        <p className="py-8 text-neutral-500">
          Your identity has no organization compliance administration role.
        </p>
      ) : (
        <>
          <div className="max-w-md">
            <SelectField
              label="Organization"
              value={org}
              onChange={setOrg}
              disabled={orgs.length === 1 && !!org}
              options={[
                { value: '', label: 'Select an organization' },
                ...orgs.map((o) => ({ value: o.id, label: o.name })),
              ]}
            />
          </div>
          <div className="flex flex-wrap gap-2 rounded-lg bg-neutral-100 p-1">
            {tabs.map(([id, label]) => (
              <Button
                key={id}
                variant={tab === id ? 'default' : 'ghost'}
                size="sm"
                onClick={() => setTab(id)}
              >
                {label}
              </Button>
            ))}
          </div>
          {org && (
            <ComplianceSection
              key={`${org}:${tab}`}
              scope={scope}
              org={org}
              tab={tab}
              canWrite={orgs.find((o) => o.id === org)!.isOrgAdmin}
            />
          )}
        </>
      )}
    </section>
  )
}
interface EventFilters { decision: string; transferType: string; actorId: string }
const emptyFilters: EventFilters = { decision: '', transferType: '', actorId: '' }
function ComplianceSection(props: { scope: OperationScope; org: string; tab: string; canWrite: boolean }) {
  const [draft, setDraft] = useState(emptyFilters), [active, setActive] = useState(emptyFilters)
  const edit = (key: keyof EventFilters, value: string) => setDraft(previous => ({ ...previous, [key]: value }))
  return <div className="space-y-4">
    {props.tab === 'events' && <Panel title="Find compliance decisions"><form aria-label="Compliance log filters" className="grid gap-3 sm:grid-cols-3" onSubmit={event => { event.preventDefault(); setActive({ ...draft, actorId: draft.actorId.trim() }) }}>
      <SelectField label="Decision" value={draft.decision} onChange={value => edit('decision', value)} options={[{ value: '', label: 'All decisions' }, { value: 'allowed', label: 'Allowed' }, { value: 'denied', label: 'Denied' }, { value: 'monitored', label: 'Monitored' }]} />
      <SelectField label="Transfer type" value={draft.transferType} onChange={value => edit('transferType', value)} options={[{ value: '', label: 'All transfer types' }, { value: 'eth', label: 'Native currency' }, { value: 'erc20', label: 'ERC-20 token' }]} />
      <Field label="Originator OPS actor ID" value={draft.actorId} onChange={value => edit('actorId', value)} hint="Exact verified identity ID; blank includes every actor in this organization." />
      <div className="flex gap-2 sm:col-span-3"><Button type="submit">Search</Button><Button type="button" variant="outline" onClick={() => { setDraft(emptyFilters); setActive(emptyFilters) }}>Reset filters</Button></div>
      <p className="text-xs text-neutral-500 sm:col-span-3">Filters run on the server. Results below use the last submitted search.</p>
    </form></Panel>}
    <ComplianceContext key={JSON.stringify(active)} {...props} filters={active} />
  </div>
}
function ComplianceContext(props: { scope: OperationScope; org: string; tab: string; canWrite: boolean; filters: EventFilters }) {
  const owned = useOperationContext(props.scope)
  return owned ? <ComplianceResults {...props} scope={owned} /> : <p role="status">Preparing the selected compliance view…</p>
}
function ComplianceResults({
  scope,
  org,
  tab,
  canWrite,
  filters,
}: {
  scope: OperationScope
  org: string
  tab: string
  canWrite: boolean
  filters: EventFilters
}) {
  const task = useNativeTask(scope),
    [data, setData] = useState<ObjectValue>(),
    [items, setItems] = useState<ObjectValue[]>([]),
    [cursor, setCursor] = useState(''),
    [visited, setVisited] = useState<{ cursor: string; number: number }[]>([]),
    [pageNumber, setPageNumber] = useState(1),
    [source, setSource] = useState(''),
    [eventDetail, setEventDetail] = useState<{ scope: OperationScope; value: ObjectValue }>()
  const base = `/api/v2/orgs/${org}/compliance/`
  const load = async (next = '', number = 1) => {
    const page = tab === 'travel-rule-records' || tab === 'events'
    const query = new URLSearchParams({ limit: '25' })
    if (next) query.set('cursor', next)
    if (tab === 'events') for (const [key, value] of Object.entries(filters)) if (value) query.set(key, value)
    const result = record(
      await scope.request(
        base +
          tab +
          (page ? '?' + query.toString() : ''),
      ),
    )
    scope.check()
    if (page) {
      setItems(rows(result[tab === 'events' ? 'events' : 'records']))
      setCursor(optionalText(result.nextCursor))
      setPageNumber(number)
      setVisited(previous => number === 1 ? [{ cursor: next, number }] : previous.some(value => value.number === number) ? previous : [...previous, { cursor: next, number }].slice(-10))
    } else {
      setSource(text(result.sourceDigest))
      if (Array.isArray(result.data)) setItems(rows(result.data, 4096))
      else setData(record(result.data))
    }
  }
  useEffect(() => {
    if (tab !== 'preview') void task.run(() => load())
  }, [])
  if (tab === 'preview') return <CompliancePreview scope={scope} base={base} />
  const actions = (
    <div className="flex flex-wrap gap-2">
      <Button
        variant="outline"
        size="sm"
        disabled={task.busy}
        onClick={() => void task.run(() => load())}
      >
        Refresh
      </Button>
      {!['travel-rule-records', 'events', 'quotes'].includes(tab) && (
        <Link
          className="text-sm text-primary self-center"
          to={`/admin/compliance/policy?org=${org}`}
        >
          View configuration policy
        </Link>
      )}
    </div>
  )
  return (
    <div className="space-y-4">
      <TaskError message={task.error} />
      <Panel title={tabs.find(([id]) => id === tab)?.[1] ?? tab} actions={actions}>
        {source && (
          <p className="mb-4 break-all text-xs text-neutral-500">
            Selected source: <code>{source}</code>. Changes take effect through Git review and
            deployment.
          </p>
        )}
        {task.busy && !data && !items.length && (
          <p role="status" className="py-4 text-neutral-500">
            Loading…
          </p>
        )}
        {tab === 'config' && data && <Settings data={data} />}
        {tab === 'tokens' && (
          <DataTable
            loading={task.busy}
            items={items}
            columns={[
              { key: 'symbol', label: 'Symbol' },
              { key: 'tokenAddress', label: 'Token', render: row => <Identifier value={text(row.tokenAddress)} label="Copy token address" /> },
              { key: 'decimals', label: 'Decimals', render: (r) => String(r.decimals) },
              {
                key: 'pricesByCurrency',
                label: 'Approved prices',
                render: (r) =>
                  Object.entries(record(r.pricesByCurrency))
                    .map(([currency, price]) => `${String(price)} ${currency}`)
                    .join(', '),
              },
              { key: 'coingeckoId', label: 'Price reference' },
            ]}
          />
        )}
        {tab === 'address-thresholds' && (
          <DataTable
            loading={task.busy}
            items={items}
            columns={[
              { key: 'address', label: 'Address', render: row => <Identifier value={text(row.address)} label="Copy threshold address" /> },
              { key: 'thresholdFiat', label: 'Threshold', render: (r) => String(r.thresholdFiat) },
              { key: 'note', label: 'Note' },
            ]}
          />
        )}
        {tab === 'sanctions' && (
          <DataTable
            loading={task.busy}
            items={items}
            columns={[
              { key: 'address', label: 'Address', render: row => <Identifier value={text(row.address)} label="Copy sanctioned address" /> },
              { key: 'reason', label: 'Reason' },
              { key: 'source', label: 'Source' },
              { key: 'scope', label: 'Scope' },
            ]}
          />
        )}
        {tab === 'quotes' && (
          <>
            <p className="mb-3 text-xs text-neutral-500">
              These are observations. Admission separately checks the configured currency, source
              and maximum age.
            </p>
            <DataTable
              loading={task.busy}
              items={items}
              columns={[
                { key: 'id', label: 'Quote' },
                {
                  key: 'value',
                  label: 'Price',
                  render: (r) => `${String(r.value)} ${text(r.currency)}`,
                },
                {
                  key: 'providerAsOf',
                  label: 'Provider time',
                  render: (r) => instant(r.providerAsOf),
                },
                { key: 'fetchedAt', label: 'Fetched', render: (r) => instant(r.fetchedAt) },
                { key: 'sourceId', label: 'Source' },
              ]}
            />
          </>
        )}
        {tab === 'travel-rule-records' && (
          <TravelRecords
            scope={scope}
            base={base}
            org={org}
            items={items}
            canWrite={canWrite}
            refresh={load}
          />
        )}
        {tab === 'events' && (
          <>
            <DataTable
              loading={task.busy}
              items={items}
              columns={[
                { key: 'decisionAt', label: 'Time', render: (r) => instant(r.decisionAt) },
                { key: 'transactionHash', label: 'Transaction', render: row => <Identifier value={text(row.transactionHash)} label="Copy transaction hash" /> },
                { key: 'actorId', label: 'Originator', render: row => <Identifier value={text(row.actorId)} label="Copy originator ID" /> },
                {
                  key: 'decision',
                  label: 'Decision',
                  render: (r) => (
                    <Badge variant={r.decision === 'allowed' ? 'success' : 'destructive'}>
                      {text(r.decision)}
                      {r.monitored ? ' · monitored' : ''}
                    </Badge>
                  ),
                },
                { key: 'coverage', label: 'Coverage' },
                { key: 'reason', label: 'Reason' },
                { key: 'amountWei', label: 'Exact amount' },
                { key: 'currency', label: 'Currency' },
                { key: 'details', label: 'Evidence', render: r => <Button size="sm" variant="outline" onClick={() => { scope.check(); setEventDetail({ scope, value: r }) }}>View details</Button> },
              ]}
            />
            <Dialog open={eventDetail?.scope === scope} onOpenChange={open => { if (!open) setEventDetail(undefined) }}><DialogContent className="max-w-3xl max-h-[85vh] overflow-y-auto"><DialogHeader><DialogTitle>Compliance event details</DialogTitle></DialogHeader>{eventDetail?.scope === scope && <ComplianceEventDetails event={eventDetail.value} />}</DialogContent></Dialog>
            <p className="mt-3 text-xs text-neutral-500">
              A monitored allow decision is not a compliance certification.
            </p>
          </>
        )}
        {(tab === 'events' || tab === 'travel-rule-records') && <div className="mt-4 flex flex-wrap items-center justify-between gap-3"><p className="text-xs text-neutral-500">Page {pageNumber}{cursor ? ' · More records available' : ' · End of the available records'}</p><div className="flex gap-2"><Button variant="outline" disabled={task.busy || !visited.some(value => value.number === pageNumber - 1)} onClick={() => { const previous = visited.find(value => value.number === pageNumber - 1); if (previous) void task.run(() => load(previous.cursor, previous.number)) }}>Previous page</Button><Button variant="outline" disabled={task.busy || !cursor} onClick={() => void task.run(() => load(cursor, pageNumber + 1))}>Next page</Button></div>{visited[0]?.number > 1 && <p className="w-full text-xs text-neutral-500">Up to 10 visited page positions are kept in this tab. Refresh starts again at page 1.</p>}</div>}
      </Panel>
    </div>
  )
}
function Identifier({ value, label }: { value: string; label: string }) { return <div className="flex max-w-xs items-center gap-1"><code className="truncate text-xs" title={value}>{value}</code><CopyValue value={value} label={label} /></div> }
function Settings({ data }: { data: ObjectValue }) {
  const spec = record(data.spec),
    settings = record(spec.settings)
  return (
    <dl className="grid gap-4 md:grid-cols-2">
      {[
        ['Travel-rule checks', settings.enabled ? 'Enabled' : 'Disabled'],
        ['Threshold', String(settings.thresholdFiat) + ' ' + text(settings.currency)],
        ['Enforcement', text(settings.enforcementMode)],
        ['Unknown price', text(settings.unknownPricePolicy)],
        ['Record lifetime', String(data.recordMaxSeconds) + ' seconds'],
        ['Maximum quote age', String(data.priceMaxAgeSeconds) + ' seconds'],
      ].map(([label, value]) => (
        <div key={label} className="rounded-lg bg-neutral-50 p-4">
          <dt className="text-xs uppercase tracking-wide text-neutral-500">{label}</dt>
          <dd className="mt-1 text-sm font-medium">{value}</dd>
        </div>
      ))}
    </dl>
  )
}
function TravelRecords({
  scope,
  base,
  org,
  items,
  canWrite,
  refresh,
}: {
  scope: OperationScope
  base: string
  org: string
  items: ObjectValue[]
  canWrite: boolean
  refresh: () => Promise<void>
}) {
  const task = useNativeTask(scope),
    [form, setForm] = useState(false),
    [detail, setDetail] = useState<{ scope: OperationScope; value: ObjectValue }>(),
    [uncertain, setUncertain] = useState(false),
    [deleteTarget, setDeleteTarget] = useState<string>()
  const [actor, setActor] = useState(scope.identity.actor),
    [originName, setOriginName] = useState(''),
    [originRef, setOriginRef] = useState(''),
    [beneficiaryName, setBeneficiaryName] = useState(''),
    [institution, setInstitution] = useState(''),
    [kind, setKind] = useState('eth'),
    [token, setToken] = useState(''),
    [beneficiary, setBeneficiary] = useState('')
  const catalog = useApprovedTokens(scope, org), selectedToken = catalog.tokens.find(t => t.address === token), live = useRef(true), detailOperation = useRef(0), detailAbort = useRef<AbortController>()
  const decimals = kind === 'eth' ? 18 : selectedToken?.decimals, amountState = useExactAmountState(`${org}:${kind}:${kind === 'eth' ? 'native' : token}:${decimals ?? 'unknown'}`, decimals)
  const { amount, mode: amountMode, setAmount, setMode: setAmountMode } = amountState
  useEffect(() => { live.current = true; return () => { live.current = false; detailOperation.current++; detailAbort.current?.abort() } }, [])
  async function create(e: React.FormEvent) {
    e.preventDefault()
    if (uncertain) return
    await task.run(async () => {
      if (!actorID(actor) || !address(beneficiary) || (kind === 'erc20' && !address(token)))
        throw Error('Check the OPS actor and lowercase addresses.')
      const amountWei = amountInBaseUnits(amount, amountMode, kind === 'eth' ? 18 : selectedToken?.decimals)
      if (amountWei === '0') throw Error('Enter a positive amount in base units.')
      const body = {
        originatorActorId: actor,
        originatorData: { name: originName, accountRef: originRef },
        beneficiaryData: { name: beneficiaryName, institution },
        transferType: kind,
        ...(kind === 'erc20' ? { tokenAddress: token } : {}),
        beneficiaryAddress: beneficiary,
        amountWei,
      }
      setUncertain(true)
      try {
        await scope.request(base + 'travel-rule-records', {
          method: 'POST',
          body: JSON.stringify(body),
        })
        scope.check()
        setForm(false)
        setUncertain(false)
        await refresh()
      } catch (error) {
        throw error
      }
    })
  }
  return (
    <div className="space-y-4">
      <TaskError message={task.error} />
      {canWrite && (
        <Button
          size="sm"
          onClick={() => {
            setUncertain(false)
            setForm(true)
          }}
          disabled={task.busy || uncertain}
        >
          Create travel-rule record
        </Button>
      )}
      {uncertain && (
        <div className="rounded-lg bg-warning-light p-3 text-sm text-warning-dark">
          <p>
            The previous create request may have committed. Refresh and check the records before
            creating another.
          </p>
          <Button
            className="mt-2"
            variant="outline"
            disabled={task.busy}
            onClick={() =>
              void task.run(async () => {
                await refresh()
                scope.check()
                setUncertain(false)
                setForm(false)
              })
            }
          >
            Refresh to check outcome
          </Button>
        </div>
      )}
      <DataTable
        items={items}
        columns={[
          { key: 'id', label: 'Record', render: row => <Identifier value={text(row.id)} label="Copy travel-rule record ID" /> },
          { key: 'originatorActorId', label: 'Originator', render: row => <Identifier value={text(row.originatorActorId)} label="Copy originator ID" /> },
          { key: 'beneficiaryAddress', label: 'Beneficiary', render: row => <Identifier value={text(row.beneficiaryAddress)} label="Copy beneficiary address" /> },
          { key: 'amountWei', label: 'Base units', render: (r) => quantity(r.amountWei) },
          {
            key: 'amountFiat',
            label: 'Recorded valuation',
            render: (r) => `${String(r.amountFiat)} ${text(r.currency)}`,
          },
          {
            key: 'status',
            label: 'Status',
            render: (r) => (
              <Badge
                variant={
                  r.usedAt
                    ? 'secondary'
                    : Date.parse(text(r.expiresAt)) <= Date.now()
                      ? 'destructive'
                      : 'success'
                }
              >
                {r.usedAt
                  ? 'Used'
                  : Date.parse(text(r.expiresAt)) <= Date.now()
                    ? 'Expired'
                    : 'Unused'}
              </Badge>
            ),
          },
          {
            key: 'actions',
            label: 'Actions',
            render: (r) => (
              <div className="flex gap-2">
                <Button
                  size="sm"
                  variant="outline"
                  disabled={task.busy}
                  onClick={() =>
                    void task.run(async () => {
                      const operation = ++detailOperation.current
                      detailAbort.current?.abort()
                      const abort = new AbortController(); detailAbort.current = abort
                      const v = record(
                        await scope.request(base + 'travel-rule-records/' + text(r.id), { signal: abort.signal }),
                      )
                      scope.check()
                      if (live.current && operation === detailOperation.current) setDetail({ scope, value: v })
                    })
                  }
                >
                  Details
                </Button>
                {canWrite && !r.usedAt && (
                  <Button
                    size="sm"
                    variant="ghost"
                    disabled={task.busy}
                    onClick={() => setDeleteTarget(text(r.id))}
                  >
                    Delete unused
                  </Button>
                )}
              </div>
            ),
          },
        ]}
      />
      <ConfirmDialog
        open={!!deleteTarget}
        onOpenChange={(open) => {
          if (!open && !task.busy) setDeleteTarget(undefined)
        }}
        title="Delete this unused travel-rule record?"
        description="This removes the unused record and its personal data. Used records cannot be deleted by this action."
        variant="destructive"
        isLoading={task.busy}
        onConfirm={() =>
          task.run(async () => {
            await scope.request(base + 'travel-rule-records/' + deleteTarget, { method: 'DELETE' })
            scope.check()
            await refresh()
            setDeleteTarget(undefined)
          })
        }
      />
      <Dialog
        open={form}
        onOpenChange={(open) => {
          if (!task.busy) setForm(open)
        }}
      >
        <DialogContent className="max-h-[85vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle>Create travel-rule record</DialogTitle>
          </DialogHeader>
          <form onSubmit={(e) => void create(e)} className="space-y-4">
            <Field
              label="Originator OPS actor ID"
              value={actor}
              onChange={setActor}
              required
              hint="Use the verified identity ID; OPS has no searchable user directory."
            />
            <div className="grid gap-3 sm:grid-cols-2">
              <Field label="Originator name" value={originName} onChange={setOriginName} required />
              <Field label="Account reference" value={originRef} onChange={setOriginRef} />
              <Field
                label="Beneficiary name"
                value={beneficiaryName}
                onChange={setBeneficiaryName}
                required
              />
              <Field
                label="Beneficiary institution"
                value={institution}
                onChange={setInstitution}
              />
            </div>
            <SelectField
              label="Transfer type"
              value={kind}
              onChange={setKind}
              options={[
                { value: 'eth', label: 'Native currency' },
                { value: 'erc20', label: 'ERC-20 token' },
              ]}
            />
            {kind === 'erc20' && (
              <TokenChoice tokens={catalog.tokens} token={token} onChange={setToken} />
            )}
            <Field
              label="Beneficiary wallet"
              value={beneficiary}
              onChange={setBeneficiary}
              required
            />
            {catalog.error && <p className="text-xs text-neutral-500">{catalog.error}</p>}
            <ExactAmount amount={amount} mode={amountMode} decimals={kind === 'eth' ? 18 : selectedToken?.decimals} unit={kind === 'eth' ? 'Native currency' : selectedToken?.symbol ?? 'Token base units'} onAmount={setAmount} onMode={setAmountMode} notice={amountState.notice} disabled={task.busy} />
            {uncertain && (
              <p role="status" className="text-sm text-warning-dark">
                This request may have created a record. Close this form and refresh the list to
                check its outcome before creating another.
              </p>
            )}
            <TaskError message={task.error} />
            <div className="flex justify-end gap-2"><Button type="button" variant="outline" disabled={task.busy} onClick={() => setForm(false)}>Cancel</Button><Button type="submit" disabled={task.busy || uncertain}>
              {task.busy ? 'Creating…' : 'Create record'}
            </Button></div>
          </form>
        </DialogContent>
      </Dialog>
      <Dialog open={detail?.scope === scope} onOpenChange={() => { detailOperation.current++; detailAbort.current?.abort(); setDetail(undefined) }}>
        <DialogContent className="max-w-3xl max-h-[85vh] overflow-y-auto"><DialogHeader><DialogTitle>Travel-rule record details</DialogTitle></DialogHeader>
          {detail?.scope === scope && <TravelRecordDetails detail={detail.value} tokens={catalog.tokens} />}
        </DialogContent>
      </Dialog>
    </div>
  )
}
function CompliancePreview({ scope, base }: { scope: OperationScope; base: string }) {
  const task = useNativeTask(scope),
    [actor, setActor] = useState(scope.identity.actor),
    [signed, setSigned] = useState(''),
    [result, setResult] = useState<ObjectValue>()
  return (
    <Panel title="Preview a signed transaction">
      <p className="mb-4 text-sm text-neutral-500">
        Checks the running compliance rules and valuation without submitting a transaction.
      </p>
      <form
        className="space-y-4"
        onSubmit={(e) => {
          e.preventDefault()
          void task.run(async () => {
            setResult(undefined)
            const v = record(
              await scope.request(base + 'preview', {
                method: 'POST',
                body: JSON.stringify({ originatorActorId: actor, signedTransaction: signed }),
              }),
            )
            scope.check()
            setResult(v)
          })
        }}
      >
        <Field
          label="Originator OPS actor ID"
          value={actor}
          disabled={task.busy}
          onChange={(value) => {
            setActor(value)
            setResult(undefined)
          }}
          required
        />
        <Field
          label="Signed transaction"
          multiline
          value={signed}
          disabled={task.busy}
          onChange={(value) => {
            setSigned(value)
            setResult(undefined)
          }}
          required
        />
        <Button type="submit" disabled={task.busy}>
          Check compliance
        </Button>
      </form>
      <TaskError message={task.error} />
      {result && (
        <div className="mt-4 rounded-lg border p-4">
          <Badge variant={result.allowed ? 'success' : 'destructive'}>
            {result.allowed ? 'Allowed' : 'Denied'}
            {result.monitored ? ' · monitored' : ''}
          </Badge>
          <p className="mt-2 text-sm">{text(result.reason)}</p>
          <p className="mt-2 text-xs text-neutral-500">
            Coverage: {text(result.coverage)} · {instant(result.decisionAt)}
          </p>
        </div>
      )}
    </Panel>
  )
}
