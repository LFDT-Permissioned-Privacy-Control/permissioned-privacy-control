import { useEffect, useRef, useState, type MutableRefObject } from 'react'
import { Link } from 'react-router-dom'
import { Badge } from '../../components/ui/badge'
import { Button } from '../../components/ui/button'
import { Dialog, DialogContent, DialogHeader, DialogTitle } from '../../components/ui/dialog'
import type { OperationScope } from './controller'
import {
  actorID,
  address,
  casePage,
  caseRecord,
  instant,
  optionalText,
  protectedData,
  quantity,
  record,
  rows,
  text,
  type NativeCase,
  type ObjectValue,
  type ProtectedData,
} from './operationsModels'
import {
  DataTable,
  Field,
  More,
  Panel,
  SelectField,
  TaskError,
  saveJSON,
  useNativeTask,
  type Column,
} from './operationsUI'

const base = '/api/v1/disclosure/cases'
const resourceOptions = [
  { value: 'transactions', label: 'Transactions' },
  { value: 'addresses', label: 'Wallet history' },
  { value: 'activity_logs', label: 'Access logs' },
  { value: 'activity_summary', label: 'Activity summary' },
  { value: 'sanctions_report', label: 'Sanctions report' },
  { value: 'compliance_report', label: 'Compliance report' },
]
export function NativeDisclosures({
  scope,
  logsOnly = false,
}: {
  scope: OperationScope
  logsOnly?: boolean
}) {
  const task = useNativeTask(scope),
    admins = scope.self.organizations.filter((o) => o.isOrgAdmin)
  const [role, setRole] = useState('recipient'),
    [org, setOrg] = useState(admins.length === 1 ? admins[0].id : ''),
    [items, setItems] = useState<NativeCase[]>([]),
    [cursor, setCursor] = useState(''),
    [scanComplete, setScanComplete] = useState(true),
    [creating, setCreating] = useState(false),
    [selected, setSelected] = useState<NativeCase>()
  const createBody = useRef<string>(),
    createInFlight = useRef(false)
  const list = async (next = '') => {
    const query = new URLSearchParams({ role, limit: '25' })
    if (role === 'data-org-admin') query.set('organizationId', org)
    if (next) query.set('cursor', next)
    const page = casePage(await scope.request(base + '?' + query.toString()))
    scope.check()
    setItems(page.items)
    setCursor(page.nextCursor)
    setScanComplete(page.scanComplete)
  }
  useEffect(() => {
    setItems([])
    setSelected(undefined)
    setCursor('')
    if (role === 'recipient' || org) void task.run(() => list())
  }, [role, org])
  return (
    <section className="space-y-6">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h2 className="text-2xl font-semibold">{logsOnly ? 'Access Logs' : 'Disclosure'}</h2>
          <p className="mt-1 text-sm text-neutral-500">
            {logsOnly
              ? 'Inspect recorded requests through an authorized disclosure case.'
              : 'Cases use standing rules approved in Git. Customers do not approve individual disclosures.'}
          </p>
        </div>
        <div className="flex gap-2">
          <Button
            variant="outline"
            disabled={task.busy || (role === 'data-org-admin' && !org)}
            onClick={() => void task.run(() => list())}
          >
            Refresh
          </Button>
          <Button onClick={() => setCreating(true)} disabled={task.busy}>
            Create case
          </Button>
        </div>
      </div>
      {!logsOnly && admins.length > 0 && (
        <div className="grid gap-3 sm:grid-cols-2">
          <SelectField
            label="Case view"
            disabled={task.busy}
            value={role}
            onChange={setRole}
            options={[
              { value: 'recipient', label: 'My received cases' },
              { value: 'data-org-admin', label: 'Organization administration' },
            ]}
          />
          {role === 'data-org-admin' && (
            <SelectField
              label="Data organization"
              disabled={task.busy}
              value={org}
              onChange={setOrg}
              options={[
                { value: '', label: 'Select an organization' },
                ...admins.map((o) => ({ value: o.id, label: o.name })),
              ]}
            />
          )}
        </div>
      )}
      <TaskError message={task.error} />
      <Panel title={logsOnly ? 'Choose an access-log case' : 'Disclosure cases'}>
        <DataTable
          items={items as unknown as ObjectValue[]}
          columns={[
            { key: 'caseReference', label: 'Reference' },
            { key: 'purpose', label: 'Purpose' },
            { key: 'recipientActorId', label: 'Recipient' },
            {
              key: 'status',
              label: 'Status',
              render: (r) => (
                <Badge variant={r.status === 'open' ? 'success' : 'secondary'}>
                  {text(r.status)}
                </Badge>
              ),
            },
            { key: 'expiresAt', label: 'Expires', render: (r) => instant(r.expiresAt) },
            { key: 'ruleId', label: 'Standing rule' },
            {
              key: 'actions',
              label: 'Actions',
              render: (r) => (
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() =>
                    void task.run(async () => {
                      const value = caseRecord(await scope.request(base + '/' + text(r.caseId)))
                      scope.check()
                      setSelected(value)
                    })
                  }
                >
                  Open case
                </Button>
              ),
            },
          ]}
        />
        {!scanComplete && !cursor && (
          <p className="text-xs text-warning-dark">
            This scan is incomplete. Refresh before concluding that no other cases exist.
          </p>
        )}
        <More cursor={cursor} busy={task.busy} onNext={() => void task.run(() => list(cursor))} />
      </Panel>
      {selected && (
        <CaseDetail
          key={`${selected.caseId}:${selected.version}`}
          scope={scope}
          selected={selected}
          logsOnly={logsOnly}
          onChanged={async () => {
            setSelected(undefined)
            await list()
          }}
        />
      )}
      <Dialog
        open={creating}
        onOpenChange={(open) => {
          if (!createInFlight.current) setCreating(open)
        }}
      >
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Create disclosure case</DialogTitle>
          </DialogHeader>
          <CreateCase
            scope={scope}
            pending={createBody}
            onPending={(value) => {
              createInFlight.current = value
            }}
            onCreated={async (value) => {
              createBody.current = undefined
              setCreating(false)
              setSelected(value)
              await list()
            }}
          />
        </DialogContent>
      </Dialog>
    </section>
  )
}
function CreateCase({
  scope,
  pending,
  onPending,
  onCreated,
}: {
  scope: OperationScope
  pending: MutableRefObject<string | undefined>
  onPending: (value: boolean) => void
  onCreated: (value: NativeCase) => Promise<void>
}) {
  const task = useNativeTask(scope),
    [rule, setRule] = useState(''),
    [recipient, setRecipient] = useState(scope.identity.actor),
    [reference, setReference] = useState(''),
    [purpose, setPurpose] = useState(''),
    [basis, setBasis] = useState(''),
    [targets, setTargets] = useState(''),
    [level, setLevel] = useState('redacted'),
    [mode, setMode] = useState('all-target-addresses'),
    [addresses, setAddresses] = useState(''),
    [resources, setResources] = useState(['transactions']),
    [start, setStart] = useState(new Date(Date.now() - 86400000).toISOString().slice(0, 16)),
    [end, setEnd] = useState(new Date().toISOString().slice(0, 16)),
    [until, setUntil] = useState(new Date(Date.now() + 3600000).toISOString().slice(0, 16)),
    [submitted, setSubmitted] = useState(!!pending.current)
  const split = (value: string) => value.split(/[\s,]+/).filter(Boolean)
  async function submit(e: React.FormEvent) {
    e.preventDefault()
    await task.run(async () => {
      if (!pending.current) {
        if (
          !actorID(recipient) ||
          !split(targets).length ||
          split(targets).some((v) => !actorID(v)) ||
          (mode === 'list' &&
            (!split(addresses).length || split(addresses).some((v) => !address(v))))
        )
          throw Error('Check the recipient, target actor IDs and lowercase wallet addresses.')
        const seconds = (value: string) => Math.floor(Date.parse(value + 'Z') / 1000),
          from = seconds(start),
          to = seconds(end),
          expiresAt = seconds(until)
        if (
          !Number.isSafeInteger(from) ||
          !Number.isSafeInteger(to) ||
          to <= from ||
          !Number.isSafeInteger(expiresAt) ||
          expiresAt <= Date.now() / 1000 ||
          !resources.length
        )
          throw Error('Check the UTC times and selected resources.')
        pending.current = JSON.stringify({
          ruleId: rule,
          recipientActorId: recipient,
          caseReference: reference,
          purpose,
          legalBasis: basis,
          scope: {
            targetActors: split(targets),
            resources,
            addresses: { mode, values: mode === 'list' ? split(addresses) : [] },
            dataTime: { start: from, end: to },
            level,
          },
          expiresAt,
          idempotencyKey: crypto.randomUUID(),
        })
      }
      setSubmitted(true)
      onPending(true)
      let result: NativeCase
      try {
        result = caseRecord(
          await scope.request(base, { method: 'POST', body: pending.current }),
        )
        scope.check()
      } finally {
        onPending(false)
      }
      await onCreated(result)
    })
  }
  return (
    <form onSubmit={(e) => void submit(e)} className="space-y-4">
      <p className="text-sm text-neutral-500">
        OPS checks this complete scope against one approved standing rule. Case creation does not
        grant permission beyond that rule.
      </p>
      <Link className="text-sm text-primary" to="/admin/rbac/disclosure-source">
        Inspect or propose standing rules
      </Link>
      {!submitted && (
        <fieldset disabled={task.busy} className="space-y-4">
          <Field label="Standing rule ID" value={rule} onChange={setRule} required />
          <Field
            label="Recipient OPS actor ID"
            value={recipient}
            onChange={setRecipient}
            required
            hint="Eligible recipients may create for themselves. An organization admin may name another recipient."
          />
          <Field label="Case reference" value={reference} onChange={setReference} required />
          <Field label="Purpose" value={purpose} onChange={setPurpose} required />
          <Field label="Legal basis" value={basis} onChange={setBasis} required />
          <Field
            label="Target OPS actor IDs"
            value={targets}
            onChange={setTargets}
            required
            hint="Separate concrete target identities with spaces. No user search or customer approval is performed."
          />
          <SelectField
            label="Privacy level"
            value={level}
            onChange={setLevel}
            options={['redacted', 'pseudonymous', 'full'].map((value) => ({ value, label: value }))}
          />
          <SelectField
            label="Wallet scope"
            value={mode}
            onChange={setMode}
            options={[
              { value: 'all-target-addresses', label: 'All qualified target wallets' },
              { value: 'list', label: 'Specific target wallets' },
            ]}
          />
          {mode === 'list' && (
            <Field
              label="Target wallet addresses"
              value={addresses}
              onChange={setAddresses}
              required
            />
          )}
          <fieldset>
            <legend className="mb-2 text-sm font-medium">Resources</legend>
            <div className="grid gap-2 sm:grid-cols-2">
              {resourceOptions.map((option) => (
                <label key={option.value} className="flex gap-2 text-sm">
                  <input
                    type="checkbox"
                    checked={resources.includes(option.value)}
                    onChange={(e) =>
                      setResources((old) =>
                        e.target.checked
                          ? [...old, option.value]
                          : old.filter((v) => v !== option.value),
                      )
                    }
                  />
                  {option.label}
                </label>
              ))}
            </div>
          </fieldset>
          <div className="grid gap-3 sm:grid-cols-2">
            <Field
              label="Data starts (UTC)"
              type="datetime-local"
              value={start}
              onChange={setStart}
              required
            />
            <Field
              label="Data ends (UTC, exclusive)"
              type="datetime-local"
              value={end}
              onChange={setEnd}
              required
            />
            <Field
              label="Case expires (UTC)"
              type="datetime-local"
              value={until}
              onChange={setUntil}
              required
            />
          </div>
        </fieldset>
      )}
      {submitted && pending.current && <SubmittedCaseReview body={pending.current} />}
      {submitted && (
        <p className="text-xs text-warning-dark">
          The submitted scope and idempotency key are fixed. If the outcome was uncertain, this
          button checks the same request; it cannot create a different case.
        </p>
      )}
      <TaskError message={task.error} />
      <Button type="submit" disabled={task.busy}>
        {task.busy ? 'Checking…' : submitted ? 'Check same submitted case' : 'Create case'}
      </Button>
    </form>
  )
}
function SubmittedCaseReview({ body }: { body: string }) {
  const value = record(JSON.parse(body)),
    scope = record(value.scope),
    at = record(scope.dataTime)
  return (
    <dl className="grid gap-3 rounded-lg bg-neutral-50 p-4 text-sm sm:grid-cols-2">
      {[
        ['Submitted reference', text(value.caseReference)],
        ['Standing rule', text(value.ruleId)],
        ['Recipient', text(value.recipientActorId)],
        ['Purpose', text(value.purpose)],
        ['Legal basis', text(value.legalBasis)],
        ['Privacy level', text(scope.level)],
        [
          'Targets',
          Array.isArray(scope.targetActors) ? scope.targetActors.map(String).join(', ') : '',
        ],
        ['Resources', Array.isArray(scope.resources) ? scope.resources.map(String).join(', ') : ''],
        ['Data begins', instant(at.start)],
        ['Data ends', instant(at.end)],
        ['Case expires', instant(value.expiresAt)],
        ['Idempotency key', text(value.idempotencyKey)],
      ].map(([label, text]) => (
        <div key={label}>
          <dt className="text-xs text-neutral-500">{label}</dt>
          <dd className="break-all">{text}</dd>
        </div>
      ))}
    </dl>
  )
}
function CaseDetail({
  scope,
  selected,
  logsOnly,
  onChanged,
}: {
  scope: OperationScope
  selected: NativeCase
  logsOnly: boolean
  onChanged: () => Promise<void>
}) {
  const task = useNativeTask(scope),
    [resource, setResource] = useState(
      logsOnly
        ? 'activity_logs'
        : (selected.scope.resources.find((v) => resourceOptions.some((o) => o.value === v)) ?? ''),
    ),
    [data, setData] = useState<ProtectedData>(),
    [cursor, setCursor] = useState(''),
    [audit, setAudit] = useState<ObjectValue[]>([]),
    [auditCursor, setAuditCursor] = useState(''),
    [reason, setReason] = useState(''),
    [revoking, setRevoking] = useState(false),
    [filter, setFilter] = useState('')
  const recipient = selected.recipientActorId === scope.identity.actor
  const read = async (next = '') => {
    setData(undefined)
    const report = resource.endsWith('_report') || resource === 'activity_summary'
    const body = {
      v: 1,
      resource,
      view: report ? 'report' : 'list',
      ...(report ? {} : { limit: 25, ...(next ? { cursor: next } : {}) }),
    }
    const value = protectedData(
      await scope.request(base + '/' + selected.caseId + '/read', {
        method: 'POST',
        body: JSON.stringify(body),
      }),
      selected,
      resource,
    )
    scope.check()
    setData(value)
    setCursor(optionalText(value.result.nextCursor))
  }
  const loadAudit = async (next = '') => {
    const value = record(
      await scope.request(
        base +
          '/' +
          selected.caseId +
          '/audit?limit=25' +
          (next ? '&cursor=' + encodeURIComponent(next) : ''),
      ),
    )
    scope.check()
    setAudit(rows(value.items))
    setAuditCursor(text(value.nextCursor))
  }
  useEffect(() => {
    setData(undefined)
    setCursor('')
  }, [resource])
  useEffect(() => {
    if (!data) return
    const timer = setTimeout(
      () => {
        setData(undefined)
        setCursor('')
      },
      Math.max(1, data.effectiveUntil * 1000 - Date.now()),
    )
    return () => clearTimeout(timer)
  }, [data])
  const allowed =
    selected.status === 'open' &&
    selected.expiresAt > Date.now() / 1000 &&
    recipient &&
    selected.scope.resources.includes(resource)
  return (
    <div className="space-y-4">
      <Panel
        title={`Case: ${selected.caseReference}`}
        actions={
          <Badge variant={selected.status === 'open' ? 'success' : 'secondary'}>
            {selected.status}
          </Badge>
        }
      >
        <dl className="grid gap-4 text-sm sm:grid-cols-2">
          {[
            ['Case ID', selected.caseId],
            ['Purpose', selected.purpose],
            ['Legal basis', selected.legalBasis],
            ['Recipient', selected.recipientActorId],
            ['Privacy level', selected.scope.level],
            ['Expires', instant(selected.expiresAt)],
            ['Data begins', instant(selected.scope.dataTime.start)],
            ['Data ends (exclusive)', instant(selected.scope.dataTime.end)],
          ].map(([label, value]) => (
            <div key={label}>
              <dt className="text-xs text-neutral-500">{label}</dt>
              <dd className="mt-1 break-all">{value}</dd>
            </div>
          ))}
        </dl>
        {!recipient && (
          <p className="mt-4 text-sm text-neutral-500">
            Organization administration can inspect case metadata. Only its authorized recipient can
            read protected data.
          </p>
        )}
        <div className="mt-4 flex flex-wrap items-end gap-3">
          <SelectField
            label="Data resource"
            value={resource}
            disabled={task.busy}
            onChange={(value) => {
              setData(undefined)
              setCursor('')
              setResource(value)
            }}
            options={resourceOptions.filter(
              (o) =>
                selected.scope.resources.includes(o.value) &&
                (!logsOnly || o.value === 'activity_logs' || o.value === 'activity_summary'),
            )}
          />
          <Button disabled={task.busy || !allowed} onClick={() => void task.run(() => read())}>
            Read permitted data
          </Button>
          <Button
            variant="outline"
            disabled={task.busy}
            onClick={() => void task.run(() => loadAudit())}
          >
            Audit trail
          </Button>
          {selected.status === 'open' && (
            <Button variant="destructive" disabled={task.busy} onClick={() => setRevoking(true)}>
              Revoke case
            </Button>
          )}
        </div>
        {selected.scope.resources.includes('events') && (
          <p className="mt-3 text-sm text-warning-dark">
            Event disclosures are unavailable. The other resources in this case remain usable.
          </p>
        )}
        {!resourceOptions.some((o) => selected.scope.resources.includes(o.value)) && (
          <p className="mt-3 text-sm text-warning-dark">
            This case has no resource supported by the current protected-data API.
          </p>
        )}
        <TaskError message={task.error} />
      </Panel>
      {data && (
        <Panel
          title={resourceOptions.find((o) => o.value === data.resource)?.label ?? data.resource}
          actions={
            <Button
              variant="outline"
              size="sm"
              onClick={() =>
                void task.run(async () => {
                  if (data.effectiveUntil <= Date.now() / 1000) {
                    setData(undefined)
                    throw Error('The case data expired. Read again if still permitted.')
                  }
                  saveJSON('ops-disclosure-report.json', data, scope.check)
                })
              }
            >
              Download verified report
            </Button>
          }
        >
          <p className="mb-4 text-xs text-neutral-500">
            Coverage: {text(data.coverage.status)} ·{' '}
            {data.coverage.populations instanceof Array
              ? data.coverage.populations.map(String).join(', ')
              : ''}{' '}
            · Valid until {instant(data.effectiveUntil)}
          </p>
          {data.resource === 'activity_logs' && (
            <div className="mb-3 max-w-md">
              <Field
                label="Filter this loaded page by method"
                value={filter}
                onChange={setFilter}
                hint="This searches the visible page only; it is not a search over all retained logs."
              />
            </div>
          )}
          <ProtectedResult data={data} filter={filter} />
          <More cursor={cursor} busy={task.busy} onNext={() => void task.run(() => read(cursor))} />
        </Panel>
      )}
      {!!audit.length && (
        <Panel title="Case audit trail">
          <DataTable
            items={audit}
            columns={[
              { key: 'time', label: 'Time', render: (r) => instant(r.time) },
              { key: 'action', label: 'Action' },
              { key: 'outcome', label: 'Outcome' },
              { key: 'count', label: 'Count', render: (r) => String(r.count) },
              { key: 'actor', label: 'Actor' },
              { key: 'ruleDigest', label: 'Rule digest' },
            ]}
          />
          <More
            cursor={auditCursor}
            busy={task.busy}
            onNext={() => void task.run(() => loadAudit(auditCursor))}
          />
        </Panel>
      )}
      <Dialog
        open={revoking}
        onOpenChange={(open) => {
          if (!task.busy) setRevoking(open)
        }}
      >
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Revoke this disclosure case?</DialogTitle>
          </DialogHeader>
          <p className="text-sm text-neutral-500">
            Further protected reads will be denied. Previously disclosed data cannot be recalled.
          </p>
          <form
            className="space-y-4"
            onSubmit={(e) => {
              e.preventDefault()
              void task.run(async () => {
                if (!reason.trim()) throw Error('Enter a revocation reason.')
                await scope.request(base + '/' + selected.caseId + '/revoke', {
                  method: 'POST',
                  body: JSON.stringify({ reason }),
                })
                scope.check()
                await onChanged()
              })
            }}
          >
            <Field label="Reason for revocation" value={reason} onChange={setReason} required />
            <TaskError message={task.error} />
            <div className="flex justify-end gap-2">
              <Button
                variant="outline"
                type="button"
                disabled={task.busy}
                onClick={() => setRevoking(false)}
              >
                Cancel
              </Button>
              <Button variant="destructive" type="submit" disabled={task.busy}>
                Revoke case
              </Button>
            </div>
          </form>
        </DialogContent>
      </Dialog>
    </div>
  )
}
function ProtectedResult({ data, filter }: { data: ProtectedData; filter: string }) {
  const result = data.result
  if (Array.isArray(result.items)) {
    const columns: Column[] =
      data.resource === 'activity_logs'
        ? [
            { key: 'time', label: 'Time', render: (r) => instant(r.time) },
            { key: 'method', label: 'Method' },
            { key: 'statusCode', label: 'Status', render: (r) => String(r.statusCode) },
            { key: 'actorId', label: 'Actor' },
            { key: 'ipAddress', label: 'IP address' },
          ]
        : data.resource === 'addresses'
          ? [
              { key: 'display', label: 'Wallet' },
              { key: 'address', label: 'Address' },
              { key: 'ensName', label: 'ENS' },
            ]
          : [
              { key: 'blockNumber', label: 'Block', render: (r) => quantity(r.blockNumber) },
              { key: 'blockTime', label: 'Time', render: (r) => instant(r.blockTime) },
              { key: 'transactionHash', label: 'Transaction' },
              { key: 'from', label: 'From' },
              { key: 'to', label: 'To' },
              { key: 'value', label: 'Value' },
              {
                key: 'status',
                label: 'Status',
                render: (r) =>
                  r.status === 1 ? 'Success' : r.status === 0 ? 'Reverted' : 'Unavailable',
              },
            ]
    const items = rows(result.items).filter(
      (r) =>
        data.resource !== 'activity_logs' ||
        text(r.method).toLowerCase().includes(filter.toLowerCase()),
    )
    return <DataTable items={items} columns={columns} />
  }
  if (data.resource === 'activity_summary') return <Summary data={result} />
  if (data.resource === 'sanctions_report') return <Sanctions data={result} />
  if (data.resource === 'compliance_report')
    return (
      <div className="space-y-4">
        <Summary data={record(result.activity)} />
        <Sanctions data={record(result.sanctions)} />
        <p className="text-sm">KYC: {text(result.kyc).replace(/_/g, ' ')}</p>
        <DataTable
          items={rows(result.evidence)}
          columns={[
            { key: 'time', label: 'Time', render: (r) => instant(r.time) },
            { key: 'decision', label: 'Admission decision' },
            { key: 'coverage', label: 'Coverage' },
            { key: 'transactionHash', label: 'Transaction' },
            { key: 'reason', label: 'Reason' },
            { key: 'policyDigest', label: 'Policy digest' },
          ]}
        />
      </div>
    )
  throw Error('Unsupported protected report')
}
function Summary({ data }: { data: ObjectValue }) {
  return (
    <>
      <dl className="mb-4 grid grid-cols-3 gap-3">
        {[
          ['total', 'Requests'],
          ['successful', 'Successful'],
          ['failed', 'Failed'],
        ].map(([key, label]) => (
          <div key={key} className="rounded-lg bg-neutral-50 p-3">
            <dt className="text-xs text-neutral-500">{label}</dt>
            <dd className="mt-1 text-lg font-semibold">{quantity(data[key])}</dd>
          </div>
        ))}
      </dl>
      <DataTable
        items={rows(data.methodBreakdown)}
        columns={[
          { key: 'method', label: 'Method' },
          { key: 'total', label: 'Requests' },
          { key: 'successful', label: 'Successful' },
          { key: 'failed', label: 'Failed' },
        ]}
      />
    </>
  )
}
function Sanctions({ data }: { data: ObjectValue }) {
  return (
    <div className="space-y-3">
      <p className="text-sm">
        Sanctions result:{' '}
        <Badge variant={data.status === 'hit' ? 'destructive' : 'secondary'}>
          {text(data.status)}
        </Badge>{' '}
        · Qualified addresses: {String(data.scopedAddressCount)}
      </p>
      <DataTable
        items={rows(data.matches)}
        columns={[
          { key: 'address', label: 'Wallet', render: (r) => text(record(r.address).display) },
          { key: 'sourceId', label: 'Source' },
          { key: 'reason', label: 'Reason' },
        ]}
      />
    </div>
  )
}
