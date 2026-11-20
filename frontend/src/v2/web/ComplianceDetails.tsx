import type { ReactNode } from 'react'
import { instant, type ObjectValue } from './operationsModels'
import { baseUnitsToDecimal } from './exactAmounts'
import type { ApprovedToken } from './approvedTokens'

const present = (value: unknown): ReactNode => value === undefined || value === null || value === '' ? 'Unavailable' : typeof value === 'object' ? JSON.stringify(value) : String(value)
const time = (value: unknown): ReactNode => value === undefined || value === null || value === '' ? 'Unavailable' : instant(value)
function Evidence({ entries }: { entries: [string, ReactNode][] }) {
  return <dl className="grid gap-3 sm:grid-cols-2">{entries.map(([label, value]) => <div key={label} className="min-w-0 rounded-lg bg-neutral-50 p-3"><dt className="text-xs text-neutral-500">{label}</dt><dd className="mt-1 break-all text-sm">{value}</dd></div>)}</dl>
}
export function ComplianceEventDetails({ event }: { event: ObjectValue }) {
  const quote = event.quote && typeof event.quote === 'object' ? event.quote as ObjectValue : null
  const fiat = (value: unknown) => value === undefined || value === null ? 'Unavailable' : `${String(value)}${typeof event.currency === 'string' ? ' ' + event.currency : ''}`
  return <div className="space-y-4"><p className="text-sm text-neutral-500">Recorded admission evidence. A monitored allow decision is not a compliance certification. Valuation and quote values describe the decision at that time.</p>
    <Evidence entries={[
      ['Decision', present(event.decision)], ['Mode', event.monitored === true ? 'Monitored' : event.monitored === false ? 'Enforced' : 'Unavailable'], ['Reason', present(event.reason)], ['Kind', present(event.kind)], ['Coverage', present(event.coverage)], ['Decision time', time(event.decisionAt)],
      ['Transaction hash', present(event.transactionHash)], ['Verified actor', present(event.actorId)], ['From', present(event.from)], ['To', present(event.to)], ['Token', present(event.token)], ['Exact amount (base units)', present(event.amountWei)], ['Recorded valuation', fiat(event.amountFiat)], ['Decision threshold', fiat(event.thresholdFiat)], ['Matching record ID', present(event.recordId)], ['Policy digest', present(event.policyDigest)],
    ]} />
    {quote && <section className="space-y-2"><h4 className="font-medium">Decision quote provenance</h4><Evidence entries={[
      ['Quote ID', present(quote.id)], ['Quote value', `${present(quote.value)} ${typeof quote.currency === 'string' ? quote.currency : ''}`], ['Source ID', present(quote.sourceId)], ['Provider time', time(quote.providerAsOf)], ['Fetched time', time(quote.fetchedAt)],
    ]} /></section>}
  </div>
}
export function TravelRecordDetails({ detail, tokens }: { detail: ObjectValue; tokens: ApprovedToken[] }) {
  const token = tokens.find(t => t.address === detail.tokenAddress), decimals = detail.transferType === 'eth' ? 18 : token?.decimals
  let amount: ReactNode = typeof detail.amountWei === 'string' ? `${detail.amountWei} base units (token decimals unavailable)` : present(detail.amountWei)
  if (typeof detail.amountWei === 'string' && decimals !== undefined) amount = `${baseUnitsToDecimal(detail.amountWei, decimals)} ${detail.transferType === 'eth' ? 'native currency' : token!.symbol} (${detail.amountWei} base units)`
  const used = detail.usedAt !== undefined && detail.usedAt !== null && detail.usedAt !== ''
  return <div className="space-y-4"><p className="text-xs text-neutral-500">Personal data is loaded only for this explicit detail view. Recorded fiat is the historical record valuation.</p>
    <Evidence entries={[
      ['Record ID', present(detail.id)], ['Organization ID', present(detail.organizationId)], ['Verified originator actor', present(detail.originatorActorId)], ['Transfer type', present(detail.transferType)], ['Token address', present(detail.tokenAddress)], ['Beneficiary wallet', present(detail.beneficiaryAddress)], ['Exact transfer amount', amount], ['Recorded valuation', detail.amountFiat === undefined || detail.amountFiat === null ? 'Unavailable' : `${String(detail.amountFiat)} ${typeof detail.currency === 'string' ? detail.currency : ''}`],
      ['Created', time(detail.createdAt)], ['Expires', time(detail.expiresAt)], ['Used at', time(detail.usedAt)], ['Used transaction hash', present(detail.usedTxHash)], ['Status', used ? 'Used' : typeof detail.expiresAt === 'string' && Date.parse(detail.expiresAt) <= Date.now() ? 'Expired' : 'Unused'],
    ]} />
    {(['originatorData', 'beneficiaryData'] as const).map(key => <section key={key} className="space-y-2"><h4 className="font-medium">{key === 'originatorData' ? 'Originator personal data' : 'Beneficiary personal data'}</h4>{detail[key] && typeof detail[key] === 'object' ? <Evidence entries={Object.entries(detail[key] as ObjectValue).map(([k, v]) => [k, present(v)])} /> : <p className="text-sm">Unavailable</p>}</section>)}
  </div>
}
