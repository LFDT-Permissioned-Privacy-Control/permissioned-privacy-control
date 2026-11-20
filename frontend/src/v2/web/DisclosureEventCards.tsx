import { Badge } from '../../components/ui/badge'
import { Card, CardContent, CardHeader } from '../../components/ui/card'
import { instant, quantity, text, type ObjectValue } from './operationsModels'

// Values arrive through the closed protected-data parser. Rendering a case does
// not establish ordinary Explorer permissions or fetch contract metadata.
export function DisclosureEventCards({ items, level }: { items: ObjectValue[]; level: string }) {
  if (!items.length) return <p className="text-sm text-neutral-500">No eligible events on this page.</p>
  const label = level === 'full' ? 'Full' : level === 'pseudonymous' ? 'Pseudonymous' : 'Redacted'
  return <div className="space-y-4">{items.map(event => {
    const disclosed = level === 'full' && event.payload === 'disclosed'
    return <Card key={text(event.eventId)} role="article" aria-label={`Disclosed event ${String(event.logIndex)}`} data-testid="disclosure-event-card" data-event-id={text(event.eventId)} className="min-w-0">
      <CardHeader className="gap-2 p-4 pb-3">
        <div className="flex flex-wrap items-center gap-2">
          <Badge className="font-mono">{String(event.logIndex)}</Badge><span className="text-sm text-neutral-500">Log Index</span>
          <Badge className="border-transparent bg-purple-100 text-purple-700">Disclosed</Badge>
          <Badge variant="outline">{label}</Badge>
        </div>
        <dl className="flex flex-wrap gap-x-5 gap-y-1 text-xs text-neutral-500">
          <div className="flex gap-1"><dt>Block</dt><dd>{quantity(event.blockNumber)}</dd></div>
          <div className="flex gap-1"><dt>Transaction index</dt><dd>{String(event.transactionIndex)}</dd></div>
          <div className="flex gap-1"><dt>Time</dt><dd>{instant(event.blockTime)}</dd></div>
        </dl>
      </CardHeader>
      <CardContent className="min-w-0 space-y-4 p-4 pt-0">
        <div className="flex flex-col gap-1 text-sm sm:flex-row sm:gap-3"><span className="w-20 shrink-0 text-neutral-500">Emitter</span><code className="min-w-0 break-all">{text(event.emitter)}</code></div>
        {!disclosed ? <p className="text-sm italic text-neutral-500">Payload withheld</p> : <>
          <div className="space-y-2"><h4 className="text-sm text-neutral-500">Topics</h4>{(event.topics as string[]).length ? <ol className="space-y-2">{(event.topics as string[]).map((topic, index) => <li key={index} className="flex items-start gap-2 text-xs"><span className="shrink-0 font-mono text-neutral-400">[{index}]</span><code className="min-w-0 break-all">{topic}</code></li>)}</ol> : <p className="text-sm text-neutral-500">No topics</p>}</div>
          <div className="space-y-2"><h4 className="text-sm text-neutral-500">Data</h4><pre className="max-h-64 overflow-auto whitespace-pre-wrap break-all rounded-lg bg-neutral-50 p-3 font-mono text-xs">{event.data as string}</pre></div>
          <details className="text-sm"><summary className="cursor-pointer text-primary">Transaction and block hashes</summary><dl className="mt-2 space-y-2 text-xs"><dt className="text-neutral-500">Transaction hash</dt><dd className="break-all font-mono">{text(event.transactionHash)}</dd><dt className="text-neutral-500">Block hash</dt><dd className="break-all font-mono">{text(event.blockHash)}</dd></dl></details>
        </>}
      </CardContent>
    </Card>
  })}</div>
}
