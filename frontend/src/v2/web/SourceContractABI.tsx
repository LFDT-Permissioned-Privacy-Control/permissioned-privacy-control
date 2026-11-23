import { useState } from 'react'
import { Check } from 'lucide-react'
import { ABIFunctionBrowser, ABIEventBrowser, type ABIEventView } from '../../components/rbac/ContractPresentation'
import { abiChoices } from './executionABI'
import { Button } from '../../components/ui/button'
import { Dialog, DialogContent, DialogHeader, DialogTitle } from '../../components/ui/dialog'
import type { JSONObject } from './sourceProject'

export function abiSummary(abi: unknown) { const rows = Array.isArray(abi) ? abi : []; return { entries: rows.length, functions: rows.filter(e => e && typeof e === 'object' && (e as JSONObject).type === 'function').length, events: rows.filter(e => e && typeof e === 'object' && (e as JSONObject).type === 'event').length } }
export function SourceContractABI({ contract }: { contract: JSONObject }) {
  const [open, setOpen] = useState(false), summary = abiSummary(contract.abi)
  return <><Button type="button" variant="outline" size="sm" className={summary.entries ? "text-success" : "text-neutral-500"} onClick={() => setOpen(true)}>{summary.entries > 0 && <Check className="mr-1 h-3.5 w-3.5" />}ABI · {summary.functions} functions · {summary.events} events</Button><Dialog open={open} onOpenChange={setOpen}><DialogContent className="max-w-3xl max-h-[85vh] overflow-y-auto"><DialogHeader><DialogTitle>{String(contract.name)} — public ABI</DialogTitle></DialogHeader><StructuredABI value={contract.abi} /><details><summary className="cursor-pointer text-sm font-medium">Advanced public ABI JSON</summary><pre className="mt-2 text-xs overflow-auto whitespace-pre-wrap break-all">{JSON.stringify(contract.abi, null, 2)}</pre></details><div className="flex justify-end"><Button variant="outline" onClick={() => setOpen(false)}>Close ABI</Button></div></DialogContent></Dialog></>
}

export function StructuredABI({ value }: { value: unknown }) {
  const summary = abiSummary(value)
  try {
    const choices = abiChoices(value), events: ABIEventView[] = []
    for (const entry of value as JSONObject[]) if (entry.type === 'event') {
      const event = abiChoices([entry]).events[0]
      events.push({ ...event, inputs: Array.isArray(entry.inputs) ? entry.inputs as unknown as ABIEventView['inputs'] : [] })
    }
    return <div className="space-y-4"><div className="rounded-lg bg-neutral-50 p-3 text-sm"><p className="font-medium">{summary.entries ? 'Public ABI loaded in source' : 'No ABI loaded'}</p><p className="mt-1 text-xs text-neutral-500">{summary.entries} entries · {summary.functions} functions · {summary.events} events. ABI assistance does not establish deployment or execution access.</p></div><ABIFunctionBrowser functions={choices.functions} /><ABIEventBrowser events={events} /></div>
  } catch (error) { return <p className="rounded-lg bg-warning-light p-3 text-sm text-warning-dark">This ABI cannot be presented safely: {(error as Error).message} It is retained in advanced JSON; use the matching Go tool to inspect it.</p> }
}
