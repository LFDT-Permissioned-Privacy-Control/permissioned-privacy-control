import { useEffect, useRef, useState } from 'react'
import { Check, Copy, KeyRound } from 'lucide-react'
import { Button } from '../../components/ui/button'
import { Card, CardContent, CardHeader, CardTitle } from '../../components/ui/card'
import { CopyValue, type AccountOrganization } from '../../components/auth/AccountPresentation'
import { SelectField } from './operationsUI'
import type { Controller } from './controller'

export function RPCOnboarding({ controller, organizations, busy, expiresAt, onCopy }: { controller: Controller; organizations: readonly AccountOrganization[]; busy: boolean; expiresAt: number; onCopy?: (format: 'token' | 'header' | 'foundry') => Promise<boolean> }) {
  const [organization, setOrganization] = useState(organizations.length === 1 ? organizations[0].id : ''), [copied, setCopied] = useState('')
  const timer = useRef<ReturnType<typeof setTimeout>>()
  useEffect(() => () => clearTimeout(timer.current), [])
  const org = organizations.find(value => value.id === organization)
  const endpoint = org ? new URL('/rpc/' + org.id, window.location.origin).href : ''
  async function copy(format: 'token' | 'header' | 'foundry') {
    setCopied('')
    if (await (onCopy ? onCopy(format) : controller.copyOwnRPCCredential(format))) { setCopied(format); clearTimeout(timer.current); timer.current = setTimeout(() => setCopied(''), 2000) }
  }
  return <Card data-testid="rpc-onboarding"><CardHeader><CardTitle className="flex items-center gap-2 text-base"><KeyRound className="h-4 w-4 text-primary" />Authenticated RPC access</CardTitle></CardHeader><CardContent className="space-y-4">
    <SelectField label="RPC organization" value={organization} onChange={setOrganization} disabled={busy || organizations.length === 1} options={[{ value: '', label: 'Select an organization' }, ...organizations.map(value => ({ value: value.id, label: value.name }))]} />
    {endpoint ? <div><p className="mb-1 text-xs uppercase tracking-wide text-neutral-400">RPC endpoint</p><div className="flex items-center gap-2 rounded-lg bg-neutral-100 p-3"><code className="min-w-0 flex-1 break-all text-xs">{endpoint}</code><CopyValue value={endpoint} label="Copy RPC URL" /></div></div> : <p className="text-sm text-neutral-500">Choose one of your verified organizations to see its RPC URL.</p>}
    <div className="flex flex-wrap gap-2">{([['token', 'Copy access token'], ['header', 'Copy Authorization header'], ['foundry', 'Copy for Foundry']] as const).map(([format, label]) => <Button key={format} variant="outline" size="sm" disabled={busy || !org} onClick={() => void copy(format)}>{copied === format ? <Check className="mr-2 h-4 w-4 text-success-dark" /> : <Copy className="mr-2 h-4 w-4" />}{copied === format ? 'Copied' : label}</Button>)}</div>
    <p className="text-xs text-neutral-500">Your token grants your verified permissions until <time dateTime={new Date(expiresAt * 1000).toISOString()}>{new Date(expiresAt * 1000).toLocaleString()}</time>. Keep it private; copy it again after renewing your session.</p>
    {endpoint && <details className="rounded-lg border border-neutral-200 p-3 text-sm"><summary className="cursor-pointer font-medium text-primary">Quick start</summary><ol className="mt-3 list-inside list-decimal space-y-2 text-neutral-600"><li>Copy the RPC URL for the organization you want to use.</li><li>Copy the Authorization header into your HTTP client, or paste the Foundry export command into your terminal.</li><li>For example, run <code className="break-all text-xs">cast block-number --rpc-url {endpoint}</code>. Every request still goes through your approved RPC and policy permissions.</li></ol></details>}
  </CardContent></Card>
}
