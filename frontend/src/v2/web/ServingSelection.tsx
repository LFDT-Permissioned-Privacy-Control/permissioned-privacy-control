import { useEffect, useRef, useState } from 'react'
import { Button } from '../../components/ui/button'
import { object, text } from '../auth/protocol'
import type { Controller } from './controller'
import type { SourceDraft } from './sourceProject'

interface Selection {
  manifestDigest: string; sourceRevision: string; environment: string
  chainId: string; profile: string; evaluatorVersion: string
}
function selection(value: unknown): Selection {
  const v = object(value, ['manifestDigest', 'sourceRevision', 'environment', 'chainId', 'profile', 'evaluatorVersion'])
  if (typeof v.manifestDigest !== 'string' || !/^sha256:[0-9a-f]{64}$/.test(v.manifestDigest) ||
    !text(v.sourceRevision, 1024) || !text(v.environment, 128) || !text(v.profile, 256) || !text(v.evaluatorVersion, 256) ||
    typeof v.chainId !== 'string' || !/^[1-9][0-9]{0,19}$/.test(v.chainId)) throw Error('Invalid selection response')
  return v as unknown as Selection
}

export function ServingSelection({ controller, draft }: { controller: Controller; draft?: SourceDraft }) {
  const [value, setValue] = useState<Selection>(), [error, setError] = useState(false), [busy, setBusy] = useState(false)
  const pending = useRef<AbortController | null>(null)
  useEffect(() => () => pending.current?.abort(), [])
  const self = controller.snapshot().self
  if (!self?.organizations.some(o => o.isOrgAdmin || o.isOrgReadonlyAdmin)) return null
  async function check() {
    pending.current?.abort()
    const abort = new AbortController(); pending.current = abort
    setBusy(true); setError(false); setValue(undefined)
    let scope: Awaited<ReturnType<Controller['captureOperations']>> | undefined
    try {
      scope = await controller.captureOperations(abort.signal)
      const result = selection(await scope.request('/api/v2/self/selection'))
      scope.check()
      if (!abort.signal.aborted && pending.current === abort) setValue(result)
    } catch {
      if (!abort.signal.aborted && pending.current === abort) setError(true)
    } finally {
      scope?.dispose()
      if (!abort.signal.aborted && pending.current === abort) setBusy(false)
    }
  }
  const differs = value && draft && (['sourceRevision', 'environment', 'chainId', 'profile', 'evaluatorVersion'] as const).some(k => value[k] !== draft[k])
  return <section className="mt-3 border-t border-neutral-200 pt-3 text-xs text-neutral-500" aria-label="Running Core configuration">
    <div className="flex flex-wrap items-center gap-3"><span className="font-medium text-neutral-700">Running Core configuration</span><Button variant="outline" size="sm" disabled={busy} onClick={() => void check()}>{busy ? 'Checking…' : 'Check this OPS instance'}</Button></div>
    {error && <p role="alert" className="mt-2 text-error-dark">Could not verify the running configuration. Try again with a current admin session.</p>}
    {value && <div className="mt-2 space-y-2" role="status"><p>Selected revision: <strong className="text-neutral-700">{value.sourceRevision}</strong> · Environment: {value.environment} · Chain: {value.chainId}</p><p>{draft ? differs ? 'These revision or runtime settings differ from the imported draft.' : 'The revision and runtime settings match the draft labels. File contents have not been compared.' : 'This is the selection reported by this OPS instance.'} This does not check other OPS instances or the broker configuration.</p><details><summary className="cursor-pointer">Selected artifact</summary><p className="mt-1 break-all font-mono">{value.manifestDigest}</p><p className="mt-1">Profile: {value.profile} · Evaluator: {value.evaluatorVersion}</p></details></div>}
  </section>
}
