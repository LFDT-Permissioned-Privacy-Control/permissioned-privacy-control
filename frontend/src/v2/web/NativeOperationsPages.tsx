import { useEffect, useState } from 'react'
import { Controller, type OperationScope, type State } from './controller'
import { NativeCompliance } from './NativeCompliance'
import { NativeDisclosures } from './NativeDisclosures'
import { NativeDiagnostics } from './NativeDiagnostics'
import { NativeAccessLogs } from './NativeAccessLogs'

export function NativeOperationsPage({
  controller,
  state,
  section,
}: {
  controller: Controller
  state: State
  section: 'compliance' | 'disclosures' | 'logs' | 'diagnostics'
}) {
  const key = `${controller.scopeRevision}:${state.self?.actorId}:${state.self?.expiresAt}:${state.self?.sourceProfileDigest}:${section}`
  return <OwnedOperations key={key} controller={controller} section={section} />
}
function OwnedOperations({
  controller,
  section,
}: {
  controller: Controller
  section: 'compliance' | 'disclosures' | 'logs' | 'diagnostics'
}) {
  const [scope, setScope] = useState<OperationScope>(),
    [error, setError] = useState<string>()
  useEffect(() => {
    const abort = new AbortController()
    let owned: OperationScope | undefined
    void controller
      .captureOperations(abort.signal)
      .then((value) => {
        owned = value
        value.check()
        if (!abort.signal.aborted) setScope(value)
        else value.dispose()
      })
      .catch(() => {
        if (!abort.signal.aborted)
          setError('Cannot verify this operational session. Refresh your session and try again.')
      })
    return () => {
      abort.abort()
      owned?.dispose()
    }
  }, [controller])
  if (error)
    return (
      <p role="alert" className="text-error-dark">
        {error}
      </p>
    )
  if (!scope)
    return (
      <p role="status" className="py-8 text-neutral-500">
        Verifying your operational session…
      </p>
    )
  if (section === 'compliance') return <NativeCompliance scope={scope} />
  if (section === 'diagnostics') return <NativeDiagnostics scope={scope} />
  if (section === 'logs') return <NativeAccessLogs scope={scope} />
  return <NativeDisclosures scope={scope} />
}
