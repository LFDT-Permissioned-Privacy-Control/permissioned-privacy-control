import { useEffect, useState } from 'react'
import type { OperationScope } from './controller'

// A view/filter context borrows its parent's verified session, but has a
// shorter lifetime. Changing context cancels reads and retires late results.
export function useOperationContext(parent: OperationScope): OperationScope | null {
  const [owned, setOwned] = useState<{ parent: OperationScope; scope: OperationScope } | null>(null)
  useEffect(() => {
    const controller = new AbortController(), cancel = () => controller.abort()
    parent.signal.addEventListener('abort', cancel, { once: true })
    if (parent.signal.aborted) cancel()
    const check = () => {
      if (controller.signal.aborted) throw Error('The selected view changed. Read the current view again.')
      parent.check()
    }
    const scope: OperationScope = {
      ...parent, signal: controller.signal, check, dispose: cancel,
      async request<T>(endpoint: string, options: RequestInit = {}): Promise<T> {
        check()
        const request = new AbortController(), stop = () => request.abort()
        controller.signal.addEventListener('abort', stop, { once: true })
        options.signal?.addEventListener('abort', stop, { once: true })
        if (options.signal?.aborted) stop()
        try {
          if (request.signal.aborted) throw Error('The selected request was canceled.')
          const value = await parent.request<T>(endpoint, { ...options, signal: request.signal })
          check()
          if (request.signal.aborted) throw Error('The selected request was canceled.')
          return value
        } finally {
          controller.signal.removeEventListener('abort', stop)
          options.signal?.removeEventListener('abort', stop)
        }
      },
    }
    setOwned({ parent, scope })
    return () => { parent.signal.removeEventListener('abort', cancel); cancel() }
  }, [parent])
  return owned?.parent === parent && !owned.scope.signal.aborted ? owned.scope : null
}
