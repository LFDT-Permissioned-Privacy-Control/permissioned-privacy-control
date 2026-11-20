import { useEffect, useState } from 'react'
import type { OperationScope } from './controller'
import { address, record, rows } from './operationsModels'
import { checkedDecimals } from './exactAmounts'

export interface ApprovedToken { address: string; symbol: string; decimals: number }
export function approvedTokens(value: unknown): ApprovedToken[] {
  const tokens = rows(record(value).data, 4096).map(row => {
    if (typeof row.tokenAddress !== 'string' || row.tokenAddress !== 'native' && !address(row.tokenAddress) || typeof row.symbol !== 'string' || row.symbol.length > 256)
      throw Error('The approved token catalog is unavailable.')
    return { address: row.tokenAddress, symbol: row.symbol, decimals: checkedDecimals(row.decimals) }
  })
  if (new Set(tokens.map(t => t.address)).size !== tokens.length) throw Error('The approved token catalog contains duplicate addresses.')
  // Native prices are valid catalog rows, but cannot be ERC-20 addresses.
  return tokens.filter(token => token.address !== 'native')
}
// Operational catalog only. Local source drafts never provide operational units.
export function useApprovedTokens(scope: OperationScope, org: string) {
  const [state, setState] = useState<{ org: string; scope: OperationScope; tokens: ApprovedToken[]; error: string | null }>({ org, scope, tokens: [], error: null })
  useEffect(() => {
    let live = true
    const abort = new AbortController()
    if (org) void (async () => {
      try {
        scope.check()
        const value = await scope.request(`/api/v2/orgs/${org}/compliance/tokens`, { signal: abort.signal })
        scope.check()
        const tokens = approvedTokens(value)
        if (live) setState({ org, scope, tokens, error: null })
      } catch {
        if (live && !scope.signal.aborted) setState({ org, scope, tokens: [], error: 'Approved token units unavailable. Use an explicit address and exact base units.' })
      }
    })()
    return () => { live = false; abort.abort() }
  }, [scope, org])
  return state.org === org && state.scope === scope ? state : { tokens: [], error: null }
}
