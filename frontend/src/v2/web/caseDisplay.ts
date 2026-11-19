import { useEffect, useState } from 'react'

interface CaseStatus { status: string; expiresAt: number }

export function caseDisplayStatus(value: CaseStatus, now = Date.now()): { label: string; variant: 'success' | 'secondary' } {
  if (value.status === 'revoked') return { label: 'Revoked', variant: 'secondary' }
  if (value.status === 'closed') return { label: 'Closed', variant: 'secondary' }
  if (value.status === 'open') return value.expiresAt * 1000 <= now
    ? { label: 'Expired', variant: 'secondary' }
    : { label: 'Open', variant: 'success' }
  return { label: value.status, variant: 'secondary' }
}

// One local timer for the nearest visible open case. The original session owner
// clears the page at its own expiry; cases expiring later need no display timer.
export function useCaseDisplayClock(cases: readonly CaseStatus[], sessionExpiresAt: number): number {
  const [revision, refresh] = useState(0), now = Date.now()
  const next = cases.reduce((earliest, value) => value.status === 'open' && value.expiresAt * 1000 > now && value.expiresAt < sessionExpiresAt
    ? Math.min(earliest, value.expiresAt * 1000) : earliest, Infinity)
  useEffect(() => {
    if (!Number.isFinite(next)) return
    const timer = setTimeout(() => refresh(value => value + 1), Math.max(1, next - Date.now()))
    return () => clearTimeout(timer)
  }, [next, revision])
  return now
}
