import { act, cleanup, renderHook } from '@testing-library/react'
import { afterEach, expect, it, vi } from 'vitest'
import { caseDisplayStatus, useCaseDisplayClock } from './caseDisplay'

const now = Date.parse('2026-11-20T12:00:00Z'), seconds = now / 1000
afterEach(() => { cleanup(); vi.useRealTimers() })

it('expires only stored-open cases at the exact boundary and preserves revoked/closed precedence', () => {
  expect(caseDisplayStatus({ status: 'open', expiresAt: seconds }, now - 1)).toEqual({ label: 'Open', variant: 'success' })
  expect(caseDisplayStatus({ status: 'open', expiresAt: seconds }, now)).toEqual({ label: 'Expired', variant: 'secondary' })
  expect(caseDisplayStatus({ status: 'open', expiresAt: seconds }, now + 1)).toEqual({ label: 'Expired', variant: 'secondary' })
  expect(caseDisplayStatus({ status: 'revoked', expiresAt: seconds - 1 }, now)).toEqual({ label: 'Revoked', variant: 'secondary' })
  expect(caseDisplayStatus({ status: 'closed', expiresAt: seconds - 1 }, now)).toEqual({ label: 'Closed', variant: 'secondary' })
})

it('updates at the nearest case expiry using one local timer and releases it on unmount', async () => {
  vi.useFakeTimers(); vi.setSystemTime(now)
  const cases = [{ status: 'open', expiresAt: seconds + 1 }, { status: 'open', expiresAt: seconds + 2 }]
  const { result, unmount } = renderHook(() => useCaseDisplayClock(cases, seconds + 3))
  expect(vi.getTimerCount()).toBe(1)
  await act(async () => { await vi.advanceTimersByTimeAsync(999) })
  expect(caseDisplayStatus(cases[0], result.current).label).toBe('Open')
  await act(async () => { await vi.advanceTimersByTimeAsync(1) })
  expect(caseDisplayStatus(cases[0], result.current).label).toBe('Expired')
  expect(caseDisplayStatus(cases[1], result.current).label).toBe('Open')
  expect(cases[0].status).toBe('open')
  expect(vi.getTimerCount()).toBe(1)
  unmount()
  expect(vi.getTimerCount()).toBe(0)
})

it('does not schedule work for expired/revoked cases or beyond the original session', () => {
  vi.useFakeTimers(); vi.setSystemTime(now)
  const cases = [{ status: 'open', expiresAt: seconds - 1 }, { status: 'revoked', expiresAt: seconds + 1 }, { status: 'open', expiresAt: seconds + 2 }, { status: 'open', expiresAt: seconds + 3 }]
  renderHook(() => useCaseDisplayClock(cases, seconds + 2))
  expect(vi.getTimerCount()).toBe(0)
})
