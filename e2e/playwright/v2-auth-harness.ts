// Owned integration fixture only; this file is never a product entry point.
import { BrowserAuthClient } from '../../frontend/src/v2/auth/client'
import type { AccessResult, BrowserSession } from '../../frontend/src/v2/auth/protocol'

let client = new BrowserAuthClient()
let requests = 0
const originalFetch = window.fetch.bind(window)
window.fetch = (...args) => { requests++; return originalFetch(...args) }
const metadata = (value: AccessResult) => ({ actorId: value.actorId, browserSessionId: value.browserSessionId })
Object.assign(window, { authHarness: {
  providers: () => client.providers(),
  start: (profileId: string) => client.startLogin(profileId),
  callback: async (state: string, code: string) => {
    history.replaceState(null, '', '/auth/azure/callback?' + new URLSearchParams({ state, code }))
    return metadata(await client.completeCallback())
  },
  currentCallback: async () => metadata(await client.completeCallback()),
  restore: async () => metadata(await client.restore()),
  logout: (expected: BrowserSession) => client.logout(expected),
  own: (expected: BrowserSession) => client.withAccess(expected, async token => {
    const response = await fetch('/__test/protected', { headers: { Authorization: 'Bearer ' + token } })
    if (!response.ok) throw new Error('fixture_protected_request')
    return response.json()
  }),
  requests: () => requests,
  reset: () => { client = new BrowserAuthClient() },
} })
