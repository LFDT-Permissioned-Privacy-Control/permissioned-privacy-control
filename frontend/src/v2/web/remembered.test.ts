import { beforeEach, describe, expect, it } from 'vitest'
import { forgetRemembered, remember, remembered } from './remembered'
import { Flow, Self } from './protocol'
import { MultiSession } from '../auth/multiProtocol'

const pair: MultiSession = { actorId: 'ops:p1:' + 'A'.repeat(43), browserSessionId: '11111111-1111-1111-1111-111111111111', provider: 'azure', sourceProfile: 'entra' }
const self: Self = { actorId: pair.actorId, principalKind: 'human', sourceProfile: 'entra', sourceProfileDigest: 'sha256:' + 'a'.repeat(64), expiresAt: 1300, organizations: [] }
const flow: Flow = { id: '22222222-2222-2222-2222-222222222222', clientId: 'explorer', displayName: 'Explorer', expiresAt: 1300 }
describe('bounded remembered same Azure pair', () => {
  beforeEach(() => localStorage.clear())
  it('requires exact client, actor, profile digest and original browser family', () => {
    expect(remembered(flow, self, pair, 1000)).toBe(false)
    remember(flow, self, pair, 1000)
    expect(remembered(flow, self, pair, 1001)).toBe(true)
    expect(remembered({ ...flow, clientId: 'other' }, self, pair, 1001)).toBe(false)
    expect(remembered(flow, { ...self, sourceProfileDigest: 'sha256:' + 'b'.repeat(64) }, pair, 1001)).toBe(false)
    expect(remembered(flow, self, { ...pair, browserSessionId: flow.id }, 1001)).toBe(false)
    expect(remembered(flow, self, { ...pair, provider: 'privado' }, 1001)).toBe(false)
  })
  it('never slides original 24h and Forget removes it', () => {
    remember(flow, self, pair, 1000); remember(flow, self, pair, 10000)
    expect(remembered(flow, self, pair, 87399)).toBe(true)
    expect(remembered(flow, self, pair, 87400)).toBe(false)
    remember(flow, self, pair, 90000); forgetRemembered(); expect(remembered(flow, self, pair, 90001)).toBe(false)
  })
  it('bounds client count and rejects malformed, duplicate and extended entries', () => {
    for (let i = 0; i < 40; i++) remember({ ...flow, clientId: 'app' + i }, self, pair, 1000)
    expect(remembered({ ...flow, clientId: 'app0' }, self, pair, 1001)).toBe(false)
    expect(remembered({ ...flow, clientId: 'app39' }, self, pair, 1001)).toBe(true)
    const key = 'ops-v2.remembered-apps', stored = localStorage.getItem(key)!
    const v = JSON.parse(stored); v.choices[0].expiresAt++; localStorage.setItem(key, JSON.stringify(v))
    expect(remembered({ ...flow, clientId: 'app39' }, self, pair, 1001)).toBe(false)
    localStorage.setItem(key, stored.replace('"version":1', '"version":1,"version":1'))
    expect(remembered({ ...flow, clientId: 'app39' }, self, pair, 1001)).toBe(false)
  })
})
