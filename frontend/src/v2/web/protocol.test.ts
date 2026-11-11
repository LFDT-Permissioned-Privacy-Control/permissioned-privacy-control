import { afterEach, describe, expect, it, vi } from 'vitest'
import { MultiAccess } from '../auth/multiProtocol'
import { completeFlow, FLOW_KEY, inspectFlow, ownSelf, readContinuation, walletLinks } from './protocol'

const pair = (): MultiAccess => ({ actorId: 'ops:p1:' + 'A'.repeat(43), browserSessionId: '11111111-1111-1111-1111-111111111111',
  accessToken: 'a.b.c', principalKind: 'human', provider: 'azure', sourceProfile: 'bank', tokenType: 'Bearer', expiresAt: Math.floor(Date.now() / 1000) + 300 })
const response = (value: unknown) => new Response(JSON.stringify(value), { headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' } })
afterEach(() => { vi.unstubAllGlobals(); sessionStorage.clear() })
describe('bounded own facts and app continuation protocol', () => {
  it('supports all 256 approved organizations and their legal Unicode/escaped names without a group directory', async () => {
    const access = pair(), value = { actorId: access.actorId, principalKind: 'human', sourceProfile: access.sourceProfile,
      sourceProfileDigest: 'sha256:' + 'a'.repeat(64), expiresAt: access.expiresAt, organizations: Array.from({ length: 256 }, (_, i) => ({
        id: (i + 1).toString(16).padStart(8, '0') + '-1111-1111-1111-111111111111', slug: 'a'.repeat(100), name: '<'.repeat(256), isOrgAdmin: true, isOrgReadonlyAdmin: false })) }
    value.organizations[0].name = 'Банк🏦<>&"\\\u2028\u2029\u0001'
    vi.stubGlobal('fetch', vi.fn(async () => response(value)))
    expect((await ownSelf(access, new AbortController().signal)).organizations).toEqual(value.organizations)
    value.organizations.push(value.organizations[0])
    await expect(ownSelf(access, new AbortController().signal)).rejects.toThrow('invalid_response')
  })
  it('rejects duplicate/oversized streamed self JSON and mismatched own identity', async () => {
    const access = pair()
    for (const raw of ['{"actorId":"one","actorId":"two"}', ' '.repeat((512 << 10) + 1) + '{}']) {
      vi.stubGlobal('fetch', vi.fn(async () => new Response(raw, { headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' } })))
      await expect(ownSelf(access, new AbortController().signal)).rejects.toThrow('invalid_response')
    }
  })
  it('inspects without a bearer, preserves original expiry and rejects Ready or ambiguous redirects', async () => {
    const a = pair(), id = '33333333-3333-3333-3333-333333333333'
    const fetcher = vi.fn(async () => response({ clientId: 'app', displayName: 'App', phase: 'pending', expiresAt: a.expiresAt }))
    vi.stubGlobal('fetch', fetcher)
    const flow = await inspectFlow(id, new AbortController().signal)
    expect((fetcher.mock.calls[0] as unknown as [string, RequestInit])[1].headers).toEqual({ 'Content-Type': 'application/json' })
    sessionStorage.setItem(FLOW_KEY, JSON.stringify({ version: 1, phase: 'pending', id, expiresAt: a.expiresAt }))
    expect(readContinuation()).toEqual({ id, expiresAt: a.expiresAt })
    for (const redirect of ['http://app.test/callback?code=' + 'A'.repeat(43) + '&state=x',
      'https://app.test/callback?code=' + 'A'.repeat(43) + '&state=x&state=y',
      'https://app.test/callback?code=' + 'B'.repeat(43) + '&state=x',
      'https://user@app.test/callback?code=' + 'A'.repeat(43) + '&state=x',
      'https://app.test/callback?code=' + 'A'.repeat(43) + '&state=x#fragment']) {
      fetcher.mockImplementation(async () => response({ redirectTo: redirect }))
      await expect(completeFlow(flow, a, a.accessToken, new AbortController().signal)).rejects.toThrow('invalid_response')
    }
    fetcher.mockImplementation(async () => response({ clientId: 'app', displayName: 'App', phase: 'ready', expiresAt: a.expiresAt }))
    await expect(inspectFlow(id, new AbortController().signal)).rejects.toThrow('invalid_response')
  })
  it('keeps real Privado message-fetch links bounded at the maximum canonical DNS origin', () => {
    const host = ['a'.repeat(63), 'b'.repeat(63), 'c'.repeat(63), 'd'.repeat(61)].join('.')
    expect(host.length).toBe(253)
    vi.stubGlobal('location', { origin: 'https://' + host + ':65535' })
    const uri = location.origin + '/api/v2/auth/privado/requests/11111111-1111-1111-1111-111111111111'
    const links = walletLinks(uri)
    expect(links.mobile.length).toBeLessThan(512); expect(links.web.length).toBeLessThan(512)
    expect(() => walletLinks(uri + '?other=1')).toThrow('invalid_response')
  })
})
