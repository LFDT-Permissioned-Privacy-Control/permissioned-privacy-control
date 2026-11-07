import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { webcrypto } from 'node:crypto'
import { NewMultiClient } from '../multiClient'
import { activeMulti, decodeMarker, deniedMulti, readMultiMarker, writeMultiMarker } from '../multiContext'
import { Candidate, multiAccess, MultiSession, proofRequired, requestUri } from '../multiProtocol'
import { access } from '../protocol'

// Deterministic unit serialization seam only. Real origin Web Locks and cookies
// are exercised by the separate Chrome/Go HTTP qualification harness.
vi.mock('../context', async original => {
  const actual = await original<typeof import('../context')>()
  let tail = Promise.resolve()
  return { ...actual, locked: <T>(work: () => Promise<T>) => {
    const result = tail.then(work); tail = result.then(() => undefined, () => undefined); return result
  } }
})

const actorA = 'ops:p1:' + 'A'.repeat(43)
const familyA = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
const requestA = 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb'
const pair: MultiSession = { actorId: actorA, browserSessionId: familyA, provider: 'privado', sourceProfile: 'role' }
const did = 'did:iden3:polygon:amoy:123456789ABCDEFGH'
let now: number
const pending = () => ({ ...pair, status: 'proof_required', provider: 'privado', principalKind: 'human', mode: 'renew',
  requestId: requestA, requestUri: requestUri(requestA), expiresAt: now + 200 })
const credential = () => ({ ...pair, accessToken: 'a.b.c', tokenType: 'Bearer', principalKind: 'human', expiresAt: now + 200 })
const candidate = (): Candidate => ({ status: 'candidate', requestId: requestA, holderDid: did, network: 'polygon:amoy',
  actorId: actorA, sourceProfile: 'role', proofDigest: 'sha256:' + 'a'.repeat(64), verifiedAt: now, expiresAt: now + 200 })
const response = (value: unknown) => new Response(JSON.stringify(value), { headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' } })
beforeEach(() => {
  now = Math.floor(Date.now() / 1000)
  localStorage.clear()
  vi.stubGlobal('location', { origin: 'https://ops.test', protocol: 'https:' })
  vi.stubGlobal('crypto', webcrypto)
})
afterEach(() => vi.unstubAllGlobals())

describe('explicit multi-provider closed protocol and marker', () => {
  it('keeps the Azure-only parser closed and rejects extended/mismatched pending identity', () => {
    expect(multiAccess(credential()).provider).toBe('privado')
    expect(() => access(credential())).toThrow('invalid_response')
    expect(proofRequired(pending()).requestId).toBe(requestA)
    for (const change of [{ accessToken: 'forbidden' }, { provider: 'azure' }, { mode: 'login' },
      { requestUri: 'https://other.test/api/v2/auth/privado/requests/' + requestA },
      { requestUri: requestUri(requestA) + '?ignored=1' }, { expiresAt: now + 1000 }, { actorId: 'did:untrusted' }]) {
      expect(() => proofRequired({ ...pending(), ...change })).toThrow('invalid_response')
    }
  })
  it('requires exact all-or-null context and disjoint flow capture, within the actual byte bound', () => {
    const marker = { ...deniedMulti(pair), pendingFlow: { kind: 'privado' as const, mode: 'renew' as const,
      requestId: requestA, sourceProfile: 'role', expiresAt: now + 200, expectedActorId: actorA, expectedSessionId: familyA } }
    expect(decodeMarker(marker)).toEqual(marker)
    for (const change of [{ version: 1 }, { actorId: null }, { sourceProfile: null }, { extra: true },
      { pendingFlow: { ...marker.pendingFlow, expectedSessionId: requestA } },
      { pendingFlow: { ...marker.pendingFlow, mode: 'login', expectedSessionId: familyA } }]) {
      expect(() => decodeMarker({ ...marker, ...change })).toThrow()
    }
    const worstProfile = '"\\'.repeat(64)
    const worst = { ...activeMulti({ ...pair, sourceProfile: worstProfile }), pendingFlow: {
      ...marker.pendingFlow, sourceProfile: worstProfile, expiresAt: Number.MAX_SAFE_INTEGER } }
    expect(new TextEncoder().encode(JSON.stringify(worst)).length).toBeLessThanOrEqual(2048)
    writeMultiMarker(worst)
    expect(readMultiMarker()).toEqual(worst)
    expect(() => decodeMarker({ ...deniedMulti(), phase: 'active' })).toThrow()
    expect(() => decodeMarker({ ...marker, pendingFlow: { ...marker.pendingFlow, proof: 'never-store' } })).toThrow()
  })
})

describe('non-authorizing continuation and explicit completion', () => {
  it('bootstraps once, preserves public UUID across reload, and never runs business work while pending', async () => {
    const fetch = vi.fn(async () => response(pending()))
    vi.stubGlobal('fetch', fetch)
    const client = NewMultiClient()
    expect((await client.restore()).status).toBe('proof_required')
    expect(JSON.parse(fetch.mock.calls[0][1].body)).toEqual({ mode: 'bootstrap' })
    const loaded = NewMultiClient()
    const [a, b] = await Promise.all([loaded.restore(), loaded.needAccess(pair)])
    expect(a).toEqual(b)
    expect(a.status).toBe('proof_required')
    const operation = vi.fn(async () => 'must-not-run')
    expect((await loaded.withAccess(pair, operation)).status).toBe('proof_required')
    expect(operation).not.toHaveBeenCalled()
    expect(fetch).toHaveBeenCalledTimes(1)
    const stored = localStorage.getItem('ops-v2.browser-context')!
    expect(stored).toContain(requestA)
    for (const forbidden of ['accessToken', 'proofDigest', 'holderDid', 'nonce', 'roles']) expect(stored).not.toContain(forbidden)
  })
  it('does not adopt cookieB when active markerA renews, including same-actor new-family', async () => {
    writeMultiMarker(activeMulti(pair))
    const fetch = vi.fn(async () => response({ ...pending(), browserSessionId: requestA }))
    vi.stubGlobal('fetch', fetch)
    const client = NewMultiClient()
    await expect(client.restore()).rejects.toThrow('session_changed')
    expect(JSON.parse(fetch.mock.calls[0][1].body)).toEqual({ mode: 'renew', expectedActorId: actorA, expectedSessionId: familyA })
    expect(readMultiMarker()?.phase).toBe('require-login')
    expect(readMultiMarker()?.pendingFlow).toBeNull()
    await expect(NewMultiClient().restore()).rejects.toThrow('login_required')
    expect(fetch).toHaveBeenCalledTimes(1)
  })
  it('requires recipient preview and explicit confirmation; consumes before POST and preserves family', async () => {
    const fetch = vi.fn(async (url: string) => {
      if (url.endsWith('/renew')) return response(pending())
      if (url.endsWith('/preview')) return response(candidate())
      if (url.endsWith('/complete')) {
        expect(readMultiMarker()?.pendingFlow).toBeNull()
        expect(readMultiMarker()?.phase).toBe('require-login')
        return response(credential())
      }
      throw new Error('unexpected route')
    })
    vi.stubGlobal('fetch', fetch)
    const client = NewMultiClient()
    await client.restore()
    await expect(client.confirmPrivado(candidate())).rejects.toThrow('invalid_response')
    const previewed = await client.previewPrivado(requestA)
    expect(previewed.status).toBe('candidate')
    expect(fetch).toHaveBeenCalledTimes(2) // No automatic completion.
    const result = await client.confirmPrivado(previewed as Candidate)
    expect(result.browserSessionId).toBe(familyA)
    const operation = vi.fn(async () => 'once')
    expect(await client.withAccess(pair, operation)).toEqual({ status: 'completed', value: 'once' })
    expect(operation).toHaveBeenCalledTimes(1)
    await expect(client.confirmPrivado(previewed as Candidate)).rejects.toThrow('login_required')
  })
  it('leaves a hard-denied marker after ambiguous completion and reload, with no old-flow retry', async () => {
    const fetch = vi.fn(async (url: string) => {
      if (url.endsWith('/renew')) return response(pending())
      if (url.endsWith('/preview')) return response(candidate())
      throw new Error('response lost after possible commit')
    })
    vi.stubGlobal('fetch', fetch)
    const client = NewMultiClient(); await client.restore()
    const selected = await client.previewPrivado(requestA)
    await expect(client.confirmPrivado(selected as Candidate)).rejects.toThrow('authentication_unavailable')
    expect(readMultiMarker()?.pendingFlow).toBeNull()
    await expect(NewMultiClient().restore()).rejects.toThrow('login_required')
    expect(fetch).toHaveBeenCalledTimes(3)
  })
  it('preserves selected LoginB while old AccessA is usable, then requires explicit B confirmation', async () => {
    const azure = { ...credential(), provider: 'azure', sourceProfile: 'azure' }
    const switched = { ...credential(), browserSessionId: requestA }
    const fetch = vi.fn(async (url: string) => {
      if (url.endsWith('/renew')) return response(azure)
      if (url.endsWith('/start')) return response({ requestId: requestA, requestUri: requestUri(requestA),
        sourceProfile: 'role', expiresAt: now + 200, expectedActorId: null })
      if (url.endsWith('/preview')) return response(candidate())
      return response(switched)
    })
    vi.stubGlobal('fetch', fetch)
    const client = NewMultiClient(); await client.restore()
    await client.startPrivadoLogin('role')
    const oldPair = { ...pair, provider: 'azure' as const, sourceProfile: 'azure' }
    expect((await client.withAccess(oldPair, async () => 'A')).status).toBe('completed')
    const clock = vi.spyOn(Date, 'now').mockReturnValue((now + 198) * 1000)
    expect((await client.needAccess(oldPair)).status).toBe('login_in_progress')
    expect(fetch).toHaveBeenCalledTimes(2) // No renewal replacing chosen LoginB.
    clock.mockRestore()
    const selected = await client.previewPrivado(requestA)
    expect((await client.confirmPrivado(selected as Candidate)).browserSessionId).toBe(requestA)
    expect(readMultiMarker()?.provider).toBe('privado')
  })
  it('rejecting an unknown holder abandons the flow and old candidate cannot complete', async () => {
    const fetch = vi.fn(async (url: string) => url.endsWith('/start')
      ? response({ requestId: requestA, requestUri: requestUri(requestA), sourceProfile: 'role', expiresAt: now + 200, expectedActorId: null })
      : response(candidate()))
    vi.stubGlobal('fetch', fetch)
    const client = NewMultiClient(); await client.startPrivadoLogin('role')
    const selected = await client.previewPrivado(requestA)
    await client.cancelPrivado(requestA)
    await expect(client.confirmPrivado(selected as Candidate)).rejects.toThrow('login_required')
    await expect(NewMultiClient().restore()).rejects.toThrow('login_required')
    expect(fetch).toHaveBeenCalledTimes(2)
  })
  it('a replacement flow or storage failure prevents completion before any network effect', async () => {
    const fetch = vi.fn(async (url: string) => url.endsWith('/renew') ? response(pending()) : response(candidate()))
    vi.stubGlobal('fetch', fetch)
    const client = NewMultiClient(); await client.restore()
    const selected = await client.previewPrivado(requestA)
    const marker = readMultiMarker()!
    writeMultiMarker({ ...marker, pendingFlow: { ...marker.pendingFlow!, requestId: familyA } } as typeof marker)
    await expect(client.confirmPrivado(selected as Candidate)).rejects.toThrow('login_required')
    writeMultiMarker(marker)
    const spy = vi.spyOn(Storage.prototype, 'setItem').mockImplementation(() => { throw new Error('quota') })
    await expect(client.confirmPrivado(selected as Candidate)).rejects.toThrow('login_required')
    spy.mockRestore()
    expect(fetch).toHaveBeenCalledTimes(2)
  })
})
