import { access, AccessResult, actor, AuthError, BrowserSession, canonicalState,
  liveExpiry, object, providers, Providers, responseJSON, same, session, text } from './protocol'
import { active, denied, hashState, locked, Marker, pairOf, readMarker,
  requireActive, requireUnchanged, writeMarker } from './context'
import { takeCallback } from './callback'

const PREFIX = '/api/v2/auth/'

// Instantiate once per browser document. This module has no V1 AuthContext,
// user directory, stored JWT, refresh-token reader or role-decoding fallback.
export class BrowserAuthClient {
  private memory: AccessResult | null = null
  private remembered: BrowserSession | null = null
  private blocked = false
  private inFlight: { key: string; promise: Promise<AccessResult> } | null = null

  private clear(): void { this.memory = null }
  private async request(path: string, body?: unknown): Promise<unknown> {
    const response = await fetch(PREFIX + path, {
      method: body === undefined ? 'GET' : 'POST', mode: 'same-origin',
      credentials: 'same-origin', redirect: 'error', cache: 'no-store',
      headers: body === undefined ? undefined : { 'Content-Type': 'application/json' },
      body: body === undefined ? undefined : JSON.stringify(body),
      signal: AbortSignal.timeout(25000),
    })
    if (path === 'logout' && response.status === 204 && response.headers.get('Cache-Control') === 'no-store') return undefined
    const data = await responseJSON(response)
    if (response.status !== 200) {
      const v = object(data, ['error'])
      if (v.error === 'session_changed') throw new AuthError('session_changed')
      if (v.error === 'reauthentication_required') throw new AuthError('login_required')
      throw new AuthError('authentication_unavailable')
    }
    if (path === 'logout') throw new AuthError('invalid_response')
    return data
  }
  async providers(): Promise<Providers> {
    return locked(async () => providers(await this.request('providers')))
  }
  async startLogin(profileId: string): Promise<{ authorizationUrl: string; expiresAt: number }> {
    return locked(async () => {
      if (!text(profileId, 128)) throw new AuthError('invalid_response')
      let current: Marker | null
      try { current = readMarker() }
      catch {
        // Explicit login may repair malformed NONcredential metadata. Other
        // operations never take this path or turn it into a bootstrap retry.
        this.clear()
        current = null
      }
      const initial = current ? { ...current, pendingLoginHash: null } : denied()
      writeMarker(initial)
      try {
        const result = object(await this.request('azure/start', { profileId }), ['authorizationUrl', 'expiresAt'])
        if (!text(result.authorizationUrl, 16384) || !liveExpiry(result.expiresAt)) throw new AuthError('invalid_response')
        const url = new URL(result.authorizationUrl)
        const state = url.searchParams.get('state')
        if (url.protocol !== 'https:' || url.host !== 'login.microsoftonline.com' || url.username || url.password ||
          url.hash || !/^\/[0-9a-f-]{36}\/oauth2\/v2\.0\/authorize$/.test(url.pathname) ||
          url.searchParams.getAll('state').length !== 1 || !canonicalState(state) ||
          url.searchParams.get('response_type') !== 'code' ||
          url.searchParams.get('redirect_uri') !== location.origin + '/auth/azure/callback') throw new AuthError('invalid_response')
        const hash = await hashState(state)
        requireUnchanged(initial)
        writeMarker({ ...initial, pendingLoginHash: hash })
        this.blocked = false
        return { authorizationUrl: url.href, expiresAt: result.expiresAt as number }
      } catch (error) { this.clear(); this.blocked = true; throw this.sanitize(error) }
    })
  }
  async completeCallback(): Promise<AccessResult> {
    // This runs synchronously up to the first await: callback secrets are gone
    // from the address bar even when storage/locks are unsupported.
    const callback = takeCallback()
    return locked(async () => {
      const current = readMarker()
      const hash = await hashState(callback.state)
      if (!current || current.pendingLoginHash !== hash) throw new AuthError('invalid_callback')
      if (callback.rejected) {
        writeMarker({ ...current, pendingLoginHash: null })
        throw new AuthError('provider_rejected')
      }
      const inFlight = denied(current)
      writeMarker(inFlight)
      this.clear()
      try {
        const result = access(await this.request('azure/complete', { state: callback.state, code: callback.code }))
        requireUnchanged(inFlight)
        writeMarker(active(result))
        this.remembered = this.pair(result)
        this.memory = result
        return { ...result }
      } catch (error) { this.clear(); this.blocked = true; throw this.sanitize(error) }
    })
  }
  // Explicit fresh-document restoration. It never turns a denied/malformed or
  // missing remembered context into an unbound bootstrap of another user.
  async restore(): Promise<AccessResult> {
    const result = await this.singleflight('restore', () => locked(async () => {
      if (this.blocked) throw new AuthError('login_required')
      const marker = readMarker()
      if (!marker) {
        if (this.remembered) throw new AuthError('login_required')
        return this.rotate(null)
      }
      if (marker.phase !== 'active') throw new AuthError('login_required')
      const pair = pairOf(marker)
      if (this.remembered && !same(this.remembered, pair)) throw new AuthError('session_changed')
      this.remembered = pair
      return this.rotate(marker)
    }))
    return this.checkedCopy(result)
  }
  async needAccess(expected: BrowserSession): Promise<AccessResult> {
    this.validExpected(expected)
    const key = expected.actorId + '/' + expected.browserSessionId
    const result = await this.singleflight(key, () => locked(async () => {
      if (this.blocked) throw new AuthError('login_required')
      const marker = requireActive(readMarker(), expected)
      if (this.remembered && !same(this.remembered, expected)) throw new AuthError('session_changed')
      this.remembered = this.pair(expected)
      if (this.memory && same(this.memory, expected) && this.memory.expiresAt > Date.now() / 1000 + 5) {
        return { ...this.memory }
      }
      return this.rotate(marker)
    }))
    return this.checkedCopy(result)
  }
  async withAccess<T>(expected: BrowserSession, operation: (accessToken: string) => Promise<T>): Promise<T> {
    const result = await this.needAccess(expected)
    // Admitted once with A's captured token. Never retry business work with B.
    return operation(result.accessToken)
  }
  async logout(expected: BrowserSession): Promise<void> {
    this.validExpected(expected)
    return locked(async () => {
      if (this.blocked) throw new AuthError('login_required')
      const current = requireActive(readMarker(), expected)
      writeMarker(denied(current))
      this.clear()
      this.remembered = this.pair(expected)
      try { await this.request('logout', { expectedActorId: expected.actorId, expectedSessionId: expected.browserSessionId }) }
      catch (error) { this.blocked = true; throw this.sanitize(error) }
    })
  }
  private async rotate(current: Marker | null): Promise<AccessResult> {
    const pair = current ? pairOf(current) : null
    const inFlight = denied(current)
    writeMarker(inFlight)
    this.clear()
    try {
      const body = pair ? { mode: 'renew', expectedActorId: pair.actorId, expectedSessionId: pair.browserSessionId } : { mode: 'bootstrap' }
      const result = access(await this.request('renew', body))
      if (pair && !same(pair, result)) throw new AuthError('session_changed')
      requireUnchanged(inFlight)
      writeMarker(active(result, current?.pendingLoginHash ?? null))
      this.remembered = this.pair(result)
      this.memory = result
      return { ...result }
    } catch (error) { this.clear(); this.blocked = true; throw this.sanitize(error) }
  }
  private async checkedCopy(result: AccessResult): Promise<AccessResult> {
    // Singleflight subscribers also recheck after another tab may have switched
    // while the original lock was released. Hints/events cannot authorize them.
    return locked(async () => {
      requireActive(readMarker(), result)
      if (!liveExpiry(result.expiresAt)) { this.clear(); throw new AuthError('login_required') }
      return { ...result }
    })
  }
  private singleflight(key: string, work: () => Promise<AccessResult>): Promise<AccessResult> {
    if (this.inFlight?.key === key) return this.inFlight.promise
    const promise = work().catch(error => { this.clear(); this.blocked = true; throw this.sanitize(error) })
    const slot = { key, promise }
    this.inFlight = slot
    void promise.finally(() => { if (this.inFlight === slot) this.inFlight = null }).catch(() => undefined)
    return promise
  }
  private pair(value: BrowserSession): BrowserSession {
    return { actorId: value.actorId, browserSessionId: value.browserSessionId }
  }
  private validExpected(value: BrowserSession): void {
    if (!actor(value?.actorId) || !session(value?.browserSessionId)) throw new AuthError('login_required')
  }
  private sanitize(error: unknown): AuthError {
    return error instanceof AuthError ? error : new AuthError('authentication_unavailable')
  }
}
