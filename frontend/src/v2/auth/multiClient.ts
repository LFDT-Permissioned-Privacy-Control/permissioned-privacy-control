import { AuthError, canonicalState, liveExpiry, object, text } from './protocol'
import { hashState, locked } from './context'
import { takeCallback } from './callback'
import { requestAuth } from './transport'
import { activeMulti, AzureFlow, deniedMulti, MultiMarker, multiPair, PrivadoFlow,
  readMultiMarker, requireMultiPair, unchangedMulti, writeMultiMarker } from './multiContext'
import { AccessOutcome, Candidate, holderDid, LoginPending, MultiAccess, multiAccess, multiProviders,
  MultiSession, OperationOutcome, Pending, Preview, preview, privadoStart, PrivadoStart,
  proofRequired, requestUri, sameSession, validSession } from './multiProtocol'

// Explicit version2 client. Tokens live only in this document; the shared
// marker selects a context/flow and never establishes identity or permissions.
export class MultiBrowserAuthClient {
  private memory: MultiAccess | null = null
  private remembered: MultiSession | null = null
  private blocked = false
  private inFlight: { key: string; promise: Promise<AccessOutcome> } | null = null
  private candidate: Candidate | null = null
  private selectedHolder: { requestId: string; did: string } | null = null

  async providers() { return locked(async () => multiProviders(await requestAuth('providers'))) }

  async startAzureLogin(profileId: string): Promise<{ authorizationUrl: string; expiresAt: number }> {
    return locked(async () => {
      if (!text(profileId, 128)) throw new AuthError('invalid_response')
      const initial = this.startMarker()
      try {
        const result = object(await requestAuth('azure/start', { profileId }), ['authorizationUrl', 'expiresAt'])
        if (!text(result.authorizationUrl, 16384) || !liveExpiry(result.expiresAt)) throw new AuthError('invalid_response')
        const url = new URL(result.authorizationUrl), state = url.searchParams.get('state')
        if (url.protocol !== 'https:' || url.host !== 'login.microsoftonline.com' || url.username || url.password ||
          url.hash || !/^\/[0-9a-f-]{36}\/oauth2\/v2\.0\/authorize$/.test(url.pathname) ||
          url.searchParams.getAll('state').length !== 1 || !canonicalState(state) ||
          url.searchParams.get('response_type') !== 'code' ||
          url.searchParams.get('redirect_uri') !== location.origin + '/auth/azure/callback') throw new AuthError('invalid_response')
        const flow: AzureFlow = { kind: 'azure', stateHash: await hashState(state), sourceProfile: profileId, expiresAt: result.expiresAt }
        unchangedMulti(initial)
        if (!liveExpiry(flow.expiresAt)) throw new AuthError('login_required')
        writeMultiMarker({ ...initial, pendingFlow: flow })
        this.blocked = false
        return { authorizationUrl: url.href, expiresAt: result.expiresAt }
      } catch (error) { return this.fail(initial, error) }
    })
  }

  async completeAzureCallback(): Promise<MultiAccess> {
    const callback = takeCallback() // Scrub query secrets synchronously.
    return locked(async () => {
      const marker = readMultiMarker(), flow = marker?.pendingFlow
      if (!marker || flow?.kind !== 'azure' || !liveExpiry(flow.expiresAt) ||
        flow.stateHash !== await hashState(callback.state)) throw new AuthError('invalid_callback')
      if (callback.rejected) {
        writeMultiMarker({ ...marker, pendingFlow: null })
        throw new AuthError('provider_rejected')
      }
      const inFlight = this.consume(marker)
      try {
        const result = multiAccess(await requestAuth('azure/complete', { state: callback.state, code: callback.code }))
        if (result.provider !== 'azure' || result.sourceProfile !== flow.sourceProfile) throw new AuthError('invalid_response')
        return this.publish(inFlight, result)
      } catch (error) { return this.fail(inFlight, error) }
    })
  }

  async startPrivadoLogin(profileId: string, expectedHolderDid?: string): Promise<PrivadoStart> {
    return locked(async () => {
      if (!text(profileId, 128) || expectedHolderDid !== undefined && !holderDid(expectedHolderDid)) throw new AuthError('invalid_response')
      const initial = this.startMarker()
      try {
        const body = expectedHolderDid === undefined ? { profileId } : { profileId, expectedHolderDid }
        const result = privadoStart(await requestAuth('privado/start', body), profileId)
        if ((expectedHolderDid === undefined) !== (result.expectedActorId === null)) throw new AuthError('invalid_response')
        const flow: PrivadoFlow = { kind: 'privado', mode: 'login', requestId: result.requestId,
          sourceProfile: result.sourceProfile, expiresAt: result.expiresAt,
          expectedActorId: result.expectedActorId, expectedSessionId: null }
        unchangedMulti(initial)
        writeMultiMarker({ ...initial, pendingFlow: flow })
        this.selectedHolder = expectedHolderDid === undefined ? null : { requestId: result.requestId, did: expectedHolderDid }
        this.blocked = false
        return { ...result }
      } catch (error) { return this.fail(initial, error) }
    })
  }

  async previewPrivado(requestId: string): Promise<Preview> {
    return locked(async () => {
      const { marker, flow } = this.currentFlow(requestId)
      try {
        const result = preview(await requestAuth('privado/preview', { requestId }), requestId, flow.sourceProfile, flow.expiresAt)
        if (result.status === 'candidate' && (flow.expectedActorId !== null && result.actorId !== flow.expectedActorId ||
          this.selectedHolder?.requestId === requestId && result.holderDid !== this.selectedHolder.did)) throw new AuthError('invalid_response')
        unchangedMulti(marker)
        this.candidate = result.status === 'candidate' ? { ...result } : null
        return { ...result }
      } catch (error) { return this.fail(marker, error) }
    })
  }

  // Call only after the UI displays full holderDID/network/profile and the user
  // explicitly selects it. Polling/restoration never invokes this operation.
  async confirmPrivado(selected: Candidate): Promise<MultiAccess> {
    return locked(async () => {
      const { marker, flow } = this.currentFlow(selected?.requestId)
      const candidate = preview(selected, flow.requestId, flow.sourceProfile, flow.expiresAt)
      if (candidate.status !== 'candidate' || !this.candidate || !this.sameCandidate(candidate, this.candidate) ||
        flow.expectedActorId !== null && candidate.actorId !== flow.expectedActorId) throw new AuthError('invalid_response')
      const body = { requestId: flow.requestId, expectedActorId: candidate.actorId,
        expectedHolderDid: candidate.holderDid, proofDigest: candidate.proofDigest,
        ...(flow.mode === 'renew' ? { expectedSessionId: flow.expectedSessionId } : {}) }
      const inFlight = this.consume(marker) // Pending disappears BEFORE POST.
      try {
        const result = multiAccess(await requestAuth('privado/complete', body))
        if (result.provider !== 'privado' || result.sourceProfile !== flow.sourceProfile || result.actorId !== candidate.actorId ||
          flow.mode === 'renew' && result.browserSessionId !== flow.expectedSessionId) throw new AuthError('session_changed')
        return this.publish(inFlight, result)
      } catch (error) { return this.fail(inFlight, error) }
    })
  }

  // Explicit local abandonment; no cancellation route or family mutation is
  // invented. The original server challenge expires and cannot restore this UI.
  async cancelPrivado(requestId: string): Promise<void> {
    return locked(async () => { const { marker } = this.currentFlow(requestId); this.consume(marker); this.blocked = true })
  }

  async restore(): Promise<AccessOutcome> {
    const result = await this.singleflight('restore', () => locked(async () => {
      const marker = readMultiMarker()
      if (this.blocked) throw new AuthError('login_required')
      if (!marker) {
        if (this.remembered) throw new AuthError('login_required')
        return this.rotate(null)
      }
      if (marker.actorId !== null) this.remember(multiPair(marker))
      if (marker.pendingFlow) return this.pending(marker)
      if (marker.phase !== 'active') throw new AuthError('login_required')
      return this.rotate(marker)
    }))
    return this.checked(result)
  }

  async needAccess(expected: MultiSession): Promise<AccessOutcome> {
    if (!validSession(expected)) throw new AuthError('login_required')
    const result = await this.singleflight(JSON.stringify(expected), () => locked(async () => {
      const marker = requireMultiPair(readMultiMarker(), expected)
      if (this.blocked) throw new AuthError('login_required')
      this.remember(expected)
      if (marker.phase === 'active' && this.memory && sameSession(this.memory, expected) && this.memory.expiresAt > Date.now() / 1000 + 5) {
        return { status: 'access' as const, access: { ...this.memory } }
      }
      if (marker.pendingFlow) return this.pending(marker)
      if (marker.phase !== 'active') throw new AuthError('login_required')
      return this.rotate(marker)
    }))
    return this.checked(result)
  }

  async withAccess<T>(expected: MultiSession, operation: (token: string) => Promise<T>): Promise<OperationOutcome<T>> {
    const result = await this.needAccess(expected)
    if (result.status !== 'access') return result
    // Exactly one captured-token operation. Pending proof never retries it.
    return { status: 'completed', value: await operation(result.access.accessToken) }
  }

  async logout(expected: MultiSession): Promise<void> {
    if (!validSession(expected)) throw new AuthError('login_required')
    return locked(async () => {
      const marker = requireMultiPair(readMultiMarker(), expected)
      const inFlight = this.consume(marker)
      this.remembered = { ...expected }
      try { await requestAuth('logout', { expectedActorId: expected.actorId, expectedSessionId: expected.browserSessionId }) }
      catch (error) { return this.fail(inFlight, error) }
    })
  }

  private startMarker(): MultiMarker {
    let marker: MultiMarker | null
    try { marker = readMultiMarker() } catch { marker = null; this.memory = null; this.remembered = null }
    const initial = marker ? { ...marker, pendingFlow: null } : deniedMulti()
    writeMultiMarker(initial)
    // Explicit user login is the sole context-replacement path. Retaining a
    // different document's old remembered pair here would make its new chosen
    // flow impossible to confirm; ordinary restore/needAccess never does this.
    this.remembered = marker?.actorId ? this.pair(multiPair(marker)) : null
    if (this.memory && (!this.remembered || !sameSession(this.memory, this.remembered))) this.memory = null
    this.candidate = null; this.selectedHolder = null
    return initial
  }
  private consume(marker: MultiMarker): MultiMarker {
    const next = deniedMulti(marker)
    writeMultiMarker(next)
    this.memory = null; this.candidate = null; this.selectedHolder = null
    return next
  }
  private publish(inFlight: MultiMarker, result: MultiAccess): MultiAccess {
    unchangedMulti(inFlight)
    if (!liveExpiry(result.expiresAt)) throw new AuthError('login_required')
    writeMultiMarker(activeMulti(result))
    this.remembered = this.pair(result); this.memory = { ...result }; this.blocked = false
    return { ...result }
  }
  private pending(marker: MultiMarker): Pending {
    const flow = marker.pendingFlow
    if (!flow || !liveExpiry(flow.expiresAt)) throw new AuthError('login_required')
    if (flow.kind === 'privado' && flow.mode === 'renew') {
      const pair = multiPair(marker)
      return { ...pair, status: 'proof_required', provider: 'privado', principalKind: 'human', mode: 'renew',
        requestId: flow.requestId, requestUri: requestUri(flow.requestId), expiresAt: flow.expiresAt }
    }
    const value: LoginPending = { status: 'login_in_progress', provider: flow.kind, sourceProfile: flow.sourceProfile, expiresAt: flow.expiresAt }
    if (flow.kind === 'privado') { value.requestId = flow.requestId; value.requestUri = requestUri(flow.requestId) }
    return value
  }
  private currentFlow(requestId: string): { marker: MultiMarker; flow: PrivadoFlow } {
    const marker = readMultiMarker(), flow = marker?.pendingFlow
    if (this.blocked || !marker || flow?.kind !== 'privado' || flow.requestId !== requestId || !liveExpiry(flow.expiresAt)) throw new AuthError('login_required')
    if (marker.actorId !== null) this.remember(multiPair(marker))
    return { marker, flow }
  }
  private async rotate(current: MultiMarker | null): Promise<AccessOutcome> {
    const pair = current ? multiPair(current) : null
    const inFlight = this.consume(current ?? deniedMulti())
    try {
      const body = pair ? { mode: 'renew', expectedActorId: pair.actorId, expectedSessionId: pair.browserSessionId } : { mode: 'bootstrap' }
      const data = await requestAuth('renew', body)
      if (data && typeof data === 'object' && (data as Record<string, unknown>).status === 'proof_required') {
        const result = proofRequired(data)
        if (pair && !sameSession(pair, result)) throw new AuthError('session_changed')
        const flow: PrivadoFlow = { kind: 'privado', mode: 'renew', requestId: result.requestId,
          sourceProfile: result.sourceProfile, expiresAt: result.expiresAt,
          expectedActorId: result.actorId, expectedSessionId: result.browserSessionId }
        unchangedMulti(inFlight)
        writeMultiMarker({ ...deniedMulti(result), pendingFlow: flow })
        this.remembered = this.pair(result)
        return result
      }
      const result = multiAccess(data)
      if (pair && !sameSession(pair, result)) throw new AuthError('session_changed')
      return { status: 'access', access: this.publish(inFlight, result) }
    } catch (error) { return this.fail(inFlight, error) }
  }
  private async checked(result: AccessOutcome): Promise<AccessOutcome> {
    try {
      return await locked(async () => {
        const marker = readMultiMarker()
        if (result.status === 'access') {
          if (!marker || marker.phase !== 'active' || !sameSession(multiPair(marker), result.access) || !liveExpiry(result.access.expiresAt)) throw new AuthError('session_changed')
          return { status: 'access', access: { ...result.access } }
        }
        if (!marker || !this.samePending(this.pending(marker), result)) throw new AuthError('session_changed')
        return { ...result }
      })
    } catch (error) {
      this.memory = null; this.blocked = true
      throw error instanceof AuthError ? error : new AuthError('authentication_unavailable')
    }
  }
  private pair(v: MultiSession): MultiSession { return { actorId: v.actorId, browserSessionId: v.browserSessionId, provider: v.provider, sourceProfile: v.sourceProfile } }
  private remember(pair: MultiSession): void {
    if (this.remembered && !sameSession(this.remembered, pair)) throw new AuthError('session_changed')
    this.remembered = this.pair(pair)
  }
  private sameCandidate(a: Candidate, b: Candidate): boolean {
    return a.requestId === b.requestId && a.holderDid === b.holderDid && a.actorId === b.actorId &&
      a.network === b.network && a.sourceProfile === b.sourceProfile && a.proofDigest === b.proofDigest &&
      a.verifiedAt === b.verifiedAt && a.expiresAt === b.expiresAt
  }
  private samePending(a: Pending, b: Pending): boolean {
    return a.status === b.status && a.provider === b.provider && a.sourceProfile === b.sourceProfile &&
      a.expiresAt === b.expiresAt && a.requestId === b.requestId && a.requestUri === b.requestUri &&
      (a.status !== 'proof_required' || b.status === 'proof_required' && sameSession(a, b))
  }
  private fail(marker: MultiMarker, error: unknown): never {
    this.memory = null; this.candidate = null; this.selectedHolder = null; this.blocked = true
    // Never overwrite another current context, including a new same-actor family.
    try { unchangedMulti(marker); writeMultiMarker(deniedMulti(marker)) } catch { /* Already denied or replaced; no adoption. */ }
    throw error instanceof AuthError ? error : new AuthError('authentication_unavailable')
  }
  private singleflight(key: string, work: () => Promise<AccessOutcome>): Promise<AccessOutcome> {
    if (this.inFlight?.key === key) return this.inFlight.promise
    const promise = work().catch(error => {
      this.memory = null; this.blocked = true
      throw error instanceof AuthError ? error : new AuthError('authentication_unavailable')
    })
    const slot = { key, promise }; this.inFlight = slot
    void promise.finally(() => { if (this.inFlight === slot) this.inFlight = null }).catch(() => undefined)
    return promise
  }
}

export function NewMultiClient(): MultiBrowserAuthClient { return new MultiBrowserAuthClient() }
