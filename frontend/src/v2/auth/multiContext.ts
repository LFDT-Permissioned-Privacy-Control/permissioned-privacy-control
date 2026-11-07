import { actor, AuthError, closedJSON, object, session } from './protocol'
import { CONTEXT_KEY } from './context'
import { MultiSession, profile, provider, requestUri, sameSession, validSession } from './multiProtocol'

export interface PrivadoFlow {
  kind: 'privado'; requestId: string; mode: 'login' | 'renew'; sourceProfile: string; expiresAt: number
  expectedActorId: string | null; expectedSessionId: string | null
}
export interface AzureFlow { kind: 'azure'; stateHash: string; sourceProfile: string; expiresAt: number }
export type Flow = PrivadoFlow | AzureFlow
export interface MultiMarker {
  version: 2; phase: 'active' | 'require-login'; actorId: string | null; browserSessionId: string | null
  provider: 'azure' | 'privado' | null; sourceProfile: string | null; pendingFlow: Flow | null
}
export function deniedMulti(value?: MultiMarker | MultiSession | null): MultiMarker {
  return { version: 2, phase: 'require-login', actorId: value?.actorId ?? null,
    browserSessionId: value?.browserSessionId ?? null, provider: value?.provider ?? null,
    sourceProfile: value?.sourceProfile ?? null, pendingFlow: null }
}
export function activeMulti(pair: MultiSession, flow: Flow | null = null): MultiMarker {
  return { ...deniedMulti(pair), phase: 'active', pendingFlow: flow }
}
export function multiPair(marker: MultiMarker): MultiSession {
  const p = { actorId: marker.actorId, browserSessionId: marker.browserSessionId, provider: marker.provider, sourceProfile: marker.sourceProfile } as MultiSession
  if (!validSession(p)) throw new AuthError('login_required')
  return p
}
export function decodeMarker(value: unknown): MultiMarker {
  const v = object(value, ['version', 'phase', 'actorId', 'browserSessionId', 'provider', 'sourceProfile', 'pendingFlow'])
  const valid = actor(v.actorId) && session(v.browserSessionId) && provider(v.provider) && profile(v.sourceProfile)
  const empty = v.actorId === null && v.browserSessionId === null && v.provider === null && v.sourceProfile === null
  if (v.version !== 2 || (v.phase !== 'active' && v.phase !== 'require-login') ||
    !(valid || v.phase === 'require-login' && empty)) throw new AuthError('login_required')
  if (v.pendingFlow !== null) {
    const f = v.pendingFlow && typeof v.pendingFlow === 'object' && !Array.isArray(v.pendingFlow) ? v.pendingFlow as Record<string, unknown> : null
    if (!f) throw new AuthError('login_required')
    if (f.kind === 'privado') {
      object(f, ['kind', 'requestId', 'mode', 'sourceProfile', 'expiresAt', 'expectedActorId', 'expectedSessionId'])
      if (!session(f.requestId) || (f.mode !== 'login' && f.mode !== 'renew') || !profile(f.sourceProfile) ||
        !(f.expectedActorId === null || actor(f.expectedActorId)) ||
        !(f.mode === 'login' ? f.expectedSessionId === null : valid && f.expectedActorId === v.actorId &&
          f.expectedSessionId === v.browserSessionId && v.provider === 'privado' && f.sourceProfile === v.sourceProfile)) throw new AuthError('login_required')
      requestUri(f.requestId)
    } else if (f.kind === 'azure') {
      object(f, ['kind', 'stateHash', 'sourceProfile', 'expiresAt'])
      if (typeof f.stateHash !== 'string' || !/^sha256:[0-9a-f]{64}$/.test(f.stateHash) || !profile(f.sourceProfile)) throw new AuthError('login_required')
    } else throw new AuthError('login_required')
    // Expired contexts stay distinguishable from absent bootstrap. Only an
    // explicit fresh start may replace them; reading never grants authority.
    if (typeof f.expiresAt !== 'number' || !Number.isSafeInteger(f.expiresAt) || f.expiresAt <= 0) throw new AuthError('login_required')
  }
  return v as unknown as MultiMarker
}
export function readMultiMarker(): MultiMarker | null {
  try {
    const raw = localStorage.getItem(CONTEXT_KEY)
    return raw === null ? null : decodeMarker(closedJSON(raw, 2048))
  } catch { throw new AuthError('login_required') }
}
export function writeMultiMarker(next: MultiMarker): void {
  try {
    decodeMarker(next)
    const raw = JSON.stringify(next)
    if (new TextEncoder().encode(raw).length > 2048) throw new Error()
    localStorage.setItem(CONTEXT_KEY, raw) // LAST persistence; no readback.
  } catch { throw new AuthError('login_required') }
}
export function unchangedMulti(expected: MultiMarker): void {
  if (JSON.stringify(readMultiMarker()) !== JSON.stringify(expected)) throw new AuthError('session_changed')
}
export function requireMultiPair(marker: MultiMarker | null, expected: MultiSession): MultiMarker {
  if (!marker) throw new AuthError('login_required')
  if (!sameSession(multiPair(marker), expected)) throw new AuthError('session_changed')
  return marker
}
