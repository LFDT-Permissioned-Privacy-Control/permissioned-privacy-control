import { actor, AuthError, BrowserSession, closedJSON, object, same, session } from './protocol'

export const CONTEXT_KEY = 'ops-v2.browser-context'
export const LOCK_NAME = 'ops-v2.identity'
export interface Marker {
  version: 1
  phase: 'active' | 'require-login'
  actorId: string | null
  browserSessionId: string | null
  pendingLoginHash: string | null
}
export function denied(pair?: BrowserSession | Marker | null): Marker {
  return { version: 1, phase: 'require-login', actorId: pair?.actorId ?? null,
    browserSessionId: pair?.browserSessionId ?? null, pendingLoginHash: null }
}
export function active(pair: BrowserSession, hash: string | null = null): Marker {
  return { version: 1, phase: 'active', actorId: pair.actorId,
    browserSessionId: pair.browserSessionId, pendingLoginHash: hash }
}
export function pairOf(marker: Marker): BrowserSession {
  if (!actor(marker.actorId) || !session(marker.browserSessionId)) throw new AuthError('login_required')
  return { actorId: marker.actorId, browserSessionId: marker.browserSessionId }
}
export function readMarker(): Marker | null {
  try {
    const raw = localStorage.getItem(CONTEXT_KEY)
    if (raw === null) return null
    const v = object(closedJSON(raw, 512), ['version', 'phase', 'actorId', 'browserSessionId', 'pendingLoginHash'])
    const validPair = actor(v.actorId) && session(v.browserSessionId)
    if (v.version !== 1 || (v.phase !== 'active' && v.phase !== 'require-login') ||
      !(validPair || v.phase === 'require-login' && v.actorId === null && v.browserSessionId === null) ||
      !(v.pendingLoginHash === null || typeof v.pendingLoginHash === 'string' && /^sha256:[0-9a-f]{64}$/.test(v.pendingLoginHash))) {
      throw new AuthError('login_required')
    }
    return v as unknown as Marker
  } catch { throw new AuthError('login_required') }
}
export function writeMarker(next: Marker): void {
  try {
    const raw = JSON.stringify(next)
    if (new TextEncoder().encode(raw).length > 512) throw new Error()
    // Web Storage setItem is synchronous and atomic on failure. Make this the
    // LAST persistence operation before local publication: a second read after
    // a successful write cannot turn it into a cross-tab transaction rollback.
    localStorage.setItem(CONTEXT_KEY, raw)
  } catch { throw new AuthError('login_required') }
}
export function requireUnchanged(expected: Marker): void {
  const current = readMarker()
  if (!current || JSON.stringify(current) !== JSON.stringify(expected)) throw new AuthError('session_changed')
}
export function requireActive(marker: Marker | null, expected: BrowserSession): Marker {
  if (!marker || marker.phase !== 'active') throw new AuthError('login_required')
  if (!same(pairOf(marker), expected)) throw new AuthError('session_changed')
  return marker
}
export async function hashState(state: string): Promise<string> {
  const bytes = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(state))
  return 'sha256:' + Array.from(new Uint8Array(bytes), n => n.toString(16).padStart(2, '0')).join('')
}
export async function locked<T>(work: () => Promise<T>): Promise<T> {
  if (!isSecureContext || location.protocol !== 'https:' || !navigator.locks || !crypto.subtle) {
    throw new AuthError('unsupported_browser')
  }
  return navigator.locks.request(LOCK_NAME, { mode: 'exclusive' }, async () => {
    // Probe a separate NONcredential key without changing another tab's marker.
    const probe = CONTEXT_KEY + '.probe'
    try {
      localStorage.setItem(probe, '1')
      if (localStorage.getItem(probe) !== '1') throw new Error()
      localStorage.removeItem(probe)
    } catch { throw new AuthError('unsupported_browser') }
    return work()
  })
}
