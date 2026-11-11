import { AuthError, canonicalState, closedJSON, liveExpiry, object, session, text } from '../auth/protocol'
import { MultiSession } from '../auth/multiProtocol'
import { MultiAccess } from '../auth/multiProtocol'

export interface Self {
  actorId: string; principalKind: 'human' | 'service'; sourceProfile: string
  sourceProfileDigest: string; expiresAt: number
  organizations: { id: string; slug: string; name: string; isOrgAdmin: boolean; isOrgReadonlyAdmin: boolean }[]
}
export interface Flow { id: string; clientId: string; expiresAt: number; displayName: string }
export const FLOW_KEY = 'ops-v2.sso-continuation'

// No credential-bearing body, URL or error is exposed to logs or storage.
async function request(path: string, body: unknown, token: string | null, signal: AbortSignal, max: number): Promise<unknown> {
  const response = await fetch(path, {
    method: body === undefined ? 'GET' : 'POST', mode: 'same-origin', credentials: 'same-origin',
    redirect: 'error', cache: 'no-store', signal,
    headers: { ...(body === undefined ? {} : { 'Content-Type': 'application/json' }), ...(token === null ? {} : { Authorization: 'Bearer ' + token }) },
    body: body === undefined ? undefined : JSON.stringify(body),
  })
  if (response.redirected || response.headers.get('Cache-Control') !== 'no-store' ||
    !/^application\/json(?:;\s*charset=utf-8)?$/i.test(response.headers.get('Content-Type') ?? '') || !response.body) throw new AuthError('invalid_response')
  const reader = response.body.getReader(), decoder = new TextDecoder('utf-8', { fatal: true })
  let raw = '', count = 0
  try {
    for (;;) {
      const item = await reader.read()
      if (item.done) break
      count += item.value.byteLength
      if (count > max) throw new AuthError('invalid_response')
      raw += decoder.decode(item.value, { stream: true })
    }
    raw += decoder.decode()
  } finally { await reader.cancel().catch(() => undefined); reader.releaseLock() }
  const value = closedJSON(raw, max)
  if (response.status !== 200) {
    const error = object(value, ['error'])
    if (response.status === 401 || error.error === 'access_denied') throw new AuthError('login_required')
    throw new AuthError('authentication_unavailable')
  }
  return value
}

export async function ownSelf(access: MultiAccess, signal: AbortSignal): Promise<Self> {
  const v = object(await request('/api/v2/self', undefined, access.accessToken, signal, 512 << 10),
    ['actorId', 'principalKind', 'sourceProfile', 'sourceProfileDigest', 'expiresAt', 'organizations'])
  if (v.actorId !== access.actorId || v.principalKind !== 'human' || v.sourceProfile !== access.sourceProfile ||
    v.expiresAt !== access.expiresAt || !liveExpiry(v.expiresAt) || typeof v.sourceProfileDigest !== 'string' ||
    !/^sha256:[0-9a-f]{64}$/.test(v.sourceProfileDigest) || !Array.isArray(v.organizations) || v.organizations.length > 256) throw new AuthError('invalid_response')
  let previous = ''
  for (const entry of v.organizations) {
    const o = object(entry, ['id', 'slug', 'name', 'isOrgAdmin', 'isOrgReadonlyAdmin'])
    if (!session(o.id) || o.id <= previous || !text(o.slug, 100) || !/^[a-zA-Z0-9][a-zA-Z0-9_-]*$/.test(o.slug) ||
      typeof o.name !== 'string' || new TextEncoder().encode(o.name).length < 1 || new TextEncoder().encode(o.name).length > 256 ||
      /[\u0000\r\n\t]/.test(o.name) || typeof o.isOrgAdmin !== 'boolean' || typeof o.isOrgReadonlyAdmin !== 'boolean') throw new AuthError('invalid_response')
    previous = o.id
  }
  return v as unknown as Self
}
export async function inspectFlow(id: string, signal: AbortSignal): Promise<Flow> {
  if (!session(id)) throw new AuthError('invalid_response')
  const v = object(await request('/api/v2/sso/flow', { action: 'inspect', flowId: id }, null, signal, 2048), ['clientId', 'displayName', 'expiresAt', 'phase'])
  if (!text(v.clientId, 128) || !/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/.test(v.clientId) || !text(v.displayName, 256) || !liveExpiry(v.expiresAt) || v.phase !== 'pending') throw new AuthError('invalid_response')
  return { id, clientId: v.clientId, displayName: v.displayName, expiresAt: v.expiresAt }
}
export async function completeFlow(flow: Flow, access: MultiSession, token: string, signal: AbortSignal): Promise<string> {
  const v = object(await request('/api/v2/sso/flow', { action: 'complete', flowId: flow.id,
    expectedActorId: access.actorId, expectedSessionId: access.browserSessionId }, token, signal, 8192), ['redirectTo'])
  if (!text(v.redirectTo, 8192)) throw new AuthError('invalid_response')
  let u: URL
  try { u = new URL(v.redirectTo) } catch { throw new AuthError('invalid_response') }
  if (u.protocol !== 'https:' || u.username || u.password || u.hash || u.href !== v.redirectTo ||
    u.searchParams.size !== 2 || u.searchParams.getAll('code').length !== 1 || !canonicalState(u.searchParams.get('code')) ||
    u.searchParams.getAll('state').length !== 1 || !text(u.searchParams.get('state'), 512)) throw new AuthError('invalid_response')
  return u.href
}
export function readContinuation(): { id: string; expiresAt: number } | null {
  try {
    const raw = sessionStorage.getItem(FLOW_KEY)
    if (raw === null) return null
    const v = object(closedJSON(raw, 256), ['version', 'phase', 'id', 'expiresAt'])
    if (v.version !== 1 || v.phase !== 'pending' || !session(v.id) || !liveExpiry(v.expiresAt)) throw new Error()
    return { id: v.id, expiresAt: v.expiresAt }
  } catch { sessionStorage.removeItem(FLOW_KEY); throw new AuthError('login_required') }
}
export function saveContinuation(flow: Flow): void {
  sessionStorage.setItem(FLOW_KEY, JSON.stringify({ version: 1, phase: 'pending', id: flow.id, expiresAt: flow.expiresAt }))
}
export function walletLinks(uri: string): { mobile: string; web: string } {
  const u = new URL(uri)
  if (u.origin !== location.origin || !/^\/api\/v2\/auth\/privado\/requests\/[0-9a-f-]{36}$/.test(u.pathname) ||
    !session(u.pathname.split('/').pop()) || u.search || u.hash || u.href !== uri || uri.length > 400) throw new AuthError('invalid_response')
  const value = encodeURIComponent(uri)
  return { mobile: 'iden3comm://?request_uri=' + value, web: 'https://wallet.privado.id/#request_uri=' + value }
}
