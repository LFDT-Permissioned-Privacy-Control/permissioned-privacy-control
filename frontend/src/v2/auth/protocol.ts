// This metadata selects a browser context. It is never proof of identity.
export interface BrowserSession {
  actorId: string
  browserSessionId: string
}
export interface AccessResult extends BrowserSession {
  accessToken: string
  tokenType: 'Bearer'
  principalKind: 'human'
  provider: 'azure'
  sourceProfile: string
  expiresAt: number
}
export interface Providers {
  profiles: { id: string; provider: 'azure'; principalKind: 'human' }[]
  completionPath: string
}
export type AuthErrorCode = 'unsupported_browser' | 'invalid_response' | 'invalid_callback' |
  'login_required' | 'session_changed' | 'provider_rejected' | 'authentication_unavailable'
export class AuthError extends Error {
  constructor(readonly code: AuthErrorCode) { super(code); this.name = 'AuthError' }
}
export function invalid(): never { throw new AuthError('invalid_response') }
export function object(value: unknown, keys: string[]): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return invalid()
  const out = value as Record<string, unknown>
  const actual = Object.keys(out)
  if (actual.length !== keys.length || keys.some(key => !Object.prototype.hasOwnProperty.call(out, key))) return invalid()
  return out
}
export function text(value: unknown, max: number): value is string {
  return typeof value === 'string' && value.length > 0 && value.length <= max &&
    new TextEncoder().encode(value).length <= max && !/[\u0000-\u001f\u007f\ud800-\udfff]/u.test(value)
}
export function canonicalState(value: unknown): value is string {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(value)) return false
  try { return btoa(atob(value.replace(/-/g, '+').replace(/_/g, '/') + '='))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '') === value } catch { return false }
}
export function actor(value: unknown): value is string {
  return typeof value === 'string' && value.startsWith('ops:p1:') && canonicalState(value.slice(7))
}
export function session(value: unknown): value is string {
  return typeof value === 'string' && /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(value) &&
    value !== '00000000-0000-0000-0000-000000000000'
}
export function same(a: BrowserSession, b: BrowserSession): boolean {
  return a.actorId === b.actorId && a.browserSessionId === b.browserSessionId
}
export function liveExpiry(value: unknown): value is number {
  const now = Date.now() / 1000
  return typeof value === 'number' && Number.isSafeInteger(value) && value > now && value <= now + 300
}
export function access(value: unknown): AccessResult {
  const v = object(value, ['accessToken', 'tokenType', 'actorId', 'principalKind', 'provider',
    'sourceProfile', 'expiresAt', 'browserSessionId'])
  if (!text(v.accessToken, 16384) || !/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(v.accessToken) ||
    v.tokenType !== 'Bearer' || v.principalKind !== 'human' || v.provider !== 'azure' ||
    !text(v.sourceProfile, 128) || !actor(v.actorId) || !session(v.browserSessionId) || !liveExpiry(v.expiresAt)) return invalid()
  // No token decoding, provider-fact extraction, group guessing or V1 DID prefix.
  return { ...v } as unknown as AccessResult
}
export function providers(value: unknown): Providers {
  const v = object(value, ['profiles', 'completionPath'])
  if (!Array.isArray(v.profiles) || v.profiles.length > 64 || !text(v.completionPath, 2048) ||
    !v.completionPath.startsWith('/') || /[%\\?#\s]/.test(v.completionPath) ||
    v.completionPath !== '/' && v.completionPath.slice(1).split('/').some(s => !s || s === '.' || s === '..')) return invalid()
  const seen = new Set<string>()
  const profiles = v.profiles.map(entry => {
    const p = object(entry, ['id', 'provider', 'principalKind'])
    if (!text(p.id, 128) || seen.has(p.id) || p.provider !== 'azure' || p.principalKind !== 'human') return invalid()
    seen.add(p.id)
    return { id: p.id, provider: 'azure' as const, principalKind: 'human' as const }
  })
  return { profiles, completionPath: v.completionPath }
}

// JSON.parse alone accepts duplicate members. Bound depth/bytes and reject them
// before interpreting this small closed protocol, including escaped spellings.
export function closedJSON(raw: string, max: number): unknown {
  if (new TextEncoder().encode(raw).length > max) return invalid()
  let at = 0
  const space = () => { while (/[\x20\t\r\n]/.test(raw[at] ?? '') && at < raw.length) at++ }
  function string(): string {
    const start = at++
    while (at < raw.length) {
      const c = raw[at++]
      if (c === '"') {
        try { return JSON.parse(raw.slice(start, at)) as string } catch { return invalid() }
      }
      if (c === '\\') at++
    }
    return invalid()
  }
  function value(depth: number): void {
    if (depth > 8) return invalid()
    space()
    if (raw[at] === '"') { string(); return }
    if (raw[at] === '{' || raw[at] === '[') {
      const isObject = raw[at++] === '{'
      const end = isObject ? '}' : ']'
      const keys = new Set<string>()
      space()
      if (raw[at] === end) { at++; return }
      for (;;) {
        if (isObject) {
          space()
          if (raw[at] !== '"') return invalid()
          const key = string()
          if (keys.has(key)) return invalid()
          keys.add(key)
          space()
          if (raw[at++] !== ':') return invalid()
        }
        value(depth + 1); space()
        if (raw[at] === end) { at++; return }
        if (raw[at++] !== ',') return invalid()
      }
    }
    const match = /^(?:true|false|null|-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?)/.exec(raw.slice(at))
    if (!match) return invalid()
    at += match[0].length
  }
  value(0); space()
  if (at !== raw.length) return invalid()
  try { return JSON.parse(raw) as unknown } catch { return invalid() }
}

export async function responseJSON(response: Response): Promise<unknown> {
  if (response.redirected || response.headers.get('Cache-Control') !== 'no-store' ||
    !/^application\/json(?:;\s*charset=utf-8)?$/i.test(response.headers.get('Content-Type') ?? '') || !response.body) return invalid()
  const reader = response.body.getReader()
  const decoder = new TextDecoder('utf-8', { fatal: true })
  let count = 0, raw = ''
  try {
    for (;;) {
      const chunk = await reader.read()
      if (chunk.done) break
      count += chunk.value.byteLength
      if (count > 24 * 1024) return invalid()
      raw += decoder.decode(chunk.value, { stream: true })
    }
    raw += decoder.decode()
    return closedJSON(raw, 24 * 1024)
  } finally {
    await reader.cancel().catch(() => undefined)
    reader.releaseLock()
  }
}
