import { AuthError, canonicalState, text } from './protocol'

export type Callback = { state: string; code: string; rejected: false } | { state: string; rejected: true }

export function takeCallback(): Callback {
  const query = location.search, fragment = location.hash
  // Scrub even malformed/unsupported callbacks before hashing, network or UI.
  history.replaceState(null, '', location.pathname)
  const bad = (): never => { throw new AuthError('invalid_callback') }
  if (location.pathname !== '/auth/azure/callback' || fragment || query.length > 32768 ||
    new TextEncoder().encode(query).length > 32768 || /%(?![0-9a-f]{2})/i.test(query)) return bad()
  const params = new URLSearchParams(query)
  const keys = new Set<string>()
  for (const [key] of params) {
    if (keys.has(key)) return bad()
    keys.add(key)
  }
  const state = params.get('state')
  if (!canonicalState(state)) return bad()
  const session = params.get('session_state')
  if (session !== null && !text(session, 1024)) return bad()
  if (params.has('error')) {
    if ([...keys].some(k => !['state', 'session_state', 'error', 'error_description', 'error_uri'].includes(k)) ||
      !text(params.get('error'), 256)) return bad()
    for (const [key, max] of [['error_description', 4096], ['error_uri', 2048]] as const) {
      const value = params.get(key)
      if (value !== null && !text(value, max)) return bad()
    }
    return { state, rejected: true }
  }
  const code = params.get('code')
  if ([...keys].some(k => !['state', 'code', 'session_state'].includes(k)) || !text(code, 8192)) return bad()
  return { state, code, rejected: false }
}
