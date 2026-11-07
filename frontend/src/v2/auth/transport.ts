import { AuthError, object, responseJSON } from './protocol'

// Both explicit helper versions use the same bounded same-origin transport.
// This never reads renewal/recipient cookies or follows a provider redirect.
export async function requestAuth(path: string, body?: unknown): Promise<unknown> {
  const response = await fetch('/api/v2/auth/' + path, {
    method: body === undefined ? 'GET' : 'POST', mode: 'same-origin',
    credentials: 'same-origin', redirect: 'error', cache: 'no-store',
    headers: body === undefined ? undefined : { 'Content-Type': 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body),
    signal: AbortSignal.timeout(25000),
  })
  if (path === 'logout' && response.status === 204 && response.headers.get('Cache-Control') === 'no-store') return undefined
  const data = await responseJSON(response)
  if (response.status !== 200) {
    const value = object(data, ['error'])
    if (value.error === 'session_changed') throw new AuthError('session_changed')
    if (value.error === 'reauthentication_required') throw new AuthError('login_required')
    throw new AuthError('authentication_unavailable')
  }
  if (path === 'logout') throw new AuthError('invalid_response')
  return data
}
