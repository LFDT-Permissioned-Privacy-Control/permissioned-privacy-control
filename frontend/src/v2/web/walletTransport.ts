import { WalletHTTPError } from './wallet'

// An immutable original-token operation. No helper renewal, cookie reading,
// arbitrary destination, logging or mutation retry is performed here.
export async function walletRequest(token: string, endpoint: string, options: RequestInit, signal: AbortSignal, check: () => void): Promise<unknown> {
  if (!/^\/eth\/(?:addresses(?:\/0x[0-9a-f]{40})?|link\/(?:challenge|verify))$/.test(endpoint)) throw Error('Invalid wallet endpoint')
  const method = options.method ?? 'GET'
  const expected = endpoint === '/eth/addresses' ? 'GET' : endpoint.startsWith('/eth/addresses/') ? 'DELETE' : 'POST'
  if (method !== expected || options.body !== undefined && typeof options.body !== 'string' || method !== 'POST' && options.body !== undefined) throw Error('Invalid wallet method or body')
  if (typeof options.body === 'string' && new TextEncoder().encode(options.body).length > 8192) throw Error('Wallet request too large')
  check()
  const response = await fetch('/api/v2' + endpoint, {
    method, mode: 'same-origin', credentials: 'same-origin', redirect: 'error', cache: 'no-store',
    headers: { Authorization: 'Bearer ' + token, Accept: 'application/json', ...(method === 'POST' ? { 'Content-Type': 'application/json' } : {}) },
    body: options.body, signal: AbortSignal.any([signal, AbortSignal.timeout(5000)]),
  })
  check()
  if (response.redirected || response.headers.get('Cache-Control') !== 'no-store' || !/^application\/json(?:;\s*charset=utf-8)?$/i.test(response.headers.get('Content-Type') ?? '') || !response.body) throw Error('Invalid wallet response')
  const reader = response.body.getReader(), decoder = new TextDecoder('utf-8', { fatal: true })
  let raw = '', count = 0
  try {
    for (;;) {
      const item = await reader.read(); check()
      if (item.done) break
      count += item.value.byteLength; if (count > 1 << 20) throw Error('Wallet response too large')
      raw += decoder.decode(item.value, { stream: true })
    }
    raw += decoder.decode(); check()
  } finally { void reader.cancel().catch(() => undefined); reader.releaseLock() }
  if (response.status !== 200) throw new WalletHTTPError(response.status)
  const value: unknown = JSON.parse(raw); check(); return value
}
