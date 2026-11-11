import { afterEach, beforeEach, expect, it, vi } from 'vitest'
import { walletRequest } from './walletTransport'

const reply = (raw: string, status = 200) => new Response(raw, { status, headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' } })
beforeEach(() => {
  // jsdom23 lacks the Chrome signal combinator; this preserves abort behavior
  // only in the directed test. Production uses the actual browser API.
  if (!AbortSignal.any) Object.defineProperty(AbortSignal, 'any', { configurable: true, value: (signals: AbortSignal[]) => {
    const abort = new AbortController()
    for (const signal of signals) { if (signal.aborted) abort.abort(); else signal.addEventListener('abort', () => abort.abort(), { once: true }) }
    return abort.signal
  } })
})
afterEach(() => vi.unstubAllGlobals())
it('sends only original bearer to the exact same-origin wallet route without action retry', async () => {
  const transport = vi.fn(async () => reply('{"error":"wallet state conflict"}', 409))
  vi.stubGlobal('fetch', transport)
  const check = vi.fn(), signal = new AbortController().signal
  await expect(walletRequest('original', '/eth/link/challenge', { method: 'POST', body: '{"address":"0x' + '1'.repeat(40) + '"}' }, signal, check)).rejects.toMatchObject({ status: 409 })
  expect(transport).toHaveBeenCalledTimes(1)
  const [path, options] = transport.mock.calls[0] as unknown as [string, RequestInit]
  expect(path).toBe('/api/v2/eth/link/challenge'); expect(options.redirect).toBe('error'); expect(options.cache).toBe('no-store'); expect((options.headers as Record<string, string>).Authorization).toBe('Bearer original')
  await expect(walletRequest('original', '/eth/addresses?actor=another', {}, signal, check)).rejects.toThrow('Invalid wallet endpoint')
  await expect(walletRequest('original', '/eth/addresses', { method: 'POST', body: '{}' }, signal, check)).rejects.toThrow('Invalid wallet method')
  expect(transport).toHaveBeenCalledTimes(1)
})
it('bounds actual streamed bytes and fences a held body before releasing it', async () => {
  let release!: () => void, changed = false
  const held = new Promise<void>(r => { release = r })
  const transport = vi.fn().mockResolvedValueOnce(reply(' '.repeat((1 << 20) + 1))).mockResolvedValueOnce(new Response(new ReadableStream({ async start(c) { c.enqueue(new TextEncoder().encode('[')); await held; c.enqueue(new TextEncoder().encode(']')); c.close() } }), { headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' } }))
  vi.stubGlobal('fetch', transport)
  const check = () => { if (changed) throw Error('old identity') }, signal = new AbortController().signal
  await expect(walletRequest('original', '/eth/addresses', {}, signal, check)).rejects.toThrow('too large')
  const result = walletRequest('original', '/eth/addresses', {}, signal, check)
  await Promise.resolve(); changed = true; release(); await expect(result).rejects.toThrow('old identity')
})
