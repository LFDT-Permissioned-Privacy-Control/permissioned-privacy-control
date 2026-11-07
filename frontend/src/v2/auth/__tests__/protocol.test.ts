import { describe, expect, it } from 'vitest'
import { access, closedJSON, responseJSON } from '../protocol'

describe('bounded V2 auth response protocol', () => {
  it('rejects ambiguous duplicate keys, deep structures and trailing material', () => {
    for (const raw of ['{"mode":1,"mo\\u0064e":2}', '[0]true', '['.repeat(10) + '0' + ']'.repeat(10), '{"x":"unterminated}', '{"x":NaN}']) {
      expect(() => closedJSON(raw, 1024)).toThrow('invalid_response')
    }
    expect(closedJSON('{"x":["escaped\\\"value",null,1e2,true]}', 1024)).toEqual({ x: ['escaped"value', null, 100, true] })
  })
  it('refuses nonhuman and extended credential responses rather than importing V1 identity conventions', () => {
    const value = { accessToken: 'a.b.c', tokenType: 'Bearer', actorId: 'ops:p1:' + 'A'.repeat(43),
      browserSessionId: 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa', principalKind: 'human', provider: 'azure',
      sourceProfile: 'azure', expiresAt: Math.floor(Date.now() / 1000) + 100 }
    expect(access(value).actorId).toBe(value.actorId)
    for (const change of [{ refreshToken: 'never' }, { actorId: 'azuread:anything' }, { principalKind: 'service' },
      { expiresAt: Math.floor(Date.now() / 1000) + 3600 }, { browserSessionId: '00000000-0000-0000-0000-000000000000' }]) {
      expect(() => access({ ...value, ...change })).toThrow('invalid_response')
    }
  })
  it('bounds streamed response bytes before JSON parsing and refuses malformed UTF8', async () => {
    const headers = { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' }
    await expect(responseJSON(new Response(' '.repeat(24 * 1024) + '{}', { headers }))).rejects.toThrow('invalid_response')
    await expect(responseJSON(new Response(new Uint8Array([0xff]), { headers }))).rejects.toThrow()
    await expect(responseJSON(new Response('{"ok":true}', { headers }))).resolves.toEqual({ ok: true })
  })
})
