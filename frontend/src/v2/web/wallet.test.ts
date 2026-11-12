import { describe, expect, it } from 'vitest'
import { ownWallets, walletChallenge } from './wallet'

const actor = 'ops:p1:' + 'A'.repeat(43), address = '0x' + '1'.repeat(40)
const nonce = 'ab'.repeat(32), issued = '1970-01-01T00:16:40Z', expiresAt = '1970-01-01T00:21:40Z'
const message = ['OPS wallet link v1', 'Service: https://wallet.test', 'Network: sha256:' + 'a'.repeat(64), 'Actor: ' + actor, 'Address: ' + address, 'Nonce: ' + nonce, 'IssuedAt: ' + issued, 'ExpiresAt: ' + expiresAt, '', 'I authorize this wallet to be linked to this OPS identity. This does not authorize a transaction.'].join('\n')
const challenge = { nonce, message, expiresAt }
describe('native browser wallet wire contract', () => {
  it('accepts only exact proof-backed wallet rows', () => {
    const row = { address, verifiedAt: issued, proofVersion: 2 }
    expect(ownWallets([row])).toEqual([row])
    for (const value of [{ addresses: [row] }, [row, row], [{ ...row, proofVersion: 1 }], [{ ...row, link_type: 'system' }], [{ ...row, verifiedAt: '2026-02-31T00:00:00Z' }]]) expect(() => ownWallets(value)).toThrow()
  })
  it('checks signed bytes, original actor/address, nonce and expiry without URL rewriting', () => {
    expect(walletChallenge(challenge, actor, address, 1000)).toEqual(challenge)
    for (const value of [{ ...challenge, message: message + '\n' }, { ...challenge, nonce: '00'.repeat(32) }, { ...challenge, expiresAt: '1970-01-01T00:21:41Z' }, { ...challenge, message: message.replace('https://wallet.test', 'https://wallet.test/path') }, { ...challenge, message: message.replace('This does not authorize a transaction.', 'I approve a transaction.') }, { ...challenge, extra: true }]) expect(() => walletChallenge(value, actor, address, 1000)).toThrow()
    expect(() => walletChallenge(challenge, 'ops:p1:' + 'B'.repeat(43), address, 1000)).toThrow()
    expect(() => walletChallenge(challenge, actor, '0x' + '2'.repeat(40), 1000)).toThrow()
    expect(() => walletChallenge(challenge, actor, address, 1300)).toThrow()
  })
})
