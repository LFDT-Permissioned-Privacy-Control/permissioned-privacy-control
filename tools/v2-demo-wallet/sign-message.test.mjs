import test from 'node:test'
import assert from 'node:assert/strict'
import { createRequire } from 'node:module'
import path from 'node:path'
import { walletModules } from '../v2-test-wallet/artifacts.mjs'
import { demoAccount } from './accounts.mjs'
import { signChallenge } from './sign-message.mjs'
const require = createRequire(path.join(walletModules, '../package.json'))
const { verifyMessage } = require('ethers')
test('public demo signer signs the actual original EIP191 message and rejects other service or account', async () => {
  const origin = 'https://localhost:8443', now = Date.now(), address = demoAccount('reader').address
  const utc = x => new Date(x).toISOString().replace(/\.\d{3}Z$/, 'Z')
  const message = ['OPS wallet link v1', 'Service: ' + origin, 'Network: sha256:' + '1'.repeat(64), 'Actor: ops:p1:' + 'A'.repeat(43), 'Address: ' + address, 'Nonce: ' + '2'.repeat(64), 'IssuedAt: ' + utc(now), 'ExpiresAt: ' + utc(now + 120_000), '', 'I authorize this wallet to be linked to this OPS identity. This does not authorize a transaction.'].join('\n')
  const result = await signChallenge('reader', message, origin, now)
  assert.equal(verifyMessage(message, result.signature), address)
  await assert.rejects(signChallenge('admin', message, origin, now))
  await assert.rejects(signChallenge('reader', message, 'https://other.test', now))
  await assert.rejects(signChallenge('reader', message + '\n', origin, now))
  await assert.rejects(signChallenge('reader', message, origin, now + 400_000))
})
