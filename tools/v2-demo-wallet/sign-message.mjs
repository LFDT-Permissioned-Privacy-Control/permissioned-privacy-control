#!/usr/bin/env node
// Signs only the explicit native wallet-link challenge with a PUBLIC demo key.
import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import { fileURLToPath } from 'node:url'
import { demoAccount } from './accounts.mjs'
import { exactOrigin } from './boundary.mjs'

export async function signChallenge(persona, message, serviceOrigin, now = Date.now()) {
  exactOrigin(serviceOrigin)
  assert.equal(typeof message, 'string'); assert.ok(Buffer.byteLength(message) <= 4096)
  const wallet = demoAccount(persona), lines = message.split('\n')
  assert.equal(lines.length, 10)
  assert.equal(lines[0], 'OPS wallet link v1')
  assert.equal(lines[1], 'Service: ' + serviceOrigin)
  assert.match(lines[2], /^Network: sha256:[0-9a-f]{64}$/)
  assert.match(lines[3], /^Actor: ops:p1:[A-Za-z0-9_-]{43}$/)
  assert.equal(lines[4].toLowerCase(), 'address: ' + wallet.address.toLowerCase())
  assert.match(lines[5], /^Nonce: [0-9a-f]{64}$/)
  assert.match(lines[6], /^IssuedAt: \d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$/)
  assert.match(lines[7], /^ExpiresAt: \d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$/)
  const issued = Date.parse(lines[6].slice(10)), expires = Date.parse(lines[7].slice(11))
  assert.ok(Number.isFinite(issued) && issued <= now + 30_000 && expires > now && expires > issued && expires - issued <= 300_000)
  assert.equal(lines[8], '')
  assert.equal(lines[9], 'I authorize this wallet to be linked to this OPS identity. This does not authorize a transaction.')
  return { persona, address: wallet.address, signature: await wallet.signMessage(message) }
}
async function main() {
  assert.equal(process.argv.length, 8)
  assert.equal(process.argv[2], '--persona'); assert.equal(process.argv[4], '--message-file'); assert.equal(process.argv[6], '--service-origin')
  const raw = await readFile(process.argv[5]); assert.ok(raw.length <= 4096)
  const message = new TextDecoder('utf-8', { fatal: true }).decode(raw)
  console.log(JSON.stringify(await signChallenge(process.argv[3], message, process.argv[7])))
}
if (process.argv[1] === fileURLToPath(import.meta.url)) main().catch(() => { console.error('Expected a live original OPS wallet-link challenge for this public demo account and service origin.'); process.exit(1) })
