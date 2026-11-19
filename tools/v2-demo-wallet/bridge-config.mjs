import assert from 'node:assert/strict'
import { exactOrigin, personas } from './boundary.mjs'

// Public fixture metadata only. This selects the expected test identity; Core
// still verifies its real proof and derives permissions from approved rules.
export function bridgeConfig(metadata, opsOrigin) {
  const origin = exactOrigin(opsOrigin)
  assert.equal(origin.hostname, 'localhost')
  assert.equal(metadata.testOnly, true)
  assert.match(metadata.network, /^[a-z0-9-]{1,32}:[a-z0-9-]{1,32}$/)
  const did = value => {
    assert.equal(typeof value, 'string')
    assert.ok(value.length <= 256 && /^did:[a-z0-9]+:[A-Za-z0-9:._-]+$/.test(value))
    return value
  }
  assert.ok(Array.isArray(metadata.personas) && metadata.personas.length === 4)
  const selected = personas.map(id => {
    const found = metadata.personas.filter(p => p.id === id)
    assert.equal(found.length, 1)
    const p = found[0]
    assert.equal(p.profileId, 'demo-' + id)
    return { id, profileId: p.profileId, holderDid: did(p.holderDid) }
  })
  assert.equal(new Set(selected.map(p => p.holderDid)).size, 4)
  const config = { v: 1, testOnly: true, opsOrigin, network: metadata.network,
    issuerDid: did(metadata.issuerDid), verifierDid: did(metadata.verifierDid), personas: selected }
  assert.ok(Buffer.byteLength(JSON.stringify(config)) <= 16384)
  return config
}
