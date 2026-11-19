import test from 'node:test'
import assert from 'node:assert/strict'
import { assertCompatibleIdentityState } from './identity-state.mjs'

const current = { version: 1, testOnly: true, network: 'polygon:mumbai', chainId: '80001',
  issuerDid: 'did:fixture:issuer', verifierDid: 'did:fixture:verifier', stateContract: '0x' + '1'.repeat(40),
  personas: ['admin', 'deployer', 'reader', 'outsider'].map((id, index) => ({ id, profileId: 'demo-privado', holderDid: 'did:fixture:' + id, roleValue: index < 3 ? index + 1 : null })),
  states: [{ id: '123', state: '456' }] }
const legacy = () => ({ ...structuredClone(current), personas: current.personas.map(persona => ({ ...persona, profileId: 'demo-' + persona.id })) })

test('an exact legacy profile-label change keeps public wallet identities and saved state intact', () => {
  const saved = legacy(), original = structuredClone(saved)
  assert.doesNotThrow(() => assertCompatibleIdentityState(current, current))
  assert.doesNotThrow(() => assertCompatibleIdentityState(saved, current))
  assert.deepEqual(saved, original)
})
test('profile-label compatibility never accepts changed identity, authority, roles or state', () => {
  for (const change of [
    value => { value.personas[0].holderDid = 'did:fixture:other' },
    value => { value.personas[0].roleValue = 3 },
    value => { value.personas[0].profileId = 'demo-reader' },
    value => { value.personas[0].profileId = 'production-profile' },
    value => { value.personas.pop() },
    value => { value.issuerDid = 'did:fixture:other' },
    value => { value.states[0].state = '457' },
    value => { value.extra = 'unexpected' },
  ]) {
    const saved = legacy(); change(saved)
    assert.throws(() => assertCompatibleIdentityState(saved, current))
  }
  assert.throws(() => assertCompatibleIdentityState(null, current))
})
