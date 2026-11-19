import { expect, it } from 'vitest'
import { demoPersonas, demoPrivadoProfile, demoReady } from './localDemoProtocol'

const ops = 'https://localhost:8443', nonce = 'a'.repeat(64)
const config = () => ({ v: 1, testOnly: true, opsOrigin: ops, network: 'polygon:mumbai',
  issuerDid: 'did:iden3:polygon:mumbai:x11111', verifierDid: 'did:iden3:polygon:mumbai:x22222',
  personas: demoPersonas.map((id, index) => ({ id, profileId: demoPrivadoProfile, holderDid: 'did:iden3:polygon:mumbai:x' + String(index + 3).repeat(10) })) })

it('accepts one shared request profile for four independent public wallet holders', () => {
  const result = demoReady({ v: 1, type: 'ready', nonce, config: config() }, nonce, ops)!
  expect(result).not.toBeNull()
  expect(new Set(result.config.personas.map(persona => persona.profileId))).toEqual(new Set([demoPrivadoProfile]))
  expect(new Set(result.config.personas.map(persona => persona.holderDid)).size).toBe(4)
  expect(result.config.personas.map(persona => persona.id)).toEqual(demoPersonas)
})
it('rejects role-specific profiles, substituted holders and injected authority claims', () => {
  for (const mutate of [
    (value: ReturnType<typeof config>) => { value.personas[0].profileId = 'demo-admin' },
    (value: ReturnType<typeof config>) => { value.personas[3].profileId = 'privado-identity-only' },
    (value: ReturnType<typeof config>) => { value.personas[1].holderDid = value.personas[0].holderDid },
    (value: ReturnType<typeof config>) => { value.personas[0].holderDid = 'did:iden3:polygon:amoy:other' },
    (value: ReturnType<typeof config>) => { Object.assign(value.personas[0], { groups: ['admin'] }) },
    (value: ReturnType<typeof config>) => { Object.assign(value, { token: 'never-authority' }) },
  ]) {
    const value = config(); mutate(value)
    expect(demoReady({ v: 1, type: 'ready', nonce, config: value }, nonce, ops)).toBeNull()
  }
})
