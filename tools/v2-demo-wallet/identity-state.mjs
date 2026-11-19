import assert from 'node:assert/strict'
import { commonProfile, personas } from './boundary.mjs'

// Changing the public request template does not change a seeded wallet. Accept
// only the known previous profile label for that same persona. All holder,
// issuer, credential-role and identity-state comparisons remain exact.
export function assertCompatibleIdentityState(saved, current) {
  const normalized = saved && typeof saved === 'object' && Array.isArray(saved.personas)
    ? { ...saved, personas: saved.personas.map(persona => personas.includes(persona?.id) && persona.profileId === 'demo-' + persona.id
      ? { ...persona, profileId: commonProfile } : persona) }
    : saved
  assert.deepEqual(normalized, current)
}
