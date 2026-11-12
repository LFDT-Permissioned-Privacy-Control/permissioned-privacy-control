// Public, isolated demo tooling. This module never accepts an access token.
import assert from 'node:assert/strict'

const uuid = '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'
const requestPath = new RegExp('^/api/v2/auth/privado/requests/(' + uuid + ')$')
const challengeType = 'https://iden3-communication.io/authorization/1.0/request'
export const personas = Object.freeze(['admin', 'deployer', 'reader', 'outsider'])
export function exactOrigin(value) {
  const url = new URL(value)
  assert.equal(url.protocol, 'https:')
  assert.equal(url.origin, value)
  assert.equal(url.username + url.password + url.search + url.hash, '')
  return url
}
export function requestLocation(value, origin) {
  assert.equal(typeof value, 'string')
  assert.ok(value.length <= 400)
  const url = new URL(value)
  assert.equal(url.origin, origin)
  assert.equal(url.href, value)
  assert.equal(url.username + url.password + url.search + url.hash, '')
  const matched = requestPath.exec(url.pathname)
  assert.ok(matched && !/^0{8}-0{4}-0{4}-0{4}-0{12}$/.test(matched[1]))
  return { path: url.pathname, id: matched[1] }
}
export function checkedChallenge(request, location, persona, metadata, origin, now = Math.floor(Date.now() / 1000)) {
  assert.ok(request && typeof request === 'object' && !Array.isArray(request))
  assert.equal(request.id, location.id)
  assert.equal(request.type, challengeType)
  assert.equal(request.from, metadata.verifierDid)
  assert.ok(Number.isSafeInteger(request.created_time) && request.created_time <= now + 30)
  assert.ok(Number.isSafeInteger(request.expires_time) && request.expires_time > now && request.expires_time - request.created_time <= 300)
  const callback = origin + '/api/v2/auth/privado/proofs/' + location.id
  assert.equal(request.body?.callbackUrl, callback)
  const scope = request.body.scope
  assert.ok(Array.isArray(scope))
  if (persona === 'outsider') assert.equal(scope.length, 0)
  else {
    assert.equal(scope.length, 1)
    const proof = scope[0], role = String(personas.indexOf(persona) + 1)
    assert.equal(proof.id, 1)
    assert.equal(proof.circuitId, metadata.circuitId)
    assert.equal(proof.optional, false)
    assert.deepEqual(proof.query, { allowedIssuers: [metadata.issuerDid], context: metadata.contextUrl,
      type: metadata.credentialType, proofType: 'BJJSignature2021', skipClaimRevocationCheck: false,
      credentialSubject: { role: { $eq: Number(role) } } })
  }
  return callback
}
export function callerAllowed(request, origin) {
  const expected = new URL(origin)
  return request.headers.host === expected.host && request.headers.origin === origin &&
    (!request.headers['sec-fetch-site'] || request.headers['sec-fetch-site'] === 'same-origin')
}
