import path from 'node:path'
import { fileURLToPath } from 'node:url'

// These are the exact public artifacts used by the real-crypto V2 tests.
// A changed upstream archive cannot silently select a different proving key.
export const artifactNames = ['circuit.wasm', 'circuit_final.zkey', 'verification_key.json']
export const artifactHashes = Object.freeze({
  authV2: [
    '70affbca1ad1947d76784ca90f6c4a8fd143119685c9917a2a6fefc15b9ed7c1',
    '6acb096a716f5f5b1e5505a7b7261c7eeb7f0a90597c5194fad7b14f91180ac1',
    '79cf543dd8300c0149454ddd200a0a1ac83eed1df4fb49bdceea4b5ebd2cec96',
  ],
  credentialAtomicQuerySigV2: [
    '8d43d3ba84dbe2245302cd2d351f399e03e3c15a0543943b9ba31c3c42e57a73',
    'a7dfd0a1e55d40992fe95ecc40b5201758cadde69f692ca3eea6ee059c07c1df',
    'f90286b8bff8d00ca4ae3b81578108967257f2efa3c103777a7306e1a8b94597',
  ],
})
export const repositoryRoot = fileURLToPath(new URL('../../', import.meta.url))
export function circuitDirectory(id) {
  const override = id === 'authV2' ? process.env.OPS_PRIVADO_AUTH_CIRCUITS : process.env.OPS_PRIVADO_SIG_CIRCUITS
  return path.resolve(override ?? path.join(process.env.OPS_PRIVADO_CIRCUITS_DIR ?? path.join(repositoryRoot, '.tmp/v2-circuits'), id))
}
export const walletModules = path.resolve(process.env.OPS_PRIVADO_WALLET_MODULES ?? path.join(repositoryRoot, 'tools/v2-test-wallet/node_modules'))
