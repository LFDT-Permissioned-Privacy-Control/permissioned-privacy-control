import { webcrypto } from 'node:crypto'
import { afterEach, expect, it, vi } from 'vitest'
import go from './testdata/execution-abi-go.json'
import { registryABIText } from './registryABIText'
import { commonABICanonical, validateABIReport } from './executionABI'
afterEach(() => vi.unstubAllGlobals())
it('exports original ABI numeric lexemes and validates the actual Go report without reserializing numbers', async () => {
  vi.stubGlobal('crypto', webcrypto)
  const fixture = go.fixtures.find(f => f.name === 'lexical')!
  expect(fixture.inputText).toContain('1.0'); expect(fixture.inputText).toContain('1e+3')
  const registry = '{"spec":{"contracts":[{"abi":[]},{"id":"chosen","abi":' + fixture.inputText + '}]}}'
  const exported = registryABIText(registry, 1)
  expect(exported).toBe(fixture.inputText)
  expect(() => commonABICanonical(fixture.input)).toThrow(/Go inspection/)
  expect((await validateABIReport(JSON.stringify(fixture.report), fixture.input, exported)).abiDigest).toBe(fixture.report.abiDigest)
  await expect(validateABIReport(JSON.stringify(fixture.report), fixture.input)).rejects.toThrow(/bytes/)
})
it('locates only the fixed registry path including escaped keys and ignores nested/string decoys', () => {
  const registry = '{"abi":["decoy"],"sp\\u0065c":{"contr\\u0061cts":[{"nested":{"abi":["other"]},"note":"quoted \\\"abi\\\": [] { }","a\\u0062i":[{"type":"function","gas":1.0,"xRate":1e+3}]}]}}'
  expect(registryABIText(registry, 0)).toBe('[{"type":"function","gas":1.0,"xRate":1e+3}]\n')
  expect(() => registryABIText('{"spec":{"contracts":[{"abi":[],"abi":[]}]}}', 0)).toThrow()
  expect(() => registryABIText(registry, 1)).toThrow()
})
