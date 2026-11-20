import { mkdirSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { webcrypto } from 'node:crypto'
import { afterEach, expect, it, vi } from 'vitest'
import go from './testdata/execution-abi-go.json'
import { abiChoices, byteDigest, commonABICanonical, deriveCommonABI, validateABIReport } from './executionABI'
import { constraintFor, saveGuidedRule } from './executionRules'
afterEach(() => vi.unstubAllGlobals())
it('matches actual Go InspectABI canonical SHA256, overload selectors, tuple arrays and HTML/U2028/U2029 escaping', async () => {
  vi.stubGlobal('crypto', webcrypto)
  expect(go.binarySHA256).toMatch(/^[0-9a-f]{64}$/)
  for (const fixture of go.fixtures) {
    expect(await byteDigest(fixture.inputText)).toBe(fixture.report.fileByteDigest)
    const choices = abiChoices(fixture.input)
    expect(choices.functions.map(({ signature, selector }) => ({ signature, selector }))).toEqual(fixture.report.functions)
    expect(choices.events).toEqual(fixture.report.events)
    if (fixture.automaticSubset) {
      const actual = await deriveCommonABI(fixture.input, fixture.inputText)
      expect(actual.abiDigest).toBe(fixture.report.abiDigest)
      expect(actual.canonicalByteDigest).toBe(fixture.report.canonicalByteDigest)
    } else expect(() => commonABICanonical(fixture.input)).toThrow(/Go inspection/)
  }
  expect(() => commonABICanonical([{ type: 'function', name: '\ud800', inputs: [] }])).toThrow(/surrogates/)
})
it('accepts the actual Go report fallback bound to exact exported bytes and rejects mismatches', async () => {
  vi.stubGlobal('crypto', webcrypto)
  for (const fixture of go.fixtures) {
    const report = fixture.report
    expect((await validateABIReport(JSON.stringify(report), fixture.input, fixture.inputText)).abiDigest).toBe(report.abiDigest)
    await expect(validateABIReport(JSON.stringify({ ...report, deploymentVerified: true }), fixture.input, fixture.inputText)).rejects.toThrow()
    await expect(validateABIReport(JSON.stringify({ ...report, fileByteDigest: 'sha256:' + '0'.repeat(64) }), fixture.input, fixture.inputText)).rejects.toThrow()
    await expect(validateABIReport(JSON.stringify({ ...report, functions: [] }), fixture.input, fixture.inputText)).rejects.toThrow(/signatures/)
  }
})
it('serializes native exact rules, upper bounds and linked addresses; preserves advanced fields on unrelated edits', async () => {
  vi.stubGlobal('crypto', webcrypto)
  const report = await deriveCommonABI(go.fixtures[0].input), fn = report.functions.find(f => f.signature === 'transfer(address,uint256)')!, address = '0x' + '1'.repeat(40), code = '0x' + '2'.repeat(40)
  const args = [constraintFor('address', 0, 'principal.linked'), constraintFor('uint256', 1, 'uintAtMost', '9007199254740993123456789')]
  const advanced = { except: [{ group: 'native-exception', target: address }], args: [{ index: 0, recordParty: { getter: '0x12345678', abiDigest: report.abiDigest, partyOutputs: [0] } }] }
  const rule = saveGuidedRule({ storageAddress: address, codeAddress: code, callTypes: ['delegatecall'], selector: fn.selector, abiDigest: '', args, maxValue: '0', minDepth: 0, maxDepth: 3 }, report)
  expect(rule).toEqual({ storageAddress: address, codeAddress: code, callTypes: ['delegatecall'], selector: '0xa9059cbb', abiDigest: report.abiDigest, args: [{ index: 0, addressEquals: { source: 'principal.linked' } }, { index: 1, uintAtMost: '9007199254740993123456789' }], maxValue: '0', minDepth: 0, maxDepth: 3 })
  expect(saveGuidedRule({ ...rule, ...advanced, maxValue: '1' }, report)).toEqual({ ...rule, ...advanced, maxValue: '1' })
  const wildcard = saveGuidedRule({ ...rule, selector: '*' }, null)
  expect(wildcard.abiDigest).toBe(''); expect(wildcard.args).toBeUndefined()
  expect(() => saveGuidedRule({ ...rule, codeAddress: undefined }, report)).toThrow(/executing code/)
  expect(() => saveGuidedRule(rule, null)).toThrow(/current ABI/)
  expect(() => constraintFor('uint8', 0, 'uintAtMost', '256')).toThrow(/fit/)
  expect(() => constraintFor('uint256', 0, 'uintAtLeast', '1')).toThrow(/no guided/)
})

it('exports actual guided serializer variants for the independent Go checker', async () => {
  vi.stubGlobal('crypto', webcrypto)
  const abi = go.fixtures[0].input, report = await deriveCommonABI(abi), storageAddress = '0x' + '1'.repeat(40), codeAddress = '0x' + '2'.repeat(40), selector = '0xa9059cbb'
  const base = { storageAddress, selector, abiDigest: '', args: [constraintFor('address', 0, 'principal.linked'), constraintFor('uint256', 1, 'uintAtMost', '9007199254740993123456789')], maxValue: '0', minDepth: 0 }
  const candidates = [
    { name: 'exact-large-bound', expectedValid: true, value: base },
    { name: 'delegate-different', expectedValid: true, value: { ...base, codeAddress, callTypes: ['delegatecall'] } },
    { name: 'delegate-same', expectedValid: true, value: { ...base, codeAddress: storageAddress, callTypes: ['delegatecall', 'call'] } },
    { name: 'org-delegate-wildcard', expectedValid: true, value: { targetClass: 'org', storageAddress: '', selector: '*', abiDigest: '', callTypes: ['delegatecall'] } },
    { name: 'literal-borrow-missing-code', expectedValid: false, value: { ...base, callTypes: ['delegatecall'] } },
    { name: 'different-code-mixed-call', expectedValid: false, value: { ...base, codeAddress, callTypes: ['delegatecall', 'call'] } },
    { name: 'code-without-borrow', expectedValid: false, value: { ...base, codeAddress: storageAddress, callTypes: ['call'] } },
    { name: 'code-with-default-calls', expectedValid: false, value: { ...base, codeAddress: storageAddress } },
  ]
  const variants = candidates.map(({ name, expectedValid, value }) => {
    if (expectedValid) return { name, expectedValid, rule: saveGuidedRule(value, report) }
    expect(() => saveGuidedRule(value, report)).toThrow()
    return { name, expectedValid, rule: { ...value, abiDigest: selector === value.selector ? report.abiDigest : '' } }
  })
  if (process.env.OPS_UI_EXPORT_DIRECTORY) {
    mkdirSync(process.env.OPS_UI_EXPORT_DIRECTORY, { recursive: true })
    writeFileSync(join(process.env.OPS_UI_EXPORT_DIRECTORY, 'execution-serializer-exports.json'), JSON.stringify({ abi, report, variants }, null, 2) + '\n')
  }
})
