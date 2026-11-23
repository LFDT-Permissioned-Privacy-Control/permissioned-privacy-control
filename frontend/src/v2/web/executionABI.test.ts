import { expect, it } from 'vitest'
import go from './testdata/execution-abi-go.json'
import { abiChoices } from './executionABI'
it('matches actual Go InspectABI overload selectors, tuple-array signatures and event eligibility', () => {
  expect(go.binarySHA256).toMatch(/^[0-9a-f]{64}$/)
  for (const fixture of go.fixtures) {
    const choices = abiChoices(fixture.input)
    expect(choices.functions.map(({ signature, selector }) => ({ signature, selector }))).toEqual(fixture.report.functions)
    expect(choices.events).toEqual(fixture.report.events)
  }
})
it('rejects unsupported, duplicate and colliding ABI shapes without inventing signatures', () => {
 expect(() => abiChoices({})).toThrow('array')
 expect(() => abiChoices([{ type: 'function', name: 'broken' }])).toThrow('incomplete')
 const fn={type:'function',name:'test',inputs:[]}
 expect(() => abiChoices([fn,fn])).toThrow('Duplicate')
})
