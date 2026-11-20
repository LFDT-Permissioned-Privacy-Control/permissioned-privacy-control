import { expect, it } from 'vitest'
import { initialScenarioFrame, parseScenarioImport, scenarioDocument, validateScenario } from './SourceScenarioBuilder'
const org = '11111111-1111-1111-1111-111111111111', context = { Org: org, Signer: '0x' + '1'.repeat(40), Groups: [], LinkedAddresses: [], Claims: 0, GroupSourceClaims: {} }
it('round-trips advanced native facts without discarding them when guided fields change', () => {
  const frame = { ...initialScenarioFrame(), facts: { CodeShared: false, StorageDeploymentNamespace: org, CreationUnresolved: true, GroupClaims: { group: 7 } } }
  const value = scenarioDocument({ context: JSON.stringify({ ...context, GroupSourceClaims: { group: 2 } }), frames: JSON.stringify([{ ...frame, value: '0', depth: 0 }]), organization: org, signer: context.Signer, groups: [] })
  const result = parseScenarioImport(JSON.stringify(value), org)
  expect(JSON.parse(result.frames)[0].facts).toEqual(frame.facts); expect(JSON.parse(result.context).GroupSourceClaims).toEqual({ group: 2 }); expect(value.frames).toEqual([{ ...frame, codeAddress: frame.storageAddress }])
})
it('enforces native frame, uint256, uint8, calldata and depth bounds', () => {
  const frame = initialScenarioFrame()
  expect(() => validateScenario(context, [])).toThrow(/one to 256/); expect(() => validateScenario(context, Array(257).fill(frame))).toThrow(/one to 256/)
  for (const value of ['-1', '01', '1e18', (1n << 256n).toString()]) expect(() => validateScenario(context, [{ ...frame, value }])).toThrow(/uint256/)
  expect(validateScenario(context, [{ ...frame, value: ((1n << 256n) - 1n).toString(), depth: 0 }])[0].depth).toBe(0)
  for (const depth of [-1, 0.5, 9007199254740992, '18446744073709551615']) expect(() => validateScenario(context, [{ ...frame, depth }])).toThrow(/depth|exact numeric range/)
  for (const calldata of ['1234', '0x1', '0xzz', '0x' + 'ab'.repeat((256 << 10) + 1)]) expect(() => validateScenario(context, [{ ...frame, calldata }])).toThrow(/calldata/)
  expect(() => validateScenario({ ...context, Claims: 256 }, [frame])).toThrow(/uint8/); expect(() => validateScenario({ ...context, LinkedAddresses: ['bad'] }, [frame])).toThrow(/Linked addresses/); expect(() => validateScenario(context, [{ ...frame, facts: { CallerAddress: 'bad' } }])).toThrow(/caller/)
  expect(() => parseScenarioImport('{"apiVersion":"ops.policy-scenario/v1","apiVersion":"ops.policy-scenario/v1"}', org)).toThrow()
})
