import { expect, it } from 'vitest'
import { diagnosticRequest, diagnosticResult } from './diagnosticTemplates'
const token = '0x' + '1'.repeat(40), owner = '0x' + '2'.repeat(40), spender = '0x' + '3'.repeat(40), recipient = '0x' + '4'.repeat(40)
const input = { token, owner, spender, recipient, amount: '9007199254740993123456789', mode: 'base' }
it('encodes native ERC20 balanceOf and allowance exactly', () => {
  expect(diagnosticRequest({ ...input, template: 'balanceOf' })).toEqual({ method: 'eth_call', params: [{ to: token, data: '0x70a08231' + owner.slice(2).padStart(64, '0') }, 'latest'] })
  expect(diagnosticRequest({ ...input, template: 'allowance' }).params).toEqual([{ to: token, data: '0xdd62ed3e' + owner.slice(2).padStart(64, '0') + spender.slice(2).padStart(64, '0') }, 'latest'])
  expect(diagnosticResult('allowance', '0x' + BigInt(input.amount).toString(16).padStart(64, '0'))).toBe(input.amount)
})
it('generates estimate-only exact uint calldata and validates addresses/amounts', () => {
  const request = diagnosticRequest({ ...input, template: 'estimate transfer', amount: '0.1', mode: 'human', decimals: 6 })
  expect(request).toEqual({ method: 'eth_estimateGas', params: [{ to: token, from: owner, data: '0xa9059cbb' + recipient.slice(2).padStart(64, '0') + (100000n).toString(16).padStart(64, '0') }] })
  expect(() => diagnosticRequest({ ...input, template: 'allowance', spender: 'bad' })).toThrow()
  expect(() => diagnosticRequest({ ...input, template: 'estimate approve', amount: '1e30' })).toThrow()
  expect(diagnosticResult('estimate approve', '0x5208')).toBe('21000 gas (estimate only)')
})
