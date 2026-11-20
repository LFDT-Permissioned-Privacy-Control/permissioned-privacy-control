import { expect, it } from 'vitest'
import { baseUnitsToDecimal, checkedDecimals, decimalToBaseUnits, exactUint256, MAX_UINT256 } from './exactAmounts'
import { amountInBaseUnits } from './ExactTokenAmount'
import { approvedTokens } from './approvedTokens'
it('converts decimals 0, 6, 18 and 77 without rounding, including values above JS safe integer', () => {
  expect(decimalToBaseUnits('0.1', 6)).toBe('100000')
  expect(decimalToBaseUnits('0.1', 18)).toBe('100000000000000000')
  expect(decimalToBaseUnits('9007199254740993123456789', 0)).toBe('9007199254740993123456789')
  expect(decimalToBaseUnits('0.' + '0'.repeat(76) + '1', 77)).toBe('1')
  expect(baseUnitsToDecimal('1', 77)).toBe('0.' + '0'.repeat(76) + '1')
  expect(baseUnitsToDecimal(MAX_UINT256.toString(), 18)).toBe('115792089237316195423570985008687907853269984665640564039457.584007913129639935')
  for (const decimals of [0, 6, 18, 77]) expect(decimalToBaseUnits(baseUnitsToDecimal(MAX_UINT256.toString(), decimals), decimals)).toBe(MAX_UINT256.toString())
})
it('rejects exponent/sign/precision errors and uint256 overflow', () => {
  for (const raw of ['-1', '+1', '1e3', '.1', '1.', ' 1', '01', 'NaN']) expect(() => decimalToBaseUnits(raw, 18)).toThrow()
  expect(() => decimalToBaseUnits('0.1', 0)).toThrow(/fractional/)
  expect(() => decimalToBaseUnits('0.0000001', 6)).toThrow(/fractional/)
  expect(() => exactUint256((MAX_UINT256 + 1n).toString())).toThrow()
  expect(() => decimalToBaseUnits('2', 77)).toThrow()
  expect(() => checkedDecimals(78)).toThrow()
  expect(() => amountInBaseUnits('1', 'human', undefined)).toThrow(/unavailable/)
})
it('operational units come only from valid approved address-bound metadata', () => {
  const token = (suffix: string, decimals: number) => ({ tokenAddress: '0x' + suffix.repeat(40), symbol: 'SAME', decimals })
  expect(approvedTokens({ data: [{ tokenAddress: 'native', symbol: 'ETH', decimals: 18 }, token('1', 0), token('2', 77)] }).map(t => t.address)).toEqual(['0x' + '1'.repeat(40), '0x' + '2'.repeat(40)])
  expect(() => approvedTokens({ data: [token('1', 255)] })).toThrow()
  expect(() => approvedTokens({ data: [token('1', 6), token('1', 18)] })).toThrow(/duplicate/)
})

it('accepts valid mixed native/6/18-decimal rows and keeps native out of the ERC20 picker', () => {
  const row = (tokenAddress: string, decimals: number) => ({ tokenAddress, symbol: tokenAddress === 'native' ? 'ETH' : 'SAME', decimals })
  expect(approvedTokens({ data: [row('native', 18), row('0x' + '1'.repeat(40), 6), row('0x' + '2'.repeat(40), 18)] })).toEqual([{ address: '0x' + '1'.repeat(40), symbol: 'SAME', decimals: 6 }, { address: '0x' + '2'.repeat(40), symbol: 'SAME', decimals: 18 }])
  expect(approvedTokens({ data: [row('native', 77)] })).toEqual([])
  expect(() => approvedTokens({ data: [row('native', 78)] })).toThrow(/0 to 77/)
  expect(() => approvedTokens({ data: [row('native', 18), row('native', 18)] })).toThrow(/duplicate/)
})
