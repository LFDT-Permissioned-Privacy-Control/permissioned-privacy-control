// Chain quantities never pass through JavaScript floating point.
export const MAX_UINT256 = (1n << 256n) - 1n
export function exactUint256(value: string): string {
  if (!/^(0|[1-9][0-9]{0,77})$/.test(value) || BigInt(value) > MAX_UINT256)
    throw Error('Enter an exact nonnegative uint256 integer (no exponent notation).')
  return value
}
export function checkedDecimals(value: unknown): number {
  if (typeof value !== 'number' || !Number.isInteger(value) || value < 0 || value > 77)
    throw Error('Approved token decimals must be an integer from 0 to 77.')
  return value
}
export function decimalToBaseUnits(value: string, decimals: number): string {
  checkedDecimals(decimals)
  if (value.length > 157 || !/^(0|[1-9][0-9]*)(\.[0-9]+)?$/.test(value))
    throw Error('Enter a nonnegative decimal amount without signs or exponent notation.')
  const [whole, fraction = ''] = value.split('.')
  if (fraction.length > decimals) throw Error(`Use at most ${decimals} fractional digits.`)
  return exactUint256((whole + fraction.padEnd(decimals, '0')).replace(/^0+(?=\d)/, ''))
}
export function baseUnitsToDecimal(value: string, decimals: number): string {
  exactUint256(value); checkedDecimals(decimals)
  if (!decimals) return value
  const padded = value.padStart(decimals + 1, '0'), fraction = padded.slice(-decimals).replace(/0+$/, '')
  return padded.slice(0, -decimals) + (fraction ? '.' + fraction : '')
}
