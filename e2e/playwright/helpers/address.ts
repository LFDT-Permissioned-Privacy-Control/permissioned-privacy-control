import { randomBytes } from 'node:crypto';

function randomHex(length: number): string {
  if (length <= 0) return '';
  return randomBytes(Math.ceil(length / 2)).toString('hex').slice(0, length);
}

// Generates a random Ethereum address.
// Optional prefix can be provided as hex (with/without 0x) for easier debugging.
export function randomAddress(prefix = ''): string {
  const normalizedPrefix = prefix
    .toLowerCase()
    .replace(/^0x/, '')
    .replace(/[^0-9a-f]/g, '')
    .slice(0, 40);

  const suffixLength = 40 - normalizedPrefix.length;
  return `0x${normalizedPrefix}${randomHex(suffixLength)}`;
}
