// PUBLIC deterministic demo keys. Never use these accounts for real funds.
import { createRequire } from 'node:module'
import path from 'node:path'
import { walletModules } from '../v2-test-wallet/artifacts.mjs'
import { personas } from './boundary.mjs'
const require = createRequire(path.join(walletModules, '../package.json'))
const { Wallet } = require('ethers')
export function demoAccount(persona) {
  const index = personas.indexOf(persona)
  if (index < 0) throw Error('unknown demo persona')
  return new Wallet('0x' + (index + 1).toString(16).padStart(64, '0'))
}
export function demoAccounts() { return personas.map(id => ({ id, address: demoAccount(id).address })) }
