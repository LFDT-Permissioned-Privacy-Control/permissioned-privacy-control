import { decodeFunctionResult, encodeFunctionData, erc20Abi, type Hex } from 'viem'
import { address } from './operationsModels'
import { amountInBaseUnits } from './ExactTokenAmount'
export const diagnosticTemplates = ['name', 'symbol', 'decimals', 'totalSupply', 'balanceOf', 'allowance', 'estimate transfer', 'estimate approve', 'estimate transferFrom'] as const
export type DiagnosticTemplate = typeof diagnosticTemplates[number]
export interface DiagnosticInputs { template: DiagnosticTemplate; token: string; owner: string; spender: string; recipient: string; amount: string; mode: string; decimals?: number }
export function diagnosticRequest(input: DiagnosticInputs): { method: 'eth_call' | 'eth_estimateGas'; params: unknown[] } {
  const { template, token, owner, spender, recipient } = input
  const checked = (value: string) => { if (!address(value)) throw Error('Enter a lowercase 20-byte address.'); return value as Hex }
  const estimate = template.startsWith('estimate '), name = template.replace('estimate ', '')
  let args: readonly unknown[] = []
  if (name === 'balanceOf') args = [checked(owner)]
  if (name === 'allowance') args = [checked(owner), checked(spender)]
  if (estimate) {
    const amount = BigInt(amountInBaseUnits(input.amount, input.mode, input.decimals))
    args = name === 'transfer' ? [checked(recipient), amount] : name === 'approve' ? [checked(spender), amount] : [checked(owner), checked(recipient), amount]
  }
  const data = encodeFunctionData({ abi: erc20Abi, functionName: name, args } as Parameters<typeof encodeFunctionData>[0])
  const call = { to: checked(token), data, ...(estimate ? { from: checked(template === 'estimate transferFrom' ? spender : owner) } : {}) }
  return { method: estimate ? 'eth_estimateGas' : 'eth_call', params: estimate ? [call] : [call, 'latest'] }
}
export function diagnosticResult(template: DiagnosticTemplate, value: unknown): string {
  if (typeof value !== 'string' || !/^0x[0-9a-fA-F]*$/.test(value)) throw Error('The RPC result has no decodable hex value.')
  if (template.startsWith('estimate ')) return `${BigInt(value).toString()} gas (estimate only)`
  const decoded = decodeFunctionResult({ abi: erc20Abi, functionName: template, data: value as Hex } as Parameters<typeof decodeFunctionResult>[0])
  return String(decoded)
}
