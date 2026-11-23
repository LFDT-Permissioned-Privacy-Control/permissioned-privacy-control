import { toFunctionSignature, toFunctionSelector, toEventSignature, toEventSelector, type AbiFunction, type AbiEvent, type AbiParameter } from 'viem'
import { object } from './sourceProject'

export interface FunctionChoice { signature: string; selector: string; inputs: readonly AbiParameter[]; stateMutability?: string }
export interface ABIChoices { functions: FunctionChoice[]; events: { signature: string; anonymous: boolean; signatureHash: string; topic0?: string; topicRuleEligible: boolean }[] }
function parameter(value: unknown): AbiParameter {
  const p = object(value)
  if (typeof p.type !== 'string') throw Error('ABI input type is required.')
  const type = p.type.replace(/^(uint|int)(?=\[|$)/, '$1256')
  return { ...p, type, ...(Array.isArray(p.components) ? { components: p.components.map(parameter) } : {}) } as unknown as AbiParameter
}
export function abiChoices(abi: unknown): ABIChoices {
  if (!Array.isArray(abi) || abi.length > 4096) throw Error('A bounded ABI array is required.')
  const functions: FunctionChoice[] = [], events: ABIChoices['events'] = []
  for (const entry of abi) {
    const item = object(entry)
    if (item.type === 'function') {
      if (typeof item.name !== 'string' || !Array.isArray(item.inputs)) throw Error('The ABI function is incomplete.')
      const fn = { ...item, inputs: item.inputs.map(parameter) } as unknown as AbiFunction
      const signature = toFunctionSignature(fn), selector = toFunctionSelector(signature).toLowerCase()
      functions.push({ signature, selector, inputs: fn.inputs, ...(typeof item.stateMutability === 'string' ? { stateMutability: item.stateMutability } : item.constant === true ? { stateMutability: 'view' } : {}) })
    }
    if (item.type === 'event') {
      if (typeof item.name !== 'string' || !Array.isArray(item.inputs)) throw Error('The ABI event is incomplete.')
      const event = { ...item, inputs: item.inputs.map(parameter) } as unknown as AbiEvent
      const signature = toEventSignature(event), signatureHash = toEventSelector(signature).toLowerCase(), anonymous = item.anonymous === true
      events.push({ signature, anonymous, signatureHash, ...(!anonymous ? { topic0: signatureHash } : {}), topicRuleEligible: !anonymous })
    }
  }
  functions.sort((a, b) => a.signature < b.signature ? -1 : a.signature > b.signature ? 1 : 0)
  events.sort((a, b) => a.signature < b.signature ? -1 : a.signature > b.signature ? 1 : 0)
  if (new Set(functions.map(f => f.signature)).size !== functions.length || new Set(functions.map(f => f.selector)).size !== functions.length || new Set(events.map(e => e.signature)).size !== events.length) throw Error('Duplicate or colliding ABI signatures require source repair.')
  return { functions, events }
}
