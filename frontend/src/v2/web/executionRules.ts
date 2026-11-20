import { address } from './operationsModels'
import { exactUint256 } from './exactAmounts'
import { object, type JSONObject } from './sourceProject'
import type { ABIReport } from './executionABI'

export function saveGuidedRule(value: JSONObject, inspection: ABIReport | null): JSONObject {
  const rule = { ...value }
  const targetClass = typeof rule.targetClass === 'string' ? rule.targetClass : ''
  if (targetClass) {
    if (!['org', 'shared', 'eoa', 'precompile', 'create'].includes(targetClass)) throw Error('Select a native target class.')
    if (rule.storageAddress || rule.codeAddress) throw Error('Target classes and literal addresses are exclusive.')
    rule.storageAddress = ''; delete rule.codeAddress
  } else if (typeof rule.storageAddress !== 'string' || !address(rule.storageAddress)) throw Error('Select a storage contract from this source.')
  if (rule.codeAddress && (typeof rule.codeAddress !== 'string' || !address(rule.codeAddress))) throw Error('Select a valid code contract.')
  const calls = rule.callTypes
  if (calls !== undefined && (!Array.isArray(calls) || calls.some(c => !['call', 'staticcall', 'delegatecall', 'callcode', 'create', 'create2'].includes(String(c))))) throw Error('Select native call types.')
  const explicitCalls = Array.isArray(calls) ? calls : [], borrows = explicitCalls.some(c => c === 'delegatecall' || c === 'callcode')
  if (new Set(explicitCalls).size !== explicitCalls.length) throw Error('Call types must not repeat.')
  if (!explicitCalls.length && rule.codeAddress) throw Error('An explicit code contract needs explicit delegatecall/callcode call types.')
  if (borrows && !rule.codeAddress && targetClass !== 'org') throw Error('Delegatecall/callcode need an explicit executing code contract for literal targets.')
  if (!borrows && rule.codeAddress) throw Error('Remove the explicit code contract for call/staticcall-only rules.')
  if (borrows && targetClass && targetClass !== 'org') throw Error('This target class supports call/staticcall only in the guided form.')
  if (rule.codeAddress && rule.codeAddress !== rule.storageAddress && (!explicitCalls.length || explicitCalls.some(c => c === 'call' || c === 'staticcall'))) throw Error('Different code/storage contracts cannot permit call/staticcall.')
  if (targetClass && !['*', '0x'].includes(String(rule.selector))) throw Error('Target classes require wildcard or empty input.')
  if (targetClass === 'eoa' && rule.selector !== '0x') throw Error('EOA targets require empty input.')
  if (targetClass === 'create' && (rule.selector !== '*' || !Array.isArray(calls) || !calls.length || calls.some(c => c !== 'create' && c !== 'create2') || rule.allowUpgrade)) throw Error('Creation targets need wildcard input and explicit create/create2 call types, with no upgrade.')
  if (rule.selector === '*' || rule.selector === '0x') { rule.abiDigest = ''; delete rule.args }
  else {
    if (!inspection || !inspection.functions.some(f => f.selector === rule.selector)) throw Error('Select a function with current ABI inspection assistance before saving.')
    rule.abiDigest = inspection.abiDigest
    const fn = inspection.functions.find(f => f.selector === rule.selector)!
    if (Array.isArray(rule.args)) for (const raw of rule.args) {
      const arg = object(raw), input = fn.inputs[Number(arg.index)]
      if (input) {
        const guided = guidedConstraint(arg, input.type)
        if (guided && guided.operator) constraintFor(input.type, Number(arg.index), guided.operator, guided.value)
      }
    }
  }
  if (rule.maxValue !== undefined) exactUint256(String(rule.maxValue))
  for (const key of ['minDepth', 'maxDepth']) if (rule[key] !== undefined && (!Number.isSafeInteger(rule[key]) || Number(rule[key]) < 0)) throw Error('Depth must be a nonnegative safe integer; zero is valid.')
  if (rule.minDepth !== undefined && rule.maxDepth !== undefined && Number(rule.minDepth) > Number(rule.maxDepth)) throw Error('Minimum depth cannot exceed maximum depth.')
  if (rule.callerAddress && (typeof rule.callerAddress !== 'string' || !address(rule.callerAddress))) throw Error('Immediate caller must be a lowercase address.')
  return rule
}
export function constraintFor(type: string, index: number, operator: string, value = ''): JSONObject | null {
  if (!operator) return null
  if (type === 'address' && ['signer', 'principal.linked', 'literal'].includes(operator)) {
    if (operator === 'literal' && !address(value)) throw Error('The literal constraint needs a lowercase address.')
    return { index, addressEquals: { source: operator, ...(operator === 'literal' ? { value } : {}) } }
  }
  if (/^uint([0-9]+)?$/.test(type) && operator === 'uintAtMost') {
    const bits = Number(type.slice(4) || 256), bound = exactUint256(value)
    if (bits < 8 || bits > 256 || bits % 8 || BigInt(bound) >= 1n << BigInt(bits)) throw Error(`The bound must fit ${type}.`)
    return { index, uintAtMost: bound }
  }
  throw Error('This ABI argument has no guided native constraint.')
}
export function guidedConstraint(value: unknown, type: string): { operator: string; value: string } | null {
  if (!value) return { operator: '', value: '' }
  const arg = object(value)
  if (type === 'address' && arg.addressEquals && Object.keys(arg).every(k => k === 'index' || k === 'addressEquals')) {
    const match = object(arg.addressEquals)
    if (['signer', 'principal.linked', 'literal'].includes(String(match.source)) && Object.keys(match).every(k => k === 'source' || k === 'value')) return { operator: String(match.source), value: String(match.value ?? '') }
  }
  if (/^uint([0-9]+)?$/.test(type) && typeof arg.uintAtMost === 'string' && Object.keys(arg).every(k => k === 'index' || k === 'uintAtMost')) return { operator: 'uintAtMost', value: arg.uintAtMost }
  return null
}
