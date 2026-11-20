import { toFunctionSignature, toFunctionSelector, toEventSignature, toEventSelector, type AbiFunction, type AbiEvent, type AbiParameter } from 'viem'
import { closedJSON } from '../auth/protocol'
import { object, type JSONObject } from './sourceProject'

const knownKeys = new Set(['type', 'name', 'inputs', 'outputs', 'stateMutability', 'payable', 'constant', 'anonymous', 'indexed', 'components', 'internalType'])
export interface FunctionChoice { signature: string; selector: string; inputs: readonly AbiParameter[] }
export interface ABIChoices { functions: FunctionChoice[]; events: { signature: string; anonymous: boolean; signatureHash: string; topic0?: string; topicRuleEligible: boolean }[] }
export interface ABIReport extends ABIChoices { fileByteDigest: string; canonicalByteDigest: string; abiDigest: string; deploymentVerified: false }
export function selectedABIBytes(abi: unknown): string { return JSON.stringify(abi, null, 2) + '\n' }
export async function byteDigest(raw: string): Promise<string> {
  const bytes = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(raw))
  return 'sha256:' + Array.from(new Uint8Array(bytes), value => value.toString(16).padStart(2, '0')).join('')
}
// Deliberately ABI-specific: values outside this small domain require the Go
// inspection workflow. In particular no browser number canonicalizer is used.
export function commonABICanonical(abi: unknown): string {
  if (!Array.isArray(abi)) throw Error('An ABI array is required.')
  let nodes = 0
  const visit = (value: unknown, depth: number): string => {
    if (++nodes > 32768 || depth > 32) throw Error('Use Go inspection for this ABI size/depth.')
    if (value === null) return 'null'
    if (typeof value === 'boolean') return String(value)
    if (typeof value === 'string') {
      for (let i = 0; i < value.length; i++) {
        const code = value.charCodeAt(i)
        if (code >= 0xd800 && code <= 0xdbff) { const next = value.charCodeAt(++i); if (!(next >= 0xdc00 && next <= 0xdfff)) throw Error('Use Go inspection for unpaired UTF-16 surrogates.') }
        else if (code >= 0xdc00 && code <= 0xdfff) throw Error('Use Go inspection for unpaired UTF-16 surrogates.')
      }
      return JSON.stringify(value).replace(/[<>&\u2028\u2029]/g, c => '\\u' + c.charCodeAt(0).toString(16).padStart(4, '0'))
    }
    if (Array.isArray(value)) return '[' + value.map(v => visit(v, depth + 1)).join(',') + ']'
    if (value && typeof value === 'object') return '{' + Object.keys(value).sort().map(key => {
      if (!/^[\x20-\x7e]+$/.test(key) || !knownKeys.has(key)) throw Error('Use Go inspection for numeric or custom ABI fields.')
      return JSON.stringify(key) + ':' + visit((value as JSONObject)[key], depth + 1)
    }).join(',') + '}'
    throw Error('Use Go inspection for numeric or unsupported ABI values.')
  }
  const raw = visit(abi, 0)
  if (new TextEncoder().encode(raw).length > 1 << 20) throw Error('The selected ABI exceeds 1 MiB.')
  return raw
}
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
      functions.push({ signature, selector, inputs: fn.inputs })
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
export async function deriveCommonABI(abi: unknown, rawBytes = selectedABIBytes(abi)): Promise<ABIReport> {
  const canonical = commonABICanonical(abi), choices = abiChoices(abi), canonicalByteDigest = await byteDigest(canonical)
  return { ...choices, fileByteDigest: await byteDigest(rawBytes), canonicalByteDigest, abiDigest: canonicalByteDigest.slice(7), deploymentVerified: false }
}
export async function validateABIReport(raw: string, abi: unknown, rawBytes = selectedABIBytes(abi)): Promise<ABIReport> {
  const report = object(closedJSON(raw, 1 << 20, 32)), expected = abiChoices(abi)
  if (Object.keys(report).sort().join() !== 'abiDigest,canonicalByteDigest,deploymentVerified,events,fileByteDigest,functions' || report.deploymentVerified !== false || typeof report.abiDigest !== 'string' || !/^[0-9a-f]{64}$/.test(report.abiDigest) || report.canonicalByteDigest !== 'sha256:' + report.abiDigest || report.fileByteDigest !== await byteDigest(rawBytes))
    throw Error('The report does not match the exported selected ABI bytes and native digest fields.')
  const functions = expected.functions.map(({ signature, selector }) => ({ signature, selector }))
  if (JSON.stringify(report.functions) !== JSON.stringify(functions) || JSON.stringify(report.events) !== JSON.stringify(expected.events)) throw Error('Report functions/events do not match the selected ABI signatures and selectors.')
  // Where common derivation is available, also check its canonical digest.
  let common: string | null = null
  try { common = commonABICanonical(abi) } catch { /* bounded fallback is explicit */ }
  if (common !== null && report.canonicalByteDigest !== await byteDigest(common)) throw Error('The report canonical digest differs from the selected common ABI.')
  return { ...expected, fileByteDigest: report.fileByteDigest as string, canonicalByteDigest: report.canonicalByteDigest as string, abiDigest: report.abiDigest, deploymentVerified: false }
}
