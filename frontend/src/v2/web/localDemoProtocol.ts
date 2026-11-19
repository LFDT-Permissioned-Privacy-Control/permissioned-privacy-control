import { holderDid } from '../auth/multiProtocol'

export const demoPersonas = ['admin', 'deployer', 'reader', 'outsider'] as const
export const demoPrivadoProfile = 'demo-privado'
export type DemoPersona = typeof demoPersonas[number]
export interface DemoIdentity { readonly id: DemoPersona; readonly profileId: string; readonly holderDid: string }
export interface DemoConfig {
  readonly v: 1; readonly testOnly: true; readonly opsOrigin: string; readonly network: string
  readonly issuerDid: string; readonly verifierDid: string; readonly personas: readonly DemoIdentity[]
}
export interface DemoReady { v: 1; type: 'ready'; nonce: string; config: DemoConfig }
export interface DemoStatus { v: 1; type: 'status'; nonce: string; status: 'working' | 'submitted' | 'failed' }
function closed(value: unknown, keys: readonly string[]): value is Record<string, unknown> {
  return !!value && typeof value === 'object' && !Array.isArray(value) && Object.keys(value).sort().join() === [...keys].sort().join()
}
function bounded(value: unknown, bytes: number): boolean {
  try { return new TextEncoder().encode(JSON.stringify(value)).byteLength <= bytes } catch { return false }
}
export function demoOrigin(value: unknown): string | null {
  if (typeof value !== 'string') return null
  try {
    const url = new URL(value)
    return url.protocol === 'https:' && url.hostname === 'localhost' && url.origin === value && !url.username && !url.password ? value : null
  } catch { return null }
}
function networkDid(value: unknown, network: string): value is string {
  return holderDid(value) && value.length <= 256 && value.split(':').slice(2, 4).join(':') === network
}
export function demoReady(value: unknown, nonce: string, opsOrigin: string): DemoReady | null {
  if (!closed(value, ['v', 'type', 'nonce', 'config']) || !bounded(value, 20 << 10) || value.v !== 1 || value.type !== 'ready' || value.nonce !== nonce) return null
  const c = value.config
  if (!closed(c, ['v', 'testOnly', 'opsOrigin', 'network', 'issuerDid', 'verifierDid', 'personas']) || !bounded(c, 16 << 10) || c.v !== 1 || c.testOnly !== true || c.opsOrigin !== opsOrigin || typeof c.network !== 'string' || !/^[a-z0-9-]{1,32}:[a-z0-9-]{1,32}$/.test(c.network) || !networkDid(c.issuerDid, c.network) || !networkDid(c.verifierDid, c.network) || !Array.isArray(c.personas) || c.personas.length !== 4) return null
  const rows: DemoIdentity[] = []
  for (const id of demoPersonas) {
    const found = c.personas.filter(p => closed(p, ['id', 'profileId', 'holderDid']) && p.id === id)
    if (found.length !== 1) return null
    const p = found[0] as Record<string, unknown>
    if (p.profileId !== demoPrivadoProfile || !networkDid(p.holderDid, c.network)) return null
    rows.push(Object.freeze({ id, profileId: p.profileId, holderDid: p.holderDid }))
  }
  if (new Set(rows.map(p => p.holderDid)).size !== 4) return null
  const config: DemoConfig = Object.freeze({ v: 1, testOnly: true, opsOrigin, network: c.network, issuerDid: c.issuerDid, verifierDid: c.verifierDid, personas: Object.freeze(rows) })
  return { v: 1, type: 'ready', nonce, config }
}
export function demoStatus(value: unknown, nonce: string): DemoStatus | null {
  if (!closed(value, ['v', 'type', 'nonce', 'status']) || !bounded(value, 1024) || value.v !== 1 || value.type !== 'status' || value.nonce !== nonce || !['working', 'submitted', 'failed'].includes(String(value.status))) return null
  return value as unknown as DemoStatus
}
export function demoRequestURI(value: unknown, id: unknown, origin: string): value is string {
  return typeof value === 'string' && value.length <= 400 && typeof id === 'string' && /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(id) && id !== '00000000-0000-0000-0000-000000000000' && value === origin + '/api/v2/auth/privado/requests/' + id
}
