import { AccessResult, actor, invalid, liveExpiry, object, session, text } from './protocol'

export type Provider = 'azure' | 'privado'
export interface MultiSession { actorId: string; browserSessionId: string; provider: Provider; sourceProfile: string }
export interface MultiAccess extends Omit<AccessResult, 'provider'> { provider: Provider }
export interface PrivadoStart {
  requestId: string; requestUri: string; expiresAt: number; sourceProfile: string; expectedActorId: string | null
}
export interface ProofRequired extends MultiSession {
  status: 'proof_required'; provider: 'privado'; principalKind: 'human'; mode: 'renew'
  requestId: string; requestUri: string; expiresAt: number
}
export interface Candidate {
  status: 'candidate'; requestId: string; holderDid: string; network: string; actorId: string
  sourceProfile: string; proofDigest: string; verifiedAt: number; expiresAt: number
}
export interface Waiting { status: 'waiting'; requestId: string; sourceProfile: string; expiresAt: number }
export type Preview = Candidate | Waiting
export interface LoginPending {
  status: 'login_in_progress'; provider: Provider; sourceProfile: string; expiresAt: number
  requestId?: string; requestUri?: string
}
export type Pending = ProofRequired | LoginPending
export type AccessOutcome = { status: 'access'; access: MultiAccess } | Pending
export type OperationOutcome<T> = { status: 'completed'; value: T } | Pending

export function provider(value: unknown): value is Provider { return value === 'azure' || value === 'privado' }
export function profile(value: unknown): value is string { return text(value, 128) }
export function sameSession(a: MultiSession, b: MultiSession): boolean {
  return a.actorId === b.actorId && a.browserSessionId === b.browserSessionId &&
    a.provider === b.provider && a.sourceProfile === b.sourceProfile
}
export function validSession(value: MultiSession): boolean {
  return actor(value?.actorId) && session(value?.browserSessionId) && provider(value?.provider) && profile(value?.sourceProfile)
}
export function requestUri(id: string): string {
  if (location.protocol !== 'https:' || !session(id)) return invalid()
  return location.origin + '/api/v2/auth/privado/requests/' + id
}
// Display-only structural validation; the server verifies the typed DID/proof.
export function holderDid(value: unknown): value is string {
  return text(value, 1024) && /^did:(?:iden3|polygonid):[a-z0-9-]+:[a-z0-9-]+:[1-9A-HJ-NP-Za-km-z]+$/.test(value)
}
export function multiAccess(value: unknown): MultiAccess {
  const v = object(value, ['accessToken', 'tokenType', 'actorId', 'principalKind', 'provider',
    'sourceProfile', 'expiresAt', 'browserSessionId'])
  if (!text(v.accessToken, 16384) || !/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(v.accessToken) ||
    v.tokenType !== 'Bearer' || v.principalKind !== 'human' || !provider(v.provider) || !profile(v.sourceProfile) ||
    !actor(v.actorId) || !session(v.browserSessionId) || !liveExpiry(v.expiresAt)) return invalid()
  return { ...v } as unknown as MultiAccess
}
export function proofRequired(value: unknown): ProofRequired {
  const v = object(value, ['status', 'provider', 'principalKind', 'mode', 'requestId', 'requestUri',
    'expiresAt', 'actorId', 'browserSessionId', 'sourceProfile'])
  if (v.status !== 'proof_required' || v.provider !== 'privado' || v.principalKind !== 'human' || v.mode !== 'renew' ||
    !session(v.requestId) || v.requestUri !== requestUri(v.requestId) || !liveExpiry(v.expiresAt) ||
    !actor(v.actorId) || !session(v.browserSessionId) || !profile(v.sourceProfile)) return invalid()
  return { ...v } as unknown as ProofRequired
}
export function privadoStart(value: unknown, expectedProfile: string): PrivadoStart {
  const v = object(value, ['requestId', 'requestUri', 'expiresAt', 'sourceProfile', 'expectedActorId'])
  if (!session(v.requestId) || v.requestUri !== requestUri(v.requestId) || !liveExpiry(v.expiresAt) ||
    v.sourceProfile !== expectedProfile || !(v.expectedActorId === null || actor(v.expectedActorId))) return invalid()
  return { ...v } as unknown as PrivadoStart
}
export function preview(value: unknown, id: string, sourceProfile: string, flowExpiry: number): Preview {
  const status = value && typeof value === 'object' && !Array.isArray(value) ? (value as Record<string, unknown>).status : null
  const keys = ['status', 'requestId', 'sourceProfile', 'expiresAt']
  const v = object(value, status === 'candidate' ? [...keys, 'holderDid', 'network', 'actorId', 'proofDigest', 'verifiedAt'] : keys)
  if ((v.status !== 'waiting' && v.status !== 'candidate') || v.requestId !== id || v.sourceProfile !== sourceProfile ||
    !liveExpiry(v.expiresAt) || v.expiresAt > flowExpiry) return invalid()
  if (v.status === 'candidate') {
    if (!holderDid(v.holderDid) || !text(v.network, 128) || v.network !== v.holderDid.split(':').slice(2, 4).join(':') ||
      !actor(v.actorId) || typeof v.proofDigest !== 'string' || !/^sha256:[0-9a-f]{64}$/.test(v.proofDigest) ||
      typeof v.verifiedAt !== 'number' || !Number.isSafeInteger(v.verifiedAt) || v.verifiedAt < 0 ||
      v.verifiedAt > Date.now() / 1000 + 30 || v.verifiedAt >= v.expiresAt) return invalid()
  }
  return { ...v } as unknown as Preview
}
export function multiProviders(value: unknown): { profiles: { id: string; provider: Provider; principalKind: 'human' }[]; completionPath: string } {
  const v = object(value, ['profiles', 'completionPath'])
  if (!Array.isArray(v.profiles) || v.profiles.length > 64 || !text(v.completionPath, 2048) ||
    !v.completionPath.startsWith('/') || /[%\\?#\s]/.test(v.completionPath) ||
    v.completionPath !== '/' && v.completionPath.slice(1).split('/').some(s => !s || s === '.' || s === '..')) return invalid()
  const seen = new Set<string>()
  const profiles = v.profiles.map(entry => {
    const p = object(entry, ['id', 'provider', 'principalKind'])
    if (!profile(p.id) || seen.has(p.id) || !provider(p.provider) || p.principalKind !== 'human') return invalid()
    seen.add(p.id)
    return { id: p.id, provider: p.provider, principalKind: 'human' as const }
  })
  return { profiles, completionPath: v.completionPath }
}
