import { actor, closedJSON, object, session, text } from '../auth/protocol'
import { MultiSession } from '../auth/multiProtocol'
import { Flow, Self } from './protocol'

const KEY = 'ops-v2.remembered-apps'
interface Choice { clientId: string; actorId: string; profile: string; digest: string; browserSessionId: string; createdAt: number; expiresAt: number }
const name = (v: unknown): v is string => text(v, 128) && /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/.test(v)
function read(now: number): Choice[] {
  try {
    const raw = localStorage.getItem(KEY)
    if (raw === null) return []
    const v = object(closedJSON(raw, 64 << 10), ['version', 'choices'])
    if (v.version !== 1 || !Array.isArray(v.choices) || v.choices.length > 32) throw new Error()
    const seen = new Set<string>(), out: Choice[] = []
    for (const item of v.choices) {
      const c = object(item, ['clientId', 'actorId', 'profile', 'digest', 'browserSessionId', 'createdAt', 'expiresAt'])
      if (new TextEncoder().encode(JSON.stringify(c)).length > 2048 || !name(c.clientId) || seen.has(c.clientId) || !actor(c.actorId) || !name(c.profile) || typeof c.digest !== 'string' || !/^sha256:[0-9a-f]{64}$/.test(c.digest) || !session(c.browserSessionId) || !Number.isSafeInteger(c.createdAt) || !Number.isSafeInteger(c.expiresAt) || (c.createdAt as number) > now || (c.createdAt as number) < 0 || (c.expiresAt as number) !== (c.createdAt as number) + 86400) throw new Error()
      seen.add(c.clientId)
      if ((c.expiresAt as number) > now) out.push(c as unknown as Choice)
    }
    return out
  } catch { return [] }
}
function matches(c: Choice, flow: Flow, self: Self, pair: MultiSession): boolean {
  return pair.provider === 'azure' && c.clientId === flow.clientId && c.actorId === self.actorId && c.actorId === pair.actorId && c.profile === self.sourceProfile && c.profile === pair.sourceProfile && c.digest === self.sourceProfileDigest && c.browserSessionId === pair.browserSessionId
}
export function remembered(flow: Flow, self: Self, pair: MultiSession, now = Math.floor(Date.now() / 1000)): boolean { return read(now).some(c => matches(c, flow, self, pair)) }
export function remember(flow: Flow, self: Self, pair: MultiSession, now = Math.floor(Date.now() / 1000)): void {
  if (pair.provider !== 'azure' || !name(flow.clientId) || self.actorId !== pair.actorId || self.sourceProfile !== pair.sourceProfile) return
  const choices = read(now)
  // An automatic handoff never calls this. An existing identical selection also
  // keeps its original lifetime; visiting the app does not slide the 24h bound.
  if (choices.some(c => matches(c, flow, self, pair))) return
  const kept = choices.filter(c => c.clientId !== flow.clientId)
  kept.push({ clientId: flow.clientId, actorId: self.actorId, profile: self.sourceProfile, digest: self.sourceProfileDigest, browserSessionId: pair.browserSessionId, createdAt: now, expiresAt: now + 86400 })
  if (kept.length > 32) kept.shift()
  const raw = JSON.stringify({ version: 1, choices: kept })
  if (new TextEncoder().encode(raw).length <= (64 << 10)) { try { localStorage.setItem(KEY, raw) } catch { /* No authority or credential is lost. */ } }
}
export function forgetRemembered(): void { try { localStorage.removeItem(KEY) } catch { /* Storage unavailable: nothing is trusted. */ } }
