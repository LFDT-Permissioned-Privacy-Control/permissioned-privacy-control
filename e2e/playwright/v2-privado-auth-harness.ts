// Owned integration fixture, never a production entry point.
import { NewMultiClient } from '../../frontend/src/v2/auth/multiClient'
import type { AccessOutcome, Candidate, MultiAccess, MultiSession, Preview } from '../../frontend/src/v2/auth/multiProtocol'

let client = NewMultiClient()
let requests: { path: string; method: string }[] = []
const originalFetch = window.fetch.bind(window)
window.fetch = (url, init) => {
  const path = typeof url === 'string' ? new URL(url, location.href).pathname : url instanceof URL ? url.pathname : new URL(url.url).pathname
  requests.push({ path, method: init?.method ?? 'GET' })
  return originalFetch(url, init)
}
const metadata = (value: MultiAccess): MultiSession => ({ actorId: value.actorId,
  browserSessionId: value.browserSessionId, provider: value.provider, sourceProfile: value.sourceProfile })
const result = (value: AccessOutcome) => value.status === 'access' ? { status: 'access', session: metadata(value.access) } : value
let confirmation: { status: 'idle' | 'working' | 'complete' | 'error'; session?: MultiSession; code?: string } = { status: 'idle' }
const clear = () => { document.getElementById('privado-candidate')?.remove(); confirmation = { status: 'idle' } }
function render(value: Preview) {
  clear()
  const box = document.createElement('section'); box.id = 'privado-candidate'
  if (value.status === 'waiting') { box.textContent = 'Waiting for wallet proof'; document.body.append(box); return }
  const title = document.createElement('h1'); title.textContent = 'Confirm the identity selected in your wallet'; box.append(title)
  for (const [name, text] of [['holderDid', value.holderDid], ['network', value.network], ['provider', 'Privado'], ['sourceProfile', value.sourceProfile]]) {
    const field = document.createElement('p'); field.dataset.field = name; field.textContent = text; box.append(field)
  }
  const accept = document.createElement('button'); accept.id = 'confirm-privado'; accept.textContent = 'Confirm this identity'
  accept.onclick = async () => {
    confirmation = { status: 'working' }; accept.disabled = true; reject.disabled = true
    try { confirmation = { status: 'complete', session: metadata(await client.confirmPrivado(value as Candidate)) } }
    catch (error) { confirmation = { status: 'error', code: (error as { code?: string }).code ?? 'unexpected_error' } }
  }
  const reject = document.createElement('button'); reject.id = 'reject-privado'; reject.textContent = 'Reject this identity'
  reject.onclick = async () => {
    accept.disabled = true; reject.disabled = true
    try { await client.cancelPrivado(value.requestId); clear() }
    catch (error) { confirmation = { status: 'error', code: (error as { code?: string }).code ?? 'unexpected_error' } }
  }
  box.append(accept, reject); document.body.append(box)
}
Object.assign(window, { multiAuthHarness: {
  providers: () => client.providers(),
  startPrivado: async (profile: string, holder?: string) => { clear(); return client.startPrivadoLogin(profile, holder) },
  startAzure: async (profile: string) => { clear(); return client.startAzureLogin(profile) },
  callback: async (state: string, code: string) => {
    history.replaceState(null, '', '/auth/azure/callback?' + new URLSearchParams({ state, code }))
    return metadata(await client.completeAzureCallback())
  },
  restore: async () => result(await client.restore()),
  need: async (expected: MultiSession) => result(await client.needAccess(expected)),
  preview: async (requestId: string) => { const value = await client.previewPrivado(requestId); render(value); return value },
  cancel: async (requestId: string) => { await client.cancelPrivado(requestId); clear() },
  confirmationResult: () => confirmation,
  logout: (expected: MultiSession) => client.logout(expected),
  own: async (expected: MultiSession) => client.withAccess(expected, async token => {
    const response = await fetch('/__test/protected', { headers: { Authorization: 'Bearer ' + token } })
    if (!response.ok) throw new Error('fixture_protected_request')
    return response.json()
  }),
  requests: () => requests.map(r => ({ ...r })),
  reset: () => { client = NewMultiClient(); requests = []; clear() },
} })
