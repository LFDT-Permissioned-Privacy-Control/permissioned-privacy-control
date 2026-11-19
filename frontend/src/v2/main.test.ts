import { afterEach, expect, it, vi } from 'vitest'

const calls = vi.hoisted(() => [] as string[])
vi.mock('./web/controller', () => ({ Controller: class {
  callback() { calls.push('scrub'); history.replaceState(null, '', '/auth/azure/callback'); return Promise.resolve({ error: Error('test') }) }
  start() { calls.push('start'); return Promise.resolve() }
} }))
vi.mock('./web/AdminApp', () => {
  calls.push('ui-import')
  expect(location.search).toBe('')
  return { mount: () => calls.push('mount') }
})
afterEach(() => { vi.resetModules(); history.replaceState(null, '', '/login') })
it('scrubs Azure callback credentials before importing the UI/provider/style graph', async () => {
  calls.length = 0
  history.replaceState(null, '', '/auth/azure/callback?code=credential&state=opaque')
  await import('./main')
  await vi.waitFor(() => expect(calls).toContain('start'))
  expect(calls).toEqual(['scrub', 'ui-import', 'mount', 'start'])
})
