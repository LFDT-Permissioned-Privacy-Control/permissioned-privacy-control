import { expect, it } from 'vitest'
import { parseMethodCatalog } from './methodCatalog'
const payload = { version: 'rpc-method-catalog/v1', methods: [{ name: 'bank_call', canonical: 'eth_call' }, { name: 'eth_call', canonical: 'eth_call' }] }
it('accepts the running catalog including aliases and rejects malformed or ambiguous responses', () => {
  expect(parseMethodCatalog(payload)).toEqual(payload)
  expect(() => parseMethodCatalog({ ...payload, methods: [payload.methods[0], payload.methods[0]] })).toThrow()
  expect(() => parseMethodCatalog({ ...payload, methods: [{ name: 'eth_call', canonical: '' }] })).toThrow()
  expect(() => parseMethodCatalog({ ...payload, extra: true })).toThrow()
})
