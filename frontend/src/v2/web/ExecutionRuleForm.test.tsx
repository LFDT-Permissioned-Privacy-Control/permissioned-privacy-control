import '@testing-library/jest-dom/vitest'
import { webcrypto } from 'node:crypto'
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, expect, it, vi } from 'vitest'
import { ExecutionRuleForm } from './ExecutionRuleForm'
import type { SourceProject } from './sourceProject'
import go from './testdata/execution-abi-go.json'
const download = vi.hoisted(() => vi.fn())
vi.mock('./SourceReview', () => ({ download }))
const address = '0x' + '1'.repeat(40), codeAddress = '0x' + '2'.repeat(40), org = 'bank', project = { roots: [], dirty: false, generation: 4, validation: 'not-checked' } as SourceProject
const contracts = (abi: unknown) => [{ id: 'storage', name: 'Storage vault', address, abi }, { id: 'code', name: 'Execution library', address: codeAddress, abi }]
function props(abi = go.fixtures[0].input) { return { project, root: 'source', organization: org, check: vi.fn(), onClose: vi.fn(), onSave: vi.fn(), contracts: contracts(abi), value: { storageAddress: '', selector: '*', abiDigest: '' } } }
afterEach(() => { cleanup(); vi.unstubAllGlobals(); download.mockReset() })
it('authors an overloaded function with native linked-address and huge uint constraints', async () => {
  vi.stubGlobal('crypto', webcrypto)
  const p = props()
  render(<ExecutionRuleForm {...p} />)
  fireEvent.change(screen.getByLabelText('Storage contract'), { target: { value: address } })
  expect(screen.getByRole('option', { name: /transfer\(address,uint256\)/ })).toBeInTheDocument()
  expect(screen.getByRole('option', { name: /transfer\(address,uint256,bytes32\)/ })).toBeInTheDocument()
  await screen.findByText(/Common ABI derived digest/)
  fireEvent.change(screen.getByLabelText('ABI function / input'), { target: { value: '0xa9059cbb' } })
  fireEvent.change(screen.getByLabelText('Argument 0 constraint'), { target: { value: 'principal.linked' } })
  fireEvent.change(screen.getByLabelText('Argument 1 constraint'), { target: { value: 'uintAtMost' } })
  fireEvent.change(screen.getByLabelText('Argument 1 exact value'), { target: { value: '9007199254740993123456789' } })
  fireEvent.change(screen.getByLabelText('Maximum native value (wei)'), { target: { value: '0' } })
  fireEvent.change(screen.getByLabelText('Minimum depth'), { target: { value: '0' } })
  await userEvent.click(screen.getByRole('button', { name: 'Save rule draft' }))
  expect(p.onSave).toHaveBeenCalledWith({ storageAddress: address, selector: '0xa9059cbb', abiDigest: go.fixtures[0].report.abiDigest, args: [{ index: 0, addressEquals: { source: 'principal.linked' } }, { index: 1, uintAtMost: '9007199254740993123456789' }], maxValue: '0', minDepth: 0 })
})
it('imports bounded Go fallback and invalidates it immediately when source generation changes', async () => {
  vi.stubGlobal('crypto', webcrypto)
  const fixture = go.fixtures.find(f => !f.automaticSubset)!, p = { ...props(fixture.input), value: { storageAddress: address, selector: fixture.report.functions[0].selector, abiDigest: '' } }
  const { rerender } = render(<ExecutionRuleForm {...p} abiBytesByAddress={{ [address]: fixture.inputText }} />)
  await screen.findByText(/Use Go inspection/)
  const report = JSON.stringify(fixture.report), file = new File([report], 'report.json')
  Object.defineProperty(file, 'text', { value: async () => report })
  fireEvent.change(screen.getByLabelText('Go ABI inspection'), { target: { files: [file] } })
  await screen.findByText(/Imported operator report/)
  rerender(<ExecutionRuleForm {...p} abiBytesByAddress={{ [address]: fixture.inputText }} project={{ ...project, generation: 5 }} />)
  expect(screen.queryByText(/Imported operator report/)).not.toBeInTheDocument()
  await userEvent.click(screen.getByRole('button', { name: 'Save rule draft' }))
  expect(p.onSave).not.toHaveBeenCalled(); expect(await screen.findByRole('alert')).toHaveTextContent('current ABI inspection')
})
it('ignores a slow report file after ABI replacement and round-trips advanced rules without rewriting constraints', async () => {
  vi.stubGlobal('crypto', webcrypto)
  const fixture = go.fixtures.find(f => !f.automaticSubset)!, p = { ...props(fixture.input), value: { storageAddress: address, selector: fixture.report.functions[0].selector, abiDigest: fixture.report.abiDigest, args: [{ index: 0, recordParty: { getter: '0x12345678', abiDigest: fixture.report.abiDigest, partyOutputs: [0] } }], except: [{ target: address, groups: ['kept'] }] } }
  const { rerender } = render(<ExecutionRuleForm {...p} />)
  let resolve!: (value: string) => void
  const file = new File(['x'], 'slow.json'); Object.defineProperty(file, 'text', { value: () => new Promise<string>(r => { resolve = r }) })
  fireEvent.change(screen.getByLabelText('Go ABI inspection'), { target: { files: [file] } })
  await waitFor(() => expect(resolve).toBeTypeOf('function'))
  rerender(<ExecutionRuleForm {...p} contracts={contracts(go.fixtures[0].input)} />)
  resolve(JSON.stringify(fixture.report))
  await screen.findByText(/Common ABI derived digest/)
  expect(screen.queryByText(/Imported operator report/)).not.toBeInTheDocument()
  await userEvent.click(screen.getByRole('button', { name: 'Advanced native JSON' }))
  await userEvent.click(screen.getByRole('button', { name: 'Save rule draft' }))
  expect(p.onSave).toHaveBeenCalledWith(p.value)
})
it('renders read-only named function and typed constraints with zero-safe bounds', async () => {
  const { ExecutionRuleDetails } = await import('./ExecutionRuleDetails')
  render(<ExecutionRuleDetails contracts={contracts(go.fixtures[0].input)} rule={{ storageAddress: address, selector: '0xa9059cbb', abiDigest: go.fixtures[0].report.abiDigest, args: [{ index: 0, addressEquals: { source: 'principal.linked' } }, { index: 1, uintAtMost: '9007199254740993123456789' }], maxValue: '0', minDepth: 0, maxDepth: 0 }} />)
  expect(screen.getAllByText('transfer(address,uint256)')).toHaveLength(2)
  expect(screen.getAllByText('Storage vault · ' + address)).toHaveLength(2)
  expect(screen.getByText('Equals an address linked to the verified principal')).toBeInTheDocument()
  expect(screen.getByText('At most (inclusive): 9007199254740993123456789')).toBeInTheDocument()
  expect(screen.getByText('0 wei')).toBeInTheDocument()
})

it('uses the V1 function browser and selected check while preserving native default call-type omission', async () => {
  vi.stubGlobal('crypto', webcrypto)
  const p = { ...props(), value: { storageAddress: address, selector: '0xa9059cbb', abiDigest: go.fixtures[0].report.abiDigest, args: [{ index: 0, addressEquals: { source: 'principal.linked' } }], except: [{ target: address, groups: ['retain'] }], futureRule: { keep: true } } }
  render(<ExecutionRuleForm {...p} />); await screen.findByText('ABI assistance ready for this source')
  expect(screen.getByRole('button', { name: 'transfer(address,uint256)' })).toHaveAttribute('aria-pressed', 'true'); expect(screen.getByLabelText('call')).toBeChecked(); expect(screen.getByLabelText('staticcall')).toBeChecked(); expect(screen.getByText(/Native default · call and staticcall/)).toBeInTheDocument()
  await userEvent.click(screen.getByRole('button', { name: 'transfer(address,uint256)' })); fireEvent.change(screen.getByLabelText('Maximum native value (wei)'), { target: { value: '0' } }); await userEvent.click(screen.getByRole('button', { name: 'Save rule draft' }))
  expect(p.onSave).toHaveBeenCalledWith({ ...p.value, maxValue: '0' }); expect(p.onSave.mock.calls[0][0]).not.toHaveProperty('callTypes')
})
it('retains unsupported target/call/argument variants visibly and provides advanced repair', async () => {
  const p = { ...props(), value: { storageAddress: '', targetClass: 'future-target', selector: '*', abiDigest: '', callTypes: ['future-call'], args: { importedShape: 'keep' }, futureRule: true } }
  render(<ExecutionRuleForm {...p} />)
  expect(screen.getByRole('option', { name: 'Unsupported imported target — retained in advanced JSON' })).toBeInTheDocument(); expect(screen.getByText(/Unsupported imported call types are retained/)).toBeInTheDocument(); expect(screen.getByText(/Unsupported imported argument shape is retained/)).toBeInTheDocument()
  await userEvent.click(screen.getByRole('button', { name: 'Advanced native JSON' })); await userEvent.click(screen.getByRole('button', { name: 'Save rule draft' })); expect(p.onSave).toHaveBeenCalledWith(p.value)
})

it('keeps malformed imported nested argument variants inspectable instead of crashing the guided view', async () => {
  vi.stubGlobal('crypto', webcrypto)
  const p = { ...props(), value: { storageAddress: address, selector: '0xa9059cbb', abiDigest: go.fixtures[0].report.abiDigest, args: [{ index: 0, addressEquals: 'future-shape', retain: true }] } }
  render(<ExecutionRuleForm {...p} />); expect(screen.getByText(/advanced constraint retained; inspect advanced JSON/)).toBeInTheDocument(); await userEvent.click(screen.getByRole('button', { name: 'Advanced native JSON' })); await userEvent.click(screen.getByRole('button', { name: 'Save rule draft' })); expect(p.onSave).toHaveBeenCalledWith(p.value)
})
