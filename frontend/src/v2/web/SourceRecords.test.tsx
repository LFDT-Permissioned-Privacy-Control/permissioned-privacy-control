import '@testing-library/jest-dom/vitest'
import { cleanup, fireEvent, render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, expect, it, vi } from 'vitest'
import { SourceRecordForm, SourceRecords } from './SourceRecords'

afterEach(cleanup)
it('edits an existing contract proposal while preserving ABI, grants and unknown source fields', async () => {
  const request = vi.fn(); vi.stubGlobal('fetch', request)
  const change = vi.fn(), contract = { id: 'contract', name: 'Original vault', address: '0x' + '1'.repeat(40), abi: [{ type: 'event', name: 'Paid' }], readGrants: [{ id: 'grant', groupId: 'group' }], futureField: { preserve: true } }
  render(<SourceRecords title="Contracts" records={[contract]} fields={[{ key: 'name', label: 'Name' }, { key: 'address', label: 'Contract address' }]} editing defaults={() => ({})} onChange={change} />)
  await userEvent.click(screen.getByTitle('Edit contracts draft'))
  const form = screen.getByRole('dialog'); await userEvent.clear(within(form).getByLabelText('Name')); await userEvent.type(within(form).getByLabelText('Name'), 'Reviewed vault')
  await userEvent.click(within(form).getByRole('button', { name: 'Save draft' }))
  expect(change).toHaveBeenCalledWith([{ ...contract, name: 'Reviewed vault' }]); expect(request).not.toHaveBeenCalled(); vi.unstubAllGlobals()
})
it('does not claim JSON validity or mutate a proposal when its complex field cannot parse', async () => {
  const change = vi.fn()
  render(<SourceRecords title="Read grants" records={[]} fields={[{ key: 'eventRules', label: 'Event rules', kind: 'json' }]} editing defaults={() => ({ eventRules: { mode: 'none', rules: [] } })} onChange={change} />)
  await userEvent.click(screen.getByRole('button', { name: 'Add read grant' }))
  fireEvent.change(screen.getByLabelText('Event rules'), { target: { value: '{broken' } })
  await userEvent.click(screen.getByRole('button', { name: 'Save draft' }))
  expect(screen.getByRole('alert')).toBeInTheDocument(); expect(change).not.toHaveBeenCalled()
})
it('refuses a new numeric field value outside the browser exact integer range', async () => {
  const change = vi.fn()
  render(<SourceRecordForm value={{ maxDepth: 1 }} fields={[{ key: 'maxDepth', label: 'Maximum depth', kind: 'number' }]} onSave={change} onClose={() => {}} />)
  fireEvent.change(screen.getByLabelText('Maximum depth'), { target: { value: '9007199254740993' } })
  await userEvent.click(screen.getByRole('button', { name: 'Save draft' }))
  expect(change).not.toHaveBeenCalled(); expect(screen.getByRole('alert')).toHaveTextContent('exact integer range')
})
it('displays configured nested fact and event permissions in row details and inspection', async () => {
  render(<SourceRecords title="Permissions" records={[{ id: 'mapping', fact: { kind: 'azure.role', value: 'payments' }, eventRules: { mode: 'allowlist', rules: [{ topic0: 'topic', name: 'Paid' }] } }]} fields={[{ key: 'fact.kind', label: 'Fact kind' }, { key: 'fact.value', label: 'Fact value' }, { key: 'eventRules.mode', label: 'Event mode' }, { key: 'eventRules.rules', label: 'Event rules', kind: 'json' }]} editing={false} defaults={() => ({})} onChange={() => {}} />)
  expect(screen.getByText('Fact kind: azure.role')).toBeInTheDocument(); expect(screen.getByText('Event mode: allowlist')).toBeInTheDocument()
  await userEvent.click(screen.getByRole('button', { name: 'mapping' }))
  expect(within(screen.getByRole('dialog')).getByText('azure.role')).toBeInTheDocument()
  expect(within(screen.getByRole('dialog')).getByText('allowlist')).toBeInTheDocument()
  const details = within(screen.getByRole('dialog')).getByText('Show event rules').closest('details')!
  expect(details).not.toHaveAttribute('open')
  await userEvent.click(within(details).getByText('Show event rules'))
  expect(within(details).getByText(/"name": "Paid"/)).toBeVisible()
  expect(within(screen.getByRole('dialog')).queryByText('Not set')).not.toBeInTheDocument()
})
