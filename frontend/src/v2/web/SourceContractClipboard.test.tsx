import '@testing-library/jest-dom/vitest'
import { act, cleanup, fireEvent, render, screen } from '@testing-library/react'
import { afterEach, expect, it, vi } from 'vitest'
import { ContractAddress } from '../../components/rbac/ContractPresentation'

const address = '0x' + '1'.repeat(40), another = '0x' + '2'.repeat(40)
afterEach(() => { cleanup(); vi.unstubAllGlobals(); vi.useRealTimers() })

it('explains clipboard unavailability instead of throwing or claiming success', async () => {
  vi.stubGlobal('navigator', {})
  Object.defineProperty(document, 'execCommand', { configurable: true, value: undefined })
  render(<ContractAddress address={address} />)
  fireEvent.click(screen.getByRole('button', { name: 'Copy address ' + address }))
  expect(await screen.findByRole('status')).toHaveTextContent('Copy failed. Select the value and copy it manually.')
  expect(screen.getByRole('button')).toHaveAttribute('title', 'Copy address ' + address)
})
it('reports a rejected clipboard write and permits an explicit successful retry', async () => {
  const writeText = vi.fn().mockRejectedValueOnce(Error('Permission denied')).mockResolvedValue(undefined)
  vi.stubGlobal('navigator', { clipboard: { writeText } })
  render(<ContractAddress address={address} />)
  fireEvent.click(screen.getByRole('button'))
  expect(await screen.findByRole('status')).toHaveTextContent('Copy failed.')
  fireEvent.click(screen.getByRole('button'))
  await act(async () => {})
  expect(writeText).toHaveBeenLastCalledWith(address)
  expect(screen.queryByRole('status')).not.toBeInTheDocument()
  expect(screen.getByRole('button')).toHaveAttribute('title', 'Copied')
})
it('does not publish a completed copy after its displayed address changes', async () => {
  let finish!: () => void
  const pending = new Promise<void>(resolve => { finish = resolve }), writeText = vi.fn(() => pending)
  vi.stubGlobal('navigator', { clipboard: { writeText } })
  const { rerender } = render(<ContractAddress address={address} />)
  fireEvent.click(screen.getByRole('button'))
  rerender(<ContractAddress address={another} />)
  await act(async () => { finish(); await pending })
  expect(writeText).toHaveBeenCalledWith(address)
  expect(screen.getByRole('button', { name: 'Copy address ' + another })).toHaveAttribute('title', 'Copy address ' + another)
  expect(screen.queryByRole('status')).not.toBeInTheDocument()
})
it('does not schedule success feedback after the address view is unmounted', async () => {
  vi.useFakeTimers()
  let finish!: () => void
  const pending = new Promise<void>(resolve => { finish = resolve })
  vi.stubGlobal('navigator', { clipboard: { writeText: vi.fn(() => pending) } })
  const { unmount } = render(<ContractAddress address={address} />)
  fireEvent.click(screen.getByRole('button')); unmount()
  await act(async () => { finish(); await pending })
  expect(vi.getTimerCount()).toBe(0)
})
