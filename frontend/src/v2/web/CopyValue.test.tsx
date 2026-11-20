import '@testing-library/jest-dom/vitest'
import { act, cleanup, fireEvent, render, screen } from '@testing-library/react'
import { afterEach, expect, it, vi } from 'vitest'
import { CopyValue } from '../../components/ui/CopyValue'

const originalExec = Object.getOwnPropertyDescriptor(document, 'execCommand')
afterEach(() => {
  cleanup(); vi.unstubAllGlobals(); vi.useRealTimers()
  if (originalExec) Object.defineProperty(document, 'execCommand', originalExec)
  else Reflect.deleteProperty(document, 'execCommand')
})
function clipboard(writeText?: (value: string) => Promise<void>, fallback?: () => boolean) {
  vi.stubGlobal('navigator', writeText ? { clipboard: { writeText } } : {})
  Object.defineProperty(document, 'execCommand', { configurable: true, value: fallback })
}
it.each(['absent', 'rejected'] as const)('reports failure when modern clipboard is %s and the fallback returns false', async modern => {
  const fallback = vi.fn(() => false)
  clipboard(modern === 'rejected' ? vi.fn(async () => { throw Error('Denied') }) : undefined, fallback)
  render(<CopyValue value="public-record-id" label="Copy record ID" />)
  fireEvent.click(screen.getByRole('button'))
  expect(await screen.findByRole('status')).toHaveTextContent('Copy failed.')
  expect(screen.getByRole('button')).toHaveAttribute('title', 'Copy record ID')
  expect(fallback).toHaveBeenCalledWith('copy')
  expect(document.querySelector('textarea')).toBeNull()
})
it.each(['absent', 'rejected'] as const)('cleans up and reports a throwing fallback after %s modern clipboard', async modern => {
  clipboard(modern === 'rejected' ? vi.fn(async () => { throw Error('Denied') }) : undefined, () => { throw Error('Browser refused copy') })
  render(<CopyValue value="public-record-id" />)
  fireEvent.click(screen.getByRole('button'))
  expect(await screen.findByRole('status')).toHaveTextContent('Copy failed.')
  expect(document.querySelector('textarea')).toBeNull()
})
it.each(['absent', 'rejected'] as const)('confirms a true fallback result after %s modern clipboard', async modern => {
  clipboard(modern === 'rejected' ? vi.fn(async () => { throw Error('Denied') }) : undefined, () => {
    expect(document.activeElement).toBeInstanceOf(HTMLTextAreaElement)
    expect((document.activeElement as HTMLTextAreaElement).value).toBe('public-record-id')
    return true
  })
  render(<CopyValue value="public-record-id" />)
  fireEvent.click(screen.getByRole('button'))
  await act(async () => {})
  expect(screen.getByRole('button')).toHaveAttribute('title', 'Copied')
  expect(screen.queryByRole('status')).not.toBeInTheDocument()
  expect(document.querySelector('textarea')).toBeNull()
})
it('uses successful modern clipboard without trying the deprecated fallback', async () => {
  const writeText = vi.fn(async () => {}), fallback = vi.fn(() => false)
  clipboard(writeText, fallback)
  render(<CopyValue value="public-record-id" />)
  fireEvent.click(screen.getByRole('button')); await act(async () => {})
  expect(writeText).toHaveBeenCalledWith('public-record-id'); expect(fallback).not.toHaveBeenCalled()
  expect(screen.getByRole('button')).toHaveAttribute('title', 'Copied')
})
it.each(['resolve', 'reject'] as const)('retires a late modern %s when the displayed value changes', async outcome => {
  let finish!: () => void, fail!: () => void
  const pending = new Promise<void>((resolve, reject) => { finish = resolve; fail = () => reject(Error('Denied')) }), fallback = vi.fn(() => true)
  clipboard(vi.fn(() => pending), fallback)
  const { rerender } = render(<CopyValue value="old-record" />)
  fireEvent.click(screen.getByRole('button')); rerender(<CopyValue value="current-record" />)
  await act(async () => { if (outcome === 'resolve') finish(); else fail(); try { await pending } catch {} })
  expect(screen.getByRole('button')).toHaveAttribute('title', 'Copy')
  expect(screen.queryByRole('status')).not.toBeInTheDocument(); expect(fallback).not.toHaveBeenCalled()
})
it('does not schedule feedback after the display is unmounted', async () => {
  vi.useFakeTimers()
  let finish!: () => void
  const pending = new Promise<void>(resolve => { finish = resolve })
  clipboard(vi.fn(() => pending))
  const { unmount } = render(<CopyValue value="public-record-id" />)
  fireEvent.click(screen.getByRole('button')); unmount()
  await act(async () => { finish(); await pending })
  expect(vi.getTimerCount()).toBe(0)
})
