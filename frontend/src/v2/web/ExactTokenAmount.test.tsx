import '@testing-library/jest-dom/vitest'
import { cleanup, fireEvent, render, screen } from '@testing-library/react'
import { afterEach, expect, it } from 'vitest'
import { ExactAmount, useExactAmountState } from './ExactTokenAmount'
function Harness({ unitsKey, decimals }: { unitsKey: string; decimals?: number }) {
  const state = useExactAmountState(unitsKey, decimals)
  return <ExactAmount amount={state.amount} mode={state.mode} decimals={decimals} unit="TOKEN" onAmount={state.setAmount} onMode={state.setMode} notice={state.notice} />
}
afterEach(cleanup)
it('defaults known decimals including zero to human; mode changes clear instead of reinterpreting text', () => {
  render(<Harness unitsKey="token:0" decimals={0} />)
  expect(screen.getByLabelText('Amount entry')).toHaveValue('human')
  fireEvent.change(screen.getByLabelText('Amount (TOKEN)'), { target: { value: '9007199254740993' } })
  expect(screen.getByText('9007199254740993')).toBeInTheDocument()
  fireEvent.change(screen.getByLabelText('Amount entry'), { target: { value: 'base' } })
  expect(screen.getByLabelText('Amount in base units')).toHaveValue('')
  expect(screen.getByText(/Amount cleared/)).toBeInTheDocument()
  fireEvent.change(screen.getByLabelText('Amount in base units'), { target: { value: '1' } })
  expect(screen.queryByText(/Amount cleared/)).not.toBeInTheDocument()
  fireEvent.change(screen.getByLabelText('Amount entry'), { target: { value: 'human' } })
  expect(screen.getByLabelText('Amount (TOKEN)')).toHaveValue('')
})
it('clears token/type/current catalog changes and never resurrects an amount on switching back', () => {
  const { rerender } = render(<Harness unitsKey="first:6" decimals={6} />)
  fireEvent.change(screen.getByLabelText('Amount (TOKEN)'), { target: { value: '0.1' } })
  expect(screen.getByText('100000')).toBeInTheDocument()
  rerender(<Harness unitsKey="second:18" decimals={18} />)
  expect(screen.getByLabelText('Amount (TOKEN)')).toHaveValue('')
  expect(screen.queryByText('100000')).not.toBeInTheDocument()
  rerender(<Harness unitsKey="first:6" decimals={6} />)
  expect(screen.getByLabelText('Amount (TOKEN)')).toHaveValue('')
  fireEvent.change(screen.getByLabelText('Amount (TOKEN)'), { target: { value: '0.1' } })
  rerender(<Harness unitsKey="native:18" decimals={18} />)
  expect(screen.getByLabelText('Amount (TOKEN)')).toHaveValue('')
})
it('uses explicit base units while metadata is unknown and clears on current catalog arrival/loss', () => {
  const { rerender } = render(<Harness unitsKey="token:unknown" />)
  expect(screen.getByLabelText('Amount entry')).toHaveValue('base')
  fireEvent.change(screen.getByLabelText('Amount in base units'), { target: { value: '100000' } })
  rerender(<Harness unitsKey="token:6" decimals={6} />)
  expect(screen.getByLabelText('Amount entry')).toHaveValue('human')
  expect(screen.getByLabelText('Amount (TOKEN)')).toHaveValue('')
  fireEvent.change(screen.getByLabelText('Amount (TOKEN)'), { target: { value: '0.1' } })
  rerender(<Harness unitsKey="token:unknown" />)
  expect(screen.getByLabelText('Amount entry')).toHaveValue('base')
  expect(screen.getByLabelText('Amount in base units')).toHaveValue('')
})
