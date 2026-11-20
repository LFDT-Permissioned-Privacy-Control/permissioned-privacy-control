import '@testing-library/jest-dom/vitest'
import { cleanup, render, screen } from '@testing-library/react'
import { afterEach, expect, it } from 'vitest'
import { CasePageSummary } from './NativeDisclosures'
import type { NativeCase } from './operationsModels'

afterEach(cleanup)
it('shows loaded-page counts with expired open cases distinct from revoked and closed cases', () => {
  const rows = [{ status: 'open', expiresAt: 101 }, { status: 'open', expiresAt: 100 }, { status: 'revoked', expiresAt: 999 }, { status: 'closed', expiresAt: 999 }] as NativeCase[]
  const view = render(<CasePageSummary items={rows} now={100000} loading={false} scanComplete={false} />)
  expect(screen.getByTestId('case-summary-total')).toHaveTextContent('Cases on this page4')
  for (const status of ['open', 'expired', 'revoked', 'closed']) expect(screen.getByTestId('case-summary-' + status).querySelector('p:last-child')).toHaveTextContent('1')
  expect(screen.getByText(/Counts cover only this loaded page and its filters, not the organization total/)).toHaveTextContent('scan is incomplete')
  // Replacing the loaded page replaces counts, without accumulating an invented total.
  view.rerender(<CasePageSummary items={rows.slice(0, 1)} now={101000} loading={false} scanComplete />)
  expect(screen.getByTestId('case-summary-total')).toHaveTextContent('Cases on this page1')
  expect(screen.getByTestId('case-summary-open').querySelector('p:last-child')).toHaveTextContent('0')
  expect(screen.getByTestId('case-summary-expired').querySelector('p:last-child')).toHaveTextContent('1')
  view.rerender(<CasePageSummary items={rows} now={100000} loading scanComplete />)
  expect(screen.getByTestId('case-summary-total')).toHaveTextContent('Cases on this page—')
})
