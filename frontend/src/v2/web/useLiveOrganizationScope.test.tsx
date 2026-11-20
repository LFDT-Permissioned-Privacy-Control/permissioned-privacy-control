import '@testing-library/jest-dom/vitest'
import { useEffect } from 'react'
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { Link, MemoryRouter, useLocation } from 'react-router-dom'
import { afterEach, expect, it, vi } from 'vitest'
import { useLiveOrganizationScope } from './useLiveOrganizationScope'

const a = '11111111-1111-4111-8111-111111111111', b = '22222222-2222-4222-8222-222222222222'
function Page({ options, request }: { options: string[]; request: (id: string) => void }) {
  const location = useLocation(), [org, select] = useLiveOrganizationScope(options.map(id => ({ id })))
  useEffect(() => { if (org) request(org) }, [org, request])
  return <><output aria-label="Selected organization">{org}</output><output aria-label="Current URL">{location.pathname + location.search}</output>
    <button onClick={() => select(b)}>Select B</button><button onClick={() => select(a)}>Select A</button>
    <Link to={'/admin/compliance/policy' + location.search}>Policy draft</Link>
    <Link to={'/admin/compliance?org=' + a}>History to A</Link></>
}
afterEach(cleanup)

it('keeps the selected live organization, draft links and later URL navigation aligned', async () => {
  const request = vi.fn()
  render(<MemoryRouter initialEntries={['/admin/compliance?org=' + a]}><Page options={[a, b]} request={request} /></MemoryRouter>)
  fireEvent.click(screen.getByRole('button', { name: 'Select B' }))
  expect(screen.getByLabelText('Selected organization')).toHaveTextContent(b)
  expect(screen.getByRole('link', { name: 'Policy draft' })).toHaveAttribute('href', '/admin/compliance/policy?org=' + b)
  expect(request).toHaveBeenLastCalledWith(b)
  fireEvent.click(screen.getByRole('link', { name: 'History to A' }))
  expect(screen.getByLabelText('Selected organization')).toHaveTextContent(a)
  expect(request).toHaveBeenLastCalledWith(a)
})

it('normalizes the sole authorized default only when no organization was requested', async () => {
  render(<MemoryRouter initialEntries={['/admin/logs']}><Page options={[a]} request={vi.fn()} /></MemoryRouter>)
  await waitFor(() => expect(screen.getByLabelText('Current URL')).toHaveTextContent('/admin/logs?org=' + a))
})

it('keeps an explicitly unauthorized scope unselected and makes no fallback read', () => {
  const request = vi.fn()
  render(<MemoryRouter initialEntries={['/admin/compliance?org=' + b]}><Page options={[a]} request={request} /></MemoryRouter>)
  expect(screen.getByLabelText('Selected organization')).toBeEmptyDOMElement()
  expect(screen.getByLabelText('Current URL')).toHaveTextContent('/admin/compliance?org=' + b)
  expect(request).not.toHaveBeenCalled()
  fireEvent.click(screen.getByRole('button', { name: 'Select B' }))
  expect(request).not.toHaveBeenCalled()
  fireEvent.click(screen.getByRole('button', { name: 'Select A' }))
  expect(screen.getByLabelText('Selected organization')).toHaveTextContent(a)
  expect(request).toHaveBeenCalledTimes(1)
  expect(request).toHaveBeenLastCalledWith(a)
})
