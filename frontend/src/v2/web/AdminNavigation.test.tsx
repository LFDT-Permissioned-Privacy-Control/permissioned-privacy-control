import '@testing-library/jest-dom/vitest'
import { cleanup, render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, expect, it, vi } from 'vitest'
import { MemoryRouter, useLocation } from 'react-router-dom'
import { AdminLayout, type AdminNavigation } from '../../components/AdminLayout'

const org = '11111111-1111-1111-1111-111111111111'
function LocationProbe() { const location = useLocation(); return <output aria-label="Current route">{location.pathname + location.search}</output> }
function shell({ path = '/admin/rbac', navigation, showNavigation = true, disabledTabs = [] }: { path?: string; navigation?: AdminNavigation; showNavigation?: boolean; disabledTabs?: ('rbac' | 'compliance' | 'disclosure' | 'logs' | 'diagnostics')[] } = {}) {
  return render(<MemoryRouter initialEntries={[path]}><AdminLayout accountMenu={<button>Account menu</button>} navigation={navigation} showNavigation={showNavigation} disabledTabs={disabledTabs}><LocationProbe /><p>Existing content slot</p></AdminLayout></MemoryRouter>)
}
function customNavigation(activeId: string | null, action = <button>Review &amp; export</button>): AdminNavigation {
  return { activeId, action, items: [
    { id: 'rbac', label: 'RBAC', path: '/admin/rbac/organizations?org=' + org },
    { id: 'identity', label: 'Identity', path: '/admin/identity/profiles?org=' + org },
    { id: 'compliance', label: 'Compliance', path: '/admin/compliance?org=' + org },
    { id: 'disclosure', label: 'Disclosure', path: '/admin/disclosure?org=' + org },
    { id: 'logs', label: 'Access Logs', path: '/admin/logs', secondary: true },
    { id: 'diagnostics', label: 'Diagnostics', path: '/admin/diagnostics', secondary: true },
    { id: 'settings', label: 'Settings', path: '/admin/settings?org=' + org, secondary: true },
  ] }
}
afterEach(cleanup)
it('preserves the V1 default shell, active tabs, disabled tabs and original organization query behavior', async () => {
  shell({ path: '/admin/compliance?org=org-1', disabledTabs: ['diagnostics'] })
  expect(screen.getByRole('heading', { name: 'Open Privacy Suite' })).toBeInTheDocument()
  expect(screen.getAllByRole('tab').map(tab => tab.getAttribute('aria-label'))).toEqual(['RBAC', 'Compliance', 'Disclosure', 'Access Logs', 'Diagnostics'])
  expect(screen.getByRole('tab', { name: 'Compliance' })).toHaveAttribute('aria-selected', 'true')
  expect(screen.queryByRole('tab', { name: 'Identity' })).not.toBeInTheDocument(); expect(screen.queryByRole('link', { name: 'Settings' })).not.toBeInTheDocument()
  await userEvent.click(screen.getByRole('tab', { name: 'RBAC' })); expect(screen.getByLabelText('Current route')).toHaveTextContent('/admin/rbac?org=org-1')
  await userEvent.click(screen.getByRole('tab', { name: 'Access Logs' })); expect(screen.getByLabelText('Current route')).toHaveTextContent('/admin/logs'); expect(screen.getByLabelText('Current route')).not.toHaveTextContent('org=')
  expect(screen.getByRole('tab', { name: 'Diagnostics' })).toBeDisabled(); await userEvent.click(screen.getByRole('tab', { name: 'Diagnostics' })); expect(screen.getByLabelText('Current route')).toHaveTextContent('/admin/logs')
  expect(screen.queryByTestId('admin-secondary-row')).not.toBeInTheDocument(); expect(screen.getByRole('button', { name: 'Account menu' })).toBeInTheDocument(); expect(screen.getByText('Existing content slot')).toBeInTheDocument()
})
it('keeps V2 primary tabs, utilities and review together in the same responsive navigation cluster', async () => {
  const review = vi.fn()
  shell({ path: '/admin/identity/profiles?org=' + org, navigation: customNavigation('identity', <button onClick={review}>Review &amp; export</button>) })
  const primary = screen.getByRole('tablist', { name: 'Primary administration' }), secondary = screen.getByRole('navigation', { name: 'More administration' })
  expect(within(primary).getAllByRole('tab').map(tab => tab.getAttribute('aria-label'))).toEqual(['RBAC', 'Identity', 'Compliance', 'Disclosure'])
  expect(within(primary).getByRole('tab', { name: 'Identity' })).toHaveAttribute('aria-selected', 'true')
  expect(within(secondary).getAllByRole('link').map(link => link.textContent)).toEqual(['Access Logs', 'Diagnostics', 'Settings'])
  const cluster = screen.getByTestId('admin-navigation')
  expect(cluster).toContainElement(primary); expect(cluster).toContainElement(secondary)
  expect(cluster).toContainElement(screen.getByRole('button', { name: 'Review & export' }))
  expect(screen.queryByTestId('admin-secondary-row')).not.toBeInTheDocument()
  expect(within(primary).queryByRole('tab', { name: 'Configuration' })).not.toBeInTheDocument(); expect(within(primary).queryByRole('tab', { name: 'Review & export' })).not.toBeInTheDocument()
  await userEvent.click(screen.getByRole('button', { name: 'Review & export' })); expect(review).toHaveBeenCalledTimes(1)
  await userEvent.click(within(primary).getByRole('tab', { name: 'Compliance' })); expect(screen.getByLabelText('Current route')).toHaveTextContent('/admin/compliance?org=' + org)
  await userEvent.click(within(secondary).getByRole('link', { name: 'Access Logs' })); expect(screen.getByLabelText('Current route')).toHaveTextContent('/admin/logs'); expect(screen.getByLabelText('Current route')).not.toHaveTextContent('org=')
})
it('marks an active secondary destination using the V1 selected colors and page semantics without selecting a primary tab', () => {
  shell({ path: '/admin/settings?org=' + org, navigation: customNavigation('settings') })
  expect(screen.getByRole('link', { name: 'Settings' })).toHaveAttribute('aria-current', 'page')
  expect(screen.getByRole('link', { name: 'Settings' })).toHaveAttribute('href', '/admin/settings?org=' + org)
  expect(screen.getByRole('link', { name: 'Settings' })).toHaveClass('bg-white', 'text-primary', 'shadow-sm')
  expect(screen.queryAllByRole('tab', { selected: true })).toHaveLength(0)
  expect(screen.getByRole('link', { name: 'Diagnostics' })).not.toHaveAttribute('aria-current')
})
it('keeps review unselected and hides all custom navigation and actions when the account boundary hides navigation', () => {
  const pane = shell({ path: '/admin/configuration', navigation: customNavigation(null) })
  expect(screen.queryAllByRole('tab', { selected: true })).toHaveLength(0)
  expect(screen.getAllByRole('link').every(link => !link.hasAttribute('aria-current'))).toBe(true)
  pane.unmount()
  shell({ path: '/admin/account', navigation: customNavigation(null), showNavigation: false })
  expect(screen.queryByRole('tablist')).not.toBeInTheDocument(); expect(screen.queryByRole('navigation', { name: 'More administration' })).not.toBeInTheDocument(); expect(screen.queryByRole('button', { name: 'Review & export' })).not.toBeInTheDocument(); expect(screen.getByRole('button', { name: 'Account menu' })).toBeInTheDocument()
})
it('keeps disabled custom primary and secondary items inert', async () => {
  const navigation = customNavigation('rbac'); navigation.items = navigation.items.map(item => ['identity', 'settings'].includes(item.id) ? { ...item, disabled: true } : item)
  shell({ path: '/admin/rbac/organizations', navigation })
  expect(screen.getByRole('tab', { name: 'Identity' })).toBeDisabled()
  const settings = screen.getByRole('link', { name: 'Settings' }); expect(settings).toHaveAttribute('aria-disabled', 'true'); expect(settings).not.toHaveAttribute('href')
  await userEvent.click(screen.getByRole('tab', { name: 'Identity' })); expect(screen.getByLabelText('Current route')).toHaveTextContent('/admin/rbac/organizations')
})

it('preserves arrow navigation between primary tabs and keyboard access to utilities, review and account', async () => {
  function RoutedShell() {
    const location = useLocation()
    const active = location.pathname.includes('/identity/') ? 'identity' : 'rbac'
    return <AdminLayout navigation={customNavigation(active)} accountMenu={<button>Account menu</button>}><LocationProbe /></AdminLayout>
  }
  render(<MemoryRouter initialEntries={['/admin/rbac/organizations']}><RoutedShell /></MemoryRouter>)
  screen.getByRole('tab', { name: 'RBAC' }).focus()
  await userEvent.keyboard('{ArrowRight}')
  expect(screen.getByRole('tab', { name: 'Identity' })).toHaveFocus()
  expect(screen.getByRole('tab', { name: 'Identity' })).toHaveAttribute('aria-selected', 'true')
  expect(screen.getByLabelText('Current route')).toHaveTextContent('/admin/identity/profiles?org=' + org)
  for (const label of ['Access Logs', 'Diagnostics', 'Settings']) {
    await userEvent.tab(); expect(screen.getByRole('link', { name: label })).toHaveFocus()
  }
  await userEvent.tab(); expect(screen.getByRole('button', { name: 'Review & export' })).toHaveFocus()
  await userEvent.tab(); expect(screen.getByRole('button', { name: 'Account menu' })).toHaveFocus()
})
