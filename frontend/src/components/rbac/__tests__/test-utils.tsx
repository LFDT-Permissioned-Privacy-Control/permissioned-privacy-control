import React, { ReactElement, useState, createContext, useContext } from 'react';
import { render, RenderOptions, screen, waitFor } from '@testing-library/react';
import { MemoryRouter, Routes, Route, Outlet } from 'react-router-dom';
import { expect } from 'vitest';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { AuthProvider } from '@/contexts/AuthContext';
import type { Organization } from '@/types/rbac';
import { mockOrganization } from '@/test/mocks/handlers';

// Create a test context that can be shared across test files
// This is exported so test files can use it in their vi.mock factories
interface OrgContextType {
  selectedOrg: Organization | null;
  setSelectedOrg: (org: Organization | null) => void;
  organizations: Organization[];
  refreshOrgs: () => Promise<void>;
}

export const TestOrgContext = createContext<OrgContextType | null>(null);

// Re-export a useOrgContext that reads from TestOrgContext
export function useOrgContext() {
  const context = useContext(TestOrgContext);
  if (!context) {
    throw new Error('useOrgContext must be used within provider');
  }
  return context;
}

// Non-throwing variant mirroring RBACManager.useOrgContextOptional. Returns
// null when no provider is present (so components that read it in isolation
// don't blow up).
export function useOrgContextOptional() {
  return useContext(TestOrgContext);
}

// Alias for backwards compatibility
export const OrgContext = TestOrgContext;

// Mock OrgContext provider for testing
interface MockOrgProviderProps {
  children: React.ReactNode;
  initialOrg?: Organization | null;
  organizations?: Organization[];
  onOrgChange?: (org: Organization | null) => void;
}

function MockOrgProvider({
  children,
  initialOrg = mockOrganization,
  organizations = [mockOrganization],
  onOrgChange,
}: MockOrgProviderProps) {
  const [selectedOrg, setSelectedOrg] = useState<Organization | null>(initialOrg);

  const handleSetSelectedOrg = (org: Organization | null) => {
    setSelectedOrg(org);
    onOrgChange?.(org);
  };

  const refreshOrgs = async () => {
    // No-op in tests, mock handlers control data
  };

  return (
    <TestOrgContext.Provider
      value={{
        selectedOrg,
        setSelectedOrg: handleSetSelectedOrg,
        organizations,
        refreshOrgs,
      }}
    >
      {children}
    </TestOrgContext.Provider>
  );
}

// Create a fresh QueryClient for each test
function createTestQueryClient() {
  return new QueryClient({
    defaultOptions: {
      queries: {
        retry: false,
        gcTime: 0,
        staleTime: 0,
      },
      mutations: {
        retry: false,
      },
    },
  });
}

// Options for renderWithRBACContext
interface RBACRenderOptions extends Omit<RenderOptions, 'wrapper'> {
  initialOrg?: Organization | null;
  organizations?: Organization[];
  initialRoute?: string;
  routes?: Array<{ path: string; element: React.ReactElement }>;
  onOrgChange?: (org: Organization | null) => void;
}

/**
 * Render helper that wraps components with all providers needed for RBAC testing:
 * - MemoryRouter (for routing)
 * - QueryClientProvider (for react-query)
 * - AuthProvider (for auth context)
 * - MockOrgProvider (for organization context)
 *
 * @example
 * ```tsx
 * const { getByText } = renderWithRBACContext(<GroupList />);
 * await waitFor(() => expect(getByText('Root Group')).toBeInTheDocument());
 * ```
 *
 * @example With custom organization
 * ```tsx
 * renderWithRBACContext(<GroupList />, {
 *   initialOrg: mockOrganizations[1],
 *   organizations: mockOrganizations,
 * });
 * ```
 *
 * @example With custom routes
 * ```tsx
 * renderWithRBACContext(<GroupList />, {
 *   initialRoute: '/admin/rbac/groups',
 *   routes: [
 *     { path: '/admin/rbac/groups', element: <GroupList /> },
 *     { path: '/admin/rbac/groups/:groupId', element: <GroupDetail /> },
 *   ],
 * });
 * ```
 */
export function renderWithRBACContext(
  ui: ReactElement,
  {
    initialOrg = mockOrganization,
    organizations = [mockOrganization],
    initialRoute = '/',
    routes,
    onOrgChange,
    ...renderOptions
  }: RBACRenderOptions = {}
) {
  const queryClient = createTestQueryClient();

  function Wrapper({ children }: { children: React.ReactNode }) {
    return (
      <QueryClientProvider client={queryClient}>
        <AuthProvider>
          <MemoryRouter future={{ v7_startTransition: true, v7_relativeSplatPath: true }} initialEntries={[initialRoute]}>
            <MockOrgProvider
              initialOrg={initialOrg}
              organizations={organizations}
              onOrgChange={onOrgChange}
            >
              {routes ? (
                <Routes>
                  {routes.map(({ path, element }) => (
                    <Route key={path} path={path} element={element} />
                  ))}
                </Routes>
              ) : (
                children
              )}
            </MockOrgProvider>
          </MemoryRouter>
        </AuthProvider>
      </QueryClientProvider>
    );
  }

  const result = render(routes ? <></> : ui, { wrapper: Wrapper, ...renderOptions });

  return {
    ...result,
    queryClient,
    // Helper to change the selected organization
    setOrg: (org: Organization | null) => {
      onOrgChange?.(org);
    },
  };
}

/**
 * Render helper for testing the full RBACManager with nested routes.
 * Use this when testing navigation between RBAC tabs.
 *
 * @example
 * ```tsx
 * const { getByTestId, user } = await renderRBACManager({
 *   initialRoute: '/admin/rbac/organizations',
 * });
 * await user.click(getByTestId('tab-groups'));
 * ```
 */
export function renderWithRBACLayout(
  ui: ReactElement,
  options: RBACRenderOptions = {}
) {
  // Wrap the UI in a layout that mimics RBACManager's Outlet pattern
  function LayoutWrapper() {
    return (
      <div data-testid="rbac-layout">
        <Outlet />
      </div>
    );
  }

  const routes = options.routes || [
    {
      path: '*',
      element: <LayoutWrapper />,
    },
  ];

  return renderWithRBACContext(ui, { ...options, routes });
}

/**
 * Wait for loading states to resolve.
 * Useful after triggering data fetches.
 *
 * @example
 * ```tsx
 * renderWithRBACContext(<UserList />);
 * await waitForLoadingToFinish();
 * expect(screen.getByText('user123')).toBeInTheDocument();
 * ```
 */
export async function waitForLoadingToFinish() {
  // Wait for common loading indicators to disappear
  await waitFor(
    () => {
      // Check for various loading indicators
      const loadingSpinner = screen.queryByTestId('loading-spinner');
      const loadingText = screen.queryByText(/loading/i);
      const skeleton = screen.queryByTestId('skeleton');

      expect(loadingSpinner).not.toBeInTheDocument();
      expect(loadingText).not.toBeInTheDocument();
      expect(skeleton).not.toBeInTheDocument();
    },
    { timeout: 3000 }
  );
}

/**
 * Wait for a specific element to appear, with better error messages.
 *
 * @example
 * ```tsx
 * await waitForElement(() => screen.getByText('Success'));
 * ```
 */
export async function waitForElement(
  finder: () => HTMLElement,
  options?: { timeout?: number }
) {
  return waitFor(finder, { timeout: options?.timeout ?? 3000 });
}

/**
 * Wait for an element to be removed from the DOM.
 *
 * @example
 * ```tsx
 * await waitForElementToBeRemoved(() => screen.queryByText('Loading...'));
 * ```
 */
export async function waitForElementToBeRemoved(
  finder: () => HTMLElement | null,
  options?: { timeout?: number }
) {
  await waitFor(
    () => {
      expect(finder()).not.toBeInTheDocument();
    },
    { timeout: options?.timeout ?? 3000 }
  );
}

// Re-export common testing utilities for convenience
export { screen, waitFor } from '@testing-library/react';
export { default as userEvent } from '@testing-library/user-event';
