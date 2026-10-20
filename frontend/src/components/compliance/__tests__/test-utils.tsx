import React, { ReactElement, useState, createContext, useContext } from 'react';
import { render, RenderOptions } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { AuthProvider } from '@/contexts/AuthContext';
import { CurrencyProvider } from '../CurrencyContext';
import type { Organization } from '@/types/rbac';
import { mockOrganization } from '@/test/mocks/handlers';

// Create a test context matching ComplianceManager's ComplianceOrgContext
interface ComplianceOrgContextType {
  selectedOrg: Organization | null;
  setSelectedOrg: (org: Organization | null) => void;
  organizations: Organization[];
}

export const TestComplianceOrgContext = createContext<ComplianceOrgContextType | null>(null);

export function useComplianceOrgContext() {
  const context = useContext(TestComplianceOrgContext);
  if (!context) {
    throw new Error('useComplianceOrgContext must be used within provider');
  }
  return context;
}

// Alias for mock resolution
export const ComplianceOrgContext = TestComplianceOrgContext;

interface MockComplianceOrgProviderProps {
  children: React.ReactNode;
  initialOrg?: Organization | null;
  organizations?: Organization[];
}

function MockComplianceOrgProvider({
  children,
  initialOrg = mockOrganization,
  organizations = [mockOrganization],
}: MockComplianceOrgProviderProps) {
  const [selectedOrg, setSelectedOrg] = useState<Organization | null>(initialOrg);

  return (
    <TestComplianceOrgContext.Provider
      value={{ selectedOrg, setSelectedOrg, organizations }}
    >
      {children}
    </TestComplianceOrgContext.Provider>
  );
}

function createTestQueryClient() {
  return new QueryClient({
    defaultOptions: {
      queries: { retry: false, gcTime: 0, staleTime: 0 },
      mutations: { retry: false },
    },
  });
}

interface ComplianceRenderOptions extends Omit<RenderOptions, 'wrapper'> {
  initialOrg?: Organization | null;
  organizations?: Organization[];
  initialRoute?: string;
}

export function renderWithComplianceContext(
  ui: ReactElement,
  {
    initialOrg = mockOrganization,
    organizations = [mockOrganization],
    initialRoute = '/',
    ...renderOptions
  }: ComplianceRenderOptions = {}
) {
  const queryClient = createTestQueryClient();

  function Wrapper({ children }: { children: React.ReactNode }) {
    return (
      <QueryClientProvider client={queryClient}>
        <AuthProvider>
          <MemoryRouter future={{ v7_startTransition: true, v7_relativeSplatPath: true }} initialEntries={[initialRoute]}>
            <CurrencyProvider orgId={initialOrg?.id}>
              <MockComplianceOrgProvider
                initialOrg={initialOrg}
                organizations={organizations}
              >
                {children}
              </MockComplianceOrgProvider>
            </CurrencyProvider>
          </MemoryRouter>
        </AuthProvider>
      </QueryClientProvider>
    );
  }

  return render(ui, { wrapper: Wrapper, ...renderOptions });
}

// Re-export for convenience
export { screen, waitFor } from '@testing-library/react';
export { default as userEvent } from '@testing-library/user-event';
