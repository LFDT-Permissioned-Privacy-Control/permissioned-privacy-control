import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, waitFor, cleanup } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { http, HttpResponse, delay } from 'msw';
import { server } from '@/test/mocks/server';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { AuthProvider } from '@/contexts/AuthContext';
import { MemoryRouter } from 'react-router-dom';
import { UserSearchInput } from '../UserSearchInput';

function renderUserSearch(
  props: {
    orgId?: string;
    value?: string;
    onChange?: (id: string) => void;
    disabled?: boolean;
  } = {}
) {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  const onChange = props.onChange || vi.fn();

  const result = render(
    <QueryClientProvider client={queryClient}>
      <AuthProvider>
        <MemoryRouter future={{ v7_startTransition: true, v7_relativeSplatPath: true }}>
          <UserSearchInput
            orgId={props.orgId || 'org-1'}
            value={props.value || ''}
            onChange={onChange}
            disabled={props.disabled}
          />
        </MemoryRouter>
      </AuthProvider>
    </QueryClientProvider>
  );

  return { ...result, onChange };
}

describe('UserSearchInput', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  afterEach(() => {
    cleanup();
  });

  it('shows search input when no user selected', () => {
    renderUserSearch();

    const input = screen.getByPlaceholderText('Search users by DID...');
    expect(input).toBeInTheDocument();
    expect(input).not.toBeDisabled();
  });

  it('shows search results after typing', async () => {
    const user = userEvent.setup();
    renderUserSearch();

    const input = screen.getByPlaceholderText('Search users by DID...');
    await user.type(input, 'user');

    await waitFor(() => {
      // DID 'did:polygonid:polygon:main:user123' truncated to 30 chars
      expect(
        screen.getByText('did:polygonid:polygon:main:use...')
      ).toBeInTheDocument();
    });
  });

  it('calls onChange when user is selected', async () => {
    const user = userEvent.setup();
    const { onChange } = renderUserSearch();

    const input = screen.getByPlaceholderText('Search users by DID...');
    await user.type(input, 'user');

    await waitFor(() => {
      expect(
        screen.getByText('did:polygonid:polygon:main:use...')
      ).toBeInTheDocument();
    });

    await user.click(screen.getByText('did:polygonid:polygon:main:use...'));

    expect(onChange).toHaveBeenCalledWith('user-1');
  });

  it('shows selected user DID when value is set', async () => {
    renderUserSearch({ value: 'user-1' });

    await waitFor(() => {
      expect(
        screen.getByText('did:polygonid:polygon:main:use...')
      ).toBeInTheDocument();
    });

    expect(screen.getByRole('button', { name: 'Clear selection' })).toBeInTheDocument();
  });

  it('clears selection when X button is clicked', async () => {
    const user = userEvent.setup();
    const { onChange } = renderUserSearch({ value: 'user-1' });

    await waitFor(() => {
      expect(
        screen.getByText('did:polygonid:polygon:main:use...')
      ).toBeInTheDocument();
    });

    await user.click(screen.getByRole('button', { name: 'Clear selection' }));

    expect(onChange).toHaveBeenCalledWith('');
  });

  it('shows loading state while searching', async () => {
    server.use(
      http.get('/api/v1/admin/users', async () => {
        await delay('infinite');
        return HttpResponse.json({ data: [], total: 0, limit: 10, offset: 0 });
      })
    );

    const user = userEvent.setup();
    renderUserSearch();

    const input = screen.getByPlaceholderText('Search users by DID...');
    await user.type(input, 'user');

    await waitFor(() => {
      expect(screen.getByText('Searching...')).toBeInTheDocument();
    });
  });

  it('shows "No users found" for empty results', async () => {
    server.use(
      http.get('/api/v1/admin/users', () => {
        return HttpResponse.json({ data: [], total: 0, limit: 10, offset: 0 });
      })
    );

    const user = userEvent.setup();
    renderUserSearch();

    const input = screen.getByPlaceholderText('Search users by DID...');
    await user.type(input, 'nonexistent');

    await waitFor(() => {
      expect(screen.getByText('No users found')).toBeInTheDocument();
    });
  });

  it('closes dropdown on Escape', async () => {
    const user = userEvent.setup();
    renderUserSearch();

    const input = screen.getByPlaceholderText('Search users by DID...');
    await user.type(input, 'user');

    await waitFor(() => {
      expect(
        screen.getByText('did:polygonid:polygon:main:use...')
      ).toBeInTheDocument();
    });

    await user.keyboard('{Escape}');

    expect(
      screen.queryByText('did:polygonid:polygon:main:use...')
    ).not.toBeInTheDocument();
  });
});
