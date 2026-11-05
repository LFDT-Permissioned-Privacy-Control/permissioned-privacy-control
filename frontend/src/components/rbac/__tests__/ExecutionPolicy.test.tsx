import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { screen, waitFor, cleanup } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { http, HttpResponse } from 'msw';
import { server } from '@/test/mocks/server';
import { renderWithRBACContext } from './test-utils';
import {
  mockDraftRevisionDetail,
  mockGuardedPolicyCapabilities,
  mockPolicyContext,
  mockPolicyRevisions,
} from '@/test/mocks/execution-policy-fixtures';

// Mock the useOrgContext hook from RBACManager, mirroring the other RBAC
// sub-tab tests: the shared TestOrgContext is what MockOrgProvider fills.
vi.mock('../RBACManager', async () => {
  const { TestOrgContext, useOrgContext, useOrgContextOptional } = await import('./test-utils');
  return {
    OrgContext: TestOrgContext,
    useOrgContext,
    useOrgContextOptional,
  };
});

import ExecutionPolicy from '../ExecutionPolicy';

const CONTEXT_ROUTE = '/api/v1/admin/orgs/:orgId/execution-policy/context';
const REVISIONS_ROUTE = '/api/v1/admin/orgs/:orgId/execution-policy/revisions';
const REVISION_ROUTE = '/api/v1/admin/orgs/:orgId/execution-policy/revisions/:revisionId';

function useDefaultHandlers() {
  server.use(
    http.get(CONTEXT_ROUTE, () => HttpResponse.json(mockPolicyContext)),
    http.get(REVISIONS_ROUTE, () => HttpResponse.json(mockPolicyRevisions)),
    http.get(REVISION_ROUTE, () => HttpResponse.json(mockDraftRevisionDetail))
  );
}

describe('ExecutionPolicy', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    useDefaultHandlers();
  });

  afterEach(() => {
    cleanup();
  });

  describe('Revision list', () => {
    it('lists every revision with its status, number and short runtime digest', async () => {
      renderWithRBACContext(<ExecutionPolicy />);

      await waitFor(() => {
        expect(screen.getByTestId('execution-policy-revisions')).toBeInTheDocument();
      });

      const draftRow = screen.getByTestId('revision-row-3');
      expect(draftRow).toHaveTextContent('draft');
      expect(draftRow).toHaveTextContent('333333333333');

      const activeRow = screen.getByTestId('revision-row-2');
      expect(activeRow).toHaveTextContent('active');
      expect(activeRow).toHaveTextContent('232323232323');

      expect(screen.getByTestId('revision-row-1')).toHaveTextContent('superseded');
    });

    it('distinguishes stored selection from actual runtime application', async () => {
      renderWithRBACContext(<ExecutionPolicy />);

      await waitFor(() => {
        expect(screen.getByTestId('active-policy-banner')).toHaveTextContent(
          'Revision 2 is selected in stored configuration'
        );
      });

      expect(screen.getByTestId('active-policy-banner')).toHaveTextContent(
        'This selection alone does not prove runtime application'
      );
      expect(
        screen.getByText(/At most one revision is selected as active/i)
      ).toBeInTheDocument();
      expect(
        screen.getByText(/drafts are review candidates/i)
      ).toBeInTheDocument();
    });

    it('reports an absent selected revision without inventing an enforcement state', async () => {
      server.use(
        http.get(CONTEXT_ROUTE, () =>
          HttpResponse.json({ ...mockPolicyContext, active: undefined })
        ),
        http.get(REVISIONS_ROUTE, () => HttpResponse.json([]))
      );

      renderWithRBACContext(<ExecutionPolicy />);

      await waitFor(() => {
        expect(screen.getByTestId('active-policy-banner')).toHaveTextContent(
          'No execution policy revision is selected'
        );
      });

      expect(
        screen.getByText(/No policy revision has been submitted for this organization yet/i)
      ).toBeInTheDocument();
    });

    it('surfaces a load failure instead of rendering an empty policy', async () => {
      server.use(
        http.get(CONTEXT_ROUTE, () =>
          HttpResponse.json({ error: 'failed to read organization' }, { status: 500 })
        )
      );

      renderWithRBACContext(<ExecutionPolicy />);

      await waitFor(() => {
        expect(screen.getByTestId('execution-policy-load-error')).toHaveTextContent(
          'failed to read organization'
        );
      });
    });
  });

  describe('Revision review', () => {
    it('shows the document, the generated Solidity and all three digests', async () => {
      const user = userEvent.setup();
      renderWithRBACContext(<ExecutionPolicy />);

      await waitFor(() => {
        expect(screen.getByTestId('revision-row-3')).toBeInTheDocument();
      });

      await user.click(screen.getByRole('button', { name: /Review revision 3/i }));

      const detail = await screen.findByTestId('revision-detail');
      expect(screen.getByTestId('revision-source')).toHaveTextContent('ContractExecutionPolicy');
      expect(screen.getByTestId('revision-solidity')).toHaveTextContent(
        'contract GeneratedExecutionPolicy'
      );
      expect(detail).toHaveTextContent(mockDraftRevisionDetail.policy_digest);
      expect(detail).toHaveTextContent(mockDraftRevisionDetail.solidity_digest);
      expect(detail).toHaveTextContent(mockDraftRevisionDetail.runtime_digest);
    });

    it('does not send an old activation when legacy has no policy consumer', async () => {
      let activations = 0;
      server.use(http.post(`${REVISION_ROUTE}/activate`, () => {
        activations++; return HttpResponse.json({});
      }));
      const user = userEvent.setup();
      renderWithRBACContext(<ExecutionPolicy />);
      await user.click(await screen.findByRole('button', { name: /Review revision 3/i }));
      const activate = await screen.findByRole('button', { name: /Activate…/i });
      expect(activate).toBeDisabled();
      expect(screen.getByLabelText('Execution policy support')).toHaveTextContent('No execution-policy consumer');
      expect(screen.getByRole('button', { name: 'Run simulation' })).toBeEnabled();
      await user.click(activate);
      expect(activations).toBe(0);
      expect(screen.queryByText('Activate revision 3?')).not.toBeInTheDocument();
    });

    it('keeps source review and withdrawal but disables execution actions if capabilities are missing', async () => {
      server.use(http.get(CONTEXT_ROUTE, () => HttpResponse.json({ ...mockPolicyContext, capabilities: undefined })));
      const user = userEvent.setup();
      renderWithRBACContext(<ExecutionPolicy />);
      await user.click(await screen.findByRole('button', { name: /Review revision 3/i }));
      expect(await screen.findByTestId('revision-source')).toBeInTheDocument();
      expect(screen.getByRole('button', { name: /Activate…/i })).toBeDisabled();
      expect(screen.getByRole('button', { name: /Withdraw draft/i })).toBeEnabled();
      expect(screen.queryByRole('button', { name: 'Run simulation' })).not.toBeInTheDocument();
      expect(screen.getByLabelText('Execution policy support')).toHaveTextContent('could not be confirmed');
    });

    it('preserves the old Reth route closure and its unmanaged withdrawal exception', async () => {
      let withdrawals = 0;
      server.use(
        http.get(CONTEXT_ROUTE, () => HttpResponse.json({ ...mockPolicyContext, capabilities: mockGuardedPolicyCapabilities })),
        http.post(`${REVISION_ROUTE}/withdraw`, () => { withdrawals++; return HttpResponse.json({ ...mockDraftRevisionDetail, status: 'withdrawn' }); }),
      );
      const user = userEvent.setup();
      renderWithRBACContext(<ExecutionPolicy />);
      await user.click(await screen.findByRole('button', { name: /Review revision 3/i }));
      expect(await screen.findByRole('button', { name: /Activate…/i })).toBeDisabled();
      expect(screen.queryByRole('button', { name: 'Run simulation' })).not.toBeInTheDocument();
      expect(screen.getByLabelText('Execution policy support')).toHaveTextContent('Use configuration revisions');
      await user.click(screen.getByRole('button', { name: /Withdraw draft…/i }));
      await user.click(await screen.findByRole('button', { name: 'Withdraw draft' }));
      await waitFor(() => expect(withdrawals).toBe(1));
    });

    it('shows the server refusal verbatim when a revision is no longer a draft', async () => {
      server.use(
        http.post(`${REVISION_ROUTE}/withdraw`, () =>
          HttpResponse.json(
            { error: 'policy revision is not a draft' },
            { status: 409 }
          )
        )
      );

      const user = userEvent.setup();
      renderWithRBACContext(<ExecutionPolicy />);

      await waitFor(() => {
        expect(screen.getByTestId('revision-row-3')).toBeInTheDocument();
      });
      await user.click(screen.getByRole('button', { name: /Review revision 3/i }));
      await screen.findByTestId('revision-detail');
      await user.click(screen.getByRole('button', { name: /Withdraw draft…/i }));
      await user.click(await screen.findByRole('button', { name: 'Withdraw draft' }));

      await waitFor(() => {
        expect(screen.getByTestId('execution-policy-action-error')).toHaveTextContent(
          'policy revision is not a draft'
        );
      });
    });
  });
});
