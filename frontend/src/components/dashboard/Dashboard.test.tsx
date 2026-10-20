import { describe, it, expect, vi } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import { http, HttpResponse } from 'msw';
import { server } from '@/test/mocks/server';

// Isolate the build-version footer (RD-1076): stub the heavier child panels so
// the test doesn't depend on their providers / dev-only gating. The default
// `/admin/status` handler lets the dashboard past its loading gate.
vi.mock('./StatusCard', () => ({ StatusCard: () => null }));
vi.mock('./TestRequestPanel', () => ({ TestRequestPanel: () => null }));
vi.mock('./DeployDemoTokenPanel', () => ({ DeployDemoTokenPanel: () => null }));

import { Dashboard } from './Dashboard';

const versionUrl = '/api/v1/admin/system/version';

describe('Dashboard — build version footer (RD-1076)', () => {
  it('renders the privacy-proxy build identity from /system/version', async () => {
    server.use(
      http.get(versionUrl, () =>
        HttpResponse.json({
          version: 'v0.11.1',
          commit: 'abcdef1234567890',
          build_time: '2026-06-11T00:00:00Z',
        }),
      ),
    );

    render(<Dashboard />);

    const footer = await screen.findByTestId('build-version');
    expect(footer).toHaveTextContent('privacy-proxy v0.11.1');
    expect(footer).toHaveTextContent('abcdef123456'); // commit truncated to 12 chars
    expect(footer).toHaveTextContent('2026-06-11T00:00:00Z');
  });

  it('hides the footer when the version endpoint fails', async () => {
    server.use(http.get(versionUrl, () => new HttpResponse(null, { status: 500 })));

    render(<Dashboard />);

    // Wait past the loading gate (status resolves from the default handler),
    // then assert the version footer is absent.
    await waitFor(() => {
      expect(screen.queryByText(/loading dashboard/i)).not.toBeInTheDocument();
    });
    expect(screen.queryByTestId('build-version')).not.toBeInTheDocument();
  });
});
