import { describe, it, expect, vi, afterEach } from 'vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { ViewAsInExplorerButton } from '../ViewAsInExplorerButton';
import { OrgContext } from '../RBACManager';
import type { Organization } from '@/types/rbac';
import { resolveExplorerUrl } from '@/lib/explorerUrl';

const TARGET = 'did:iden3:privado:test:abc123';
const ORG_ID = 'org-uuid-1234';

const FAKE_ORG: Organization = {
  id: ORG_ID,
  slug: 'acme',
  name: 'Acme',
  settings: {},
  created_at: '',
  updated_at: '',
};

afterEach(() => {
  vi.unstubAllEnvs();
  delete window.__runtimeConfig;
});

describe('resolveExplorerUrl', () => {
  it('uses the runtime-config value when present', () => {
    window.__runtimeConfig = {
      VITE_BLOCK_EXPLORER_URL: 'https://explorer.devnet.example.com',
    };
    expect(resolveExplorerUrl()).toBe('https://explorer.devnet.example.com');
  });

  it('trims trailing slashes', () => {
    window.__runtimeConfig = { VITE_BLOCK_EXPLORER_URL: 'https://x.example.com//' };
    expect(resolveExplorerUrl()).toBe('https://x.example.com');
  });

  it('returns empty (no localhost fallback) when unconfigured in a production build', () => {
    vi.stubEnv('DEV', false);
    window.__runtimeConfig = {};
    expect(resolveExplorerUrl()).toBe('');
  });

  it('falls back to the local explorer only in the dev server', () => {
    vi.stubEnv('DEV', true);
    window.__runtimeConfig = {};
    expect(resolveExplorerUrl()).toBe('http://localhost:3001');
  });

  it('rejects non-http(s) schemes (defence-in-depth)', () => {
    window.__runtimeConfig = {
      VITE_BLOCK_EXPLORER_URL: 'javascript:alert(1)',
    };
    expect(resolveExplorerUrl()).toBe('');
  });

  it('rejects values that are not absolute URLs', () => {
    window.__runtimeConfig = { VITE_BLOCK_EXPLORER_URL: 'not a url' };
    expect(resolveExplorerUrl()).toBe('');
  });
});

describe('ViewAsInExplorerButton', () => {
  it('is disabled when the explorer URL is not configured (prod)', () => {
    vi.stubEnv('DEV', false);
    window.__runtimeConfig = {};
    render(<ViewAsInExplorerButton targetDID={TARGET} variant="inline" />);
    expect(screen.getByRole('button')).toBeDisabled();
  });

  it('navigates same-tab to the explorer /view-as handoff (no ?org= without a selected org)', async () => {
    window.__runtimeConfig = {
      VITE_BLOCK_EXPLORER_URL: 'https://explorer.devnet.example.com',
    };
    const hrefSetter = vi.fn();
    const originalLocation = window.location;
    Object.defineProperty(window, 'location', {
      configurable: true,
      value: { ...originalLocation, set href(v: string) { hrefSetter(v); } },
    });

    // No OrgContext provider → selectedOrg is null → no &org= appended.
    render(<ViewAsInExplorerButton targetDID={TARGET} variant="inline" />);
    await userEvent.click(screen.getByRole('button'));

    expect(hrefSetter).toHaveBeenCalledWith(
      `https://explorer.devnet.example.com/view-as?did=${encodeURIComponent(TARGET)}`,
    );

    Object.defineProperty(window, 'location', {
      configurable: true,
      value: originalLocation,
    });
  });

  // RD-994: when rendered inside RBACManager's OrgContext with an org
  // selected, the redirect must carry &org=<selectedOrg.id> so the
  // impersonated session anchors to the org the admin is looking at.
  it('appends the selected org as ?org= when an org is selected', async () => {
    window.__runtimeConfig = {
      VITE_BLOCK_EXPLORER_URL: 'https://explorer.devnet.example.com',
    };
    const hrefSetter = vi.fn();
    const originalLocation = window.location;
    Object.defineProperty(window, 'location', {
      configurable: true,
      value: { ...originalLocation, set href(v: string) { hrefSetter(v); } },
    });

    render(
      <OrgContext.Provider
        value={{
          selectedOrg: FAKE_ORG,
          setSelectedOrg: () => {},
          organizations: [FAKE_ORG],
          refreshOrgs: async () => {},
        }}
      >
        <ViewAsInExplorerButton targetDID={TARGET} variant="inline" />
      </OrgContext.Provider>,
    );
    await userEvent.click(screen.getByRole('button'));

    expect(hrefSetter).toHaveBeenCalledWith(
      `https://explorer.devnet.example.com/view-as?did=${encodeURIComponent(TARGET)}&org=${encodeURIComponent(ORG_ID)}`,
    );

    Object.defineProperty(window, 'location', {
      configurable: true,
      value: originalLocation,
    });
  });
});
