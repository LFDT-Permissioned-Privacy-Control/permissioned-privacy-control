import { describe, it, expect, afterEach, vi } from 'vitest';
import { getRpcEndpoint, getAddNetworkParams } from '../rpc';

// RD-1198 regression guard: the displayed RPC URL must be the dashboard's own
// origin — every serving mode (Vite dev proxy, frontend nginx, backend-served)
// routes /rpc on it. The old code force-rewrote the port to 8080, which
// produced unreachable URLs on any deployed setup.
describe('getRpcEndpoint', () => {
  afterEach(() => {
    vi.unstubAllEnvs();
  });

  it('uses the current origin verbatim — no port rewrite', () => {
    expect(getRpcEndpoint()).toBe(`${window.location.origin}/rpc`);
    expect(getRpcEndpoint()).not.toContain(':8080');
  });

  it('uses VITE_BACKEND_URL when set', () => {
    vi.stubEnv('VITE_BACKEND_URL', 'https://proxy.example.com');
    expect(getRpcEndpoint()).toBe('https://proxy.example.com/rpc');
  });

  it('feeds the same URL into the MetaMask add-network params', () => {
    expect(getAddNetworkParams().rpcUrls).toEqual([`${window.location.origin}/rpc`]);
  });
});
