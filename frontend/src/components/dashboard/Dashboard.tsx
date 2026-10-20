import { useState, useEffect, useCallback } from 'react';
import { StatusCard } from './StatusCard';
import { TestRequestPanel } from './TestRequestPanel';
import { DeployDemoTokenPanel } from './DeployDemoTokenPanel';
import { statusApi, StatusResponse, systemApi, SystemVersion } from '@/api/client';
import { Loader2 } from 'lucide-react';

export function Dashboard() {
  const [status, setStatus] = useState<StatusResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [build, setBuild] = useState<SystemVersion | null>(null);

  const fetchStatus = useCallback(async () => {
    try {
      const response = await statusApi.get();
      setStatus(response.data);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to fetch status');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchStatus();
    const interval = setInterval(fetchStatus, 5000);
    return () => clearInterval(interval);
  }, [fetchStatus]);

  // RD-1076: build identity is static for the process lifetime — fetch once,
  // no polling. Failure is non-fatal (the footer just stays hidden).
  useEffect(() => {
    systemApi
      .getVersion()
      .then(res => setBuild(res.data))
      .catch(() => {});
  }, []);

  if (loading) {
    return (
      <div className="flex items-center justify-center py-16" role="status" aria-live="polite">
        <div className="flex flex-col items-center gap-4">
          <Loader2 className="w-8 h-8 text-primary animate-spin" aria-hidden="true" />
          <p className="text-neutral-500">Loading dashboard...</p>
        </div>
      </div>
    );
  }

  if (error && !status) {
    return (
      <div className="bg-white border border-neutral-200 rounded-xl shadow-card p-6 animate-fade-in">
        <div className="flex items-center gap-3 text-error-dark">
          <div className="w-2 h-2 rounded-full bg-error animate-pulse" />
          <span>Failed to load status: {error}</span>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Status Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6 items-stretch">
        <div className="animate-fade-in-up h-full" style={{ animationDelay: '0ms' }}>
          <StatusCard
            title="Proxy"
            status={status?.proxy.status || 'unknown'}
            port={status?.proxy.port}
          />
        </div>
        <div className="animate-fade-in-up h-full" style={{ animationDelay: '100ms' }}>
          <StatusCard
            title="Node"
            status={status?.node.status || 'unknown'}
            url={status?.node.url}
            latency={status?.node.latency_ms}
            error={status?.node.error}
          />
        </div>
      </div>

      {/* Test Request Panel */}
      <div className="animate-fade-in-up" style={{ animationDelay: '200ms' }}>
        <TestRequestPanel />
      </div>

      {/* Dev Tools - only visible in development */}
      <div className="animate-fade-in-up" style={{ animationDelay: '250ms' }}>
        <DeployDemoTokenPanel />
      </div>

      {/* RD-1076: privacy-proxy build identity (version / commit / build time). */}
      {build && (
        <div
          className="animate-fade-in-up pt-2 text-center"
          style={{ animationDelay: '300ms' }}
          data-testid="build-version"
        >
          <p className="text-xs text-neutral-400 font-mono">
            privacy-proxy {build.version}
            {build.commit && build.commit !== 'none' ? ` · ${build.commit.slice(0, 12)}` : ''}
            {build.build_time && build.build_time !== 'unknown' ? ` · ${build.build_time}` : ''}
          </p>
        </div>
      )}
    </div>
  );
}
