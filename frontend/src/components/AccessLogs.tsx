import { useEffect, useMemo, useState } from 'react';
import {
  logsApi,
  AccessLog,
  AccessLogFilters,
  AccessLogOutcome,
} from '../api/client';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Input } from '@/components/ui/input';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';
import Pagination from '@/components/ui/Pagination';
import { ScrollText, RefreshCw, Loader2, Clock, Filter } from 'lucide-react';

const PAGE_SIZE = 100;

interface FilterState {
  externalId: string;
  method: string;
  outcome: AccessLogOutcome;
  correlationId: string;
  from: string; // datetime-local
  to: string; // datetime-local
}

const emptyFilters: FilterState = {
  externalId: '',
  method: '',
  outcome: 'all',
  correlationId: '',
  from: '',
  to: '',
};

function toRFC3339(localValue: string): string | undefined {
  if (!localValue) return undefined;
  const d = new Date(localValue);
  if (isNaN(d.getTime())) return undefined;
  return d.toISOString();
}

function AccessLogs() {
  const [logs, setLogs] = useState<AccessLog[]>([]);
  const [total, setTotal] = useState<number>(0);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);

  // Pending = what's in the form right now. Active = what's actually applied.
  const [pending, setPending] = useState<FilterState>(emptyFilters);
  const [active, setActive] = useState<FilterState>(emptyFilters);
  const [offset, setOffset] = useState<number>(0);
  const [autoRefresh, setAutoRefresh] = useState<boolean>(true);

  const apiFilters: AccessLogFilters = useMemo(
    () => ({
      externalId: active.externalId.trim() || undefined,
      method: active.method.trim() || undefined,
      outcome: active.outcome,
      correlationId: active.correlationId.trim() || undefined,
      from: toRFC3339(active.from),
      to: toRFC3339(active.to),
      limit: PAGE_SIZE,
      offset,
    }),
    [active, offset]
  );

  useEffect(() => {
    void loadLogs();
    if (!autoRefresh) return;
    const interval = setInterval(() => void loadLogs(), 5000);
    return () => clearInterval(interval);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [apiFilters, autoRefresh]);

  const loadLogs = async () => {
    try {
      const response = await logsApi.list(apiFilters);
      setLogs(response.data?.data ?? []);
      setTotal(response.data?.total ?? 0);
    } catch (error: unknown) {
      console.error('Failed to load logs:', error);
      setLogs([]);
      setTotal(0);
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  };

  const handleRefresh = () => {
    setRefreshing(true);
    void loadLogs();
  };

  const handleApply = (e: React.FormEvent) => {
    e.preventDefault();
    setOffset(0);
    setActive(pending);
  };

  const handleReset = () => {
    setPending(emptyFilters);
    setActive(emptyFilters);
    setOffset(0);
  };

  const getStatusBadgeVariant = (
    statusCode: number
  ): 'success' | 'warning' | 'destructive' | 'default' => {
    if (statusCode >= 200 && statusCode < 300) return 'success';
    if (statusCode >= 400 && statusCode < 500) return 'warning';
    return 'destructive';
  };

  const formatDateTime = (timestamp: string) => {
    const date = new Date(timestamp);
    return {
      date: date.toLocaleDateString(),
      time: date.toLocaleTimeString(),
    };
  };

  // Humanize a curated denial-reason code (RD-1137), e.g. "sender_not_linked"
  // -> "Sender not linked". Returns null when there's no reason.
  const formatReason = (reason?: string | null) => {
    if (!reason) return null;
    const spaced = reason.replace(/_/g, ' ');
    return spaced.charAt(0).toUpperCase() + spaced.slice(1);
  };

  const filtersActive =
    active.externalId !== '' ||
    active.method !== '' ||
    active.outcome !== 'all' ||
    active.correlationId !== '' ||
    active.from !== '' ||
    active.to !== '';

  return (
    <Card className="animate-fade-in">
      <CardHeader className="pb-3">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-lg bg-primary-50 flex items-center justify-center">
              <ScrollText className="w-5 h-5 text-primary" />
            </div>
            <div>
              <CardTitle className="text-lg">Access Logs</CardTitle>
              <div
                className="flex items-center gap-2 mt-1"
                role="status"
                aria-live="polite"
              >
                <div
                  className={`w-1.5 h-1.5 rounded-full ${autoRefresh ? 'bg-success animate-pulse' : 'bg-neutral-300'}`}
                  aria-hidden="true"
                />
                <span className="text-xs text-neutral-500">
                  {autoRefresh ? 'Auto-refreshing every 5s' : 'Auto-refresh paused'}
                </span>
              </div>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <Button
              variant="outline"
              size="sm"
              onClick={() => setAutoRefresh((v) => !v)}
              className="gap-2"
            >
              {autoRefresh ? 'Pause' : 'Resume'}
            </Button>
            <Button
              variant="outline"
              size="sm"
              onClick={handleRefresh}
              disabled={refreshing}
              className="gap-2"
            >
              <RefreshCw className={`w-4 h-4 ${refreshing ? 'animate-spin' : ''}`} />
              Refresh
            </Button>
          </div>
        </div>
      </CardHeader>
      <CardContent>
        <form
          onSubmit={handleApply}
          className="grid grid-cols-1 md:grid-cols-3 lg:grid-cols-6 gap-3 mb-4"
          aria-label="Access log filters"
        >
          <Input
            placeholder="External ID"
            value={pending.externalId}
            onChange={(e) =>
              setPending((p) => ({ ...p, externalId: e.target.value }))
            }
          />
          <Input
            placeholder="Method (e.g. eth_call)"
            value={pending.method}
            onChange={(e) =>
              setPending((p) => ({ ...p, method: e.target.value }))
            }
          />
          <Select
            value={pending.outcome}
            onValueChange={(value) =>
              setPending((p) => ({ ...p, outcome: value as AccessLogOutcome }))
            }
          >
            <SelectTrigger>
              <SelectValue placeholder="Outcome" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All outcomes</SelectItem>
              <SelectItem value="success">Success (2xx)</SelectItem>
              <SelectItem value="denied">Denied (4xx)</SelectItem>
              <SelectItem value="error">Error (5xx)</SelectItem>
            </SelectContent>
          </Select>
          <Input
            placeholder="Correlation ID"
            value={pending.correlationId}
            onChange={(e) =>
              setPending((p) => ({ ...p, correlationId: e.target.value }))
            }
          />
          <Input
            type="datetime-local"
            value={pending.from}
            onChange={(e) =>
              setPending((p) => ({ ...p, from: e.target.value }))
            }
            aria-label="From"
          />
          <Input
            type="datetime-local"
            value={pending.to}
            onChange={(e) => setPending((p) => ({ ...p, to: e.target.value }))}
            aria-label="To"
          />

          <div className="md:col-span-3 lg:col-span-6 flex items-center gap-2">
            <Button type="submit" size="sm" className="gap-2">
              <Filter className="w-4 h-4" />
              Apply filters
            </Button>
            {filtersActive && (
              <Button
                type="button"
                variant="ghost"
                size="sm"
                onClick={handleReset}
              >
                Reset
              </Button>
            )}
            <span className="text-xs text-neutral-500 ml-auto">
              {total > 0
                ? `${total.toLocaleString()} matching ${total === 1 ? 'entry' : 'entries'}`
                : ''}
            </span>
          </div>
        </form>

        {loading && logs.length === 0 ? (
          <div
            className="flex items-center justify-center py-12"
            role="status"
            aria-live="polite"
          >
            <Loader2
              className="w-6 h-6 text-neutral-400 animate-spin"
              aria-hidden="true"
            />
            <span className="sr-only">Loading access logs...</span>
          </div>
        ) : logs.length === 0 ? (
          <div className="text-center py-12">
            <div className="w-16 h-16 mx-auto mb-4 rounded-full bg-primary-50 flex items-center justify-center">
              <Clock className="w-8 h-8 text-neutral-400" />
            </div>
            <p className="text-neutral-400">
              {filtersActive
                ? 'No access logs match the current filters'
                : 'No access logs yet'}
            </p>
            <p className="text-neutral-400 text-sm mt-1">
              {filtersActive
                ? 'Adjust the filters or reset to see all entries'
                : 'Logs will appear here when requests are made'}
            </p>
          </div>
        ) : (
          <>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Time</TableHead>
                  <TableHead>External ID</TableHead>
                  <TableHead>Method</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Reason</TableHead>
                  <TableHead>IP Address</TableHead>
                  <TableHead>Correlation</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {logs.map((log, index) => {
                  const { date, time } = formatDateTime(log.created_at);
                  return (
                    <TableRow
                      key={log.id}
                      className="animate-fade-in"
                      style={{ animationDelay: `${index * 15}ms` }}
                    >
                      <TableCell>
                        <div className="flex flex-col">
                          <span className="font-mono text-xs text-neutral-700">
                            {time}
                          </span>
                          <span className="font-mono text-xs text-neutral-400">
                            {date}
                          </span>
                        </div>
                      </TableCell>
                      <TableCell className="font-mono text-sm text-neutral-700">
                        {log.external_id}
                      </TableCell>
                      <TableCell>
                        <Badge variant="outline" className="font-mono text-xs">
                          {log.method}
                        </Badge>
                      </TableCell>
                      <TableCell>
                        <Badge variant={getStatusBadgeVariant(log.status_code)}>
                          {log.status_code}
                        </Badge>
                      </TableCell>
                      <TableCell className="text-xs text-neutral-600">
                        {formatReason(log.denial_reason) ?? (
                          <span className="text-neutral-300">-</span>
                        )}
                      </TableCell>
                      <TableCell className="font-mono text-xs text-neutral-500">
                        {log.ip_address || '-'}
                      </TableCell>
                      <TableCell className="font-mono text-xs text-neutral-500">
                        {log.correlation_id ?? '-'}
                      </TableCell>
                    </TableRow>
                  );
                })}
              </TableBody>
            </Table>
            {total > 0 && (
              <Pagination
                total={total}
                limit={PAGE_SIZE}
                offset={offset}
                onPageChange={(newOffset) => setOffset(newOffset)}
              />
            )}
          </>
        )}
      </CardContent>
    </Card>
  );
}

export default AccessLogs;
