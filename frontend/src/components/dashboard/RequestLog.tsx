import { useState, useEffect, useCallback } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';
import { logsApi, AccessLog } from '@/api/client';
import { ScrollText, Pause, Play, Loader2 } from 'lucide-react';

function getStatusBadgeVariant(statusCode: number): 'success' | 'warning' | 'destructive' | 'default' {
  if (statusCode >= 200 && statusCode < 300) return 'success';
  if (statusCode === 403) return 'warning';
  if (statusCode >= 500) return 'destructive';
  return 'default';
}

function formatTime(timestamp: string): string {
  const date = new Date(timestamp);
  return date.toLocaleTimeString();
}

export function RequestLog() {
  const [logs, setLogs] = useState<AccessLog[]>([]);
  const [isPaused, setIsPaused] = useState(false);
  const [loading, setLoading] = useState(true);

  const fetchLogs = useCallback(async () => {
    try {
      const response = await logsApi.list({ limit: 50 });
      setLogs(response.data?.data ?? []);
    } catch (error) {
      console.error('Failed to fetch logs:', error);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchLogs();
  }, [fetchLogs]);

  useEffect(() => {
    if (isPaused) return;

    const interval = setInterval(fetchLogs, 2000);
    return () => clearInterval(interval);
  }, [isPaused, fetchLogs]);

  return (
    <Card>
      <CardHeader className="pb-3">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-lg bg-primary-50 flex items-center justify-center">
              <ScrollText className="w-5 h-5 text-primary" />
            </div>
            <CardTitle className="text-lg">Request Log</CardTitle>
            {!isPaused && !loading && (
              <div className="flex items-center gap-2 px-2 py-1 rounded-full bg-success-light" role="status" aria-live="polite">
                <div className="w-1.5 h-1.5 rounded-full bg-success animate-pulse" aria-hidden="true" />
                <span className="text-xs text-success-dark">Live</span>
              </div>
            )}
          </div>
          <Button
            variant={isPaused ? 'default' : 'outline'}
            size="sm"
            onClick={() => setIsPaused(!isPaused)}
            className="gap-2"
            aria-label={isPaused ? 'Resume live log updates' : 'Pause live log updates'}
          >
            {isPaused ? (
              <>
                <Play className="w-3.5 h-3.5" aria-hidden="true" />
                Resume
              </>
            ) : (
              <>
                <Pause className="w-3.5 h-3.5" aria-hidden="true" />
                Pause
              </>
            )}
          </Button>
        </div>
      </CardHeader>
      <CardContent>
        {loading ? (
          <div className="flex items-center justify-center py-8" role="status" aria-live="polite">
            <Loader2 className="w-6 h-6 text-neutral-500 animate-spin" aria-hidden="true" />
            <span className="sr-only">Loading request logs...</span>
          </div>
        ) : logs.length === 0 ? (
          <div className="text-center py-8 text-neutral-500">
            No requests yet
          </div>
        ) : (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Time</TableHead>
                <TableHead>Method</TableHead>
                <TableHead>Status</TableHead>
                <TableHead>Identity</TableHead>
                <TableHead>IP</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {logs.map((log, index) => (
                <TableRow
                  key={log.id}
                  className="animate-fade-in"
                  style={{ animationDelay: `${index * 20}ms` }}
                >
                  <TableCell className="font-mono text-xs text-neutral-500">
                    {formatTime(log.created_at)}
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
                  <TableCell className="font-mono text-xs text-neutral-700 truncate max-w-[150px]">
                    {log.external_id}
                  </TableCell>
                  <TableCell className="font-mono text-xs text-neutral-500">
                    {log.ip_address}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )}
      </CardContent>
    </Card>
  );
}
