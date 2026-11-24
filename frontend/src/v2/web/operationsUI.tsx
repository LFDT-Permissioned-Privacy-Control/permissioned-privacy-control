import { useEffect, useRef, useState, type ReactNode } from 'react'
import { Button } from '../../components/ui/button'
import { Card, CardContent, CardHeader, CardTitle } from '../../components/ui/card'
import { Input } from '../../components/ui/input'
import { Textarea } from '../../components/ui/textarea'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '../../components/ui/table'
import type { OperationScope } from './controller'
import { optionalText, type ObjectValue } from './operationsModels'

export function Panel({
  title,
  actions,
  children,
}: {
  title: string
  actions?: ReactNode
  children: ReactNode
}) {
  return (
    <Card className="min-w-0 max-w-full">
      <CardHeader>
        <div className="flex items-center justify-between gap-3">
          <CardTitle className="text-lg">{title}</CardTitle>
          {actions}
        </div>
      </CardHeader>
      <CardContent>{children}</CardContent>
    </Card>
  )
}
export function Field({
  label,
  value,
  onChange,
  type = 'text',
  required = false,
  disabled = false,
  hint,
  step,
  multiline = false,
}: {
  label: string
  value: string
  onChange: (v: string) => void
  type?: string
  required?: boolean
  disabled?: boolean
  hint?: string
  step?: number
  multiline?: boolean
}) {
  return (
    <label className="block space-y-1 text-sm font-medium text-neutral-700">
      {label}
      {multiline ? <Textarea
        aria-label={label}
        variant="code"
        value={value}
        onChange={(e) => onChange(e.target.value)}
        required={required}
        disabled={disabled}
      /> : <Input
        aria-label={label}
        type={type}
        value={value}
        onChange={(e) => onChange(e.target.value)}
        required={required}
        disabled={disabled}
        step={step}
      />}
      {hint && <span className="block text-xs font-normal text-neutral-500">{hint}</span>}
    </label>
  )
}
export function SelectField({
  label,
  value,
  onChange,
  options,
  disabled = false,
}: {
  label: string
  value: string
  onChange: (v: string) => void
  options: readonly { value: string; label: string }[]
  disabled?: boolean
}) {
  return (
    <label className="block space-y-1 text-sm font-medium text-neutral-700">
      {label}
      <select
        aria-label={label}
        className="w-full rounded-lg border border-neutral-300 bg-white px-3 py-2 text-sm"
        value={value}
        onChange={(e) => onChange(e.target.value)}
        disabled={disabled}
      >
        {options.map((o) => (
          <option key={o.value} value={o.value}>
            {o.label}
          </option>
        ))}
      </select>
    </label>
  )
}
export interface Column {
  key: string
  label: string
  render?: (row: ObjectValue) => ReactNode
}
export function DataTable({
  items,
  columns,
  empty = 'No records in this scope.',
  loading = false,
}: {
  items: ObjectValue[]
  columns: Column[]
  empty?: string
  loading?: boolean
}) {
  if (loading) return <p role="status" className="py-8 text-center text-sm text-neutral-500">Loading…</p>
  return (
    <div className="min-w-0 max-w-full overflow-x-auto">
      <Table>
        <TableHeader>
          <TableRow>
            {columns.map((column) => (
              <TableHead key={column.key}>{column.label}</TableHead>
            ))}
          </TableRow>
        </TableHeader>
        <TableBody>
          {items.map((row, index) => (
            <TableRow key={String(row.id ?? row.caseId ?? row.eventId ?? index)}>
              {columns.map((column) => (
                <TableCell key={column.key} className="max-w-xs break-all">
                  {column.render ? column.render(row) : optionalText(row[column.key]) || '—'}
                </TableCell>
              ))}
            </TableRow>
          ))}
        </TableBody>
      </Table>
      {!items.length && <p className="py-8 text-center text-sm text-neutral-500">{empty}</p>}
    </div>
  )
}
export function useNativeTask(scope: OperationScope) {
  const [busy, setBusy] = useState(false),
    [error, setError] = useState<string | null>(null),
    live = useRef(true),
    running = useRef(false)
  useEffect(() => {
    live.current = true
    return () => {
      live.current = false
    }
  }, [])
  async function run(action: () => Promise<void>) {
    if (running.current) return
    running.current = true
    setBusy(true)
    setError(null)
    try {
      scope.check()
      await action()
      scope.check()
    } catch (e) {
      try {
        scope.check()
        if (live.current) setError(e instanceof Error ? e.message : 'The operation failed.')
      } catch {
        /* selected owner clears this view */
      }
    } finally {
      running.current = false
      if (live.current) setBusy(false)
    }
  }
  return { busy, error, run, clearError: () => setError(null) }
}
export function TaskError({ message }: { message: string | null }) {
  return message ? (
    <p
      role="alert"
      className="rounded-lg border border-error/30 bg-error-light p-3 text-sm text-error-dark"
    >
      {message}
    </p>
  ) : null
}
export function More({
  cursor,
  busy,
  onNext,
}: {
  cursor: string
  busy: boolean
  onNext: () => void
}) {
  return cursor ? (
    <div className="flex justify-end pt-4">
      <Button variant="outline" disabled={busy} onClick={onNext}>
        Next page
      </Button>
    </div>
  ) : null
}
export function saveJSON(name: string, value: unknown, check: () => void) {
  check()
  const url = URL.createObjectURL(
    new Blob([JSON.stringify(value, null, 2) + '\n'], { type: 'application/json' }),
  )
  try {
    const link = document.createElement('a')
    link.href = url
    link.download = name
    check()
    link.click()
  } finally {
    URL.revokeObjectURL(url)
  }
}
