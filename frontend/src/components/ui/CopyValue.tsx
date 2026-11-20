import { useEffect, useRef, useState } from 'react'
import { Check, Copy } from 'lucide-react'
import { Button } from './button'

// Noncredential display values only. Credential handoffs have their own
// explicit controller action and must never be passed into component state.
export function CopyValue({ value, label = 'Copy' }: { value: string; label?: string }) {
  const [feedback, setFeedback] = useState<{ value: string; status: 'copied' | 'failed' }>()
  const timer = useRef<ReturnType<typeof setTimeout>>(), live = useRef(false), serial = useRef(0), currentValue = useRef(value)
  currentValue.current = value
  useEffect(() => {
    live.current = true; serial.current++; setFeedback(undefined)
    return () => { live.current = false; serial.current++; clearTimeout(timer.current) }
  }, [value])
  async function copy() {
    const selected = value, operation = ++serial.current
    const current = () => live.current && operation === serial.current && currentValue.current === selected
    clearTimeout(timer.current); setFeedback(undefined)
    try {
      let written = false
      if (navigator.clipboard?.writeText) {
        try { await navigator.clipboard.writeText(selected); written = true }
        catch { /* Try the established local copy fallback while still current. */ }
      }
      if (!current()) return
      if (!written) {
        const input = document.createElement('textarea'), focused = document.activeElement
        input.value = selected; input.readOnly = true; input.style.position = 'fixed'; input.style.left = '-999999px'
        try {
          document.body.appendChild(input); input.focus(); input.select()
          if (!current()) return
          written = typeof document.execCommand === 'function' && document.execCommand('copy') === true
        } finally {
          input.remove()
          if (current() && focused instanceof HTMLElement && focused.isConnected) focused.focus()
        }
      }
      if (!current()) return
      if (!written) throw Error('Copy failed')
      setFeedback({ value: selected, status: 'copied' })
      timer.current = setTimeout(() => { if (current()) setFeedback(undefined) }, 2000)
    } catch {
      if (current()) setFeedback({ value: selected, status: 'failed' })
    }
  }
  const copied = feedback?.value === value && feedback.status === 'copied', failed = feedback?.value === value && feedback.status === 'failed'
  return <span className="inline-flex flex-col items-start"><Button type="button" onClick={() => { void copy() }} variant="ghost" size="icon" className="h-8 w-8 flex-shrink-0" title={copied ? 'Copied' : label} aria-label={label}>
    {copied ? <Check className="h-4 w-4 text-success-dark" /> : <Copy className="h-4 w-4 text-neutral-400" />}
  </Button>{failed && <span role="status" className="text-xs text-error-dark">Copy failed. Select the value and copy it manually.</span>}</span>
}
