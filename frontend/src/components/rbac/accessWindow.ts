// Shared helper for the membership access-window control (RD-1145
// time-boxed access). Kept in its own non-component module so the
// AccessWindowField component file only exports a component (react-refresh).

// resolveExpiry turns the access-window preset into an RFC3339 timestamp for a
// membership's expires_at. 'none' -> undefined (a permanent membership).
// Presets are relative to now; 'custom' uses the operator-picked
// datetime-local value. Returns undefined for an unparseable custom date so
// the caller can surface a validation error.
export function resolveExpiry(preset: string, custom: string): string | undefined {
  const now = Date.now();
  const day = 24 * 60 * 60 * 1000;
  switch (preset) {
    case '24h':
      return new Date(now + day).toISOString();
    case '7d':
      return new Date(now + 7 * day).toISOString();
    case '30d':
      return new Date(now + 30 * day).toISOString();
    case 'custom': {
      if (!custom) return undefined;
      const d = new Date(custom);
      return isNaN(d.getTime()) ? undefined : d.toISOString();
    }
    default:
      return undefined;
  }
}
