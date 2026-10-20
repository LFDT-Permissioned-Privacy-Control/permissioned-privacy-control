import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { Clock } from 'lucide-react';

interface AccessWindowFieldProps {
  preset: string;
  onPresetChange: (value: string) => void;
  custom: string;
  onCustomChange: (value: string) => void;
  disabled?: boolean;
}

// AccessWindowField is the shared "how long should this membership last" control
// used by both the add-member and onboard-by-DID flows. Picking a window makes
// the membership auto-expire — e.g. a time-limited regulator/auditor profile
// granted for 24h or 7 days (RD-1145). The parent owns the two pieces of
// state and computes the timestamp with resolveExpiry at submit time.
export default function AccessWindowField({
  preset,
  onPresetChange,
  custom,
  onCustomChange,
  disabled,
}: AccessWindowFieldProps) {
  return (
    <div className="space-y-2">
      <label className="flex items-center gap-2 text-sm font-medium text-neutral-700">
        <Clock className="w-4 h-4 text-neutral-400" />
        Access window
      </label>
      <Select value={preset} onValueChange={onPresetChange} disabled={disabled}>
        <SelectTrigger>
          <SelectValue />
        </SelectTrigger>
        <SelectContent>
          <SelectItem value="none">No expiry (permanent)</SelectItem>
          <SelectItem value="24h">24 hours</SelectItem>
          <SelectItem value="7d">7 days</SelectItem>
          <SelectItem value="30d">30 days</SelectItem>
          <SelectItem value="custom">Custom date…</SelectItem>
        </SelectContent>
      </Select>
      {preset === 'custom' && (
        <input
          type="datetime-local"
          value={custom}
          onChange={e => onCustomChange(e.target.value)}
          disabled={disabled}
          className="w-full rounded-md border border-neutral-300 px-3 py-2 text-sm"
        />
      )}
      {preset !== 'none' && (
        <p className="text-xs text-neutral-500">
          Access is revoked automatically once the window passes — use this for a
          time-limited regulator or auditor profile.
        </p>
      )}
    </div>
  );
}
