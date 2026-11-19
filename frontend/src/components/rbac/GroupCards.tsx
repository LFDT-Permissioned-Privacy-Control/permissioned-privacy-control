import type { ReactNode } from 'react';
import { ChevronRight, Eye, Shield, Users } from 'lucide-react';
import { Badge } from '../ui/badge';
import { Checkbox } from '../ui/checkbox';

export interface GroupCardItem {
  id: string;
  name: string;
  slug: string;
  isOrgAdmin: boolean;
  isOrgReadonlyAdmin: boolean;
  methodCount: number;
}
interface GroupCardsProps {
  groups: readonly GroupCardItem[];
  selectedIds?: ReadonlySet<string>;
  onToggle?(id: string): void;
  renderActions?(id: string): ReactNode;
}

// The existing flat group-card layout, with optional selection/actions supplied
// by the V1 or file-workspace container rather than an embedded API client.
export function GroupCards({ groups, selectedIds, onToggle, renderActions }: GroupCardsProps) {
  return <div className="space-y-2">
    {groups.map(group => <div key={group.id} data-testid="group-card" className="animate-fade-in">
      <div className={`flex items-center gap-3 p-3 rounded-lg bg-neutral-100 hover:bg-primary-50 transition-colors ${selectedIds?.has(group.id) ? 'ring-2 ring-primary/30' : ''}`}>
        {onToggle && <Checkbox checked={selectedIds?.has(group.id) ?? false} onCheckedChange={() => onToggle(group.id)} className="flex-shrink-0" />}
        <div className="flex items-center gap-2 flex-1 min-w-0">
          <Users className="w-5 h-5 text-primary flex-shrink-0" />
          <div className="min-w-0">
            <div className="flex items-center gap-2">
              <span className="font-medium truncate text-neutral-900">{group.name}</span>
              <Badge variant="outline" className="font-mono text-xs flex-shrink-0">{group.slug}</Badge>
              {group.isOrgAdmin && <Badge className="bg-warning-light text-warning-dark border-warning/40 gap-1 flex-shrink-0"><Shield className="w-3 h-3" />Org Admin</Badge>}
              {group.isOrgReadonlyAdmin && <Badge variant="outline" className="bg-neutral-50 text-neutral-700 border-neutral-300 gap-1 flex-shrink-0"><Eye className="w-3 h-3" />Read-only Admin</Badge>}
            </div>
            <div className="flex items-center gap-1 text-xs text-neutral-400 mt-0.5">
              {group.methodCount > 0 && <><ChevronRight className="w-3 h-3" /><span>{group.methodCount} methods</span></>}
            </div>
          </div>
        </div>
        <div className="flex items-center gap-1 flex-shrink-0">{renderActions?.(group.id)}</div>
      </div>
    </div>)}
  </div>;
}
