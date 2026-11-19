import { Building2, Pencil } from 'lucide-react';
import { Badge } from '../ui/badge';
import { Button } from '../ui/button';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '../ui/table';

export interface OrganizationRow {
  id: string;
  name: string;
  slug: string;
  createdAt?: string;
}

interface OrganizationTableProps {
  organizations: readonly OrganizationRow[];
  onSelect(id: string): void;
  canEdit?(id: string): boolean;
  onEdit?(id: string): void;
}

// Shared presentation from the established organization list. Data ownership
// and mutation permissions remain with the runtime-specific container.
export function OrganizationTable({ organizations, onSelect, canEdit, onEdit }: OrganizationTableProps) {
  return <Table>
    <TableHeader>
      <TableRow>
        <TableHead>Name</TableHead>
        <TableHead>Slug</TableHead>
        <TableHead>Created</TableHead>
        <TableHead className="text-right">Actions</TableHead>
      </TableRow>
    </TableHeader>
    <TableBody>
      {organizations.map((org, index) => <TableRow key={org.id} className="animate-fade-in cursor-pointer"
        style={{ animationDelay: `${index * 30}ms` }} onClick={() => onSelect(org.id)}>
        <TableCell>
          <div className="flex items-center gap-2">
            <Building2 className="w-4 h-4 text-primary" />
            <span className="font-medium">{org.name}</span>
          </div>
        </TableCell>
        <TableCell><Badge variant="outline" className="font-mono text-xs">{org.slug}</Badge></TableCell>
        <TableCell className="text-neutral-500 text-sm">
          {org.createdAt ? new Date(org.createdAt).toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric' })
            : <span title="Creation time is not recorded in this policy source">—</span>}
        </TableCell>
        <TableCell>
          <div className="flex items-center justify-end gap-2">
            {canEdit?.(org.id) && onEdit && <Button variant="ghost" size="sm" title="Edit organization"
              onClick={event => { event.stopPropagation(); onEdit(org.id); }}><Pencil className="w-4 h-4" /></Button>}
          </div>
        </TableCell>
      </TableRow>)}
    </TableBody>
  </Table>;
}
