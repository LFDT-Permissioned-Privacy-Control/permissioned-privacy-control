import { Badge } from "@/components/ui/badge";

const methodColors: Record<string, string> = {
  GET: "bg-success/10 text-success border-success/20",
  POST: "bg-info/10 text-info border-info/20",
  PUT: "bg-warning/10 text-warning border-warning/20",
  DELETE: "bg-destructive/10 text-destructive border-destructive/20",
  WS: "bg-primary/10 text-primary border-primary/20",
};

export function ApiEndpoint({
  method,
  path,
  description,
}: {
  method: string;
  path: string;
  description?: string;
}) {
  return (
    <div className="my-4 flex items-start gap-3 rounded-lg border bg-card p-4">
      <Badge
        className={methodColors[method] || "bg-muted text-muted-foreground"}
      >
        {method}
      </Badge>
      <div>
        <code className="text-sm font-mono font-semibold">{path}</code>
        {description && (
          <p className="mt-1 text-sm text-muted-foreground">{description}</p>
        )}
      </div>
    </div>
  );
}
