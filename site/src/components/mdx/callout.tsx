import { cn } from "@/lib/utils";
import { AlertCircle, Info, AlertTriangle } from "lucide-react";

type CalloutVariant = "info" | "warning" | "danger";

const variants: Record<
  CalloutVariant,
  { icon: typeof Info; bg: string; border: string; text: string }
> = {
  info: {
    icon: Info,
    bg: "bg-info/5",
    border: "border-info/20",
    text: "text-info",
  },
  warning: {
    icon: AlertTriangle,
    bg: "bg-warning/5",
    border: "border-warning/20",
    text: "text-warning",
  },
  danger: {
    icon: AlertCircle,
    bg: "bg-destructive/5",
    border: "border-destructive/20",
    text: "text-destructive",
  },
};

export function Callout({
  variant = "info",
  title,
  children,
}: {
  variant?: CalloutVariant;
  title?: string;
  children: React.ReactNode;
}) {
  const v = variants[variant];
  const Icon = v.icon;

  return (
    <div
      className={cn(
        "my-6 rounded-lg border p-4",
        v.bg,
        v.border
      )}
    >
      <div className="flex gap-3">
        <Icon className={cn("size-5 shrink-0 mt-0.5", v.text)} />
        <div className="min-w-0">
          {title && (
            <p className={cn("font-semibold text-sm mb-1", v.text)}>
              {title}
            </p>
          )}
          <div className="text-sm text-foreground [&>p]:m-0">{children}</div>
        </div>
      </div>
    </div>
  );
}
