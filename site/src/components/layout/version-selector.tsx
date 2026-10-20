"use client";

import { useRef, useState, useEffect } from "react";
import { ChevronDown } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";
import {
  versions,
  currentVersion,
  hasMultipleVersions,
  type DocsVersion,
} from "@/lib/versions";

function VersionLink({ version }: { version: DocsVersion }) {
  const href = version.basePath ?? "/";
  return (
    <a
      href={href}
      className={cn(
        "block px-3 py-2 text-sm font-mono rounded-md transition-colors",
        version.isLatest
          ? "bg-accent text-accent-foreground font-medium"
          : "text-muted-foreground hover:text-foreground hover:bg-accent"
      )}
    >
      {version.label}
    </a>
  );
}

export function VersionSelector() {
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!open) return;
    function handleClick(e: MouseEvent) {
      if (ref.current && !ref.current.contains(e.target as Node)) {
        setOpen(false);
      }
    }
    document.addEventListener("mousedown", handleClick);
    return () => document.removeEventListener("mousedown", handleClick);
  }, [open]);

  if (!hasMultipleVersions) {
    return <Badge variant="secondary">v{currentVersion.version}</Badge>;
  }

  return (
    <div ref={ref} className="relative">
      <button
        onClick={() => setOpen(!open)}
        className={cn(
          "inline-flex items-center gap-1 rounded-md border px-2.5 py-0.5",
          "text-xs font-semibold font-mono transition-colors",
          "border-transparent bg-secondary text-secondary-foreground",
          "hover:bg-secondary/80"
        )}
      >
        v{currentVersion.version}
        <ChevronDown className="size-3" />
      </button>
      {open && (
        <div className="absolute right-0 top-full mt-1 w-48 rounded-md border bg-popover p-1 shadow-md z-50">
          {versions.map((v) => (
            <VersionLink key={v.version} version={v} />
          ))}
        </div>
      )}
    </div>
  );
}

export function MobileVersionBadge() {
  if (!hasMultipleVersions) {
    return (
      <div className="flex items-center gap-2 px-3 py-2 text-sm text-muted-foreground">
        <Badge variant="secondary">v{currentVersion.version}</Badge>
        <span>Documentation</span>
      </div>
    );
  }

  return (
    <div className="space-y-1">
      <h4 className="px-3 text-xs font-semibold uppercase tracking-wider text-muted-foreground">
        Version
      </h4>
      {versions.map((v) => (
        <VersionLink key={v.version} version={v} />
      ))}
    </div>
  );
}
