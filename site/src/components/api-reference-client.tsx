"use client";

import dynamic from "next/dynamic";
import { withBasePath } from "@/lib/base-path";
import "@scalar/api-reference-react/style.css";

// The Scalar reference is a purely client-side app (it mounts itself into a
// DOM node), so it is loaded dynamically and excluded from the static
// prerender. This keeps the statically exported page valid while the full
// reference hydrates in the browser.
const ApiReferenceReact = dynamic(
  () =>
    import("@scalar/api-reference-react").then((mod) => mod.ApiReferenceReact),
  {
    ssr: false,
    loading: () => (
      <div className="flex items-center justify-center py-24 text-sm text-muted-foreground">
        Loading API reference…
      </div>
    ),
  }
);

export function ApiReferenceClient() {
  return (
    <ApiReferenceReact
      configuration={{
        // Served from site/public/; the generated spec overwrites the
        // placeholder in the build pipeline (make api-spec).
        url: withBasePath("/openapi.json"),
        hideDarkModeToggle: true,
      }}
    />
  );
}
