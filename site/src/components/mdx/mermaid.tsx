"use client";

import { useEffect, useId, useRef, useState } from "react";

export function Mermaid({ chart }: { chart: string }) {
  const id = useId();
  const containerRef = useRef<HTMLDivElement>(null);
  const [svg, setSvg] = useState("");

  useEffect(() => {
    let cancelled = false;

    async function render() {
      const { default: mermaid } = await import("mermaid");
      mermaid.initialize({
        startOnLoad: false,
        securityLevel: "loose",
        fontFamily: "inherit",
        theme: "default",
      });

      try {
        const { svg: rendered } = await mermaid.render(
          id.replaceAll(":", ""),
          chart,
          containerRef.current ?? undefined,
        );
        if (!cancelled) setSvg(rendered);
      } catch (err) {
        console.error("Mermaid render error:", err);
      }
    }

    render();
    return () => { cancelled = true; };
  }, [chart, id]);

  return (
    <div
      ref={containerRef}
      className="my-6 flex justify-center [&>svg]:max-w-full"
      dangerouslySetInnerHTML={{ __html: svg }}
    />
  );
}
