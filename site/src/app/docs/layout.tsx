import { Sidebar } from "@/components/layout/sidebar";
import { TableOfContents } from "@/components/layout/toc";

export default function DocsLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <div className="mx-auto max-w-7xl px-4 md:px-6">
      <div className="flex gap-8">
        <Sidebar />
        <article className="flex-1 min-w-0 py-8 prose prose-gray max-w-none">
          {children}
        </article>
        <TableOfContents />
      </div>
    </div>
  );
}
