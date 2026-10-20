export function Step({
  number,
  title,
  children,
}: {
  number: number;
  title: string;
  children: React.ReactNode;
}) {
  return (
    <div className="my-6 flex gap-4">
      <div className="flex size-8 shrink-0 items-center justify-center rounded-full bg-primary text-primary-foreground text-sm font-semibold">
        {number}
      </div>
      <div className="min-w-0 pt-0.5">
        <h4 className="font-semibold text-base mb-2">{title}</h4>
        <div className="text-sm text-muted-foreground [&>pre]:mt-2 [&>p]:m-0">
          {children}
        </div>
      </div>
    </div>
  );
}
