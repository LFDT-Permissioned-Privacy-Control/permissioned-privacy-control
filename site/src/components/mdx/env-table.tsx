interface EnvVar {
  name: string;
  default: string;
  description: string;
}

export function EnvTable({ vars }: { vars: EnvVar[] }) {
  return (
    <div className="my-6 overflow-x-auto rounded-lg border">
      <table className="w-full text-sm">
        <thead>
          <tr className="border-b bg-muted/50">
            <th className="px-4 py-2.5 text-left font-semibold">Variable</th>
            <th className="px-4 py-2.5 text-left font-semibold">Default</th>
            <th className="px-4 py-2.5 text-left font-semibold">Description</th>
          </tr>
        </thead>
        <tbody>
          {vars.map((v) => (
            <tr key={v.name} className="border-b last:border-b-0">
              <td className="px-4 py-2.5">
                <code className="bg-secondary text-secondary-foreground px-1.5 py-0.5 rounded text-xs font-mono">
                  {v.name}
                </code>
              </td>
              <td className="px-4 py-2.5 font-mono text-xs text-muted-foreground">
                {v.default}
              </td>
              <td className="px-4 py-2.5 text-muted-foreground">
                {v.description}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
