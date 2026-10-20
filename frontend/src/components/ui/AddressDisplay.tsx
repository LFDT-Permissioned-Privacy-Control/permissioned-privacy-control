import { useState } from 'react';
import { Check, Copy } from 'lucide-react';
import { Button } from './button';

interface AddressDisplayProps {
  address: string;
  ensName?: string | null;
  showFull?: boolean;
}

export function AddressDisplay({ address, ensName, showFull = false }: AddressDisplayProps) {
  const [copied, setCopied] = useState(false);

  const truncatedAddress = showFull
    ? address
    : `${address.slice(0, 6)}...${address.slice(-4)}`;

  const handleCopy = async () => {
    await navigator.clipboard.writeText(address);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="flex items-center gap-2">
      <div className="flex flex-col">
        {ensName && (
          <span className="text-sm font-medium text-primary">{ensName}</span>
        )}
        <span
          className="font-mono text-xs text-neutral-500"
          title={address}
        >
          {truncatedAddress}
        </span>
      </div>
      <Button
        variant="ghost"
        size="sm"
        onClick={handleCopy}
        className="h-6 w-6 p-0 text-neutral-400 hover:text-neutral-500"
        title="Copy address"
      >
        {copied ? (
          <Check className="w-3 h-3 text-success" />
        ) : (
          <Copy className="w-3 h-3" />
        )}
      </Button>
    </div>
  );
}
