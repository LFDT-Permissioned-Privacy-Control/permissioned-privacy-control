import { useState, useEffect } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Input } from '@/components/ui/input';
import { Textarea } from '@/components/ui/textarea';
import {
  Select,
  SelectContent,
  SelectGroup,
  SelectItem,
  SelectLabel,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { testApi, TestRequestResult } from '@/api/client';
import { Send, Loader2, Zap, ShieldX, ShieldCheck, AlertTriangle, ChevronDown, ChevronRight } from 'lucide-react';
import { UserContextPanel, type UserLookupResult } from './UserContextPanel';
import { ContractInfoPanel } from './ContractInfoPanel';
import { rbacApi } from '../../api/rbac';
import { complianceApi } from '../../api/compliance';

const RPC_METHODS = [
  { value: 'eth_blockNumber', label: 'eth_blockNumber' },
  { value: 'eth_chainId', label: 'eth_chainId' },
  { value: 'eth_getBalance', label: 'eth_getBalance' },
  { value: 'eth_call', label: 'eth_call' },
  { value: 'net_version', label: 'net_version' },
  { value: 'web3_clientVersion', label: 'web3_clientVersion' },
];

interface ERC20Method {
  value: string;
  label: string;
  selector: string;
  fields: { name: string; type: 'address' | 'uint256'; placeholder: string }[];
}

const ERC20_METHODS: ERC20Method[] = [
  {
    value: 'erc20_balanceOf',
    label: 'ERC20 - balanceOf',
    selector: '0x70a08231',
    fields: [
      { name: 'owner', type: 'address', placeholder: 'Owner address (0x...)' },
    ],
  },
  {
    value: 'erc20_totalSupply',
    label: 'ERC20 - totalSupply',
    selector: '0x18160ddd',
    fields: [],
  },
  {
    value: 'erc20_allowance',
    label: 'ERC20 - allowance',
    selector: '0xdd62ed3e',
    fields: [
      { name: 'owner', type: 'address', placeholder: 'Owner address (0x...)' },
      { name: 'spender', type: 'address', placeholder: 'Spender address (0x...)' },
    ],
  },
  {
    value: 'erc20_transfer',
    label: 'ERC20 - transfer',
    selector: '0xa9059cbb',
    fields: [
      { name: 'recipient', type: 'address', placeholder: 'Recipient address (0x...)' },
      { name: 'amount', type: 'uint256', placeholder: 'Amount (in wei)' },
    ],
  },
  {
    value: 'erc20_approve',
    label: 'ERC20 - approve',
    selector: '0x095ea7b3',
    fields: [
      { name: 'spender', type: 'address', placeholder: 'Spender address (0x...)' },
      { name: 'amount', type: 'uint256', placeholder: 'Amount (in wei)' },
    ],
  },
];

function encodeAddress(addr: string): string {
  const hex = addr.startsWith('0x') ? addr.slice(2) : addr;
  return hex.toLowerCase().padStart(64, '0');
}

function encodeUint256(value: string): string {
  const n = BigInt(value);
  return n.toString(16).padStart(64, '0');
}

function buildERC20Calldata(erc20Method: ERC20Method, fieldValues: Record<string, string>): string {
  let data = erc20Method.selector;
  for (const field of erc20Method.fields) {
    const val = fieldValues[field.name] || '';
    if (field.type === 'address') {
      data += encodeAddress(val);
    } else {
      data += encodeUint256(val);
    }
  }
  return data;
}

function isERC20(method: string): boolean {
  return method.startsWith('erc20_');
}

function ethToHexWei(eth: string): string {
  const [whole = '0', frac = ''] = eth.split('.');
  const paddedFrac = frac.padEnd(18, '0').slice(0, 18);
  const weiStr = whole + paddedFrac;
  const wei = BigInt(weiStr.replace(/^0+/, '') || '0');
  return '0x' + wei.toString(16);
}

function isValidAddress(addr: string): boolean {
  return /^0x[0-9a-fA-F]{40}$/.test(addr);
}

const TX_METHODS = [
  { value: 'eth_sendTransaction', label: 'eth_sendTransaction' },
];

const isDev = import.meta.env.DEV;

// Anvil's deterministic default accounts (each pre-funded with 10,000 ETH)
const ANVIL_ACCOUNTS = [
  '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266',
  '0x70997970C51812dc3A010C7d01b50e0d17dc79C8',
  '0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC',
  '0x90F79bf6EB2c4f870365E785982E1f101E93b906',
  '0x15d34AAf54267DB7D7c367839AAf71A00a2C6A65',
  '0x9965507D1a55bcC2695C58ba16FB37d819B0A4dc',
  '0x976EA74026E726554dB657fA54763abd0C3a0aa9',
  '0x14dC79964da2C08dA15Fd353d30d9CBa8C7C3f04',
  '0x23618e81E3f5cdF7f54C3d65f7FBc0aBf5B21E8f',
  '0xa0Ee7A142d267C1f36714E4a8F75612F20a79720',
];

function getERC20Method(method: string): ERC20Method | undefined {
  return ERC20_METHODS.find((m) => m.value === method);
}

export function TestRequestPanel() {
  const [method, setMethod] = useState('eth_blockNumber');
  const [params, setParams] = useState('');
  const [jwtToken, setJwtToken] = useState('');
  const [contractAddress, setContractAddress] = useState('');
  const [erc20Fields, setErc20Fields] = useState<Record<string, string>>({});
  const [result, setResult] = useState<TestRequestResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [showAdvanced, setShowAdvanced] = useState(false);
  const [txFrom, setTxFrom] = useState('');
  const [txTo, setTxTo] = useState('');
  const [txValue, setTxValue] = useState('');
  const [userLinkedAddresses, setUserLinkedAddresses] = useState<Array<{ address: string; verified_at: string }>>([]);
  const [ethPriceUsd, setEthPriceUsd] = useState<number | null>(null);
  const [priceLoadWarning, setPriceLoadWarning] = useState<string | null>(null);

  useEffect(() => {
    (async () => {
      try {
        const orgsRes = await rbacApi.orgs.list({ limit: 1 });
        const orgs = orgsRes.data.data;
        if (!orgs || orgs.length === 0) return;
        const orgId = orgs[0].id;
        const tokensRes = await complianceApi.tokens.list(orgId);
        const tokens = tokensRes.data.data;
        const nativeToken = tokens?.find((t) => t.token_address === 'native');
        if (nativeToken) {
          setEthPriceUsd(nativeToken.price_fiat);
          setPriceLoadWarning(null);
        }
      } catch {
        setPriceLoadWarning('Unable to load ETH price. Fiat estimate unavailable.');
      }
    })();
  }, []);

  const erc20Method = getERC20Method(method);
  const isErc20 = isERC20(method);
  const isSendTx = method === 'eth_sendTransaction';

  const handleUserLoaded = (data: UserLookupResult | null) => {
    setUserLinkedAddresses(data?.linkedAddresses || []);
  };

  const handleMethodChange = (value: string) => {
    setMethod(value);
    setErc20Fields({});
    setContractAddress('');
    setParams('');
    setTxFrom('');
    setTxTo('');
    setTxValue('');
    setResult(null);
    setError(null);
  };

  const handleSend = async () => {
    setLoading(true);
    setError(null);
    setResult(null);

    try {
      let rpcMethod: string;
      let parsedParams: unknown[];

      if (isErc20 && erc20Method) {
        if (!contractAddress.trim()) {
          setError('Contract address is required');
          setLoading(false);
          return;
        }
        for (const field of erc20Method.fields) {
          if (!erc20Fields[field.name]?.trim()) {
            setError(`${field.name} is required`);
            setLoading(false);
            return;
          }
        }
        const calldata = buildERC20Calldata(erc20Method, erc20Fields);
        rpcMethod = 'eth_call';
        parsedParams = [{ to: contractAddress, data: calldata }, 'latest'];
      } else if (isSendTx) {
        if (!txFrom.trim() || !isValidAddress(txFrom.trim())) {
          setError('Valid "From" address is required (0x + 40 hex chars)');
          setLoading(false);
          return;
        }
        if (!txTo.trim() || !isValidAddress(txTo.trim())) {
          setError('Valid "To" address is required (0x + 40 hex chars)');
          setLoading(false);
          return;
        }
        if (!txValue.trim() || isNaN(parseFloat(txValue)) || parseFloat(txValue) <= 0) {
          setError('A positive ETH amount is required');
          setLoading(false);
          return;
        }
        rpcMethod = 'eth_sendTransaction';
        parsedParams = [{
          from: txFrom.trim(),
          to: txTo.trim(),
          value: ethToHexWei(txValue.trim()),
        }];
      } else {
        rpcMethod = method;
        parsedParams = [];
        if (params.trim()) {
          parsedParams = JSON.parse(params);
          if (!Array.isArray(parsedParams)) {
            parsedParams = [parsedParams];
          }
        }
      }

      const response = await testApi.send(rpcMethod, parsedParams, jwtToken);
      setResult(response);
    } catch (err) {
      if (err instanceof SyntaxError) {
        setError('Invalid JSON in params');
      } else {
        setError(err instanceof Error ? err.message : 'Request failed');
      }
    } finally {
      setLoading(false);
    }
  };

  return (
    <Card>
      <CardHeader className="pb-3">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-lg bg-warning-light flex items-center justify-center">
            <Zap className="w-5 h-5 text-warning-dark" />
          </div>
          <CardTitle className="text-lg">Test Request</CardTitle>
        </div>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="flex gap-3">
          <Select value={method} onValueChange={handleMethodChange}>
            <SelectTrigger className="w-[260px]">
              <SelectValue placeholder="Select method" />
            </SelectTrigger>
            <SelectContent>
              <SelectGroup>
                <SelectLabel>RPC Methods</SelectLabel>
                {RPC_METHODS.map((m) => (
                  <SelectItem key={m.value} value={m.value}>
                    {m.label}
                  </SelectItem>
                ))}
              </SelectGroup>
              <SelectGroup>
                <SelectLabel>Transactions</SelectLabel>
                {TX_METHODS.map((m) => (
                  <SelectItem key={m.value} value={m.value}>
                    {m.label}
                  </SelectItem>
                ))}
              </SelectGroup>
              <SelectGroup>
                <SelectLabel>ERC20 Contract Calls</SelectLabel>
                {ERC20_METHODS.map((m) => (
                  <SelectItem key={m.value} value={m.value}>
                    {m.label}
                  </SelectItem>
                ))}
              </SelectGroup>
            </SelectContent>
          </Select>
          <Button onClick={handleSend} disabled={loading} className="gap-2">
            {loading ? (
              <>
                <Loader2 className="w-4 h-4 animate-spin" />
                Sending...
              </>
            ) : (
              <>
                <Send className="w-4 h-4" />
                Send
              </>
            )}
          </Button>
        </div>

        {isErc20 && (
          <div className="space-y-3 animate-fade-in">
            <div>
              <label className="block text-sm font-medium text-neutral-700 mb-2">
                Contract Address
              </label>
              <Input
                value={contractAddress}
                onChange={(e) => setContractAddress(e.target.value)}
                placeholder="0x..."
              />
              <ContractInfoPanel contractAddress={contractAddress} />
            </div>
            {erc20Method?.fields.map((field) => (
              <div key={field.name}>
                <label className="block text-sm font-medium text-neutral-700 mb-2">
                  {field.name.charAt(0).toUpperCase() + field.name.slice(1)}
                  {field.type === 'uint256' && (
                    <span className="text-xs text-neutral-500 ml-1">(uint256)</span>
                  )}
                </label>
                <Input
                  value={erc20Fields[field.name] || ''}
                  onChange={(e) =>
                    setErc20Fields((prev) => ({ ...prev, [field.name]: e.target.value }))
                  }
                  placeholder={field.placeholder}
                />
              </div>
            ))}
          </div>
        )}

        {isSendTx && (
          <div className="space-y-3 animate-fade-in">
            <div>
              <label className="block text-sm font-medium text-neutral-700 mb-2">
                From Address
              </label>
              {(userLinkedAddresses.length > 0 || isDev) ? (
                <Select value={txFrom} onValueChange={setTxFrom}>
                  <SelectTrigger>
                    <SelectValue placeholder="Select sender address" />
                  </SelectTrigger>
                  <SelectContent>
                    {userLinkedAddresses.length > 0 && (
                      <SelectGroup>
                        <SelectLabel>User Linked Addresses</SelectLabel>
                        {userLinkedAddresses.map((addr) => (
                          <SelectItem key={addr.address} value={addr.address}>
                            <span className="font-mono text-sm">{addr.address}</span>
                          </SelectItem>
                        ))}
                      </SelectGroup>
                    )}
                    {isDev && (
                      <SelectGroup>
                        <SelectLabel>Anvil Dev Accounts</SelectLabel>
                        {ANVIL_ACCOUNTS.map((addr, i) => (
                          <SelectItem key={addr} value={addr}>
                            <span className="font-mono text-sm">
                              <span className="text-neutral-500">#{i}</span>{' '}
                              {addr.slice(0, 10)}...{addr.slice(-4)}
                            </span>
                          </SelectItem>
                        ))}
                      </SelectGroup>
                    )}
                  </SelectContent>
                </Select>
              ) : (
                <Input
                  value={txFrom}
                  onChange={(e) => setTxFrom(e.target.value)}
                  placeholder="0x..."
                />
              )}
              {txFrom && !isValidAddress(txFrom) && (
                <p className="text-xs text-red-600 mt-1">Invalid address format (expected 0x + 40 hex chars)</p>
              )}
            </div>
            <div>
              <label className="block text-sm font-medium text-neutral-700 mb-2">
                To Address
              </label>
              <Input
                value={txTo}
                onChange={(e) => setTxTo(e.target.value)}
                placeholder="0x..."
              />
              {txTo && !isValidAddress(txTo) && (
                <p className="text-xs text-red-600 mt-1">Invalid address format (expected 0x + 40 hex chars)</p>
              )}
              {isDev && (
                <div className="flex flex-wrap gap-1 mt-1.5">
                  {ANVIL_ACCOUNTS.slice(0, 5).map((addr, i) => (
                    <button
                      key={addr}
                      type="button"
                      onClick={() => setTxTo(addr)}
                      className="rounded border border-transparent bg-neutral-100 px-1.5 py-0.5 font-mono text-xs text-neutral-500 transition-colors hover:border-neutral-300 hover:bg-neutral-200 hover:text-neutral-700 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary/40"
                    >
                      #{i} {addr.slice(0, 6)}...{addr.slice(-4)}
                    </button>
                  ))}
                </div>
              )}
            </div>
            <div>
              <label className="block text-sm font-medium text-neutral-700 mb-2">
                Amount (ETH)
              </label>
              <Input
                type="number"
                value={txValue}
                onChange={(e) => setTxValue(e.target.value)}
                placeholder="0.1"
                min="0"
                step="0.001"
              />
              {txValue && !isNaN(parseFloat(txValue)) && parseFloat(txValue) > 0 && (
                <div className="mt-1 space-y-0.5">
                  {ethPriceUsd != null && (
                    <p className="text-sm font-medium text-neutral-700">
                      ≈ ${(parseFloat(txValue) * ethPriceUsd).toLocaleString(undefined, { minimumFractionDigits: 2, maximumFractionDigits: 2 })} USD{' '}
                      <span className="text-xs font-normal text-neutral-500">
                        (at ${ethPriceUsd.toLocaleString(undefined, { minimumFractionDigits: 2, maximumFractionDigits: 2 })}/ETH)
                      </span>
                    </p>
                  )}
                  <p className="text-xs text-neutral-500">
                    = {ethToHexWei(txValue)} wei
                  </p>
                </div>
              )}
              {priceLoadWarning && (
                <p className="mt-1 text-xs text-warning-dark">{priceLoadWarning}</p>
              )}
            </div>
          </div>
        )}

        {!isErc20 && !isSendTx && (
          <div>
            <label className="block text-sm font-medium text-neutral-700 mb-2">
              Params (JSON array, optional)
            </label>
            <Textarea
              variant="code"
              value={params}
              onChange={(e) => setParams(e.target.value)}
              placeholder='["0x...", "latest"]'
              className="h-20"
            />
          </div>
        )}

        <div>
          <button
            type="button"
            onClick={() => setShowAdvanced(!showAdvanced)}
            className="flex items-center gap-2 rounded px-1 text-sm text-neutral-500 transition-colors hover:text-neutral-700 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary/40"
          >
            {showAdvanced ? (
              <ChevronDown className="w-4 h-4" />
            ) : (
              <ChevronRight className="w-4 h-4" />
            )}
            Advanced: Test with JWT Token
          </button>

          {showAdvanced && (
            <div className="mt-3 space-y-2 animate-fade-in">
              <label className="block text-sm font-medium text-neutral-700 mb-2">
                JWT Token
              </label>
              <Textarea
                variant="code"
                value={jwtToken}
                onChange={(e) => setJwtToken(e.target.value)}
                placeholder="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
                className="h-20"
              />
              <p className="text-xs text-neutral-500">
                Paste a JWT token to test as a specific user identity. Copy from the user dashboard after authentication.
              </p>
              <UserContextPanel jwtToken={jwtToken} onUserLoaded={handleUserLoaded} />
            </div>
          )}
        </div>

        {error && (
          <div className="p-4 rounded-lg bg-error-light border border-error/30 flex items-start gap-3">
            <AlertTriangle className="w-5 h-5 text-error-dark flex-shrink-0 mt-0.5" />
            <span className="text-error-dark text-sm">{error}</span>
          </div>
        )}

        {result && (
          <div className="space-y-3 animate-fade-in">
            <div className="flex items-center gap-3 flex-wrap">
              {result.status === 403 ? (
                <Badge variant="destructive" className="gap-1.5">
                  <ShieldX className="w-3 h-3" />
                  403 FORBIDDEN
                </Badge>
              ) : result.status === 200 ? (
                <Badge variant="success" className="gap-1.5">
                  <ShieldCheck className="w-3 h-3" />
                  200 OK
                </Badge>
              ) : (
                <Badge variant="warning" className="gap-1.5">
                  <AlertTriangle className="w-3 h-3" />
                  {result.status} ERROR
                </Badge>
              )}
              {result.data.latency_ms !== undefined && (
                <span className="text-sm text-neutral-500">
                  {result.data.latency_ms}ms
                </span>
              )}
              {result.data.identity && (
                <span className="text-xs text-neutral-500 font-mono truncate max-w-[300px]" title={result.data.identity}>
                  Identity: {result.data.identity}
                </span>
              )}
            </div>
            {result.status === 200 && result.data.result !== undefined && (
              <div className="code-block">
                <pre className="whitespace-pre-wrap break-all">
                  {JSON.stringify(result.data.result, null, 2)}
                </pre>
              </div>
            )}
            {result.data.error && (
              <div className="p-4 rounded-lg bg-warning-light border border-warning/40">
                <span className="text-warning-dark text-sm">{result.data.error}</span>
                {result.status === 403 && !jwtToken.trim() && (
                  <p className="text-amber-800 text-xs mt-2">
                    No JWT token provided. Expand "Advanced: Test with JWT Token" below the Send button and paste a valid token to test as a specific user.
                  </p>
                )}
              </div>
            )}
          </div>
        )}
      </CardContent>
    </Card>
  );
}
