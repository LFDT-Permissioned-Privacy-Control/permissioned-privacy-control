import { recoverMessageAddress, stringToHex, type Hex } from 'viem';
export interface WalletScope {
  readonly identity: Readonly<{ actor: string; expires: number }>;
  readonly signal: AbortSignal;
  check(): void;
  request<T>(endpoint: string, options?: RequestInit): Promise<T>;
  dispose(): void;
}
export class WalletHTTPError extends Error {
  readonly status: number;
  constructor(status: number) { super(status === 409 ? 'Wallet state conflict. The challenge may be expired or used, or this link may be revoked.' : `Wallet request failed (${status}). Refresh links before trying another action.`); this.status = status; }
}

export interface OwnWallet { address: string; verifiedAt: string; proofVersion: 2 }
interface Challenge { nonce: string; message: string; expiresAt: string }
export interface WalletProvider {
  request(args: { method: string; params?: unknown[] }): Promise<unknown>;
  on?(event: string, listener: () => void): void;
  removeListener?(event: string, listener: () => void): void;
}
export interface WalletState {
  links: OwnWallet[]; accounts: string[]; selected: string | null;
  stage: 'idle' | 'choose' | 'sign' | 'confirm'; message: string | null;
  busy: boolean; error: string | null; unlink: string | null;
}
interface Owner {
  scope: WalletScope; provider: WalletProvider | null; clean: () => void;
  address: string | null; challenge: Challenge | null; signature: string | null;
  expiry: ReturnType<typeof setTimeout> | null;
}
const address = (v: unknown): v is string => typeof v === 'string' && /^0x[0-9a-f]{40}$/.test(v);
function object(value: unknown, keys: string[]): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value) || Object.keys(value).length !== keys.length || !Object.keys(value).every(k => keys.includes(k))) throw Error('Invalid wallet response');
  return value as Record<string, unknown>;
}
function utc(value: unknown): number {
  if (typeof value !== 'string' || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(value)) throw Error('Invalid wallet time');
  const ms = Date.parse(value);
  if (!Number.isFinite(ms) || ms < 0 || new Date(ms).toISOString().replace('.000Z', 'Z') !== value) throw Error('Invalid wallet time');
  return ms / 1000;
}
export function ownWallets(value: unknown): OwnWallet[] {
  if (!Array.isArray(value) || value.length > 4096) throw Error('Invalid wallet list');
  const seen = new Set<string>();
  return value.map(raw => {
    const v = object(raw, ['address', 'verifiedAt', 'proofVersion']);
    if (!address(v.address) || seen.has(v.address) || v.proofVersion !== 2) throw Error('Invalid wallet list');
    utc(v.verifiedAt); seen.add(v.address);
    return v as unknown as OwnWallet;
  });
}
export function walletChallenge(value: unknown, actor: string, selected: string, now: number): Challenge {
  const v = object(value, ['nonce', 'message', 'expiresAt']);
  if (typeof v.nonce !== 'string' || !/^[0-9a-f]{64}$/.test(v.nonce) || typeof v.message !== 'string' || new TextEncoder().encode(v.message).length > 4096) throw Error('Invalid wallet challenge');
  const lines = v.message.split('\n');
  if (lines.length !== 10 || lines[0] !== 'OPS wallet link v1' || !lines[1].startsWith('Service: ') || !/^Network: sha256:[0-9a-f]{64}$/.test(lines[2]) || lines[3] !== 'Actor: ' + actor || lines[4] !== 'Address: ' + selected || lines[5] !== 'Nonce: ' + v.nonce || !lines[6].startsWith('IssuedAt: ') || lines[7] !== 'ExpiresAt: ' + v.expiresAt || lines[8] !== '' || lines[9] !== 'I authorize this wallet to be linked to this OPS identity. This does not authorize a transaction.') throw Error('Invalid wallet challenge');
  const origin = lines[1].slice(9), issued = utc(lines[6].slice(10)), expires = utc(v.expiresAt);
  // This is a backend-owned binding string, not a browser destination. Do not
  // normalize it with WHATWG URL or infer equality with the SSO browser origin.
  if (!/^https:\/\/[^/?#@\\]+$/.test(origin) || new TextEncoder().encode(origin).length > 2048 || /[\u0000-\u0020\u007f]/.test(origin) || expires <= now || issued > now + 30 || expires <= issued || expires - issued > 300) throw Error('Invalid wallet challenge');
  return v as unknown as Challenge;
}
function accounts(value: unknown): string[] {
  if (!Array.isArray(value) || value.length < 1 || value.length > 256 || value.some(v => typeof v !== 'string' || !/^0x[0-9a-fA-F]{40}$/.test(v))) throw Error('Invalid wallet accounts');
  return [...new Set((value as string[]).map(v => v.toLowerCase()))];
}
const empty = (): WalletState => ({ links: [], accounts: [], selected: null, stage: 'idle', message: null, busy: false, error: null, unlink: null });
export function injectedWallet(): WalletProvider | null {
  const value = (window as unknown as { ethereum?: WalletProvider }).ethereum;
  return value && typeof value.request === 'function' ? value : null;
}

// Document-only proof state, with one immutable app activation across prompts.
// The native OPS service remains the ownership and signature authority.
export class WalletController {
  private state = empty();
  private listeners = new Set<() => void>();
  private owner: Owner | null = null;
  private live = true;
  private capture: (signal: AbortSignal) => Promise<WalletScope>;
  private warmup: AbortController | null = null;
  private provider: () => WalletProvider | null;
  private now: () => number;
  private recover: typeof recoverMessageAddress;
  private flush: (work: () => void) => void;
  constructor(capture: (signal: AbortSignal) => Promise<WalletScope>, options: { provider?: () => WalletProvider | null; now?: () => number; recover?: typeof recoverMessageAddress; flush?: (work: () => void) => void } = {}) {
    this.capture = capture; this.provider = options.provider ?? injectedWallet;
    this.now = options.now ?? (() => Math.floor(Date.now() / 1000)); this.recover = options.recover ?? recoverMessageAddress;
    this.flush = options.flush ?? (work => work());
  }
  snapshot = () => this.state;
  subscribe = (f: () => void) => { this.listeners.add(f); return () => { this.listeners.delete(f); }; };
  private set(value: Partial<WalletState>) { this.state = { ...this.state, ...value }; this.listeners.forEach(f => f()); }
  cancel = () => {
    this.warmup?.abort(); this.warmup = null;
    const old = this.owner; this.owner = null;
    if (old) { if (old.expiry) clearTimeout(old.expiry); old.signature = null; old.challenge = null; old.clean(); old.scope.dispose(); }
    this.set(empty());
  };
  stop = () => { this.live = false; this.cancel(); };
  private async begin(provider: WalletProvider | null = null): Promise<Owner> {
    this.cancel();
    if (!this.live) throw Error('Wallet panel is closed');
    const warmup = new AbortController(); this.warmup = warmup;
    this.set({ busy: true });
    let scope: WalletScope;
    try { scope = await this.capture(warmup.signal); }
    catch (error) {
      if (this.warmup === warmup) { this.warmup = null; this.set({ busy: false, error: 'Cannot verify the current identity. Refresh the session before starting a new wallet action.' }); }
      throw error;
    }
    if (!this.live || this.warmup !== warmup || warmup.signal.aborted) { scope.dispose(); throw Error('Wallet warm-up changed'); }
    this.warmup = null;
    const owner: Owner = { scope, provider, clean: () => {}, address: null, challenge: null, signature: null, expiry: null };
    this.owner = owner;
    const cancel = () => { if (this.owner === owner) this.flush(this.cancel); };
    scope.signal.addEventListener('abort', cancel, { once: true });
    provider?.on?.('accountsChanged', cancel); provider?.on?.('disconnect', cancel);
    owner.clean = () => { scope.signal.removeEventListener('abort', cancel); provider?.removeListener?.('accountsChanged', cancel); provider?.removeListener?.('disconnect', cancel); };
    try { this.check(owner); this.expiry(owner); return owner; }
    catch (error) { this.cancel(); throw error; }
  }
  private expiry(owner: Owner) {
    if (owner.expiry) clearTimeout(owner.expiry);
    const until = Math.min(owner.scope.identity.expires, owner.challenge ? utc(owner.challenge.expiresAt) : Infinity);
    owner.expiry = setTimeout(() => { if (this.owner === owner) this.flush(this.cancel); }, Math.max(0, (until - this.now()) * 1000));
  }
  private check(owner: Owner) {
    if (!this.live || this.owner !== owner) throw Error('Wallet operation changed');
    owner.scope.check();
    if (owner.provider && this.provider() !== owner.provider || owner.challenge && utc(owner.challenge.expiresAt) <= this.now()) throw Error('Wallet operation expired or changed');
  }
  private failed(owner: Owner | null, error: unknown) {
    if (!owner || this.owner !== owner || !this.live) return;
    try { this.check(owner); } catch { this.cancel(); return; }
    owner.signature = null; owner.challenge = null;
    this.expiry(owner);
    this.set({ links: [], stage: 'idle', message: null, accounts: [], selected: null, busy: false, unlink: null,
      error: error instanceof WalletHTTPError ? error.message : 'The wallet operation did not complete. Refresh links before starting a new action; an uncertain action is not retried.' });
  }
  private async currentAccount(owner: Owner) {
    this.check(owner);
    if (!owner.provider || !owner.address) throw Error('No selected wallet');
    const active = accounts(await owner.provider.request({ method: 'eth_accounts' })); this.check(owner);
    if (!active.includes(owner.address)) throw Error('Selected wallet changed');
  }
  private async list(owner: Owner) {
    const value = await owner.scope.request('/eth/addresses'); this.check(owner);
    const links = ownWallets(value); this.check(owner);
    this.set({ links, busy: false, stage: 'idle', accounts: [], selected: null, message: null, unlink: null, error: null });
    owner.signature = null; owner.challenge = null;
    this.expiry(owner);
  }
  load = async () => {
    let owner: Owner | null = null;
    try { owner = await this.begin(); this.check(owner); this.set({ busy: true }); await this.list(owner); }
    catch (e) { this.failed(owner, e); }
  };
  connect = async () => {
    let owner: Owner | null = null;
    try {
      const provider = this.provider();
      if (!provider) { this.cancel(); this.set({ error: 'Connect an injected Ethereum wallet to link an address.' }); return; }
      owner = await this.begin(provider); this.check(owner); this.set({ busy: true });
      const selected = accounts(await provider.request({ method: 'eth_requestAccounts' })); this.check(owner);
      this.set({ accounts: selected, stage: 'choose', busy: false });
    } catch (e) { this.failed(owner, e); }
  };
  select = async (selected: string) => {
    const owner = this.owner;
    if (!owner || this.state.busy || this.state.stage !== 'choose' || !this.state.accounts.includes(selected)) return;
    try {
      this.check(owner); owner.address = selected; this.set({ busy: true, selected });
      await this.currentAccount(owner); this.check(owner);
      const value = await owner.scope.request('/eth/link/challenge', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ address: selected }) }); this.check(owner);
      owner.challenge = walletChallenge(value, owner.scope.identity.actor, selected, this.now()); this.check(owner); this.expiry(owner);
      this.set({ stage: 'sign', message: owner.challenge.message, busy: false, accounts: [] });
    } catch (e) { this.failed(owner, e); }
  };
  sign = async () => {
    const owner = this.owner;
    if (!owner?.provider || !owner.address || !owner.challenge || this.state.busy || this.state.stage !== 'sign') return;
    try {
      this.check(owner); this.set({ busy: true });
      await this.currentAccount(owner); this.check(owner);
      const signature = await owner.provider.request({ method: 'personal_sign', params: [stringToHex(owner.challenge.message), owner.address] }); this.check(owner);
      await this.currentAccount(owner); this.check(owner);
      if (typeof signature !== 'string' || !/^0x[0-9a-fA-F]{130}$/.test(signature)) throw Error('Invalid signature');
      const recovered = await this.recover({ message: owner.challenge.message, signature: signature as Hex }); this.check(owner);
      if (recovered.toLowerCase() !== owner.address) throw Error('Wrong signer');
      owner.signature = signature;
      this.set({ stage: 'confirm', busy: false });
    } catch (e) { this.failed(owner, e); }
  };
  confirm = async () => {
    const owner = this.owner;
    if (!owner?.signature || !owner.challenge || !owner.address || this.state.busy || this.state.stage !== 'confirm') return;
    try {
      this.check(owner); this.set({ busy: true });
      await this.currentAccount(owner); this.check(owner);
      const value = await owner.scope.request('/eth/link/verify', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ nonce: owner.challenge.nonce, address: owner.address, signature: owner.signature }) }); this.check(owner);
      const result = object(value, ['address', 'status']);
      if (result.address !== owner.address || result.status !== 'linked') throw Error('Invalid wallet result');
      owner.signature = null; owner.challenge = null;
      await this.list(owner); this.check(owner);
    } catch (e) { this.failed(owner, e); }
  };
  prepareUnlink = (selected: string) => {
    const owner = this.owner;
    if (!owner || this.state.busy || !this.state.links.some(v => v.address === selected)) return;
    try { this.check(owner); this.set({ unlink: selected }); } catch { this.cancel(); }
  };
  unlink = async () => {
    const owner = this.owner, selected = this.state.unlink;
    if (!owner || !selected || this.state.busy) return;
    try {
      this.check(owner); this.set({ busy: true });
      const value = await owner.scope.request('/eth/addresses/' + selected, { method: 'DELETE' }); this.check(owner);
      const result = object(value, ['address', 'status']);
      if (result.address !== selected || result.status !== 'revoked') throw Error('Invalid wallet result');
      await this.list(owner); this.check(owner);
    } catch (e) { this.failed(owner, e); }
  };
}
