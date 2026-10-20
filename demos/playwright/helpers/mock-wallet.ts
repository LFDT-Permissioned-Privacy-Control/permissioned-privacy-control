import { Page } from "@playwright/test";

/**
 * Mock wallet configuration for demo recordings.
 * Simulates Web3 wallet interactions without requiring actual wallet connections.
 */
export interface MockWalletConfig {
  address: string;
  chainId: number;
  balance: string;
}

const DEFAULT_CONFIG: MockWalletConfig = {
  address: "0x742d35Cc6634C0532925a3b844Bc9e7595f5dE21",
  chainId: 1,
  balance: "10.5",
};

/**
 * Injects a mock Ethereum provider into the page.
 * This allows demos to show wallet connection flows without real wallets.
 */
export async function injectMockWallet(
  page: Page,
  config: Partial<MockWalletConfig> = {}
): Promise<void> {
  const finalConfig = { ...DEFAULT_CONFIG, ...config };

  await page.addInitScript((cfg) => {
    const mockProvider = {
      isMetaMask: true,
      isConnected: () => true,
      selectedAddress: cfg.address,
      chainId: `0x${cfg.chainId.toString(16)}`,

      request: async ({ method, params }: { method: string; params?: unknown[] }) => {
        switch (method) {
          case "eth_requestAccounts":
          case "eth_accounts":
            return [cfg.address];

          case "eth_chainId":
            return `0x${cfg.chainId.toString(16)}`;

          case "net_version":
            return cfg.chainId.toString();

          case "eth_getBalance":
            const balanceWei = BigInt(parseFloat(cfg.balance) * 1e18);
            return `0x${balanceWei.toString(16)}`;

          case "personal_sign":
          case "eth_sign":
            // Return a mock signature
            return "0x" + "ab".repeat(65);

          case "eth_signTypedData_v4":
            return "0x" + "cd".repeat(65);

          case "wallet_switchEthereumChain":
            return null;

          case "wallet_addEthereumChain":
            return null;

          default:
            console.log(`[MockWallet] Unhandled method: ${method}`, params);
            throw new Error(`Method not supported: ${method}`);
        }
      },

      on: (event: string, callback: (...args: unknown[]) => void) => {
        console.log(`[MockWallet] Event listener registered: ${event}`);
      },

      removeListener: (event: string, callback: (...args: unknown[]) => void) => {
        console.log(`[MockWallet] Event listener removed: ${event}`);
      },

      removeAllListeners: () => {},
    };

    // Inject as window.ethereum
    Object.defineProperty(window, "ethereum", {
      value: mockProvider,
      writable: false,
      configurable: false,
    });

    // Dispatch event to notify dApps
    window.dispatchEvent(new Event("ethereum#initialized"));
  }, finalConfig);
}

/**
 * Simulates a wallet connection animation for visual effect in demos.
 */
export async function simulateWalletConnection(
  page: Page,
  duration: number = 1500
): Promise<void> {
  // Add a brief delay to simulate connection process
  await page.waitForTimeout(duration);
}

/**
 * Helper to format addresses for display (0x1234...5678).
 */
export function formatAddress(address: string): string {
  return `${address.slice(0, 6)}...${address.slice(-4)}`;
}
