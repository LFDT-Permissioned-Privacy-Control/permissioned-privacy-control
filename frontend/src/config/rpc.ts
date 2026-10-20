// RPC endpoint URL shown to the user (dashboard, MetaMask add-network,
// copyable examples). Kept free of wagmi/rainbowkit imports so it stays
// cheap to unit-test.
//
// Every serving mode routes /rpc on the dashboard's own origin: the Vite dev
// server proxies it (vite.config.ts), the frontend nginx container proxies it
// (nginx.prod.conf / nginx.e2e.conf), and the backend serves it directly.
// So the displayed URL is simply the current origin — rewriting the port to
// 8080 here produced wrong, unreachable URLs on any deployed setup (RD-1198).
// VITE_BACKEND_URL stays as an explicit override for split-origin setups.
export function getRpcEndpoint(): string {
  const backendUrl = import.meta.env.VITE_BACKEND_URL;
  if (backendUrl) {
    return `${backendUrl}/rpc`;
  }
  return `${window.location.origin}/rpc`;
}

// Generate Add to MetaMask params
export function getAddNetworkParams() {
  const rpcUrl = getRpcEndpoint();

  return {
    chainId: '0x1', // Mainnet - adjust based on actual chain
    chainName: 'Open Privacy Suite (Mainnet)',
    nativeCurrency: {
      name: 'Ether',
      symbol: 'ETH',
      decimals: 18,
    },
    rpcUrls: [rpcUrl],
    blockExplorerUrls: ['https://etherscan.io'],
  };
}
