import { connectorsForWallets, WalletList } from '@rainbow-me/rainbowkit';
import {
  metaMaskWallet,
  walletConnectWallet,
  rainbowWallet,
  injectedWallet,
} from '@rainbow-me/rainbowkit/wallets';
import { createConfig, http } from 'wagmi';
import { mainnet, polygon, arbitrum, optimism, base } from 'wagmi/chains';

// WalletConnect project ID - get one at https://cloud.walletconnect.com/
// Only include WalletConnect wallet when a valid project ID is configured
const projectId = import.meta.env.VITE_WALLETCONNECT_PROJECT_ID || '';
const hasWalletConnect = projectId.length > 0;

// Build wallet list based on available configuration
const wallets: WalletList = [
  {
    groupName: 'Popular',
    wallets: [
      metaMaskWallet,
      injectedWallet,
      // Only include WalletConnect-dependent wallets when projectId is available
      ...(hasWalletConnect ? [rainbowWallet, walletConnectWallet] : []),
    ],
  },
];

// Explicitly define wallets to exclude Coinbase (which pulls in LGPL dependencies)
const connectors = connectorsForWallets(wallets, {
  appName: 'Open Privacy Suite',
  projectId: projectId || 'placeholder', // RainbowKit requires a non-empty string
});

// RainbowKit configuration
export const wagmiConfig = createConfig({
  connectors,
  chains: [mainnet, polygon, arbitrum, optimism, base],
  transports: {
    [mainnet.id]: http(),
    [polygon.id]: http(),
    [arbitrum.id]: http(),
    [optimism.id]: http(),
    [base.id]: http(),
  },
  ssr: false,
});

// The user-facing RPC endpoint helpers (getRpcEndpoint, getAddNetworkParams)
// live in ./rpc — kept out of this module so they can be unit-tested without
// importing the wagmi/rainbowkit configuration (RD-1198).
