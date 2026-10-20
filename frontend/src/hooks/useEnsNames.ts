import { useQuery } from '@tanstack/react-query';
import { createPublicClient, http } from 'viem';
import { mainnet } from 'viem/chains';

const mainnetClient = createPublicClient({
  chain: mainnet,
  transport: http(),
});

interface UseEnsNamesOptions {
  /** Pre-cached ENS names from server (address -> name) */
  cachedNames?: Record<string, string | null>;
}

export function useEnsNames(addresses: string[], options?: UseEnsNamesOptions) {
  const { cachedNames = {} } = options || {};

  // Filter out addresses that already have cached names
  const uncachedAddresses = addresses.filter(
    (addr) => !(addr.toLowerCase() in cachedNames)
  );

  const query = useQuery({
    queryKey: ['ensNames', uncachedAddresses.sort().join(',')],
    queryFn: async () => {
      const results: Record<string, string | null> = {};
      await Promise.all(
        uncachedAddresses.map(async (addr) => {
          try {
            const ensName = await mainnetClient.getEnsName({
              address: addr as `0x${string}`,
            });
            results[addr.toLowerCase()] = ensName;
          } catch {
            results[addr.toLowerCase()] = null;
          }
        })
      );
      return results;
    },
    enabled: uncachedAddresses.length > 0,
    staleTime: 1000 * 60 * 60, // Cache 1 hour
  });

  // Merge cached names with queried names
  const mergedData: Record<string, string | null> = { ...cachedNames };
  if (query.data) {
    Object.assign(mergedData, query.data);
  }

  return {
    ...query,
    data: mergedData,
    // Only loading if we actually have addresses to query
    isLoading: uncachedAddresses.length > 0 && query.isLoading,
  };
}
