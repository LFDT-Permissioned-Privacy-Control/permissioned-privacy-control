package ens

import (
	"context"
	"fmt"
	"strings"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
)

// ENS contract addresses on mainnet
var (
	// ENS Registry address on mainnet
	ensRegistryAddress = common.HexToAddress("0x00000000000C2E074eC69A0dFb2997BA6C7d2e1e")
	// addr.reverse suffix for reverse resolution
	reverseRegistrarSuffix = ".addr.reverse"
)

// Resolver handles ENS name resolution
type Resolver struct {
	client *ethclient.Client
}

// NewResolver creates a new ENS resolver with the given RPC URL
func NewResolver(rpcURL string) (*Resolver, error) {
	client, err := ethclient.Dial(rpcURL)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to ethereum node: %w", err)
	}

	return &Resolver{client: client}, nil
}

// ResolveAddress performs reverse resolution to get the ENS name for an address.
// Returns empty string if no ENS name is set or if resolution fails.
func (r *Resolver) ResolveAddress(ctx context.Context, address string) (string, error) {
	// Normalize address
	addr := common.HexToAddress(address)

	// Build the reverse node name: <address>.addr.reverse
	// The address should be lowercase without 0x prefix
	reverseName := strings.ToLower(addr.Hex()[2:]) + reverseRegistrarSuffix

	// Get the namehash of the reverse name
	node := namehash(reverseName)

	// Get the resolver for this node from the ENS registry
	registry, err := NewENSRegistry(ensRegistryAddress, r.client)
	if err != nil {
		return "", fmt.Errorf("failed to create registry contract: %w", err)
	}

	resolverAddr, err := registry.Resolver(&bind.CallOpts{Context: ctx}, node)
	if err != nil {
		return "", fmt.Errorf("failed to get resolver: %w", err)
	}

	// Check if resolver is set (not zero address)
	if resolverAddr == (common.Address{}) {
		return "", nil // No resolver set, no ENS name
	}

	// Call the resolver's name() function to get the ENS name
	resolver, err := NewPublicResolver(resolverAddr, r.client)
	if err != nil {
		return "", fmt.Errorf("failed to create resolver contract: %w", err)
	}

	name, err := resolver.Name(&bind.CallOpts{Context: ctx}, node)
	if err != nil {
		return "", fmt.Errorf("failed to resolve name: %w", err)
	}

	// Verify forward resolution matches (to prevent spoofing)
	if name != "" {
		forwardAddr, err := r.forwardResolve(ctx, name)
		if err != nil || !strings.EqualFold(forwardAddr.Hex(), addr.Hex()) {
			// Forward resolution doesn't match, return empty
			return "", nil
		}
	}

	return name, nil
}

// forwardResolve resolves an ENS name to an address
func (r *Resolver) forwardResolve(ctx context.Context, name string) (common.Address, error) {
	node := namehash(name)

	registry, err := NewENSRegistry(ensRegistryAddress, r.client)
	if err != nil {
		return common.Address{}, err
	}

	resolverAddr, err := registry.Resolver(&bind.CallOpts{Context: ctx}, node)
	if err != nil {
		return common.Address{}, err
	}

	if resolverAddr == (common.Address{}) {
		return common.Address{}, fmt.Errorf("no resolver set")
	}

	resolver, err := NewPublicResolver(resolverAddr, r.client)
	if err != nil {
		return common.Address{}, err
	}

	return resolver.Addr(&bind.CallOpts{Context: ctx}, node)
}

// Close closes the underlying ethclient connection
func (r *Resolver) Close() {
	if r.client != nil {
		r.client.Close()
	}
}

// namehash implements the ENS namehash algorithm
// See: https://docs.ens.domains/resolution/names#namehash
func namehash(name string) [32]byte {
	var node [32]byte // Start with 0x0

	if name == "" {
		return node
	}

	// Split by dots and process from right to left
	labels := strings.Split(name, ".")
	for i := len(labels) - 1; i >= 0; i-- {
		labelHash := keccak256([]byte(labels[i]))
		node = keccak256(append(node[:], labelHash[:]...))
	}

	return node
}

// keccak256 computes the Keccak-256 hash
func keccak256(data []byte) [32]byte {
	var result [32]byte
	copy(result[:], crypto.Keccak256(data))
	return result
}
