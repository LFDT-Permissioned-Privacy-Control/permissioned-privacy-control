package ens

import (
	"strings"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
)

// Minimal ENS Registry ABI - only the resolver() function we need
const ensRegistryABI = `[{"inputs":[{"internalType":"bytes32","name":"node","type":"bytes32"}],"name":"resolver","outputs":[{"internalType":"address","name":"","type":"address"}],"stateMutability":"view","type":"function"}]`

// Minimal Public Resolver ABI - only name() and addr() functions we need
const publicResolverABI = `[{"inputs":[{"internalType":"bytes32","name":"node","type":"bytes32"}],"name":"name","outputs":[{"internalType":"string","name":"","type":"string"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"bytes32","name":"node","type":"bytes32"}],"name":"addr","outputs":[{"internalType":"address payable","name":"","type":"address"}],"stateMutability":"view","type":"function"}]`

// ENSRegistry wraps the ENS registry contract
type ENSRegistry struct {
	contract *bind.BoundContract
}

// NewENSRegistry creates a new ENS registry instance
func NewENSRegistry(address common.Address, backend bind.ContractBackend) (*ENSRegistry, error) {
	parsed, err := abi.JSON(strings.NewReader(ensRegistryABI))
	if err != nil {
		return nil, err
	}
	contract := bind.NewBoundContract(address, parsed, backend, backend, backend)
	return &ENSRegistry{contract: contract}, nil
}

// Resolver returns the resolver address for a node
func (r *ENSRegistry) Resolver(opts *bind.CallOpts, node [32]byte) (common.Address, error) {
	var result []interface{}
	err := r.contract.Call(opts, &result, "resolver", node)
	if err != nil {
		return common.Address{}, err
	}
	return result[0].(common.Address), nil
}

// PublicResolver wraps an ENS resolver contract
type PublicResolver struct {
	contract *bind.BoundContract
}

// NewPublicResolver creates a new public resolver instance
func NewPublicResolver(address common.Address, backend bind.ContractBackend) (*PublicResolver, error) {
	parsed, err := abi.JSON(strings.NewReader(publicResolverABI))
	if err != nil {
		return nil, err
	}
	contract := bind.NewBoundContract(address, parsed, backend, backend, backend)
	return &PublicResolver{contract: contract}, nil
}

// Name returns the ENS name for a node (reverse resolution)
func (r *PublicResolver) Name(opts *bind.CallOpts, node [32]byte) (string, error) {
	var result []interface{}
	err := r.contract.Call(opts, &result, "name", node)
	if err != nil {
		return "", err
	}
	return result[0].(string), nil
}

// Addr returns the address for a node (forward resolution)
func (r *PublicResolver) Addr(opts *bind.CallOpts, node [32]byte) (common.Address, error) {
	var result []interface{}
	err := r.contract.Call(opts, &result, "addr", node)
	if err != nil {
		return common.Address{}, err
	}
	return result[0].(common.Address), nil
}
