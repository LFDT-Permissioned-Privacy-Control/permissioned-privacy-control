package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/ethereum/go-ethereum/common"
)

// BroadcastFile represents the Foundry broadcast JSON format.
type BroadcastFile struct {
	Transactions []BroadcastTransaction `json:"transactions"`
	Receipts     []BroadcastReceipt     `json:"receipts"`
	Libraries    []string               `json:"libraries"`
	Pending      []any          `json:"pending"`
	Returns      map[string]any `json:"returns"`
	Timestamp    uint64                 `json:"timestamp"`
	Chain        uint64                 `json:"chain"`
	Multi        bool                   `json:"multi"`
	Commit       string                 `json:"commit"`
}

// BroadcastTransaction represents a transaction in the broadcast file.
type BroadcastTransaction struct {
	Hash             string                 `json:"hash"`
	TransactionType  string                 `json:"transactionType"`
	ContractName     string                 `json:"contractName"`
	ContractAddress  string                 `json:"contractAddress"`
	Function         string                 `json:"function"`
	Arguments        []any          `json:"arguments"`
	Transaction      TransactionData        `json:"transaction"`
	AdditionalFields map[string]any `json:"additionalContracts"`
}

// TransactionData represents the transaction details.
type TransactionData struct {
	Type     string `json:"type"`
	From     string `json:"from"`
	To       string `json:"to"`
	Gas      string `json:"gas"`
	Value    string `json:"value"`
	Data     string `json:"data"`
	Nonce    string `json:"nonce"`
	ChainID  string `json:"chainId"`
	GasPrice string `json:"gasPrice,omitempty"`
}

// BroadcastReceipt represents a transaction receipt in the broadcast file.
type BroadcastReceipt struct {
	TransactionHash   string `json:"transactionHash"`
	TransactionIndex  string `json:"transactionIndex"`
	BlockHash         string `json:"blockHash"`
	BlockNumber       string `json:"blockNumber"`
	From              string `json:"from"`
	To                string `json:"to"`
	ContractAddress   string `json:"contractAddress"`
	CumulativeGasUsed string `json:"cumulativeGasUsed"`
	GasUsed           string `json:"gasUsed"`
	Status            string `json:"status"`
}

// ContractDeployment represents a parsed contract deployment.
type ContractDeployment struct {
	Name            string   `json:"name"`
	Address         string   `json:"address"`
	Bytecode        string   `json:"bytecode"`
	BytecodeHash    string   `json:"bytecode_hash"`
	ConstructorArgs string   `json:"constructor_args"` // Hex-encoded constructor args
	Dependencies    []string `json:"dependencies"` // Addresses this contract depends on
	DeployerAddress string   `json:"deployer_address"`
}

// ParseBroadcastFile parses a Foundry broadcast JSON file.
func ParseBroadcastFile(path string) (*BroadcastFile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read broadcast file: %w", err)
	}

	var broadcast BroadcastFile
	if err := json.Unmarshal(data, &broadcast); err != nil {
		return nil, fmt.Errorf("failed to parse broadcast file: %w", err)
	}

	return &broadcast, nil
}

// ExtractDeployments extracts contract deployments from the broadcast file.
func ExtractDeployments(broadcast *BroadcastFile) ([]ContractDeployment, error) {
	var deployments []ContractDeployment
	deployedAddresses := make(map[string]string) // address -> contract name

	for _, tx := range broadcast.Transactions {
		// Check if this is a contract creation transaction
		if tx.TransactionType != "CREATE" && tx.TransactionType != "CREATE2" {
			continue
		}

		// Get the contract address from transaction or receipt
		contractAddr := tx.ContractAddress
		if contractAddr == "" {
			// Try to find it in receipts
			for _, receipt := range broadcast.Receipts {
				if receipt.TransactionHash == tx.Hash {
					contractAddr = receipt.ContractAddress
					break
				}
			}
		}

		if contractAddr == "" {
			continue
		}

		// Normalize address
		contractAddr = strings.ToLower(contractAddr)
		if !strings.HasPrefix(contractAddr, "0x") {
			contractAddr = "0x" + contractAddr
		}

		// Extract bytecode and constructor args from transaction data
		bytecode := tx.Transaction.Data
		constructorArgs := ""

		// For now, we'll use the full data as bytecode
		// In a more sophisticated implementation, we'd separate bytecode from constructor args
		// using the contract's ABI

		deployment := ContractDeployment{
			Name:            tx.ContractName,
			Address:         contractAddr,
			Bytecode:        bytecode,
			ConstructorArgs: constructorArgs,
			DeployerAddress: strings.ToLower(tx.Transaction.From),
		}

		// Calculate bytecode hash
		if bytecode != "" {
			deployment.BytecodeHash = calculateBytecodeHash(bytecode)
		}

		deployments = append(deployments, deployment)
		deployedAddresses[contractAddr] = tx.ContractName
	}

	// Now resolve dependencies - find address references in constructor args
	for i := range deployments {
		deps := findAddressDependencies(deployments[i].Bytecode, deployedAddresses)
		deployments[i].Dependencies = deps
	}

	return deployments, nil
}

// calculateBytecodeHash calculates the keccak256 hash of bytecode.
func calculateBytecodeHash(bytecode string) string {
	bytecode = strings.TrimPrefix(bytecode, "0x")
	data := common.FromHex(bytecode)
	hash := common.BytesToHash(data)
	return hash.Hex()
}

// findAddressDependencies finds address references in bytecode that match deployed contracts.
func findAddressDependencies(bytecode string, deployedAddresses map[string]string) []string {
	var deps []string
	seen := make(map[string]bool)

	bytecode = strings.ToLower(strings.TrimPrefix(bytecode, "0x"))

	for addr, name := range deployedAddresses {
		// Remove 0x prefix and convert to lowercase
		addrHex := strings.ToLower(strings.TrimPrefix(addr, "0x"))

		// Check if the address appears in the bytecode
		if strings.Contains(bytecode, addrHex) {
			if !seen[addr] {
				deps = append(deps, fmt.Sprintf("%s (%s)", name, addr))
				seen[addr] = true
			}
		}
	}

	// Sort for consistent output
	sort.Strings(deps)
	return deps
}

// FindBroadcastFile searches for a broadcast file in common locations.
func FindBroadcastFile(scriptPath string, chainID uint64) (string, error) {
	// Try common broadcast locations
	patterns := []string{
		fmt.Sprintf("broadcast/%s/%d/run-latest.json", scriptPath, chainID),
		fmt.Sprintf("broadcast/%s/%d/dry-run/run-latest.json", scriptPath, chainID),
	}

	// Also try without chain ID for local deployments
	if chainID == 0 {
		patterns = append(patterns,
			fmt.Sprintf("broadcast/%s/31337/run-latest.json", scriptPath),
			fmt.Sprintf("broadcast/%s/31337/dry-run/run-latest.json", scriptPath),
		)
	}

	for _, pattern := range patterns {
		matches, err := filepath.Glob(pattern)
		if err != nil {
			continue
		}
		if len(matches) > 0 {
			return matches[0], nil
		}
	}

	return "", fmt.Errorf("broadcast file not found for script %s", scriptPath)
}

// PrepareRequest represents the request to register a deployment with the proxy.
type PrepareRequest struct {
	Contracts []ContractPrepareInfo `json:"contracts"`
}

// ContractPrepareInfo represents a single contract in the prepare request.
type ContractPrepareInfo struct {
	Name            string `json:"name"`
	BytecodeHash    string `json:"bytecode_hash"`
	ConstructorABI  []any  `json:"constructor_abi,omitempty"`
	ConstructorArgs []any  `json:"constructor_args,omitempty"`
}

// PrepareResponse represents the response from registering a deployment.
type PrepareResponse struct {
	DeploymentID string            `json:"deployment_id"`
	Addresses    map[string]string `json:"addresses"`
	ExpiresAt    string            `json:"expires_at"`
}
