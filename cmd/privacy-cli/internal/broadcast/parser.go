// Package broadcast provides types and parsing for Foundry broadcast files.
package broadcast

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// ParseFile parses a Foundry broadcast JSON file and returns the broadcast data.
func ParseFile(path string) (*BroadcastFile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read broadcast file: %w", err)
	}

	return Parse(data)
}

// Parse parses broadcast JSON data and returns the broadcast data.
func Parse(data []byte) (*BroadcastFile, error) {
	var broadcast BroadcastFile
	if err := json.Unmarshal(data, &broadcast); err != nil {
		return nil, fmt.Errorf("failed to parse broadcast JSON: %w", err)
	}

	return &broadcast, nil
}

// ExtractDeploymentAddresses extracts all contract addresses that will be deployed
// from a broadcast file. It supports CREATE and CREATE2 deployments, as well as
// contracts deployed as side effects of CALL transactions.
func ExtractDeploymentAddresses(broadcast *BroadcastFile) []DeploymentAddress {
	var addresses []DeploymentAddress

	for _, tx := range broadcast.Transactions {
		txType := strings.ToUpper(tx.Type)

		switch txType {
		case "CREATE":
			// Direct CREATE deployment
			if tx.ContractAddress != "" {
				addresses = append(addresses, DeploymentAddress{
					Address:        strings.ToLower(tx.ContractAddress),
					ContractName:   tx.ContractName,
					DeploymentType: DeploymentCREATE,
				})
			}

		case "CREATE2":
			// Direct CREATE2 deployment
			if tx.ContractAddress != "" {
				addresses = append(addresses, DeploymentAddress{
					Address:        strings.ToLower(tx.ContractAddress),
					ContractName:   tx.ContractName,
					DeploymentType: DeploymentCREATE2,
				})
			}

		case "CALL":
			// Extract additional contracts deployed by this call
			for _, additional := range tx.AdditionalContracts {
				addr := DeploymentAddress{
					Address:      strings.ToLower(additional.Address),
					ContractName: tx.ContractName, // Use parent tx contract name
				}

				additionalType := strings.ToUpper(additional.TransactionType)
				switch additionalType {
				case "CREATE2":
					addr.DeploymentType = DeploymentCREATE2
				default:
					addr.DeploymentType = DeploymentCREATE
				}

				addresses = append(addresses, addr)
			}
		}
	}

	return addresses
}

// ExtractAddresses is a convenience function that returns just the addresses as strings.
func ExtractAddresses(broadcast *BroadcastFile) []string {
	deployments := ExtractDeploymentAddresses(broadcast)
	addresses := make([]string, len(deployments))
	for i, d := range deployments {
		addresses[i] = d.Address
	}
	return addresses
}

// FilterByType filters deployment addresses by deployment type.
func FilterByType(addresses []DeploymentAddress, deploymentType DeploymentType) []DeploymentAddress {
	var filtered []DeploymentAddress
	for _, addr := range addresses {
		if addr.DeploymentType == deploymentType {
			filtered = append(filtered, addr)
		}
	}
	return filtered
}
