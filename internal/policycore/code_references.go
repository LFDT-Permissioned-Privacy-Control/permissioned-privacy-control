package policycore

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/ethereum/go-ethereum/common"
)

type codeReferences struct {
	catalog   CodeReferenceCatalog
	canonical map[string]bool
	version   string
}

func validateCodeReferences(owned Catalog, refs CodeReferenceCatalog) error {
	for address, ref := range refs {
		if len(address) != 42 || !strings.HasPrefix(address, "0x") || address != strings.ToLower(address) || !common.IsHexAddress(address) || common.HexToAddress(address) == (common.Address{}) || ref.OwnerOrg == "" {
			return fmt.Errorf("policy: invalid code reference identity")
		}
		if own, ok := owned.Contracts[address]; ok && (ref.OwnerOrg != owned.Org || ref.ABI != own.ABI) {
			return fmt.Errorf("policy: code reference conflicts with owned contract")
		}
		if ref.OwnerOrg == owned.Org {
			if _, ok := owned.Contracts[address]; !ok {
				return fmt.Errorf("policy: code reference cannot manufacture owned registration")
			}
		}
	}
	return nil
}

func resolveCodeReference(storage, code string, owned Catalog, refs *codeReferences) (ContractInfo, string, error) {
	if own, ok := owned.Contracts[code]; ok {
		return own, "", nil
	}
	if refs == nil {
		return ContractInfo{}, "", fmt.Errorf("codeAddress is not registered to this organisation")
	}
	ref, ok := refs.catalog[code]
	if !ok || storage == code || ref.OwnerOrg == "" || ref.OwnerOrg == owned.Org {
		return ContractInfo{}, "", fmt.Errorf("codeAddress is not registered to this organisation or an explicit foreign code reference")
	}
	if refs.canonical[code] {
		return ContractInfo{ABI: ref.ABI}, ref.OwnerOrg, nil
	}
	// The bounded bundle ABI parser is the production validation boundary. Here
	// also refuse noncanonical compile input; never retain the caller's map.
	decoder := json.NewDecoder(strings.NewReader(ref.ABI))
	decoder.UseNumber()
	var entries []any
	if err := decoder.Decode(&entries); err != nil || entries == nil {
		return ContractInfo{}, "", fmt.Errorf("code reference ABI must be a canonical JSON array")
	}
	canonical, err := json.Marshal(entries)
	if err != nil || !bytes.Equal(canonical, []byte(ref.ABI)) {
		return ContractInfo{}, "", fmt.Errorf("code reference ABI must be a canonical JSON array")
	}
	refs.canonical[code] = true
	return ContractInfo{ABI: ref.ABI}, ref.OwnerOrg, nil
}
