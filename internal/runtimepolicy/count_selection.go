package runtimepolicy

import (
	"bytes"
	"sort"

	"github.com/ethereum/go-ethereum/common"
)

// AssociatedContractAddresses enumerates the complete ordinary address
// association, without copying ABI payloads or deriving event authority.
// Incomplete enumeration never returns a truncated authorization filter.
func (v *View) AssociatedContractAddresses(org string, max int) ([]common.Address, bool) {
	if v == nil || v.factory == nil || max < 1 || v.RequireLive() != nil || len(v.factory.contracts) > 20000 {
		return nil, false
	}
	out := []common.Address{}
	for address, contract := range v.factory.contracts {
		if contract.owner != org {
			continue
		}
		_, associated, _, _ := v.contractAssociation(contract, false)
		if !associated {
			continue
		}
		if len(out) == max {
			return nil, false
		}
		out = append(out, address)
	}
	sort.Slice(out, func(i, j int) bool { return bytes.Compare(out[i][:], out[j][:]) < 0 })
	return out, true
}
