package nativeadmission

import (
	"errors"
	"fmt"

	"github.com/ethereum/go-ethereum/common"
	"privacy-proxy/internal/creationfacts"
	"privacy-proxy/internal/rpcexecution"
	"privacy-proxy/internal/runtimepolicy"
)

// WithCurrentAddressFacts adds no executable rule or group. Only the original
// CreationObserved engine can compile this same-View operation-owned overlay.
// The adapter and independently selected binding remain trusted startup code.
func (n *Engine) WithCurrentAddressFacts(view *runtimepolicy.View, metadata creationfacts.AddressReaderMetadata, expected creationfacts.AddressReadBinding, passes []*creationfacts.AddressAssociations) (*Engine, error) {
	bad := func() (*Engine, error) { return nil, errors.New("invalid current native facts") }
	if n == nil || !n.creationObserved || n.currentView != nil || view == nil || view.RequireLive() != nil || view.Metadata().ManifestDigest != n.metadata.ManifestDigest || !expected.Valid() || expected.Network.Environment != n.metadata.Environment || expected.Network.ChainID != n.metadata.ChainID || metadata.Binding != expected || !metadata.Identity.Valid() || len(passes) > 64 {
		return bad()
	}
	runtime, ok := view.Runtime()
	if !ok || runtime.Digest() != n.runtime.Digest() {
		return bad()
	}
	owned := *n
	owned.currentView = view
	// Global registry/program/source maps remain immutable and shared. Only
	// operation additions are allocated, bounded by the actual <=64 passes.
	owned.currentOwners, owned.qualifiedOwners = map[common.Address]string{}, map[common.Address]string{}
	owned.currentAssociated, owned.currentObserved = map[common.Address]bool{}, map[common.Address]bool{}
	owned.currentWork = map[common.Address]uint64{}
	owned.currentBasis = map[common.Address]runtimeBasis{}
	seen := map[common.Address]bool{}
	var stamp creationfacts.AddressReadStamp
	bytes := 0
	for i, pass := range passes {
		if pass == nil {
			return bad()
		}
		target := pass.Target()
		if seen[target] || pass.ValidateFor(metadata.Identity, expected, target) != nil || pass.CandidateBytes() > (256<<10)-bytes {
			return bad()
		}
		seen[target], bytes = true, bytes+pass.CandidateBytes()
		if i == 0 {
			stamp = pass.ObservationStamp()
		} else if stamp != pass.ObservationStamp() {
			return bad()
		}
		rows := pass.Candidates()
		namespaces, actors, births := map[string]bool{}, map[string]bool{}, map[string]bool{}
		for _, row := range rows {
			namespaces[row.Namespace] = true
			births[fmt.Sprintf("%s:%s:%d", row.Inclusion.Hash, row.TransactionHash, row.Record)] = true
			if row.Kind == "WALLET" {
				actors[row.WalletActor] = true
			}
		}
		// Current positive Git authority is selected without a read by the
		// facade; an unnecessary old pass cannot veto that current permission.
		_, member, associated, registered := view.ContractAssociation(target)
		if registered && member && associated {
			continue
		}
		if len(births) > 1 || len(actors) > 1 || len(namespaces) > 1 && !registered {
			return bad()
		}
		owner := owned.registeredOwner(target)
		if owner == "" {
			if len(namespaces) > 1 {
				return bad()
			}
			for namespace := range namespaces {
				owner = namespace
			}
			owned.currentOwners[target] = owner
		}
		if len(rows) == 0 {
			continue
		}
		basis := basisFor(rows[0])
		for _, row := range rows[1:] {
			if basisFor(row) != basis {
				return bad()
			}
		}
		owned.currentBasis[target] = basis
		owned.currentObserved[target] = true
		if len(namespaces) == 1 && namespaces[owner] {
			owned.qualifiedOwners[target] = owner
		}
		if org, mapped := view.Org(owner); mapped {
			owned.currentAssociated[target] = actors[view.ActorID()] || owned.qualifiedOwners[target] == owner && org.IsOrgAdmin()
		}
		owned.currentWork[target] = 1 + uint64(len(rows))
	}
	return &owned, nil
}

type runtimeBasis struct {
	Hash          common.Hash
	Length        int
	Number        uint64
	InclusionHash common.Hash
	Index         uint32
}

func basisFor(row creationfacts.AddressAssociation) runtimeBasis {
	return runtimeBasis{row.OutputHash, row.OutputLength, row.Inclusion.Number, row.Inclusion.Hash, row.Index}
}

// ValidateCurrentRuntime returns a requirement to bind the execution anchor,
// never a policy verdict. Actual code is opaque acquisition output. A current
// birth is not a proof of arbitrary old runtime or a fresh execution epoch.
func (n *Engine) ValidateCurrentRuntime(view *runtimepolicy.View, address common.Address, code rpcexecution.CodeInfo, anchor rpcexecution.Anchor) (bool, error) {
	if n == nil || n.currentView == nil || n.currentView != view || view.RequireLive() != nil {
		return false, errors.New("invalid current native view")
	}
	return n.validateRuntimeBasis(address, code, anchor)
}
func (n *Engine) validateRuntimeBasis(address common.Address, code rpcexecution.CodeInfo, anchor rpcexecution.Anchor) (bool, error) {
	if n.currentView == nil || n.owners[address] != "" || n.qualifiedOwners[address] == "" || !code.HasCode() || code.Precompile() {
		return false, nil
	}
	if _, fresh := code.CreationRecordIndex(); fresh {
		return false, nil
	}
	basis, ok := n.currentBasis[address]
	if !ok || code.Delegated() || anchor.ChainID != n.metadata.ChainID || anchor.Hash == (common.Hash{}) || anchor.Number < basis.Number || anchor.Number == basis.Number && anchor.Hash != basis.InclusionHash || code.Hash() != basis.Hash || code.Length() != basis.Length {
		return false, errors.New("invalid current runtime basis")
	}
	if n.minedPoint != nil && (n.minedPoint.number != anchor.Number || n.minedPoint.hash != anchor.Hash || basis.Number == anchor.Number && basis.Index >= n.minedPoint.index) {
		return false, errors.New("invalid mined runtime birth ordinal")
	}
	return true, nil
}
func (n *Engine) runtimeOwnerFor(address common.Address, code rpcexecution.CodeInfo, anchor rpcexecution.Anchor) string {
	if !code.HasCode() || code.Precompile() {
		return ""
	}
	if owner := n.owners[address]; owner != "" {
		return owner
	}
	used, err := n.validateRuntimeBasis(address, code, anchor)
	if err != nil || !used {
		return ""
	}
	return n.qualifiedOwners[address]
}

// CurrentOwner is only an isolation label, never a permission verdict. The
// facade uses the same compiled overlay to select its existing org credential.
func (n *Engine) CurrentOwner(view *runtimepolicy.View, address common.Address) (string, error) {
	if n == nil || n.currentView == nil || n.currentView != view || view.RequireLive() != nil {
		return "", errors.New("invalid current native view")
	}
	return n.registeredOwner(address), nil
}

func (n *Engine) runtimeOwner(address common.Address) string {
	if owner := n.owners[address]; owner != "" {
		return owner
	}
	return n.qualifiedOwners[address]
}

func (n *Engine) associationCost(address common.Address) (uint64, bool) {
	base, known := n.associationWork[address]
	extra, added := n.currentWork[address]
	return base + extra, known || added
}

func (n *Engine) contractAssociation(view *runtimepolicy.View, address common.Address) (string, bool, bool, bool) {
	owner, member, associated, registered := view.ContractAssociation(address)
	if n.currentView == nil || associated {
		return owner, member, associated, registered
	}
	owner = n.registeredOwner(address)
	_, member = view.Org(owner)
	return owner, member, member && n.currentAssociated[address], registered || n.currentObserved[address]
}
