// Package nativeadmission qualifies anchored facts, then invokes the one native
// evaluator. It does not query a directory or implement a second rule matcher.
package nativeadmission

import (
	"context"
	"errors"

	"github.com/ethereum/go-ethereum/common"

	"privacy-proxy/internal/identity"
	"privacy-proxy/internal/policybundle"
	"privacy-proxy/internal/policycore"
	"privacy-proxy/internal/rpcexecution"
	"privacy-proxy/internal/runtimepolicy"
)

type Engine struct {
	metadata policybundle.BundleMetadata
	runtime  *policybundle.RuntimeCatalog
	owners   map[common.Address]string
	shared   map[common.Address]*common.Hash
	work     map[string]map[string]ruleWork
}

func New(snapshot *policybundle.CatalogSnapshot, clock identity.Clock) (*Engine, error) {
	if snapshot == nil || clock == nil {
		return nil, errors.New("invalid native admission snapshot")
	}
	metadata := snapshot.Metadata()
	runtime, ok := snapshot.Runtime()
	if !ok || metadata.Profile != policybundle.RuntimeCallProfileID || metadata.EvaluatorVersion != policybundle.NativeV2EvaluatorVersion || metadata.RuntimeCatalog == nil || metadata.RuntimeCatalog.SemanticDigest != runtime.Digest() {
		return nil, errors.New("invalid native admission snapshot")
	}
	n := &Engine{metadata: metadata, runtime: runtime, owners: map[common.Address]string{}, shared: map[common.Address]*common.Hash{}, work: map[string]map[string]ruleWork{}}
	for _, org := range snapshot.Organizations() {
		catalog, ok := snapshot.NativeCatalog(org.ID)
		if !ok {
			return nil, errors.New("invalid native admission snapshot")
		}
		for address := range catalog.Contracts {
			a := common.HexToAddress(address)
			if _, duplicate := n.owners[a]; duplicate {
				return nil, errors.New("invalid native admission snapshot")
			}
			n.owners[a] = org.ID
		}
		program, ok := snapshot.Execution(org.ID)
		if !ok {
			return nil, errors.New("invalid native admission snapshot")
		}
		n.work[org.ID] = sourceWork(program.Policy())
	}
	for _, entry := range runtime.Source().SharedInfrastructure {
		var pin *common.Hash
		if entry.CodeHash != nil {
			h := common.HexToHash(*entry.CodeHash)
			pin = &h
		}
		n.shared[common.HexToAddress(entry.Address)] = pin
	}
	return n, nil
}

func invalid() policycore.Decision { return policycore.Decision{Code: policycore.DenialInvalidFacts} }

func (n *Engine) owner(execution *rpcexecution.CallExecution, address common.Address) string {
	code, ok := execution.Code(address)
	if !ok || !code.HasCode() || code.Precompile() || code.Delegated() {
		return ""
	}
	return n.owners[address]
}

func (n *Engine) sharedCode(execution *rpcexecution.CallExecution, address common.Address) (bool, bool) {
	pin, configured := n.shared[address]
	if !configured {
		return false, true
	}
	code, ok := execution.Code(address)
	if !ok {
		return false, false
	}
	if pin != nil && *pin != code.Hash() {
		return false, false
	}
	if !code.HasCode() || code.Precompile() {
		return false, true
	}
	return true, true
}

// Check consumes only a paired opaque acquisition and the captured request
// View. Supplied-from ownership is enforced here as well as before node work.
func (n *Engine) Check(ctx context.Context, view *runtimepolicy.View, selectedOrg string, execution *rpcexecution.CallExecution, wallets WalletSnapshot) policycore.Decision {
	if ctx.Err() != nil || n == nil || view == nil || execution == nil || execution.Tree() == nil || view.RequireLive() != nil {
		return invalid()
	}
	metadata := view.Metadata()
	runtime, ok := view.Runtime()
	if !ok || metadata.ManifestDigest != n.metadata.ManifestDigest || metadata.ChainID != n.metadata.ChainID || runtime.Digest() != n.runtime.Digest() {
		return invalid()
	}
	anchor := execution.Anchor()
	if anchor.ChainID != metadata.ChainID || anchor.OrganizationID != selectedOrg || anchor.Profile != runtime.NodeEvidenceProfile() {
		return invalid()
	}
	org, ok := view.Org(selectedOrg)
	if !ok {
		return invalid()
	}
	groups := org.Groups()
	if len(groups) > 4096 || len(wallets.addresses) > MaxWalletAddresses || len(wallets.addresses) > MaxWalletBytes/common.AddressLength {
		return invalid()
	}
	var weight ruleWork
	for _, group := range groups {
		w := n.work[selectedOrg][group]
		var valid bool
		weight.rules, valid = add(weight.rules, w.rules)
		if !valid {
			return invalid()
		}
		weight.items, valid = add(weight.items, w.items)
		if !valid {
			return invalid()
		}
		weight.linked, valid = add(weight.linked, w.linked)
		if !valid {
			return invalid()
		}
	}
	if (execution.Call().FromSupplied() || weight.linked > 0) && (!wallets.valid || wallets.actorID != view.ActorID()) {
		return invalid()
	}
	if wallets.valid && wallets.actorID != view.ActorID() {
		return invalid()
	}
	if execution.Call().FromSupplied() && !wallets.Contains(execution.Call().From()) {
		return invalid()
	}
	if _, ok := admissionWork(uint64(execution.RecordCount()), uint64(len(groups)), weight, uint64(len(wallets.addresses))); !ok {
		return invalid()
	}
	if ctx.Err() != nil {
		return invalid()
	}
	frames, ok := n.materialize(org, execution)
	if !ok {
		return invalid()
	}
	if ctx.Err() != nil || view.RequireLive() != nil {
		return invalid()
	}
	decision := org.NativeProgram().Evaluate(policycore.Context{Org: selectedOrg, Groups: groups, LinkedAddresses: wallets.addresses}, frames)
	if ctx.Err() != nil || view.RequireLive() != nil {
		return invalid()
	}
	return decision
}
