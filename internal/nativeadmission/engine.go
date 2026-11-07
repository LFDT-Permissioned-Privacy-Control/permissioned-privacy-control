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
	raw             bool
	multiOrg        bool
	lifecycle       bool
	creationIntents bool
	factories       map[common.Address]policybundle.FactoryAttribution
	metadata        policybundle.BundleMetadata
	runtime         *policybundle.RuntimeCatalog
	owners          map[common.Address]string
	shared          map[common.Address]*common.Hash
	work            map[string]map[string]ruleWork
	associationWork map[common.Address]uint64
}

func New(snapshot *policybundle.CatalogSnapshot, clock identity.Clock) (*Engine, error) {
	return newEngine(snapshot, clock, policybundle.RuntimeCallProfileID)
}

// NewRaw composes signed CALL authorization and unchanged simulation checks.
func NewRaw(snapshot *policybundle.CatalogSnapshot, clock identity.Clock) (*Engine, error) {
	return newEngine(snapshot, clock, policybundle.RuntimeRawSendProfileID)
}

func NewMultiOrg(snapshot *policybundle.CatalogSnapshot, clock identity.Clock) (*Engine, error) {
	return newEngine(snapshot, clock, policybundle.RuntimeMultiOrgProfileID)
}

func NewLifecycle(snapshot *policybundle.CatalogSnapshot, clock identity.Clock) (*Engine, error) {
	return newEngine(snapshot, clock, policybundle.RuntimeLifecycleProfileID)
}

func NewSimulation(snapshot *policybundle.CatalogSnapshot, clock identity.Clock) (*Engine, error) {
	return newEngine(snapshot, clock, policybundle.RuntimeSimulationProfileID)
}

func NewCreationIntents(snapshot *policybundle.CatalogSnapshot, clock identity.Clock) (*Engine, error) {
	return newEngine(snapshot, clock, policybundle.RuntimeCreationIntentProfileID)
}

func newEngine(snapshot *policybundle.CatalogSnapshot, clock identity.Clock, expectedProfile string) (*Engine, error) {
	if snapshot == nil || clock == nil {
		return nil, errors.New("invalid native admission snapshot")
	}
	metadata := snapshot.Metadata()
	runtime, ok := snapshot.Runtime()
	expectedEvaluator := policybundle.NativeV2EvaluatorVersion
	lifecycle := expectedProfile == policybundle.RuntimeLifecycleProfileID || expectedProfile == policybundle.RuntimeSimulationProfileID || expectedProfile == policybundle.RuntimeCreationIntentProfileID
	if expectedProfile == policybundle.RuntimeMultiOrgProfileID {
		expectedEvaluator = policybundle.NativeV3EvaluatorVersion
	}
	if lifecycle {
		expectedEvaluator = policybundle.NativeV4EvaluatorVersion
	}
	if !ok || metadata.Profile != expectedProfile || metadata.EvaluatorVersion != expectedEvaluator || metadata.RuntimeCatalog == nil || metadata.RuntimeCatalog.SemanticDigest != runtime.Digest() {
		return nil, errors.New("invalid native admission snapshot")
	}
	n := &Engine{raw: expectedProfile != policybundle.RuntimeCallProfileID, multiOrg: expectedProfile == policybundle.RuntimeMultiOrgProfileID || lifecycle, lifecycle: lifecycle, metadata: metadata, runtime: runtime, owners: map[common.Address]string{}, shared: map[common.Address]*common.Hash{}, work: map[string]map[string]ruleWork{}, associationWork: map[common.Address]uint64{}}
	n.creationIntents = expectedProfile == policybundle.RuntimeCreationIntentProfileID
	if n.creationIntents {
		source, found := runtime.CreationIntentSource()
		if !found {
			return nil, errors.New("invalid creation intent snapshot")
		}
		n.factories = map[common.Address]policybundle.FactoryAttribution{}
		for _, f := range source.CreationAttribution.Factories {
			n.factories[common.HexToAddress(f.Address)] = f
		}
	}
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
			if n.multiOrg {
				contract, found := snapshot.Contract(org.ID, a)
				if !found {
					return nil, errors.New("invalid native admission snapshot")
				}
				n.associationWork[a] = 1 + uint64(len(contract.ReadGrants))
			}
		}
		program, ok := snapshot.Execution(org.ID)
		if !ok {
			return nil, errors.New("invalid native admission snapshot")
		}
		n.work[org.ID] = sourceWork(program.Policy())
	}
	for _, entry := range runtime.SharedInfrastructure() {
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

// registeredOwner is an isolation label even when an account currently has no
// code. It is separate from evidence capable of supplying operational claims.
func (n *Engine) registeredOwner(address common.Address) string { return n.owners[address] }

func (n *Engine) qualifiedRuntimeOwner(execution *rpcexecution.CallExecution, address common.Address) string {
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
	return n.check(ctx, view, selectedOrg, execution, wallets, false, nil)
}

// CheckSigned accepts only opaque signed acquisition on the explicitly selected
// raw profile. Its signer never supplies an ActorID-to-wallet association.
func (n *Engine) CheckSigned(ctx context.Context, view *runtimepolicy.View, selectedOrg string, execution *rpcexecution.CallExecution, wallets WalletSnapshot) policycore.Decision {
	if n == nil || !n.raw {
		return invalid()
	}
	return n.check(ctx, view, selectedOrg, execution, wallets, true, nil)
}

func (n *Engine) check(ctx context.Context, view *runtimepolicy.View, selectedOrg string, execution *rpcexecution.CallExecution, wallets WalletSnapshot, signed bool, capture *creationCapture) policycore.Decision {
	if ctx.Err() != nil || n == nil || view == nil || execution == nil || execution.Signed() != signed || execution.Tree() == nil || view.RequireLive() != nil {
		return invalid()
	}
	metadata := view.Metadata()
	runtime, ok := view.Runtime()
	if !ok || metadata.ManifestDigest != n.metadata.ManifestDigest || metadata.ChainID != n.metadata.ChainID || runtime.Digest() != n.runtime.Digest() {
		return invalid()
	}
	anchor := execution.Anchor()
	expectedEvidence := runtime.NodeEvidenceProfile()
	var signer common.Address
	if signed {
		var known bool
		signer, known = execution.VerifiedSigner()
		hash, hashKnown := execution.TransactionHash()
		if !known || !hashKnown || hash == (common.Hash{}) || execution.Call().From() != signer {
			return invalid()
		}
		switch runtime.RawSubmissionMode() {
		case policybundle.RawSubmissionGuardV1:
			expectedEvidence = rpcexecution.GuardRetainedProfileID
			if n.lifecycle {
				expectedEvidence = rpcexecution.LifecycleGuardProfileID
			}
		case policybundle.RawSubmissionOPSPreflight:
			expectedEvidence = rpcexecution.SignedCallProfileID
			if n.lifecycle {
				expectedEvidence = rpcexecution.LifecycleSignedProfileID
			}
		default:
			return invalid()
		}
	}
	if anchor.ChainID != metadata.ChainID || anchor.OrganizationID != selectedOrg || anchor.Profile != expectedEvidence {
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
	orgIDs := []string{selectedOrg}
	if n.multiOrg {
		orgIDs = view.OrgIDs()
	}
	var totalGroups uint64
	for _, orgID := range orgIDs {
		current, known := view.Org(orgID)
		if !known {
			return invalid()
		}
		currentGroups := current.Groups()
		if len(currentGroups) > 4096 {
			return invalid()
		}
		var valid bool
		totalGroups, valid = add(totalGroups, uint64(len(currentGroups)))
		if !valid {
			return invalid()
		}
		for _, group := range currentGroups {
			w := n.work[orgID][group]
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
	}
	needsFromProof := !signed && execution.Call().FromSupplied()
	if (needsFromProof || weight.linked > 0) && (!wallets.valid || wallets.actorID != view.ActorID()) {
		return invalid()
	}
	if wallets.valid && wallets.actorID != view.ActorID() {
		return invalid()
	}
	if needsFromProof && !wallets.Contains(execution.Call().From()) {
		return invalid()
	}
	work, valid := admissionWork(uint64(execution.RecordCount()), totalGroups, weight, uint64(len(wallets.addresses)))
	if !valid {
		return invalid()
	}
	if n.lifecycle {
		qualification := execution.QualificationWork()
		if qualification == 0 {
			return invalid()
		}
		work, valid = add(work, qualification)
		if !valid || work > MaxAdmissionWork {
			return invalid()
		}
	}
	if ctx.Err() != nil {
		return invalid()
	}
	if n.lifecycle {
		return n.checkLifecycle(ctx, view, selectedOrg, execution, wallets, signer, work, capture)
	}
	if n.multiOrg {
		return n.checkMultiOrg(ctx, view, selectedOrg, execution, wallets, signer, work)
	}
	frames, ok := n.materialize(org, execution)
	if !ok {
		return invalid()
	}
	if ctx.Err() != nil || view.RequireLive() != nil {
		return invalid()
	}
	decision := org.NativeProgram().Evaluate(policycore.Context{Org: selectedOrg, Groups: groups, LinkedAddresses: wallets.addresses, Signer: signer}, frames)
	if ctx.Err() != nil || view.RequireLive() != nil {
		return invalid()
	}
	return decision
}
