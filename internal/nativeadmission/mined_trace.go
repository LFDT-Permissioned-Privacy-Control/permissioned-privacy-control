package nativeadmission

import (
	"context"
	"errors"

	"github.com/ethereum/go-ethereum/common"
	"privacy-proxy/internal/executionfacts"
	"privacy-proxy/internal/policycore"
	"privacy-proxy/internal/rpcexecution"
	"privacy-proxy/internal/runtimepolicy"
)

// Only concrete CallExecution/MinedExecution public entrypoints reach these
// shared helpers. This interface is private, not a caller-supplied authority.
type executionEvidence interface {
	Anchor() rpcexecution.Anchor
	Tree() *executionfacts.Tree
	Code(common.Address) (rpcexecution.CodeInfo, bool)
	RecordCount() int
	QualificationWork() uint64
	FrameCode(int) (rpcexecution.CodeInfo, bool)
	RuntimeCodeAt(int, common.Address) (rpcexecution.CodeInfo, bool)
	CreationContext(int) (rpcexecution.CreationContext, bool)
}
type minedRuntimePoint struct {
	number uint64
	hash   common.Hash
	index  uint32
}

func (n *Engine) withMinedPoint(view *runtimepolicy.View, org string, e *rpcexecution.MinedExecution) (*Engine, error) {
	if n == nil || !n.creationObserved || view == nil || n.currentView != view || view.RequireLive() != nil || e == nil || e.Purpose() != rpcexecution.MinedClientTraceProfileID || e.Tree() == nil || e.TransactionHash() == (common.Hash{}) {
		return nil, errors.New("invalid mined trace authority")
	}
	a := e.Anchor()
	runtime, ok := view.Runtime()
	if !ok || runtime.Digest() != n.runtime.Digest() || view.Metadata().ManifestDigest != n.metadata.ManifestDigest || a.ChainID != n.metadata.ChainID || a.Profile != rpcexecution.MinedClientTraceProfileID || a.OrganizationID != org {
		return nil, errors.New("invalid mined trace binding")
	}
	if _, ok := view.Org(org); !ok {
		return nil, errors.New("invalid mined trace org")
	}
	owned := *n
	owned.minedPoint = &minedRuntimePoint{a.Number, a.Hash, e.InclusionIndex()}
	return &owned, nil
}

func (n *Engine) ValidateMinedRuntime(view *runtimepolicy.View, a common.Address, code rpcexecution.CodeInfo, e *rpcexecution.MinedExecution) (bool, error) {
	if e == nil {
		return false, errors.New("invalid mined evidence")
	}
	owned, err := n.withMinedPoint(view, e.Anchor().OrganizationID, e)
	if err != nil {
		return false, err
	}
	return owned.ValidateCurrentRuntime(view, a, code, e.Anchor())
}

func (n *Engine) CheckMinedClientTrace(ctx context.Context, view *runtimepolicy.View, org string, e *rpcexecution.MinedExecution, w WalletSnapshot) policycore.Decision {
	if ctx == nil || ctx.Err() != nil || e == nil || e.TopOnly() {
		return invalid()
	}
	owned, err := n.withMinedPoint(view, org, e)
	if err != nil {
		return invalid()
	}
	targets, extra, ok := owned.clientTraceTargets(ctx, view, org, e)
	if !ok {
		return invalid()
	}
	decision := owned.checkPrepared(ctx, view, org, e, w, e.VerifiedSigner(), false, common.Address{}, nil, extra, org)
	return owned.finishClientTrace(ctx, view, org, targets, decision)
}

func (n *Engine) MinedTracePrivateStorage(view *runtimepolicy.View, org string, e *rpcexecution.MinedExecution) (map[common.Address]bool, error) {
	if e == nil || e.TopOnly() {
		return nil, errors.New("invalid full mined trace")
	}
	owned, err := n.withMinedPoint(view, org, e)
	if err != nil {
		return nil, err
	}
	return owned.clientTracePrivateStorage(view, org, e)
}

// This is only a cheap candidate for whether an actual trace may be acquired.
// A dynamic candidate must match actual mined runtime before it grants output.
func (n *Engine) CurrentAddressAdminCandidate(view *runtimepolicy.View, org string, a common.Address) bool {
	if n == nil || n.currentView != view || view == nil || view.RequireLive() != nil {
		return false
	}
	owner, admin, registered := view.ContractReadAdmin(a)
	if registered {
		return owner == org && admin
	}
	o, ok := view.Org(org)
	return ok && o.IsOrgAdmin() && n.qualifiedOwners[a] == org && n.currentObserved[a]
}
func (n *Engine) MinedTargetAdmin(view *runtimepolicy.View, org string, e *rpcexecution.MinedExecution) bool {
	if e == nil {
		return false
	}
	a, call := e.Transaction().To()
	if !call {
		return false
	}
	owned, err := n.withMinedPoint(view, org, e)
	if err != nil || !owned.CurrentAddressAdminCandidate(view, org, a) {
		return false
	}
	if _, _, registered := view.ContractReadAdmin(a); registered {
		return true
	}
	code, ok := e.RuntimeCodeAt(0, a)
	if !ok {
		return false
	}
	used, err := owned.validateRuntimeBasis(a, code, e.Anchor())
	return used && err == nil
}

func (n *Engine) CheckMinedParticipantTop(ctx context.Context, view *runtimepolicy.View, org string, e *rpcexecution.MinedExecution, w WalletSnapshot) error {
	bad := errors.New("mined transaction not visible")
	if ctx == nil || ctx.Err() != nil || view == nil || e == nil || !e.TopOnly() || e.RecordCount() != 1 || !w.valid || w.actorID != view.ActorID() {
		return bad
	}
	owned, err := n.withMinedPoint(view, org, e)
	if err != nil {
		return bad
	}
	tx := e.Transaction()
	to, call := tx.To()
	if !w.Contains(tx.From()) && (!call || !w.Contains(to)) {
		return bad
	}
	if !call {
		created, ok := e.CreationContext(0)
		if !ok {
			return bad
		}
		if created.Address.Known {
			if owner := owned.registeredOwner(created.Address.Value); owner != "" && owner != org {
				return bad
			}
		}
		return view.RequireLive()
	}
	if owner := owned.registeredOwner(to); owner != "" && owner != org {
		return bad
	}
	code, ok := e.FrameCode(0)
	if !ok || code.Delegated() {
		return bad
	}
	shared, valid := owned.temporalShared(to, code)
	if !valid {
		return bad
	}
	if shared || tracePublic(to) {
		return view.RequireLive()
	}
	if owned.owners[to] == org {
		return view.RequireLive()
	}
	if owned.qualifiedOwners[to] != org || !owned.currentObserved[to] {
		return bad
	}
	used, err := owned.validateRuntimeBasis(to, code, e.Anchor())
	if err != nil || !used {
		return bad
	}
	return view.RequireLive()
}
