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

func tracePublic(a common.Address) bool {
	for _, b := range a[:19] {
		if b != 0 {
			return false
		}
	}
	return a[19] > 0 && a[19] <= 9
}

// CheckClientTrace adds the V1 client capability to the SAME native matcher.
// It never changes the approved runtime knob or ordinary call/raw behavior.
func (n *Engine) CheckClientTrace(ctx context.Context, view *runtimepolicy.View, selectedOrg string, e *rpcexecution.CallExecution, wallets WalletSnapshot) policycore.Decision {
	if n == nil || !n.creationObserved || n.currentView != view || view == nil || e == nil || e.Signed() || e.Tree() == nil || e.Anchor().OrganizationID != selectedOrg || ctx.Err() != nil || view.RequireLive() != nil {
		return invalid()
	}
	records := e.Tree().Records()
	targets := map[common.Address]bool{}
	extra := uint64(len(records)) * 12 // Strict scope and private-value context queries.
	for i, r := range records {
		if ctx.Err() != nil || view.RequireLive() != nil {
			return invalid()
		}
		if _, created := e.CreationContext(i); created {
			if r.To.Known {
				owner := n.registeredOwner(r.To.Value)
				if owner != "" && owner != selectedOrg {
					return invalid()
				}
				registered := n.owners[r.To.Value] != "" || n.currentObserved[r.To.Value]
				if registered {
					targets[r.To.Value] = true
				}
			}
			continue
		}
		address := r.NominalCodeAddress.Value
		code, known := e.FrameCode(i)
		if r.Kind == executionfacts.SelfDestruct {
			address = r.To.Value
			code, known = e.RuntimeCodeAt(i, address)
		}
		if !known {
			return invalid()
		}
		shared, valid := n.temporalShared(address, code)
		if !valid {
			return invalid()
		}
		if (r.Kind == executionfacts.Call || r.Kind == executionfacts.StaticCall) && shared && r.NominalCodeAddress == r.StorageAddress {
			continue
		}
		if tracePublic(address) {
			continue
		}
		owner := n.registeredOwner(address)
		if owner != "" && owner != selectedOrg {
			return invalid()
		}
		storage := r.StorageAddress.Value
		if r.Kind == executionfacts.SelfDestruct {
			storage = address
		}
		if n.registeredOwner(storage) != selectedOrg {
			return invalid()
		}
		// Native creation namespaces are not persistent client read grants.
		if _, fresh := code.CreationRecordIndex(); fresh {
			git := n.owners[storage] != ""
			if !git {
				return invalid()
			}
		}
		targets[storage] = true
	}
	for a := range targets {
		cost, known := n.associationCost(a)
		if !known || cost == 0 {
			return invalid()
		}
		var ok bool
		extra, ok = add(extra, 2*cost)
		if !ok || extra > MaxAdmissionWork {
			return invalid()
		}
	}
	decision := n.checkBudget(ctx, view, selectedOrg, e, wallets, false, nil, extra, selectedOrg)
	if !decision.Allowed {
		return decision
	}
	for a := range targets {
		if ctx.Err() != nil || view.RequireLive() != nil {
			return invalid()
		}
		owner, member, associated, registered := n.contractAssociation(view, a)
		if !registered || !member || !associated || owner != selectedOrg {
			return invalid()
		}
	}
	return decision
}

// ClientTracePrivateStorage supplies only current target-specific admin facts.
// The facade independently requires the selected storage-read method. A plain
// wallet/deployer or an old persisted birth cannot grant fresh runtime admin.
func (n *Engine) ClientTracePrivateStorage(view *runtimepolicy.View, org string, e *rpcexecution.CallExecution) (map[common.Address]bool, error) {
	if n == nil || n.currentView != view || view == nil || view.RequireLive() != nil || e == nil || e.Tree() == nil || e.Signed() || e.Anchor().OrganizationID != org {
		return nil, errors.New("invalid trace storage scope")
	}
	records := e.Tree().Records()
	contexts := make([]common.Address, len(records))
	out := map[common.Address]bool{}
	current, member := view.Org(org)
	if !member {
		return nil, errors.New("invalid trace org")
	}
	type gitAdmin struct {
		owner             string
		admin, registered bool
	}
	admins := map[common.Address]gitAdmin{}
	observe := func(a common.Address, i int) {
		if a == (common.Address{}) {
			return
		}
		can := false
		info, seen := admins[a]
		if !seen {
			owner, admin, registered := view.ContractReadAdmin(a)
			info = gitAdmin{owner, admin, registered}
			admins[a] = info
		}
		if info.registered {
			can = info.owner == org && info.admin
		} else if current.IsOrgAdmin() && n.qualifiedOwners[a] == org {
			code, known := e.RuntimeCodeAt(i, a)
			if known {
				used, err := n.ValidateCurrentRuntime(view, a, code, e.Anchor())
				can = used && err == nil
			}
		}
		if old, seen := out[a]; seen {
			can = can && old
		}
		out[a] = can
	}
	for i, r := range records {
		if view.RequireLive() != nil {
			return nil, errors.New("expired trace view")
		}
		if (r.Kind == executionfacts.DelegateCall || r.Kind == executionfacts.CallCode) && r.ParentIndex >= 0 {
			contexts[i] = contexts[r.ParentIndex]
		} else if r.To.Known {
			contexts[i] = r.To.Value
		}
		if i > 0 && r.ParentIndex >= 0 {
			observe(contexts[r.ParentIndex], i)
			observe(contexts[i], i)
		}
	}
	return out, nil
}

// Only linked rules in the actually selected client-trace organization can
// consume this proof; an unrelated membership must not add wallet I/O.
func (n *Engine) ClientTraceNeedsWallets(view *runtimepolicy.View, org string) bool {
	if n == nil || view == nil {
		return false
	}
	o, ok := view.Org(org)
	if !ok {
		return false
	}
	for _, g := range o.Groups() {
		if n.work[org][g].linked > 0 {
			return true
		}
	}
	return false
}
