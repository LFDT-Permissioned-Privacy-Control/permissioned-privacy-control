package nativeadmission

import (
	"context"
	"fmt"

	"github.com/ethereum/go-ethereum/common"

	"privacy-proxy/internal/executionfacts"
	"privacy-proxy/internal/policycore"
	"privacy-proxy/internal/rpcexecution"
	"privacy-proxy/internal/runtimepolicy"
)

type routedFrame struct {
	frame policycore.Frame
	org   string
}

// checkMultiOrg plans one complete dispatch before association scans or native
// matching. Root anchor/node/financial selection remain unchanged throughout.
func (n *Engine) checkMultiOrg(ctx context.Context, view *runtimepolicy.View, rootOrg string, execution *rpcexecution.CallExecution, wallets WalletSnapshot, signer common.Address, work uint64) policycore.Decision {
	records := execution.Tree().Records()
	if len(records) == 0 {
		return invalid()
	}
	plan := make([]routedFrame, 0, len(records))
	foreign := make(map[common.Address]bool)
	for i, record := range records {
		if ctx.Err() != nil {
			return invalid()
		}
		frame, ok := n.qualifyFrame(record, execution)
		if !ok {
			return invalid()
		}
		authority := rootOrg
		if i > 0 {
			if record.ParentIndex < 0 || record.ParentIndex >= i {
				return invalid()
			}
			authority = plan[record.ParentIndex].org
			switch record.Kind {
			case executionfacts.Call, executionfacts.StaticCall:
				if !frame.CodeShared && frame.StorageOrg != "" {
					authority = frame.StorageOrg
				}
			case executionfacts.DelegateCall, executionfacts.CallCode:
				if frame.StorageOrg != "" {
					authority = frame.StorageOrg
				}
			}
		}
		if (record.Kind == executionfacts.DelegateCall || record.Kind == executionfacts.CallCode) && frame.CodeShared {
			return policycore.Decision{Code: policycore.DenialOwnership}
		}
		if _, member := view.Org(authority); !member {
			return policycore.Decision{Code: policycore.DenialOwnership}
		}
		if frame.CodeAddress != frame.StorageAddress && frame.CodeOrg != "" && frame.CodeOrg != frame.StorageOrg {
			if !foreign[frame.CodeAddress] {
				foreign[frame.CodeAddress] = true
				cost, known := n.associationWork[frame.CodeAddress]
				if !known || cost == 0 {
					return invalid()
				}
				var valid bool
				work, valid = add(work, cost)
				if !valid || work > MaxAdmissionWork {
					return invalid()
				}
			}
		}
		plan = append(plan, routedFrame{frame, authority})
	}
	// Every potentially expensive association lookup is covered by the composed
	// budget above, including repeated targets and groups with no native rules.
	codeAccess := make(map[common.Address]bool, len(foreign))
	for address := range foreign {
		if ctx.Err() != nil || view.RequireLive() != nil {
			return invalid()
		}
		owner := n.owners[address]
		_, member := view.Org(owner)
		accessible := member
		if member && n.runtime.IntraOrgGrantTracing() {
			actualOwner, actualMember, associated, registered := view.ContractAssociation(address)
			accessible = registered && actualOwner == owner && actualMember && associated
		}
		codeAccess[address] = accessible
	}
	type orgContext struct {
		view   *runtimepolicy.OrgView
		groups []string
		masks  []runtimepolicy.GroupMask
	}
	contexts := make(map[string]orgContext)
	for i, entry := range plan {
		if ctx.Err() != nil || view.RequireLive() != nil {
			return invalid()
		}
		org, cached := contexts[entry.org]
		if !cached {
			v, known := view.Org(entry.org)
			if !known {
				return invalid()
			}
			org = orgContext{v, v.Groups(), v.GroupMasks()}
			contexts[entry.org] = org
		}
		frame := entry.frame
		frame.CodeAccessible = codeAccess[frame.CodeAddress]
		setFrameMasks(&frame, org.masks, n.qualifiedRuntimeOwner(execution, frame.StorageAddress), entry.org)
		decision := org.view.NativeProgram().Evaluate(policycore.Context{Org: entry.org, Groups: org.groups, LinkedAddresses: wallets.addresses, Signer: signer}, []policycore.Frame{frame})
		if !decision.Allowed {
			// Preserve the original record index without interpreting or rewriting
			// the evaluator's private reason string (which names its local frame0).
			return policycore.Decision{Code: decision.Code, Reason: fmt.Sprintf("execution record %d denied", i)}
		}
	}
	if ctx.Err() != nil || view.RequireLive() != nil {
		return invalid()
	}
	return policycore.Decision{Allowed: true}
}
