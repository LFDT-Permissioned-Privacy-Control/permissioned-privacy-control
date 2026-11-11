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

type lifecyclePlan struct {
	frame         policycore.Frame
	org           string
	self          bool
	beneficiary   common.Address
	benefitCode   rpcexecution.CodeInfo
	benefitNS     string
	benefitShared bool
	storageCode   rpcexecution.CodeInfo
}

func (n *Engine) temporalShared(address common.Address, code rpcexecution.CodeInfo) (bool, bool) {
	pin, configured := n.shared[address]
	if !configured {
		return false, true
	}
	if pin != nil && *pin != code.Hash() {
		return false, false
	}
	return code.HasCode() && !code.Precompile(), true
}

func (n *Engine) temporalOwner(address common.Address, code rpcexecution.CodeInfo, anchor rpcexecution.Anchor) string {
	if !code.HasCode() || code.Precompile() || code.Delegated() {
		return ""
	}
	return n.runtimeOwnerFor(address, code, anchor)
}

// checkLifecycle caches at most6 opaque indexed queries per original record:
// creation metadata, frame code, storage, caller, upgrade target, SELF target.
// The reviewed16-query bound is therefore conservative across ALL passes;
// matching and association scans consume only these copied cheap facts.
func (n *Engine) checkLifecycle(ctx context.Context, view *runtimepolicy.View, rootOrg string, e executionEvidence, wallets WalletSnapshot, signer common.Address, work uint64, capture *creationCapture) policycore.Decision {
	var valid bool
	work, valid = add(work, uint64(e.RecordCount()))
	if !valid || work > MaxAdmissionWork {
		return invalid()
	}
	records := e.Tree().Records() // One owned copy for the complete native pass.
	plan := make([]lifecyclePlan, len(records))
	namespaces := make([]string, len(records))
	fresh := make([]bool, len(records))
	active := map[int]bool{}
	stack := []int{}
	associations := map[common.Address]bool{}
	namespace := func(code rpcexecution.CodeInfo) (string, bool) {
		index, created := code.CreationRecordIndex()
		if !created {
			return "", true
		}
		if index < 0 || index >= len(namespaces) || !fresh[index] || namespaces[index] == "" {
			return "", false
		}
		return namespaces[index], true
	}
	needAssociation := func(address common.Address) bool {
		if associations[address] {
			return true
		}
		cost, known := n.associationCost(address)
		if !known || cost == 0 {
			return false
		}
		work, valid = add(work, cost)
		if !valid || work > MaxAdmissionWork {
			return false
		}
		associations[address] = true
		return true
	}
	for i, r := range records {
		if ctx.Err() != nil || view.RequireLive() != nil || r.Value == nil {
			return invalid()
		}
		for len(stack) > 0 && records[stack[len(stack)-1]].Depth >= r.Depth {
			delete(active, stack[len(stack)-1])
			stack = stack[:len(stack)-1]
		}
		inherited := rootOrg
		if i > 0 {
			if r.ParentIndex < 0 || r.ParentIndex >= i {
				return invalid()
			}
			inherited = plan[r.ParentIndex].org
		}
		entry := lifecyclePlan{org: inherited}
		if r.Kind == executionfacts.SelfDestruct {
			if !r.To.Known {
				return invalid()
			}
			code, known := e.RuntimeCodeAt(i, r.To.Value)
			if !known {
				return invalid()
			}
			if _, err := n.validateRuntimeBasis(r.To.Value, code, e.Anchor()); err != nil {
				return invalid()
			}
			ns, known := namespace(code)
			if !known {
				return invalid()
			}
			shared, qualified := n.temporalShared(r.To.Value, code) // STRICT pin-first.
			if !qualified {
				return invalid()
			}
			entry.self, entry.beneficiary, entry.benefitCode, entry.benefitNS, entry.benefitShared = true, r.To.Value, code, ns, shared
			if !shared && !code.Precompile() && n.registeredOwner(r.To.Value) != "" && !needAssociation(r.To.Value) {
				return invalid()
			}
			plan[i] = entry
			stack = append(stack, i)
			continue
		}
		creation, isCreation := e.CreationContext(i)
		code, codeKnown := e.FrameCode(i)
		if !codeKnown {
			return invalid()
		}
		if r.NominalCodeAddress.Known {
			if _, err := n.validateRuntimeBasis(r.NominalCodeAddress.Value, code, e.Anchor()); err != nil {
				return invalid()
			}
		}
		f := policycore.Frame{CallerAddress: r.CallerAddress.Value, Depth: uint64(r.Depth), Value: r.Value, Calldata: r.Input}
		if r.NominalCodeAddress.Known {
			f.CodeAddress = r.NominalCodeAddress.Value
			f.CodeOrg = n.registeredOwner(f.CodeAddress)
		}
		if r.StorageAddress.Known {
			f.StorageAddress = r.StorageAddress.Value
			f.StorageOrg = n.registeredOwner(f.StorageAddress)
		}
		f.CodeKind = policycore.CodeEOA
		if code.Precompile() {
			f.CodeKind = policycore.CodePrecompile
		} else if code.HasCode() {
			f.CodeKind = policycore.CodeContract
		}
		caller, callerKnown := e.RuntimeCodeAt(i, r.From)
		if !callerKnown || !r.CallerAddress.Known {
			return invalid()
		}
		// DELEGATECALL preserves effective msg.sender, not its raw tracer From.
		if r.CallerAddress.Value != r.From {
			caller, callerKnown = e.RuntimeCodeAt(i, r.CallerAddress.Value)
			if !callerKnown {
				return invalid()
			}
		}
		if _, err := n.validateRuntimeBasis(r.CallerAddress.Value, caller, e.Anchor()); err != nil {
			return invalid()
		}
		f.CallerOrg = n.temporalOwner(r.CallerAddress.Value, caller, e.Anchor())
		if isCreation {
			if (r.Kind != executionfacts.Create && r.Kind != executionfacts.Create2) || creation.Creator != r.From || creation.Address != r.StorageAddress {
				return invalid()
			}
			f.CallType = policycore.CallTypeCreate
			if r.Kind == executionfacts.Create2 {
				f.CallType = policycore.CallTypeCreate2
			}
			if creation.Address.Known {
				if owner := n.registeredOwner(creation.Address.Value); owner != "" {
					entry.org = owner
				}
			} else {
				f.CreationUnresolved = true
			}
			f.CreationNamespace = entry.org // Attempt authority, not observed owner.
			if creation.Kind == rpcexecution.FreshConstructor {
				fresh[i], namespaces[i], active[i] = true, entry.org, true
				f.StorageDeploymentNamespace, f.CodeDeploymentNamespace = entry.org, entry.org
			}
			// CREATE/input has no installed-runtime shared or upgrade interpretation.
		} else {
			switch r.Kind {
			case executionfacts.Call:
				f.CallType = policycore.CallTypeCall
			case executionfacts.StaticCall:
				f.CallType = policycore.CallTypeStaticCall
			case executionfacts.DelegateCall:
				f.CallType = policycore.CallTypeDelegateCall
			case executionfacts.CallCode:
				f.CallType = policycore.CallTypeCallCode
			default:
				return invalid()
			}
			if !r.StorageAddress.Known || !r.NominalCodeAddress.Known {
				return invalid()
			}
			storage, known := e.RuntimeCodeAt(i, f.StorageAddress)
			if !known {
				return invalid()
			}
			if _, err := n.validateRuntimeBasis(f.StorageAddress, storage, e.Anchor()); err != nil {
				return invalid()
			}
			entry.storageCode = storage
			f.StorageRuntimeHasCode = storage.HasCode() && !storage.Precompile()
			f.StorageDeploymentNamespace, known = namespace(storage)
			if !known {
				return invalid()
			}
			f.CodeDeploymentNamespace, known = namespace(code)
			if !known {
				return invalid()
			}
			if f.CodeKind == policycore.CodeEOA && n.runtimeOwner(f.CodeAddress) != "" && f.CodeDeploymentNamespace == "" {
				return invalid() // Registered empty remains distinct from an EOA.
			}
			epoch, created := code.CreationRecordIndex()
			emptySelf := r.Kind == executionfacts.Call && r.From == f.CodeAddress && f.CodeAddress == f.StorageAddress && !code.HasCode() && !code.Precompile() && created && active[epoch]
			if !emptySelf {
				f.CodeShared, known = n.temporalShared(f.CodeAddress, code)
				if !known {
					return invalid()
				}
			}
			if f.CodeAddress == f.StorageAddress {
				f.StorageShared = f.CodeShared
			} else {
				storageEpoch, storageCreated := storage.CreationRecordIndex()
				emptyConstructorStorage := (r.Kind == executionfacts.DelegateCall || r.Kind == executionfacts.CallCode) && code.HasCode() && !code.Precompile() && !f.CodeShared && !storage.HasCode() && !storage.Precompile() && storageCreated && active[storageEpoch]
				if !emptyConstructorStorage {
					f.StorageShared, known = n.temporalShared(f.StorageAddress, storage)
					if !known {
						return invalid()
					}
				}
			}
			if i > 0 {
				if (r.Kind == executionfacts.Call || r.Kind == executionfacts.StaticCall) && f.CodeShared {
					// Qualified shared-first inherits actual parent authority.
				} else if f.StorageOrg != "" {
					entry.org = f.StorageOrg
				} else if f.StorageDeploymentNamespace != "" {
					entry.org = f.StorageDeploymentNamespace
				}
			}
			if f.CodeShared && (r.Kind == executionfacts.DelegateCall || r.Kind == executionfacts.CallCode) {
				return policycore.Decision{Code: policycore.DenialOwnership}
			}
			if f.CodeKind == policycore.CodeContract {
				if target, recognized, err := policycore.InspectUpgradeTarget(r.Input); recognized {
					if err != nil {
						return invalid()
					}
					implementation, known := e.RuntimeCodeAt(i, target)
					if !known {
						return invalid()
					}
					if _, err := n.validateRuntimeBasis(target, implementation, e.Anchor()); err != nil {
						return invalid()
					}
					if implementation.HasCode() && !implementation.Precompile() {
						f.UpgradeTargetOrg = n.registeredOwner(target)
						if f.UpgradeTargetOrg == "" {
							f.UpgradeTargetOrg, known = namespace(implementation)
							if !known {
								return invalid()
							}
						}
					}
				}
			}
			if f.CodeAddress != f.StorageAddress && f.CodeOrg != "" && f.CodeOrg != entry.org && !needAssociation(f.CodeAddress) {
				return invalid()
			}
		}
		if _, member := view.Org(entry.org); !member {
			return policycore.Decision{Code: policycore.DenialOwnership}
		}
		entry.frame = f
		plan[i] = entry
		stack = append(stack, i)
	}
	// All grant scans are covered BEFORE any scan or matcher invocation. The
	// immutable association result is shared across code-access and SELF checks.
	access := make(map[common.Address]bool, len(associations))
	for address := range associations {
		if ctx.Err() != nil || view.RequireLive() != nil {
			return invalid()
		}
		owner := n.registeredOwner(address)
		_, member := view.Org(owner)
		allowed := member
		if member && n.runtime.IntraOrgGrantTracing() {
			actual, actualMember, associated, registered := n.contractAssociation(view, address)
			allowed = registered && actual == owner && actualMember && associated
		}
		access[address] = allowed
	}
	type orgContext struct {
		view   *runtimepolicy.OrgView
		groups []string
		masks  []runtimepolicy.GroupMask
		source map[string]uint8
	}
	contexts := map[string]orgContext{}
	for i, entry := range plan {
		if ctx.Err() != nil || view.RequireLive() != nil {
			return invalid()
		}
		if entry.self {
			continue
		}
		org, found := contexts[entry.org]
		if !found {
			v, _ := view.Org(entry.org)
			org = orgContext{view: v, groups: v.Groups(), masks: v.GroupMasks(), source: map[string]uint8{}}
			for _, mask := range org.masks {
				org.source[mask.GroupID] = mask.Claims
			}
			contexts[entry.org] = org
		}
		f := entry.frame
		if f.CodeAddress != f.StorageAddress {
			if f.CodeOrg != "" && f.CodeOrg != entry.org {
				f.CodeAccessible = access[f.CodeAddress]
			} else if f.CodeDeploymentNamespace != "" {
				_, f.CodeAccessible = view.Org(f.CodeDeploymentNamespace)
			}
		}
		qualifiedStorage := ""
		if f.StorageRuntimeHasCode {
			qualifiedStorage = n.runtimeOwnerFor(f.StorageAddress, entry.storageCode, e.Anchor())
		}
		setFrameMasks(&f, org.masks, qualifiedStorage, entry.org)
		decision := org.view.NativeProgram().Evaluate(policycore.Context{Org: entry.org, Groups: org.groups, GroupSourceClaims: org.source, LinkedAddresses: wallets.addresses, Signer: signer}, []policycore.Frame{f})
		if !decision.Allowed {
			return policycore.Decision{Code: decision.Code, Reason: fmt.Sprintf("execution record %d denied", i)}
		}
	}
	for _, entry := range plan {
		if !entry.self {
			continue
		}
		if ctx.Err() != nil || view.RequireLive() != nil {
			return invalid()
		}
		switch {
		case entry.benefitShared, entry.benefitCode.Precompile():
		case n.registeredOwner(entry.beneficiary) != "":
			if !access[entry.beneficiary] {
				return policycore.Decision{Code: policycore.DenialOwnership}
			}
		case entry.benefitNS != "":
			if _, member := view.Org(entry.benefitNS); !member {
				return policycore.Decision{Code: policycore.DenialOwnership}
			}
		case !entry.benefitCode.HasCode():
		default:
			return policycore.Decision{Code: policycore.DenialOwnership}
		}
	}
	if ctx.Err() != nil || view.RequireLive() != nil {
		return invalid()
	}
	if capture != nil {
		actual, ok := e.(*rpcexecution.CallExecution)
		if !ok || !n.captureCreations(ctx, view, rootOrg, actual, records, plan, fresh, work, capture) {
			return invalid()
		}
	}
	return policycore.Decision{Allowed: true}
}
