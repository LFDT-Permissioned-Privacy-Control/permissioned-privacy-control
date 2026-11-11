package nativeadmission

import (
	"privacy-proxy/internal/executionfacts"
	"privacy-proxy/internal/policycore"
	"privacy-proxy/internal/runtimepolicy"
)

func (n *Engine) materialize(org *runtimepolicy.OrgView, execution executionEvidence) ([]policycore.Frame, bool) {
	records := execution.Tree().Records()
	if len(records) == 0 {
		return nil, false
	}
	masks := org.GroupMasks()
	frames := make([]policycore.Frame, 0, len(records))
	for _, record := range records {
		frame, ok := n.qualifyFrame(record, execution)
		if !ok {
			return nil, false
		}
		setFrameMasks(&frame, masks, n.qualifiedRuntimeOwner(execution, frame.StorageAddress), execution.Anchor().OrganizationID)
		frames = append(frames, frame)
	}
	return frames, true
}

func setFrameMasks(frame *policycore.Frame, masks []runtimepolicy.GroupMask, qualifiedStorageOrg, authorityOrg string) {
	frame.GroupClaims = make(map[string]uint8, len(masks))
	for _, mask := range masks {
		claims := uint8(0)
		if frame.StorageOrg == authorityOrg && qualifiedStorageOrg == authorityOrg {
			claims = mask.Claims
		}
		frame.GroupClaims[mask.GroupID] = claims
	}
}

// qualifyFrame is shared by all native versions; routing cannot relabel its
// anchored owner/code/caller facts or manufacture a different execution.
func (n *Engine) qualifyFrame(record executionfacts.Record, execution executionEvidence) (policycore.Frame, bool) {
	var zero policycore.Frame
	var callType policycore.CallType
	switch record.Kind {
	case executionfacts.Call:
		callType = policycore.CallTypeCall
	case executionfacts.StaticCall:
		callType = policycore.CallTypeStaticCall
	case executionfacts.DelegateCall:
		callType = policycore.CallTypeDelegateCall
	case executionfacts.CallCode:
		callType = policycore.CallTypeCallCode
	default:
		return zero, false
	}
	if !record.NominalCodeAddress.Known || !record.StorageAddress.Known || !record.CallerAddress.Known || record.Value == nil {
		return zero, false
	}
	code, ok := execution.Code(record.NominalCodeAddress.Value)
	if !ok {
		return zero, false
	}
	if _, ok := execution.Code(record.StorageAddress.Value); !ok {
		return zero, false
	}
	kind := uint8(policycore.CodeEOA)
	if code.Precompile() {
		kind = policycore.CodePrecompile
	} else if code.HasCode() {
		kind = policycore.CodeContract
	}
	// Registry isolation is independent of code presence, but a registered
	// contract rule must not turn an empty account into executable authority.
	// Unregistered EOAs and genuine precompiles keep their separate classes.
	if kind == policycore.CodeEOA && n.registeredOwner(record.NominalCodeAddress.Value) != "" {
		return zero, false
	}
	codeShared, ok := n.sharedCode(execution, record.NominalCodeAddress.Value)
	if !ok {
		return zero, false
	}
	storageShared, ok := n.sharedCode(execution, record.StorageAddress.Value)
	if !ok {
		return zero, false
	}
	frame := policycore.Frame{CallType: callType, CodeAddress: record.NominalCodeAddress.Value, StorageAddress: record.StorageAddress.Value, CallerAddress: record.CallerAddress.Value, Depth: uint64(record.Depth), Value: record.Value, Calldata: record.Input, CodeKind: kind, CodeOrg: n.registeredOwner(record.NominalCodeAddress.Value), StorageOrg: n.registeredOwner(record.StorageAddress.Value), CallerOrg: n.qualifiedRuntimeOwner(execution, record.CallerAddress.Value), CodeShared: codeShared, StorageShared: storageShared}
	if target, recognized, err := policycore.InspectUpgradeTarget(record.Input); recognized {
		if err != nil {
			return zero, false
		}
		frame.UpgradeTargetOrg = n.qualifiedRuntimeOwner(execution, target)
	}
	return frame, true
}
