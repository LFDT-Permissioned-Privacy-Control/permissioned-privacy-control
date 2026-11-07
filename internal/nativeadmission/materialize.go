package nativeadmission

import (
	"privacy-proxy/internal/executionfacts"
	"privacy-proxy/internal/policycore"
	"privacy-proxy/internal/rpcexecution"
	"privacy-proxy/internal/runtimepolicy"
)

func (n *Engine) materialize(org *runtimepolicy.OrgView, execution *rpcexecution.CallExecution) ([]policycore.Frame, bool) {
	records := execution.Tree().Records()
	if len(records) == 0 {
		return nil, false
	}
	masks := org.GroupMasks()
	frames := make([]policycore.Frame, 0, len(records))
	for _, record := range records {
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
			return nil, false
		}
		if !record.NominalCodeAddress.Known || !record.StorageAddress.Known || !record.CallerAddress.Known || record.Value == nil {
			return nil, false
		}
		code, ok := execution.Code(record.NominalCodeAddress.Value)
		if !ok {
			return nil, false
		}
		if _, ok := execution.Code(record.StorageAddress.Value); !ok {
			return nil, false
		}
		kind := uint8(policycore.CodeEOA)
		if code.Precompile() {
			kind = policycore.CodePrecompile
		} else if code.HasCode() {
			kind = policycore.CodeContract
		}
		codeShared, ok := n.sharedCode(execution, record.NominalCodeAddress.Value)
		if !ok {
			return nil, false
		}
		storageShared, ok := n.sharedCode(execution, record.StorageAddress.Value)
		if !ok {
			return nil, false
		}
		frame := policycore.Frame{CallType: callType, CodeAddress: record.NominalCodeAddress.Value, StorageAddress: record.StorageAddress.Value, CallerAddress: record.CallerAddress.Value, Depth: uint64(record.Depth), Value: record.Value, Calldata: record.Input, CodeKind: kind, CodeOrg: n.owner(execution, record.NominalCodeAddress.Value), StorageOrg: n.owner(execution, record.StorageAddress.Value), CallerOrg: n.owner(execution, record.CallerAddress.Value), CodeShared: codeShared, StorageShared: storageShared, GroupClaims: make(map[string]uint8, len(masks))}
		for _, mask := range masks {
			claims := uint8(0)
			if frame.StorageOrg == execution.Anchor().OrganizationID {
				claims = mask.Claims
			}
			frame.GroupClaims[mask.GroupID] = claims
		}
		if target, recognized, err := policycore.InspectUpgradeTarget(record.Input); recognized {
			if err != nil {
				return nil, false
			}
			frame.UpgradeTargetOrg = n.owner(execution, target)
		}
		frames = append(frames, frame)
	}
	return frames, true
}
