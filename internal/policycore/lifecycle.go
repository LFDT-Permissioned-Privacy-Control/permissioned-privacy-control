package policycore

import (
	"fmt"

	"github.com/ethereum/go-ethereum/common"
)

// IsPraguePrecompile is the fixed qualified Prague address set. It performs no
// fork discovery and imports no execution VM.
func IsPraguePrecompile(a common.Address) bool {
	for _, b := range a[:19] {
		if b != 0 {
			return false
		}
	}
	return a[19] >= 1 && a[19] <= 17
}

func (key frameKey) matchesTargetV4(org string, f Frame) bool {
	if f.CreationUnresolved {
		return key.targetClass == "create" && (f.CallType == CallTypeCreate || f.CallType == CallTypeCreate2)
	}
	switch key.targetClass {
	case "deployment-context":
		return f.StorageDeploymentNamespace == org && ((key.code == (common.Address{}) && f.CodeAddress == f.StorageAddress) || key.code == f.CodeAddress)
	case "precompile":
		return f.CodeKind == CodePrecompile && IsPraguePrecompile(f.CodeAddress)
	case "eoa":
		return f.StorageDeploymentNamespace == "" && f.CodeDeploymentNamespace == "" && key.matchesTarget(org, f)
	case "", "org":
		return f.StorageRuntimeHasCode && key.matchesTarget(org, f)
	default:
		return key.matchesTarget(org, f)
	}
}

func (r *compiledRule) checkAuthorityV4(ctx Context, f Frame, targetClaims, sourceClaims uint8, key frameKey) (DenialCode, error) {
	deployment := sourceClaims&(ClaimAdmin|ClaimDeploy) != 0
	if f.CallType == CallTypeCreate || f.CallType == CallTypeCreate2 {
		if key.targetClass != "create" || f.CreationNamespace != ctx.Org {
			return DenialOwnership, fmt.Errorf("creation namespace differs from policy organisation")
		}
		if !deployment {
			return DenialOperationalClaim, fmt.Errorf("binding group lacks source deploy claim")
		}
		return "", nil
	}
	if key.targetClass == "precompile" {
		if f.CallType == CallTypeDelegateCall || f.CallType == CallTypeCallCode {
			if f.StorageOrg != ctx.Org && f.StorageDeploymentNamespace != ctx.Org {
				return DenialOwnership, fmt.Errorf("precompile storage is outside policy organisation")
			}
			if f.StorageDeploymentNamespace != "" && !deployment {
				return DenialOperationalClaim, fmt.Errorf("binding group lacks source deploy claim")
			}
		} else if f.CodeAddress != f.StorageAddress {
			return DenialOwnership, fmt.Errorf("precompile call storage differs from target")
		}
		return "", nil
	}
	if key.targetClass == "deployment-context" {
		if !deployment || f.StorageDeploymentNamespace != ctx.Org {
			return DenialOperationalClaim, fmt.Errorf("binding group lacks deployment-context authority")
		}
		if f.CodeAddress != f.StorageAddress {
			switch {
			case f.CodeKind == CodePrecompile && IsPraguePrecompile(f.CodeAddress):
			case f.CodeDeploymentNamespace != "":
				if f.CodeDeploymentNamespace != ctx.Org && !f.CodeAccessible {
					return DenialOwnership, fmt.Errorf("created code namespace is inaccessible")
				}
			case f.CodeKind == CodeContract && f.CodeOrg == ctx.Org:
			case r.foreignCodeOrg != "" && f.CodeKind == CodeContract && f.CodeOrg == r.foreignCodeOrg && f.CodeAccessible:
			default:
				return DenialOwnership, fmt.Errorf("borrowed code is not qualified for deployment context")
			}
		}
		if f.CodeKind == CodeContract {
			if target, recognized, err := InspectUpgradeTarget(f.Calldata); recognized {
				if err != nil {
					return DenialMalformedCalldata, err
				}
				if !r.allowUpgrade || sourceClaims&(ClaimAdmin|ClaimUpgrade) == 0 {
					return DenialOperationalClaim, fmt.Errorf("binding group lacks source upgrade claim")
				}
				if target == (common.Address{}) || f.UpgradeTargetOrg != ctx.Org {
					return DenialOwnership, fmt.Errorf("upgrade target is outside deployment namespace")
				}
			}
		}
		return "", nil
	}
	// Empty and precompile inputs are not contract ABI calls under v4. Preserve
	// all ordinary ownership checks while excluding meaningless upgrade parsing.
	if f.CodeKind != CodeContract {
		withoutInput := f
		withoutInput.Calldata = nil
		return r.checkAuthority(ctx, withoutInput, targetClaims, key)
	}
	return r.checkAuthority(ctx, f, targetClaims, key)
}
