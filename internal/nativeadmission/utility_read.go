package nativeadmission

import (
	"github.com/ethereum/go-ethereum/common"
	"privacy-proxy/internal/rpcexecution"
	"privacy-proxy/internal/runtimepolicy"
)

// UtilityReadAccess describes current address/storage disclosure after an actual
// checked simulation. A call permission alone never grants private slot reads.
func (n *Engine) UtilityReadAccess(view *runtimepolicy.View, org string, a common.Address, e *rpcexecution.CallExecution) (plain, admin bool) {
	if n == nil || view == nil || n.currentView != view || view.RequireLive() != nil || e == nil || e.Signed() || e.Anchor().OrganizationID != org {
		return false, false
	}
	owner, member, associated, registered := n.contractAssociation(view, a)
	if !registered || !member || !associated || owner != org {
		return false, false
	}
	_, readAdmin, git := view.ContractReadAdmin(a)
	if git {
		return true, readAdmin
	}
	code, known := e.Code(a)
	if !known {
		return false, false
	}
	used, err := n.validateRuntimeBasis(a, code, e.Anchor())
	if !used || err != nil {
		return false, false
	}
	o, ok := view.Org(org)
	return true, ok && o.IsOrgAdmin()
}
