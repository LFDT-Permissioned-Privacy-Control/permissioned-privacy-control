package nativeadmission

import (
	"github.com/ethereum/go-ethereum/common"
	"privacy-proxy/internal/runtimepolicy"
)

// Passive test-only observation of operand distinctions; no production API.
func (n *Engine) CurrentFactsForTest(v *runtimepolicy.View, a common.Address) (string, bool, bool) {
	_, member, associated, _ := n.contractAssociation(v, a)
	return n.runtimeOwner(a), member, associated
}
