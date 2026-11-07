package rpcexecution

import (
	"context"

	"github.com/ethereum/go-ethereum/common"
	"privacy-proxy/internal/policybundle"
)

const SimulationCallProfileID = policybundle.RuntimeSimulationNodeEvidenceProfileID

// RootCreationScopeCheck is trusted orchestration, never request input. The
// engine supplies one bounded lookup against its captured View, after same-hash
// nonce qualification and before tracing. It is not native permission proof.
type RootCreationScopeCheck func(common.Address) bool

func (c *Client) AcquireSimulationCall(ctx context.Context, call Call, block BlockSelector, scope RootCreationScopeCheck) (*CallExecution, error) {
	if c == nil || !c.selected || c.binding.Profile != SimulationCallProfileID || call.signedInput || call.wire == nil || call.value == nil || block.selector == "" || (call.creation && scope == nil) {
		return nil, failure(InvalidBinding)
	}
	return c.acquireScopedProfile(ctx, call, block, nil, true, scope)
}
