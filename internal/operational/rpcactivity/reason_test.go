package rpcactivity

import (
	"testing"

	"privacy-proxy/internal/activityreasondata"
	"privacy-proxy/internal/rpcengine"
)

func TestCompletionPreservesOwnedBranchReasonAndTrustedPeer(t *testing.T) {
	for _, code := range []activityreasondata.Code{activityreasondata.MethodNotAllowed, activityreasondata.SenderNotLinked, activityreasondata.PolicyArgumentConstraint} {
		m := rpcengine.OperationMetadata{Method: rpcengine.EthCall, Class: rpcengine.DeniedCompletion, Reason: code}
		got, err := completion(m, "127.0.0.1:1234")
		if err != nil || got.Reason != code || got.TrustedIP != "127.0.0.1" || got.ActorID != "" || got.DataOrganizationID != "" {
			t.Fatal("completion changed reason or invented identity", got, err)
		}
	}
}
