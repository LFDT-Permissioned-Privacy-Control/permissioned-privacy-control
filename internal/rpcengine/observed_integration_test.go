package rpcengine_test

import (
	"encoding/json"
	"strings"
	"sync/atomic"
	"testing"

	"privacy-proxy/internal/nativeadmission"
	"privacy-proxy/internal/policybundle"
	"privacy-proxy/internal/policycore"
	"privacy-proxy/internal/rpcengine"
	"privacy-proxy/internal/rpcexecution"
	"privacy-proxy/internal/runtimepolicy"
)

func TestObservedNativeCreationSamePassDecisionAndCapability(t *testing.T) {
	f := creationIntentRuntimeFixture()
	n := &node{}
	intentCheck(t, f, n, func(native *nativeadmission.Engine, factory *runtimepolicy.Factory, view *runtimepolicy.View, execution *rpcexecution.CallExecution, wallet nativeadmission.WalletSnapshot) {
		decision, approved, err := native.CheckSignedWithCreationPlanObserved(t.Context(), view, orgA, execution, wallet)
		if err != nil || !decision.Allowed || decision.Code != "" || approved == nil || approved.RequireMatches(view, orgA, execution, wallet) != nil {
			t.Fatal("genuine capability lost", decision, err)
		}
		if approved.RequireMatches(view, orgB, execution, wallet) == nil {
			t.Fatal("org capability widened")
		}
		bad, capability, err := native.CheckSignedWithCreationPlanObserved(t.Context(), view, orgA, nil, wallet)
		if err == nil || bad.Allowed || bad.Code != policycore.DenialInvalidFacts || capability != nil {
			t.Fatal("invalid facts indistinguishable", bad, err)
		}
		legacy, err := native.CheckSignedWithCreationPlan(t.Context(), view, orgA, nil, wallet)
		if err != nativeadmission.ErrCreationIntent || legacy != nil {
			t.Fatal("legacy error changed", err)
		}
	})
}

func TestObservedActualEngineOriginalViewAndLegacyResponse(t *testing.T) {
	d := rawPostgres(t)
	if _, err := d.owner.Exec(t.Context(), `CREATE ROLE raw_observer LOGIN PASSWORD 'raw-test-only';CREATE ROLE raw_facts LOGIN PASSWORD 'raw-test-only'`); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{policybundle.RawSubmissionOPSPreflight, policybundle.RawSubmissionGuardV1} {
		t.Run(mode, func(t *testing.T) {
			f := creationIntentRuntimeFixture()
			f.creationObserved = true
			f.rawMode = mode
			var instant atomic.Int64
			instant.Store(now)
			f.clock = &instant
			n := &node{}
			e, tok, financial, _ := mountedRawEngine(t, f, n, d, false)
			raw := []byte(`{"jsonrpc":"2.0","id":"same","method":"eth_call","params":[{"to":"` + addressA + `","data":"0x0102"}]}`)
			observed := e.CallObserved(t.Context(), tok, orgA, raw)
			meta, err := observed.MetadataFor(e)
			if err != nil || meta.Class != rpcengine.SuccessfulCompletion || meta.ActorID == "" || meta.OrganizationID != orgA || meta.PolicyDigest == "" || meta.RPCErrorCode != nil {
				t.Fatal(meta, err)
			}
			encoded, err := observed.MarshalResponseFor(e)
			if err != nil || !strings.Contains(string(encoded), "0xfeed") {
				t.Fatal(string(encoded), err)
			}
			legacy, _ := json.Marshal(e.Call(t.Context(), tok, orgA, raw))
			if strings.TrimSpace(string(encoded)) != string(legacy) {
				t.Fatal("legacy response diverged")
			}
			binding := e.OperationBinding()
			if binding.NetworkKey != financial.Metadata().NetworkKey.String() || len(binding.OrganizationIDs) != 2 {
				t.Fatal(binding)
			}
			binding.OrganizationIDs[0] = "mutated"
			binding.Methods[0] = rpcengine.InvalidRPCRequest
			if e.OperationBinding().OrganizationIDs[0] == "mutated" || e.OperationBinding().Methods[0] != rpcengine.EthCall {
				t.Fatal("mutable binding")
			}
			// Same captured View observes the original clock; no new JWT/build occurs.
			instant.Store(now + 300)
			if observed.RequireDeliverable(t.Context(), e) == nil {
				t.Fatal("expired original View delivered")
			}
			instant.Store(now)
			n.mutate = func(root map[string]any) { root["error"] = "execution reverted"; root["output"] = "0xdead" }
			reverted := e.CallObserved(t.Context(), tok, orgA, raw)
			m, _ := reverted.MetadataFor(e)
			if m.Class != rpcengine.EvaluationFailedCompletion || m.RPCErrorCode == nil || *m.RPCErrorCode != 3 {
				t.Fatal(m)
			}
			instant.Store(now + 300)
			if reverted.RequireDeliverable(t.Context(), e) == nil {
				t.Fatal("expired revert delivered")
			}
			if _, err := reverted.MarshalResponseFor(e); err != nil {
				t.Fatal("serialization must not rebuild authority", err)
			}
			instant.Store(now)
		})
	}
}
