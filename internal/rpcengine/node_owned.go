package rpcengine

import (
	"context"
	"encoding/json"
	"strconv"

	"github.com/ethereum/go-ethereum/common"
	"privacy-proxy/internal/nativeadmission"
	"privacy-proxy/internal/rpcexecution"
	"privacy-proxy/internal/runtimepolicy"
)

func (e *Engine) nodeOwnedObserved(ctx context.Context, q utilityRequest, view *runtimepolicy.View, org, ref string, wallet nativeadmission.WalletSnapshot, r *TraceOperationResult) *TraceOperationResult {
	if !e.utilities.options.NodeSigning || !q.call.FromSupplied() || q.call.From() == (common.Address{}) || !wallet.Contains(q.call.From()) {
		return r.fail(DeniedCompletion, -32001)
	}
	if e.raw.readProfile == "strict" && q.present {
		return r.fail(InvalidCompletion, -32602)
	}
	metadata := rawRequest{metadata: q.metadata, present: q.present}
	if _, ok := metadata.entries(); !ok {
		return r.fail(InvalidCompletion, -32602)
	}
	binding, ok := e.raw.bindings[org][ref]
	if !ok || binding.client == nil || !e.raw.sendEnabled {
		return r.fail(UnavailableCompletion, -32002)
	}
	if binding.pair != nil && !binding.pair.Ready() {
		return r.fail(UnavailableCompletion, -32002)
	}
	call, err := binding.client.PrepareNodeCall(ctx, q.call)
	if err != nil {
		return r.fail(UnavailableCompletion, -32002)
	}
	if binding.pair != nil && call.Object()["type"] == "0x1" {
		return r.fail(UnavailableCompletion, -32002)
	}
	client, err := e.clients[org].WithCredential(ref)
	if err != nil {
		return r.fail(UnavailableCompletion, -32002)
	}
	session, err := client.NewUtilitySession(ctx, call, q.block, e.utilities.options.Limits)
	if err != nil {
		return r.fail(UnavailableCompletion, -32002)
	}
	qualify := func(gas uint64) (*rpcexecution.CallExecution, error) {
		x, err := session.Probe(ctx, gas, nil, false, func(target common.Address) bool {
			actual, yes, err := r.current.selectOrg(ctx, org, target)
			return err == nil && yes && actual == org
		})
		if err != nil {
			return nil, err
		}
		if r.current.collect(ctx, x) != nil || r.current.requireExecution(ctx, session.DeliveryCheckpoint().Client()) != nil {
			return nil, errOperation
		}
		native, err := r.current.engine()
		if err != nil {
			return nil, err
		}
		if !native.Check(ctx, view, org, x, wallet).Allowed {
			return nil, errUtilityDenied
		}
		return x, nil
	}
	// Check the actual requested intent before invoking the signing key. Gas
	// defaults use only individually checked probes on one captured state.
	gas := session.GasCap()
	if _, specified := call.Object()["gas"]; specified {
		if _, err = qualify(gas); err != nil {
			return utilityError(r, err)
		}
	} else {
		gas, err = estimateChecked(gas, qualify)
		if err != nil {
			return utilityError(r, err)
		}
	}
	wire := call.Object()
	wire["gas"] = "0x" + strconv.FormatUint(gas, 16)
	data, _ := json.Marshal(wire)
	call, err = rpcexecution.NormalizeSimulationCall(data)
	if err != nil {
		return r.fail(InvalidCompletion, -32602)
	}
	if !r.fence.live() || view.RequireLive() != nil {
		return r.fail(UnavailableCompletion, -32002)
	}
	// Sign-only never broadcasts. The adapter verifies the actual signed
	// envelope against every filled field; no signed bytes leave this scope.
	tx, err := binding.client.SignNodeCall(ctx, call)
	if err != nil {
		return r.fail(UnavailableCompletion, -32002)
	}
	request := map[string]any{"jsonrpc": "2.0", "id": q.id, "method": "eth_sendRawTransaction", "params": []any{tx.RawHex()}}
	if q.present {
		entries, ok := metadata.entries()
		if !ok {
			return r.fail(InvalidCompletion, -32602)
		}
		request["visibleTo"] = entries
	}
	raw, _ := json.Marshal(request)
	base := &OperationResult{owner: e, fence: r.fence, metadata: OperationMetadata{Method: InvalidRPCRequest, Class: UnavailableCompletion}}
	response := e.submitRawAuthorized(ctx, "", org, raw, base, &rawAuthorization{view: view, wallet: wallet, method: q.method})
	base.response = response
	base.finish(ctx, response)
	r.rawResult = base
	r.metadata.Class = base.metadata.Class
	r.metadata.RPCErrorCode = base.metadata.RPCErrorCode
	return r
}
