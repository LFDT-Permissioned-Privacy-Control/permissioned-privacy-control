package rpcengine

import (
	"context"
	"encoding/json"

	share "privacy-proxy/internal/admissionsharedata"
	"privacy-proxy/internal/rpcexecution"
	"privacy-proxy/internal/runtimepolicy"
)

// Only a checked, projected object and its original small authority metadata
// survive into synchronous recording. No source execution is reachable here.
type MinedTraceOperationResult struct {
	owner                       *Engine
	id                          json.RawMessage
	notification, hiddenFailure bool
	projection                  json.RawMessage
	code                        int
	view                        *runtimepolicy.View
	metadata                    TraceOperationMetadata
	checkpoint                  *rpcexecution.MinedTraceCheckpoint
	current                     *nativeAddressPass
	fence                       *nativeOperationFence
	shareFence                  share.Fence
	shares                      *share.SharePass
	walletVersion               string
}

func (r *MinedTraceOperationResult) fail(class CompletionClass, code int) *MinedTraceOperationResult {
	r.metadata.Class = class
	r.code = code
	r.projection = nil
	c := int32(code)
	r.metadata.RPCErrorCode = &c
	return r
}
func (r *MinedTraceOperationResult) hidden(class CompletionClass) *MinedTraceOperationResult {
	r.hiddenFailure = true
	return r.fail(class, -32001)
}
func (r *MinedTraceOperationResult) MetadataFor(e *Engine) (TraceOperationMetadata, error) {
	if r == nil || e == nil || r.owner != e {
		return TraceOperationMetadata{}, errOperation
	}
	m := r.metadata
	if m.RPCErrorCode != nil {
		c := *m.RPCErrorCode
		m.RPCErrorCode = &c
	}
	return m, nil
}
func (r *MinedTraceOperationResult) IsNotificationFor(e *Engine) (bool, error) {
	if r == nil || e == nil || r.owner != e {
		return false, errOperation
	}
	return r.notification, nil
}
func (r *MinedTraceOperationResult) PreflightFor(e *Engine) error {
	if r == nil || e == nil || r.owner != e || len(r.id) == 0 || len(r.id) > MaxRequestBytes {
		return errOperation
	}
	if r.code != 0 {
		if r.projection != nil || r.metadata.RPCErrorCode == nil || int(*r.metadata.RPCErrorCode) != r.code {
			return errOperation
		}
		return nil
	}
	if e.mined == nil || r.view == nil || r.checkpoint == nil || r.current == nil || r.current.owner != e || r.current.view != r.view || r.fence == nil || r.walletVersion == "" || !e.mined.methods[r.metadata.Method] || len(r.projection) == 0 || len(r.projection)+len(r.id)+128 > MaxObservedResponseBytes {
		return errOperation
	}
	n, bound := r.checkpoint.BoundNetwork()
	if !bound || n != e.network {
		return errOperation
	}
	return nil
}
func (r *MinedTraceOperationResult) MarshalResponseFor(e *Engine) ([]byte, error) {
	if r.PreflightFor(e) != nil {
		return nil, errOperation
	}
	if r.code != 0 {
		if r.hiddenFailure && e.mined != nil && e.mined.profile.Strict() {
			return marshalMinedFixedError(r.id, r.code, "transaction not found"), nil
		}
		return marshalTraceFixedError(r.id, r.code), nil
	}
	raw := make([]byte, 0, len(r.id)+len(r.projection)+64)
	raw = append(raw, `{"jsonrpc":"2.0","id":`...)
	raw = append(raw, r.id...)
	raw = append(raw, `,"result":`...)
	raw = append(raw, r.projection...)
	raw = append(raw, '}')
	return raw, nil
}
func marshalMinedFixedError(id json.RawMessage, code int, message string) []byte {
	encoded, _ := json.Marshal(RPCError{Code: code, Message: message})
	raw := append([]byte(`{"jsonrpc":"2.0","id":`), id...)
	raw = append(raw, `,"error":`...)
	raw = append(raw, encoded...)
	return append(raw, '}')
}
func (r *MinedTraceOperationResult) MarshalRecordingFailureFor(e *Engine) ([]byte, error) {
	if r == nil || e == nil || r.owner != e {
		return nil, errOperation
	}
	return marshalTraceFixedError(r.id, -32002), nil
}
func (r *MinedTraceOperationResult) RequireDeliverable(parent context.Context, e *Engine) error {
	if r.PreflightFor(e) != nil || parent == nil || parent.Err() != nil || e.raw == nil || e.raw.closed.Load() {
		return errOperation
	}
	ctx := parent
	if r.fence != nil {
		bounded, cancel, err := r.fence.context(parent)
		if err != nil {
			return err
		}
		defer cancel()
		ctx = bounded
	}
	if r.code != 0 {
		return ctx.Err()
	}
	if r.shareFence.Check() != nil {
		return errOperation
	}
	wallet, err := e.wallets.Load(ctx, r.view.ActorID())
	if err != nil || wallet.ActorID() != r.view.ActorID() || wallet.Version() != r.walletVersion {
		return errOperation
	}
	if r.shares != nil {
		m := e.mined.options.Shares.Metadata()
		if m.Binding != e.mined.options.ShareExpected || m.Identity != e.mined.identity || m.Mode != "reader" || r.shares.ValidateFor(m.Identity, m.Binding) != nil || e.mined.options.Shares.Recheck(ctx, r.shares) != nil {
			return errOperation
		}
	}
	if r.current.recheck(ctx, e) != nil {
		return errOperation
	}
	if r.checkpoint.RequireCurrent(ctx, r.current.head) != nil {
		return errOperation
	}
	if ctx.Err() != nil || !r.fence.live() || r.shareFence.Check() != nil || e.raw.closed.Load() {
		return errOperation
	}
	return r.view.RequireLive()
}
