package rpcengine

import (
	"context"
	"encoding/json"
	"privacy-proxy/internal/policybundle"
	"privacy-proxy/internal/rpcexecution"
	"privacy-proxy/internal/runtimepolicy"
)

type TraceOperationMetadata struct {
	Method                  string
	Class                   CompletionClass
	ActorID, OrganizationID string
	PolicyDigest            policybundle.Digest
	RPCErrorCode            *int32
}

// Concrete owned result: callers cannot provide arbitrary JSON or replace the
// original engine/View/current source. The only retained object is redacted.
type TraceOperationResult struct {
	owner         *Engine
	id            json.RawMessage
	notification  bool
	projection    json.RawMessage
	code          int
	view          *runtimepolicy.View
	metadata      TraceOperationMetadata
	source        *rpcexecution.Client
	current       *nativeAddressPass
	fence         *nativeOperationFence
	utility       *rpcexecution.UtilityCheckpoint
	rawResult     *OperationResult
	walletVersion string
}

func (r *TraceOperationResult) fail(class CompletionClass, code int) *TraceOperationResult {
	r.metadata.Class = class
	r.code = code
	r.projection = nil
	c := int32(code)
	r.metadata.RPCErrorCode = &c
	return r
}
func (r *TraceOperationResult) MetadataFor(e *Engine) (TraceOperationMetadata, error) {
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
func (r *TraceOperationResult) IsNotificationFor(e *Engine) (bool, error) {
	if r == nil || e == nil || r.owner != e {
		return false, errOperation
	}
	return r.notification, nil
}
func (r *TraceOperationResult) PreflightFor(e *Engine) error {
	if r == nil || e == nil || r.owner != e || len(r.id) == 0 || len(r.id) > MaxRequestBytes {
		return errOperation
	}
	if r.rawResult != nil {
		if e.utilities == nil || e.utilities.methods[r.metadata.Method] != "eth_sendTransaction" || r.rawResult.view != r.view || r.rawResult.fence != r.fence {
			return errOperation
		}
		return r.rawResult.PreflightFor(e)
	}
	if r.code != 0 {
		if r.projection != nil || r.metadata.RPCErrorCode == nil || int(*r.metadata.RPCErrorCode) != r.code {
			return errOperation
		}
		return nil
	}
	if r.view == nil || r.source == nil || r.current == nil || r.fence == nil || r.current.owner != e || r.current.view != r.view || (!e.traceMethods[r.metadata.Method] && (e.utilities == nil || e.utilities.methods[r.metadata.Method] == "")) || len(r.projection) == 0 || len(r.projection)+len(r.id)+128 > MaxObservedResponseBytes {
		return errOperation
	}
	b, bound := r.source.BoundNetwork()
	if !bound || b != e.network {
		return errOperation
	}
	return nil
}
func traceErrorMessage(code int) string {
	switch code {
	case -32600:
		return "invalid request"
	case -32601:
		return "method not found"
	case -32602:
		return "invalid params"
	case -32001:
		return "not authorized"
	default:
		return "unavailable"
	}
}
func (r *TraceOperationResult) MarshalResponseFor(e *Engine) ([]byte, error) {
	if r.PreflightFor(e) != nil {
		return nil, errOperation
	}
	if r.rawResult != nil {
		return r.rawResult.MarshalResponseFor(e)
	}
	if r.code != 0 {
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
func (r *TraceOperationResult) MarshalRecordingFailureFor(e *Engine) ([]byte, error) {
	if r == nil || r.owner != e || e == nil {
		return nil, errOperation
	}
	if r.rawResult != nil {
		if r.PreflightFor(e) != nil {
			return nil, errOperation
		}
		// A node-owned send has already crossed the raw lane's effect boundary.
		// Preserve its original unknown-outcome hash after recording failure.
		return r.rawResult.MarshalRecordingFailureFor(e)
	}
	return marshalTraceFixedError(r.id, -32002), nil
}
func (r *TraceOperationResult) RequireDeliverable(ctx context.Context, e *Engine) error {
	if r.PreflightFor(e) != nil || ctx == nil || ctx.Err() != nil || e.raw == nil || e.raw.closed.Load() {
		return errOperation
	}
	if r.rawResult != nil {
		return r.rawResult.RequireDeliverable(ctx, e)
	}
	if r.fence != nil {
		bounded, cancel, err := r.fence.context(ctx)
		if err != nil {
			return err
		}
		defer cancel()
		ctx = bounded
	}
	if r.walletVersion != "" {
		if r.view == nil || e.wallets == nil {
			return errOperation
		}
		w, err := e.wallets.Load(ctx, r.view.ActorID())
		if err != nil || w.ActorID() != r.view.ActorID() || w.Version() != r.walletVersion {
			return errOperation
		}
	}
	if r.utility != nil {
		if r.current.recheck(ctx, e) != nil || r.utility.RequireCurrent(ctx, r.current.head) != nil {
			return errOperation
		}
	} else if r.current != nil {
		if r.current.requireCall(ctx, e, r.source) != nil {
			return errOperation
		}
	}
	if ctx.Err() != nil || e.raw.closed.Load() {
		return errOperation
	}
	if r.view != nil {
		return r.view.RequireLive()
	}
	if r.code == 0 {
		return errOperation
	}
	return nil
}

func marshalTraceFixedError(id json.RawMessage, code int) []byte {
	errJSON, _ := json.Marshal(&RPCError{Code: code, Message: traceErrorMessage(code)})
	raw := make([]byte, 0, len(id)+len(errJSON)+64)
	raw = append(raw, `{"jsonrpc":"2.0","id":`...)
	raw = append(raw, id...)
	raw = append(raw, `,"error":`...)
	raw = append(raw, errJSON...)
	return append(raw, '}')
}
