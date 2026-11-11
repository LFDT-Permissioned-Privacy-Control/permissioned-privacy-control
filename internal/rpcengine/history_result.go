package rpcengine

import (
	"context"
	"encoding/json"

	"privacy-proxy/internal/historyfacts"
	"privacy-proxy/internal/policybundle"
	"privacy-proxy/internal/rpcexecution"
)

type HistoryOperationMetadata struct {
	Method                  string
	Canonical               rpcexecution.HistoryMethod
	Class                   CompletionClass
	ActorID, OrganizationID string
	PolicyDigest            policybundle.Digest
	RPCErrorCode            *int32
}
type HistoryOperationResult struct {
	owner        *HistoryEngine
	current      *historyfacts.Current
	anonymous    bool
	client       *rpcexecution.HistoryReadClient
	observation  *rpcexecution.HistoryReadObservation
	id           json.RawMessage
	notification bool
	code         int32
	metadata     HistoryOperationMetadata
	result       json.RawMessage
}

func (r *HistoryOperationResult) fail(class CompletionClass, code int32) *HistoryOperationResult {
	r.observation = nil
	r.result = nil
	r.code = code
	r.metadata.Class = class
	r.metadata.RPCErrorCode = &code
	return r
}
func (r *HistoryOperationResult) owned(e *HistoryEngine) bool {
	return r != nil && e != nil && e.policy != nil && r.owner == e
}
func (r *HistoryOperationResult) MetadataFor(e *HistoryEngine) (HistoryOperationMetadata, error) {
	if !r.owned(e) {
		return HistoryOperationMetadata{}, errHistory
	}
	m := r.metadata
	if m.RPCErrorCode != nil {
		code := *m.RPCErrorCode
		m.RPCErrorCode = &code
	}
	return m, nil
}
func (r *HistoryOperationResult) IsNotificationFor(e *HistoryEngine) (bool, error) {
	if !r.owned(e) {
		return false, errHistory
	}
	return r.notification, nil
}
func (r *HistoryOperationResult) PreflightFor(e *HistoryEngine) error {
	if !r.owned(e) || len(r.id) == 0 || len(r.id) > 1<<20 || r.metadata.PolicyDigest != historyDigestText(e.policy.Digest()) {
		return errHistory
	}
	if r.code != 0 {
		if metadataErrorMessage(r.code) == "" || r.observation != nil || r.result != nil {
			return errHistory
		}
		return nil
	}
	if r.metadata.Class != SuccessfulCompletion || r.current == nil && !r.anonymous || r.observation == nil || r.observation.Source() != r.client.Source() || len(r.result) == 0 || int64(len(r.result)) > e.limits.MaxResultBytes || int64(len(r.result))+6*int64(len(r.id))+512 > MaxObservedResponseBytes {
		return errHistory
	}
	return nil
}
func (r *HistoryOperationResult) RequireDeliverable(ctx context.Context, e *HistoryEngine) error {
	if ctx == nil || ctx.Err() != nil || r.PreflightFor(e) != nil {
		return errHistory
	}
	if r.code != 0 {
		if r.current != nil {
			return r.current.RequireLive(ctx)
		}
		return nil
	}
	if r.client.Recheck(ctx, r.observation) != nil {
		return errHistory
	}
	if r.current != nil {
		if r.current.Recheck(ctx) != nil {
			return errHistory
		}
		// Check the same concrete source/full network after mutable SQL gates,
		// then the SAME original View/fence after that final source I/O.
		if r.client.Recheck(ctx, r.observation) != nil || r.current.RequireLive(ctx) != nil {
			return errHistory
		}
	} else if !r.anonymous || !e.policy.AllowsAnonymous(r.metadata.Method) {
		return errHistory
	}
	return nil
}
func (r *HistoryOperationResult) MarshalResponseFor(e *HistoryEngine) ([]byte, error) {
	if r.PreflightFor(e) != nil {
		return nil, errHistory
	}
	if r.notification {
		return nil, nil
	}
	out := metadataWireResponse{JSONRPC: "2.0", ID: r.id}
	if r.code != 0 {
		out.Error = &RPCError{Code: int(r.code), Message: metadataErrorMessage(r.code)}
	} else {
		out.Result = r.result
	}
	return marshalMetadataWire(out)
}
func (r *HistoryOperationResult) MarshalRecordingFailureFor(e *HistoryEngine) ([]byte, error) {
	if !r.owned(e) || len(r.id) == 0 || len(r.id) > 1<<20 {
		return nil, errHistory
	}
	if r.notification {
		return nil, nil
	}
	return marshalMetadataWire(metadataWireResponse{JSONRPC: "2.0", ID: r.id, Error: &RPCError{Code: -32002, Message: "unavailable"}})
}
