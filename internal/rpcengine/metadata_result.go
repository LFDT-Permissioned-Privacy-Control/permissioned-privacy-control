package rpcengine

import (
	"context"
	"encoding/json"

	"privacy-proxy/internal/policybundle"
	"privacy-proxy/internal/rpcexecution"
	"privacy-proxy/internal/runtimepolicy"
)

type MetadataOperationMetadata struct {
	Method                  string
	Canonical               rpcexecution.MetadataMethod
	Class                   CompletionClass
	ActorID, OrganizationID string
	PolicyDigest            policybundle.Digest
	RPCErrorCode            *int32
}

// MetadataOperationResult keeps the original verified View or a private
// admitted-anonymous branch. It exposes no generic response or permission setter.
type MetadataOperationResult struct {
	owner                 *MetadataEngine
	view                  *runtimepolicy.View
	anonymous             bool
	observation           *rpcexecution.MetadataObservation
	source                rpcexecution.MetadataSourceMetadata
	id                    json.RawMessage
	notification          bool
	completedNotification bool
	code                  int32
	metadata              MetadataOperationMetadata
}

func (r *MetadataOperationResult) fail(class CompletionClass, code int32) *MetadataOperationResult {
	r.observation = nil
	r.completedNotification = false
	r.code = code
	r.metadata.Class = class
	r.metadata.RPCErrorCode = &code
	return r
}
func metadataErrorMessage(code int32) string {
	switch code {
	case -32600:
		return "invalid request"
	case -32601:
		return "method not found"
	case -32602:
		return "invalid params"
	case -32001:
		return "not authorized"
	case -32002:
		return "unavailable"
	}
	return ""
}
func (r *MetadataOperationResult) owned(e *MetadataEngine) bool {
	return r != nil && e != nil && e.policy != nil && r.owner == e
}
func (r *MetadataOperationResult) MetadataFor(e *MetadataEngine) (MetadataOperationMetadata, error) {
	if !r.owned(e) {
		return MetadataOperationMetadata{}, errMetadata
	}
	m := r.metadata
	if m.RPCErrorCode != nil {
		code := *m.RPCErrorCode
		m.RPCErrorCode = &code
	}
	return m, nil
}
func (r *MetadataOperationResult) IsNotificationFor(e *MetadataEngine) (bool, error) {
	if !r.owned(e) {
		return false, errMetadata
	}
	return r.notification, nil
}
func (r *MetadataOperationResult) preflightObservation() error {
	if r == nil || r.owner == nil || r.observation == nil || r.observation.Method() != r.metadata.Canonical || r.metadata.Canonical == rpcexecution.InvalidMetadataMethod || r.observation.Source() != r.source || r.observation.ResultSize() < 1 || r.observation.ResultSize() > r.owner.limits.MaxResultBytes {
		return errMetadata
	}
	return nil
}
func (r *MetadataOperationResult) PreflightFor(e *MetadataEngine) error {
	if !r.owned(e) || len(r.id) == 0 || len(r.id) > 1<<20 || r.metadata.PolicyDigest != metadataDigestText(e.policy.Digest()) {
		return errMetadata
	}
	if r.code != 0 {
		if metadataErrorMessage(r.code) == "" || r.observation != nil || r.completedNotification {
			return errMetadata
		}
		return nil
	}
	if r.metadata.Class != SuccessfulCompletion || r.view == nil && !r.anonymous {
		return errMetadata
	}
	if r.notification && r.completedNotification && r.observation == nil {
		return nil
	}
	if r.notification || r.completedNotification || r.preflightObservation() != nil {
		return errMetadata
	}
	// Raw ID escaping can expand sixfold. The normalized typed result has an
	// independent escape reserve; no output allocation occurs during preflight.
	if r.observation.ResultSize()+6*int64(len(r.id))+(64<<10)+512 > MaxObservedResponseBytes {
		return errMetadata
	}
	return nil
}
func (r *MetadataOperationResult) RequireDeliverable(ctx context.Context, e *MetadataEngine) error {
	if ctx == nil || ctx.Err() != nil || r.PreflightFor(e) != nil {
		return errMetadata
	}
	if r.view != nil {
		return r.view.RequireLive()
	}
	if r.code != 0 {
		return nil
	} // Only closed safe errors are admitted here.
	if !r.anonymous || !e.policy.AllowsAnonymous(r.metadata.Method) {
		return errMetadata
	}
	return nil
}

type metadataWireResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *RPCError       `json:"error,omitempty"`
}

func (r *MetadataOperationResult) MarshalResponseFor(e *MetadataEngine) ([]byte, error) {
	if err := r.PreflightFor(e); err != nil {
		return nil, err
	}
	if r.notification {
		return nil, nil
	}
	out := metadataWireResponse{JSONRPC: "2.0", ID: r.id}
	if r.code != 0 {
		out.Error = &RPCError{Code: int(r.code), Message: metadataErrorMessage(r.code)}
	} else {
		out.Result = r.observation.ResultJSON()
	}
	return marshalMetadataWire(out)
}
func (r *MetadataOperationResult) MarshalRecordingFailureFor(e *MetadataEngine) ([]byte, error) {
	if !r.owned(e) || len(r.id) == 0 || len(r.id) > 1<<20 {
		return nil, errMetadata
	}
	if r.notification {
		return nil, nil
	}
	return marshalMetadataWire(metadataWireResponse{JSONRPC: "2.0", ID: r.id, Error: &RPCError{Code: -32002, Message: "unavailable"}})
}
func marshalMetadataWire(out metadataWireResponse) ([]byte, error) {
	encoded, err := json.Marshal(out)
	if err != nil || len(encoded) >= MaxObservedResponseBytes {
		return nil, errMetadata
	}
	return append(encoded, '\n'), nil
}
