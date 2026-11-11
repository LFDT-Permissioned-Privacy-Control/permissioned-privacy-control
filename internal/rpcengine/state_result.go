package rpcengine

import (
	"context"
	"encoding/json"

	"privacy-proxy/internal/creationfacts"
	"privacy-proxy/internal/nativeadmission"
	"privacy-proxy/internal/policybundle"
	"privacy-proxy/internal/rpcexecution"
	"privacy-proxy/internal/runtimepolicy"
)

type StateOperationMetadata struct {
	Method                  string
	Canonical               rpcexecution.StateMethod
	Class                   CompletionClass
	ActorID, OrganizationID string
	PolicyDigest            policybundle.Digest
	RPCErrorCode            *int32
}

// StateOperationResult keeps the original verified View or a private
// admitted-anonymous branch. It exposes no generic response or permission setter.
type StateOperationResult struct {
	owner                 *StateEngine
	view                  *runtimepolicy.View
	anonymous             bool
	observation           *rpcexecution.StateObservation
	source                rpcexecution.StateSourceMetadata
	client                *rpcexecution.StateClient
	query                 rpcexecution.StateQuery
	association           *creationfacts.AddressAssociations
	wallet                *nativeadmission.WalletSnapshot
	id                    json.RawMessage
	notification          bool
	completedNotification bool
	code                  int32
	metadata              StateOperationMetadata
}

func (r *StateOperationResult) fail(class CompletionClass, code int32) *StateOperationResult {
	r.observation = nil
	r.association = nil
	r.wallet = nil
	r.completedNotification = false
	r.code = code
	r.metadata.Class = class
	r.metadata.RPCErrorCode = &code
	return r
}
func (r *StateOperationResult) owned(e *StateEngine) bool {
	return r != nil && e != nil && e.policy != nil && r.owner == e
}
func (r *StateOperationResult) MetadataFor(e *StateEngine) (StateOperationMetadata, error) {
	if !r.owned(e) {
		return StateOperationMetadata{}, errMetadata
	}
	m := r.metadata
	if m.RPCErrorCode != nil {
		code := *m.RPCErrorCode
		m.RPCErrorCode = &code
	}
	return m, nil
}
func (r *StateOperationResult) IsNotificationFor(e *StateEngine) (bool, error) {
	if !r.owned(e) {
		return false, errMetadata
	}
	return r.notification, nil
}
func (r *StateOperationResult) preflightObservation() error {
	if r == nil || r.owner == nil || r.observation == nil || r.observation.Method() != r.metadata.Canonical || r.metadata.Canonical == rpcexecution.InvalidStateMethod || r.observation.Source() != r.source || r.observation.Query().Digest() != r.query.Digest() || r.observation.ResultSize() < 1 || r.observation.ResultSize() > r.owner.limits.MaxResultBytes {
		return errMetadata
	}
	if r.metadata.Canonical == rpcexecution.StateProof {
		presence, ok := r.observation.ProofAccountPresence()
		if !ok || !positiveStateAccount(presence) {
			return errMetadata
		}
	}
	return nil
}
func (r *StateOperationResult) PreflightFor(e *StateEngine) error {
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
	if r.wallet != nil && (e.wallets == nil || r.view == nil || r.wallet.ActorID() != r.metadata.ActorID || r.wallet.Version() == "" || !r.wallet.Contains(r.query.Target())) {
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
func (r *StateOperationResult) RequireDeliverable(ctx context.Context, e *StateEngine) error {
	if ctx == nil || ctx.Err() != nil || r.PreflightFor(e) != nil {
		return errMetadata
	}
	if r.association != nil {
		if e.associations == nil || r.client == nil || r.client.Source() != r.source || r.association.ValidateFor(e.associationMetadata.Identity, e.associationMetadata.Binding, r.query.Target()) != nil || e.associations.RecheckAddressAssociations(ctx, r.association) != nil {
			return errMetadata
		}
	}
	if r.wallet != nil {
		current, err := e.wallets.Load(ctx, r.wallet.ActorID())
		if err != nil || current.ActorID() != r.wallet.ActorID() || current.Version() != r.wallet.Version() || !current.Contains(r.query.Target()) {
			return errMetadata
		}
	}
	// Every blocking SQL check, including the original wallet recheck, precedes
	// this last sampled canonicality observation on the SAME selected client.
	if r.association != nil && r.client.RequireCanonicalHeader(ctx, r.association.ObserverHead()) != nil {
		return errMetadata
	}
	// This gate is deliberately AFTER both potentially blocking SQL and the
	// same original selected node's final ancestor-canonicality recheck.
	if ctx.Err() != nil {
		return errMetadata
	}
	if r.view != nil {
		return r.view.RequireLive()
	}
	if r.code != 0 {
		return nil
	}
	if !r.anonymous || !e.policy.AllowsAnonymous(r.metadata.Method) {
		return errMetadata
	}
	return nil
}

func (r *StateOperationResult) MarshalResponseFor(e *StateEngine) ([]byte, error) {
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
func (r *StateOperationResult) MarshalRecordingFailureFor(e *StateEngine) ([]byte, error) {
	if !r.owned(e) || len(r.id) == 0 || len(r.id) > 1<<20 {
		return nil, errMetadata
	}
	if r.notification {
		return nil, nil
	}
	return marshalMetadataWire(metadataWireResponse{JSONRPC: "2.0", ID: r.id, Error: &RPCError{Code: -32002, Message: "unavailable"}})
}
