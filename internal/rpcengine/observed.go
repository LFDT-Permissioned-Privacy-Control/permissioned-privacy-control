package rpcengine

import (
	"context"
	"encoding/json"
	"errors"
	"sort"
	"strings"

	"privacy-proxy/internal/admission"
	"privacy-proxy/internal/policybundle"
	"privacy-proxy/internal/policycore"
	"privacy-proxy/internal/rpcexecution"
	"privacy-proxy/internal/runtimepolicy"
)

// CompletionClass describes the selected application operation before recording
// and wire delivery. It does not attest that a response reached its recipient.
type CompletionClass uint8

const (
	InvalidCompletion CompletionClass = iota + 1
	UnauthenticatedCompletion
	DeniedCompletion
	EvaluationFailedCompletion
	UnavailableCompletion
	UnconfirmedCompletion
	SuccessfulCompletion
)

type CapturedMethod uint8

const (
	InvalidRPCRequest CapturedMethod = iota + 1
	EthCall
	EthSendRawTransaction
)

type OperationMetadata struct {
	Method                  CapturedMethod
	Class                   CompletionClass
	ActorID, OrganizationID string
	PolicyDigest            policybundle.Digest
	RPCErrorCode            *int32
}
type OperationBinding struct {
	Environment, ChainID, Profile, NetworkKey string
	ManifestDigest                            policybundle.Digest
	Methods                                   []CapturedMethod
	OrganizationIDs                           []string
}

func (e *Engine) OperationBinding() OperationBinding {
	if e == nil || e.snapshot == nil || e.raw == nil || e.raw.admission == nil || e.raw.closed.Load() {
		return OperationBinding{}
	}
	m := e.snapshot.Metadata()
	b := OperationBinding{Environment: m.Environment, ChainID: m.ChainID, Profile: m.Profile, ManifestDigest: m.ManifestDigest, NetworkKey: e.raw.admission.Metadata().NetworkKey.String(), Methods: []CapturedMethod{EthCall, EthSendRawTransaction}}
	for _, o := range e.snapshot.Organizations() {
		b.OrganizationIDs = append(b.OrganizationIDs, o.ID)
	}
	sort.Strings(b.OrganizationIDs)
	return b
}

// OperationResult has no public response accessor: in particular a large
// canonical ID is not cloned and retained while synchronous recording blocks.
// Its metadata is informational; only its original View gates delivery.
type OperationResult struct {
	owner      *Engine
	response   Response
	view       *runtimepolicy.View
	metadata   OperationMetadata
	phase      uint8
	signedHash string
	callSource *rpcexecution.Client
}

const (
	admissionEffect uint8 = iota + 1
	guardEffect
	broadcastEffect
)

var errOperation = errors.New("invalid owned RPC operation")

const MaxObservedResponseBytes = 16 << 20

func (r *OperationResult) class(c CompletionClass) {
	if r != nil {
		r.metadata.Class = c
	}
}
func (r *OperationResult) method(m CapturedMethod) {
	if r != nil {
		r.metadata.Method = m
	}
}
func (r *OperationResult) accept(v *runtimepolicy.View) {
	if r != nil {
		r.view = v
		r.metadata.ActorID = v.ActorID()
	}
}
func (r *OperationResult) selectOrg(org string) {
	if r != nil {
		r.metadata.OrganizationID = org
		r.metadata.PolicyDigest = r.view.Metadata().ManifestDigest
	}
}
func (r *OperationResult) effect(phase uint8) {
	if r != nil {
		r.phase = phase
	}
}
func (r *OperationResult) failure(c CompletionClass, out Response) Response { r.class(c); return out }
func (r *OperationResult) finish(ctx context.Context, out Response) *OperationResult {
	r.response = out
	if out.Error != nil {
		code := int32(out.Error.Code)
		r.metadata.RPCErrorCode = &code
	}
	// The broadcast branch has already selected the submission outcome. A
	// later cancellation/expiry may withhold delivery, but cannot rewrite an
	// actual acknowledged or uncertain submission into a pre-effect failure.
	if r.phase >= broadcastEffect && (r.metadata.Class == SuccessfulCompletion || r.metadata.Class == UnconfirmedCompletion) {
		return r
	}
	if ctx.Err() != nil {
		r.metadata.Class = UnavailableCompletion
	} else if r.view != nil && r.view.RequireLive() != nil {
		r.metadata.Class = UnauthenticatedCompletion
	}
	return r
}
func (e *Engine) CallObserved(ctx context.Context, assertion, org string, raw []byte) *OperationResult {
	r := &OperationResult{owner: e, metadata: OperationMetadata{Method: InvalidRPCRequest, Class: UnavailableCompletion}}
	return r.finish(ctx, e.call(ctx, assertion, org, raw, r))
}
func (e *Engine) SubmitRawObserved(ctx context.Context, assertion, org string, raw []byte) *OperationResult {
	r := &OperationResult{owner: e, metadata: OperationMetadata{Method: InvalidRPCRequest, Class: UnavailableCompletion}}
	return r.finish(ctx, e.submitRaw(ctx, assertion, org, raw, r))
}
func (r *OperationResult) owned(e *Engine) bool { return r != nil && e != nil && r.owner == e }
func (r *OperationResult) MetadataFor(e *Engine) (OperationMetadata, error) {
	if !r.owned(e) {
		return OperationMetadata{}, errOperation
	}
	m := r.metadata
	if m.RPCErrorCode != nil {
		code := *m.RPCErrorCode
		m.RPCErrorCode = &code
	}
	return m, nil
}
func (r *OperationResult) PreflightFor(e *Engine) error {
	if !r.owned(e) {
		return errOperation
	}
	if r.view == nil && (r.response.Result != nil || r.response.Error == nil || r.response.Error.Data != nil) {
		return errOperation
	}
	if r.callSource != nil {
		network, bound := r.callSource.BoundNetwork()
		if !bound || network != e.network || r.metadata.Method != EthCall || r.view == nil {
			return errOperation
		}
	}
	return preflightResponse(r.response)
}
func (r *OperationResult) MarshalResponseFor(e *Engine) ([]byte, error) {
	if err := r.PreflightFor(e); err != nil {
		return nil, err
	}
	return marshalObserved(r.response)
}
func (r *OperationResult) RequireDeliverable(ctx context.Context, e *Engine) error {
	if !r.owned(e) || ctx == nil || ctx.Err() != nil || e.raw == nil || e.raw.closed.Load() || r.PreflightFor(e) != nil {
		return errOperation
	}
	if r.callSource != nil && r.callSource.RequireBoundNetwork(ctx) != nil {
		return errOperation
	}
	// This must remain after every potentially blocking source probe. Future
	// SQL/source rechecks also belong before the final full network sample.
	if ctx.Err() != nil || e.raw.closed.Load() {
		return errOperation
	}
	if r.view != nil {
		return r.view.RequireLive()
	}
	return r.PreflightFor(e) // Only safe fixed errors are permitted without a View.
}
func (r *OperationResult) MarshalRecordingFailureFor(e *Engine) ([]byte, error) {
	if !r.owned(e) {
		return nil, errOperation
	}
	out := responseError(r.response.ID, -32002, "unavailable")
	if r.phase >= broadcastEffect && canonicalHash(r.signedHash) {
		out = responseError(r.response.ID, -32004, "submission outcome unknown")
		out.Error.Data = map[string]string{"transactionHash": r.signedHash}
	}
	return marshalObserved(out)
}
func canonicalHex(s string) bool {
	if len(s) < 2 || len(s)%2 != 0 || !strings.HasPrefix(s, "0x") {
		return false
	}
	for _, c := range s[2:] {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}
func canonicalHash(s string) bool { return len(s) == 66 && canonicalHex(s) }

// ID comes only from the strict parser's json.Marshal(nil|string|Number).
// It is private thereafter. Bound lengths BEFORE scanning/copying/encoding.
func preflightResponse(out Response) error {
	if out.JSONRPC != "2.0" || len(out.ID) == 0 || len(out.ID) > 12<<20 || (out.Result == nil) == (out.Error == nil) {
		return errOperation
	}
	budget := MaxObservedResponseBytes - 512
	add := func(n int) bool {
		if n < 0 || n > budget {
			return false
		}
		budget -= n
		return true
	}
	if !add(len(out.ID)) {
		return errOperation
	}
	if out.Result != nil {
		if !add(len(*out.Result)) || !canonicalHex(*out.Result) {
			return errOperation
		}
		return nil
	}
	er := out.Error
	validMessage := false
	switch er.Code {
	case -32600:
		validMessage = er.Message == "invalid request"
	case -32601:
		validMessage = er.Message == "method not found"
	case -32602:
		validMessage = er.Message == "invalid params" || er.Message == "unsupported or invalid block selector" || er.Message == "visibleTo is not supported on this network"
	case -32001:
		validMessage = er.Message == "not authorized"
	case -32002:
		validMessage = er.Message == "unavailable" || er.Message == "execution unavailable"
	case -32003:
		validMessage = er.Message == "transaction blocked by compliance policy"
	case -32004:
		validMessage = er.Message == "submission outcome unknown"
	case -32000:
		validMessage = er.Message == "execution failed"
	case 3:
		validMessage = er.Message == "execution reverted"
	}
	if !validMessage {
		return errOperation
	}
	switch data := er.Data.(type) {
	case nil:
		if er.Code == 3 || er.Code == -32004 {
			return errOperation
		}
	case string:
		if er.Code != 3 {
			return errOperation
		}
		if !add(len(data)) || !canonicalHex(data) {
			return errOperation
		}
	case map[string]string:
		if er.Code != -32004 {
			return errOperation
		}
		if len(data) != 1 || !canonicalHash(data["transactionHash"]) {
			return errOperation
		}
	default:
		return errOperation
	}
	return nil
}
func marshalObserved(out Response) ([]byte, error) {
	if err := preflightResponse(out); err != nil {
		return nil, err
	}
	b, err := json.Marshal(out)
	if err != nil || len(b)+1 > MaxObservedResponseBytes {
		return nil, errOperation
	}
	return append(b, '\n'), nil
}
func nativeClass(d policycore.Decision) CompletionClass {
	if d.Allowed {
		if d.Code == "" {
			return SuccessfulCompletion
		}
		return EvaluationFailedCompletion
	}
	switch d.Code {
	case policycore.DenialNoMatchingRule, policycore.DenialArgumentConstraint, policycore.DenialMalformedCalldata, policycore.DenialOwnership, policycore.DenialValue, policycore.DenialDepth, policycore.DenialUnsupportedCreate, policycore.DenialCaller, policycore.DenialOperationalClaim:
		return DeniedCompletion
	default:
		return EvaluationFailedCompletion
	}
}

func (r *OperationResult) broadcast(hash string) {
	if r != nil {
		r.phase = broadcastEffect
		r.signedHash = hash
	}
}
func (r *OperationResult) rawFailure(id json.RawMessage, err error) Response {
	c := UnavailableCompletion
	if errors.Is(err, admission.ErrUnauthorized) {
		c = UnauthenticatedCompletion
	} else if errors.Is(err, admission.ErrForbidden) || errors.Is(err, admission.ErrConflict) {
		c = DeniedCompletion
	}
	return r.failure(c, rawFailure(id, err))
}
