// Package rpcactivity records one native RPC operation through the real local
// durable recorder before releasing protected output. It mounts no listener.
package rpcactivity

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"time"

	"privacy-proxy/internal/activitylog"
	"privacy-proxy/internal/networkidentity"
	"privacy-proxy/internal/policybundle"
	"privacy-proxy/internal/rpcengine"
	"privacy-proxy/internal/rpcmethoddata"
)

type Config struct {
	Engine   *rpcengine.Engine
	Metadata *rpcengine.MetadataEngine
	State    *rpcengine.StateEngine
	History  *rpcengine.HistoryEngine
	Recorder *activitylog.Recorder
	Network  networkidentity.Binding
}
type Service struct {
	engine         *rpcengine.Engine
	metadata       *rpcengine.MetadataEngine
	state          *rpcengine.StateEngine
	stateMethods   map[string]bool
	traceMethods   map[string]bool
	minedMethods   map[string]bool
	utilityMethods map[string]bool
	history        *rpcengine.HistoryEngine
	historyMethods map[string]bool
	recorder       *activitylog.Recorder
	organizations  []string
	slots          chan struct{}
}

var ErrInvalid = errors.New("invalid audited RPC service")
var labels = []string{"eth_call", "eth_sendRawTransaction", "rpc.invalid_request", "rpc.invalid_transport"}

func newNativeService(c Config) (*Service, error) {
	key, err := c.Network.Key()
	if err != nil || c.Engine == nil || c.Recorder == nil || c.Recorder.Healthy() != nil {
		return nil, ErrInvalid
	}
	binding := c.Engine.OperationBinding()
	m := c.Recorder.Metadata()
	n := c.Recorder.Bounds()
	if binding.Profile != policybundle.RuntimeCreationObservedProfileID || binding.Environment != c.Network.Environment || binding.ChainID != c.Network.ChainID || binding.NetworkKey != "sha256:"+hex.EncodeToString(key[:]) || m.NetworkKey != activitylog.Digest(key) || m.Format != activitylog.Format() || !activitylog.CanonicalUUID(m.SourceID) || !activitylog.CanonicalUUID(m.Generation) || m.Configuration == (activitylog.Digest{}) || !n.Valid() || len(binding.OrganizationIDs) == 0 || len(binding.ManifestDigest) != 71 || !slices.Equal(binding.Methods, []rpcengine.CapturedMethod{rpcengine.EthCall, rpcengine.EthSendRawTransaction}) {
		return nil, ErrInvalid
	}
	trace := c.Engine.TraceOperationBinding()
	traceNames := map[string]bool{}
	if len(trace.Methods) > 0 {
		if trace.Profile != binding.Profile || trace.ManifestDigest != binding.ManifestDigest || trace.NetworkKey != binding.NetworkKey || trace.ChainID != binding.ChainID || trace.Environment != binding.Environment || !slices.Equal(trace.OrganizationIDs, binding.OrganizationIDs) {
			return nil, ErrInvalid
		}
		for _, name := range trace.Methods {
			if !activitylog.ValidMethod(name) {
				return nil, ErrInvalid
			}
			traceNames[name] = true
		}
	}
	mined := c.Engine.MinedTraceOperationBinding()
	minedNames := map[string]bool{}
	if len(mined.Methods) > 0 {
		if mined.Profile != binding.Profile || mined.ManifestDigest != binding.ManifestDigest || mined.NetworkKey != binding.NetworkKey || mined.ChainID != binding.ChainID || mined.Environment != binding.Environment || !slices.Equal(mined.OrganizationIDs, binding.OrganizationIDs) {
			return nil, ErrInvalid
		}
		for _, name := range mined.Methods {
			if !activitylog.ValidMethod(name) {
				return nil, ErrInvalid
			}
			minedNames[name] = true
		}
	}
	utility := c.Engine.UtilityOperationBinding()
	utilityNames := map[string]bool{}
	if len(utility.Methods) > 0 {
		if utility.Profile != binding.Profile || utility.ManifestDigest != binding.ManifestDigest || utility.NetworkKey != binding.NetworkKey || utility.ChainID != binding.ChainID || utility.Environment != binding.Environment || !slices.Equal(utility.OrganizationIDs, binding.OrganizationIDs) {
			return nil, ErrInvalid
		}
		for _, name := range utility.Methods {
			if !activitylog.ValidMethod(name) {
				return nil, ErrInvalid
			}
			utilityNames[name] = true
		}
	}
	methods := c.Recorder.Methods()
	for _, label := range labels {
		if !slices.Contains(methods, label) {
			return nil, ErrInvalid
		}
	}
	for name := range traceNames {
		if !slices.Contains(methods, name) {
			return nil, ErrInvalid
		}
	}
	for name := range minedNames {
		if !slices.Contains(methods, name) {
			return nil, ErrInvalid
		}
	}
	for name := range utilityNames {
		if !slices.Contains(methods, name) {
			return nil, ErrInvalid
		}
	}
	return &Service{engine: c.Engine, utilityMethods: utilityNames, minedMethods: minedNames, traceMethods: traceNames, recorder: c.Recorder, organizations: slices.Clone(binding.OrganizationIDs), slots: make(chan struct{}, n.InFlight)}, nil
}
func (s *Service) Handler(selectedOrg string) (http.Handler, error) {
	if s == nil || selectedOrg != "" && !slices.Contains(s.organizations, selectedOrg) {
		return nil, ErrInvalid
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { s.serve(w, r, selectedOrg) }), nil
}

var busy = []byte("{\"jsonrpc\":\"2.0\",\"id\":null,\"error\":{\"code\":-32002,\"message\":\"unavailable\"}}\n")
var badTransport = []byte("{\"jsonrpc\":\"2.0\",\"id\":null,\"error\":{\"code\":-32600,\"message\":\"invalid request\"}}\n")

func write(w http.ResponseWriter, status int, body []byte) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = w.Write(body)
}
func peer(remote string) string {
	host, _, err := net.SplitHostPort(remote)
	if err != nil {
		return ""
	}
	ip, err := netip.ParseAddr(host)
	if err != nil || ip.Zone() != "" {
		return ""
	}
	return ip.Unmap().String()
}
func category(c rpcengine.CompletionClass) activitylog.Outcome {
	switch c {
	case rpcengine.InvalidCompletion:
		return activitylog.Invalid
	case rpcengine.UnauthenticatedCompletion:
		return activitylog.Unauthenticated
	case rpcengine.DeniedCompletion:
		return activitylog.Denied
	case rpcengine.EvaluationFailedCompletion:
		return activitylog.EvaluationFailed
	case rpcengine.UnconfirmedCompletion:
		return activitylog.Unconfirmed
	case rpcengine.SuccessfulCompletion:
		return activitylog.Success
	default:
		return activitylog.Unavailable
	}
}
func completion(m rpcengine.OperationMetadata, remote string) (activitylog.Completion, error) {
	c := activitylog.Completion{ActorID: m.ActorID, DataOrganizationID: m.OrganizationID, HTTPStatus: 200, RPCErrorCode: m.RPCErrorCode, Outcome: category(m.Class), TrustedIP: peer(remote), Method: "rpc.invalid_request"}
	switch m.Method {
	case rpcengine.EthCall:
		c.Method = "eth_call"
	case rpcengine.EthSendRawTransaction:
		c.Method = "eth_sendRawTransaction"
	}
	if m.PolicyDigest != "" {
		raw := string(m.PolicyDigest)
		if len(raw) != 71 || !strings.HasPrefix(raw, "sha256:") {
			return c, ErrInvalid
		}
		b, err := hex.DecodeString(raw[7:])
		if err != nil || len(b) != 32 {
			return c, ErrInvalid
		}
		copy(c.PolicyDigest[:], b)
	}
	return c, nil
}
func (s *Service) serve(w http.ResponseWriter, r *http.Request, org string) {
	// Even a busy rejection may block on socket/HTTP2 flow control. Establish
	// its original write deadline before the admission decision and first byte.
	deadline := time.Now().Add(20 * time.Second)
	if d, ok := r.Context().Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	controller := http.NewResponseController(w)
	if controller.SetWriteDeadline(deadline) != nil {
		write(w, 503, busy)
		return
	}
	select {
	case s.slots <- struct{}{}:
		defer func() { <-s.slots }()
	default:
		write(w, 503, busy)
		return
	}
	if controller.SetReadDeadline(deadline) != nil {
		write(w, 503, busy)
		return
	}
	ctx, cancel := context.WithDeadline(r.Context(), deadline)
	defer cancel()
	slot, err := s.recorder.Reserve()
	if err != nil {
		write(w, 503, busy)
		return
	}
	// Every successful reservation is completed once. No I/O retry or background
	// replacement can release its credit before the actual Append returns.
	transport := func(status int) {
		code := int32(-32600)
		_, err := slot.Complete(activitylog.Completion{Method: "rpc.invalid_transport", TrustedIP: peer(r.RemoteAddr), HTTPStatus: uint16(status), RPCErrorCode: &code, Outcome: activitylog.Invalid})
		if err != nil {
			write(w, 503, busy)
			return
		}
		write(w, status, badTransport)
	}
	if r.Method != http.MethodPost {
		transport(405)
		return
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, rpcengine.MaxRawRequestBytes+1))
	if err != nil || len(raw) > rpcengine.MaxRawRequestBytes {
		transport(400)
		return
	}
	assertion := ""
	if values := r.Header.Values("Authorization"); len(values) == 1 {
		parts := strings.Split(values[0], " ")
		if len(parts) == 2 && strings.EqualFold(parts[0], "Bearer") {
			assertion = parts[1]
		}
	}
	var route struct {
		Method string `json:"method"`
	}
	var result observedOperation
	decoded := json.Unmarshal(raw, &route) == nil
	stateMethod := route.Method
	if canonical, known := rpcmethoddata.CanonicalBuiltin(stateMethod); known {
		stateMethod = canonical
	}
	if decoded && s.engine != nil && s.utilityMethods[stateMethod] {
		result.trace = s.engine.UtilityObserved(ctx, assertion, org, raw)
	} else if decoded && s.engine != nil && s.minedMethods[stateMethod] {
		result.mined = s.engine.TraceTransactionObserved(ctx, assertion, org, raw)
	} else if decoded && s.engine != nil && s.traceMethods[stateMethod] {
		result.trace = s.engine.TraceCallObserved(ctx, assertion, org, raw)
	} else if decoded && s.history != nil && s.historyMethods[stateMethod] {
		result.history = s.history.QueryObserved(ctx, rpcengine.MetadataAuthorization(r.Header.Values("Authorization")), org, raw)
	} else if decoded && s.state != nil && s.stateMethods[stateMethod] {
		result.state = s.state.QueryObserved(ctx, rpcengine.MetadataAuthorization(r.Header.Values("Authorization")), org, raw)
	} else if s.metadata != nil && (s.engine == nil || !decoded || route.Method != "eth_call" && route.Method != "eth_sendRawTransaction") {
		result.metadata = s.metadata.QueryObserved(ctx, rpcengine.MetadataAuthorization(r.Header.Values("Authorization")), org, raw)
	} else if s.engine != nil && decoded && route.Method == "eth_sendRawTransaction" {
		result.native = s.engine.SubmitRawObserved(ctx, assertion, org, raw)
	} else if s.engine != nil {
		result.native = s.engine.CallObserved(ctx, assertion, org, raw)
	} else if s.history != nil {
		result.history = s.history.QueryObserved(ctx, rpcengine.MetadataAuthorization(r.Header.Values("Authorization")), org, raw)
	} else {
		result.state = s.state.QueryObserved(ctx, rpcengine.MetadataAuthorization(r.Header.Values("Authorization")), org, raw)
	}
	raw = nil
	assertion = ""
	notification, notificationErr := result.notification(s)
	respond := func(status int, body []byte) {
		if notification {
			body = nil
		}
		write(w, status, body)
	}
	c, completionErr := result.completion(s, r.RemoteAddr)
	preflightErr := result.preflight(s)
	if notificationErr != nil || completionErr != nil || preflightErr != nil {
		// An internal invalid response still settles the reservation; it cannot
		// publish data or be retried. Existing captured outcome is never rewritten.
		_, _ = slot.Complete(c)
		respond(503, busy)
		return
	}
	if _, err := slot.Complete(c); err != nil {
		body, failureErr := result.recordingFailure(s)
		if failureErr != nil {
			respond(503, busy)
		} else {
			respond(503, body)
		}
		return
	}
	body, err := result.marshal(s)
	if err != nil {
		respond(503, busy)
		return
	}
	if err := result.deliver(ctx, s); err != nil {
		body = nil
		body, err = result.recordingFailure(s)
		if err != nil {
			respond(503, busy)
		} else {
			respond(503, body)
		}
		return
	}
	respond(200, body)
}
