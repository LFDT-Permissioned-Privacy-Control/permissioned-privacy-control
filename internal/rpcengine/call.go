// Package rpcengine implements authenticated native simulations and signed raw
// admission. It neither imports the legacy server nor issues a second eth_call.
package rpcengine

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"slices"

	"github.com/ethereum/go-ethereum/common"

	"privacy-proxy/internal/identity"
	"privacy-proxy/internal/nativeadmission"
	"privacy-proxy/internal/networkidentity"
	"privacy-proxy/internal/policybundle"
	"privacy-proxy/internal/policycore"
	"privacy-proxy/internal/rpcexecution"
	"privacy-proxy/internal/runtimepolicy"
)

type RPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}
type Response struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  *string         `json:"result,omitempty"`
	Error   *RPCError       `json:"error,omitempty"`
}
type WalletResolver interface {
	Load(context.Context, string) (nativeadmission.WalletSnapshot, error)
}
type Engine struct {
	snapshot     *policybundle.CatalogSnapshot
	factory      *runtimepolicy.Factory
	native       *nativeadmission.Engine
	clients      map[string]*rpcexecution.Client
	wallets      WalletResolver
	needsWallets bool
	raw          *rawEngine
	network      networkidentity.Binding
	current      *nativeAddressSource
	traceMethods map[string]bool
}

func New(snapshot *policybundle.CatalogSnapshot, bindings map[string]*rpcexecution.Client, wallets WalletResolver, clock identity.Clock) (*Engine, error) {
	return newEngine(snapshot, bindings, wallets, clock, policybundle.RuntimeCallProfileID)
}

func newEngine(snapshot *policybundle.CatalogSnapshot, bindings map[string]*rpcexecution.Client, wallets WalletResolver, clock identity.Clock, expectedProfile string) (*Engine, error) {
	if snapshot == nil || clock == nil {
		return nil, errors.New("invalid RPC engine configuration")
	}
	runtime, ok := snapshot.Runtime()
	metadata := snapshot.Metadata()
	raw := expectedProfile != policybundle.RuntimeCallProfileID
	if !ok || metadata.Profile != expectedProfile {
		return nil, errors.New("invalid RPC engine configuration")
	}
	factory, err := runtimepolicy.NewFactory(snapshot, clock)
	if err != nil {
		return nil, errors.New("invalid RPC engine configuration")
	}
	newNative := nativeadmission.New
	if raw {
		newNative = nativeadmission.NewRaw
	}
	if expectedProfile == policybundle.RuntimeMultiOrgProfileID {
		newNative = nativeadmission.NewMultiOrg
	}
	if expectedProfile == policybundle.RuntimeLifecycleProfileID {
		newNative = nativeadmission.NewLifecycle
	}
	if expectedProfile == policybundle.RuntimeSimulationProfileID {
		newNative = nativeadmission.NewSimulation
	}
	if expectedProfile == policybundle.RuntimeCreationIntentProfileID {
		newNative = nativeadmission.NewCreationIntents
	}
	if expectedProfile == policybundle.RuntimeCreationObservedProfileID {
		newNative = nativeadmission.NewCreationObserved
	}
	native, err := newNative(snapshot, clock)
	if err != nil {
		return nil, errors.New("invalid RPC engine configuration")
	}
	e := &Engine{snapshot: snapshot, factory: factory, native: native, clients: make(map[string]*rpcexecution.Client, len(bindings)), wallets: wallets, needsWallets: slices.Contains(snapshot.Requirements().Capabilities, policybundle.CapabilityLinkedWallets)}
	if e.needsWallets && wallets == nil {
		return nil, errors.New("wallet resolver required")
	}
	if len(bindings) != len(snapshot.Organizations()) {
		return nil, errors.New("invalid node bindings")
	}
	for _, org := range snapshot.Organizations() {
		client := bindings[org.ID]
		if client == nil {
			return nil, errors.New("invalid node bindings")
		}
		binding := client.Metadata()
		if binding.OrganizationID != org.ID || binding.ChainID != metadata.ChainID || binding.Profile != runtime.NodeEvidenceProfile() {
			return nil, errors.New("invalid node bindings")
		}
		catalog, ok := snapshot.NativeCatalog(org.ID)
		if !ok {
			return nil, errors.New("invalid node bindings")
		}
		for group := range catalog.Groups {
			g, ok := snapshot.Group(org.ID, group)
			if !ok {
				return nil, errors.New("invalid RPC engine configuration")
			}
			if raw && !slices.Contains(g.AllowedMethods, "eth_call") {
				continue
			}
			if g.RpcCredential != nil {
				if _, err := client.WithCredential(g.RpcCredential.FromEnv); err != nil {
					return nil, errors.New("unbound RPC credential")
				}
			} else if raw {
				if _, err := client.WithCredential(""); err != nil {
					return nil, errors.New("unbound RPC credential")
				}
			}
		}
		e.clients[org.ID] = client
	}
	return e, nil
}

func denied(id json.RawMessage) Response { return responseError(id, -32001, "not authorized") }
func responseError(id json.RawMessage, code int, message string) Response {
	if len(id) == 0 {
		id = json.RawMessage("null")
	}
	return Response{JSONRPC: "2.0", ID: id, Error: &RPCError{Code: code, Message: message}}
}

func selectedOrganization(view *runtimepolicy.View, explicit string, call rpcexecution.Call) (string, bool) {
	return selectedAddressOrganization(view, explicit, call.To())
}

func selectedAddressOrganization(view *runtimepolicy.View, explicit string, address common.Address) (string, bool) {
	contract, registered := view.Contract(address)
	if explicit != "" {
		if _, ok := view.Org(explicit); !ok {
			return "", false
		}
		if registered && contract.OwnerOrg() != explicit {
			return "", false
		}
		return explicit, true
	}
	if registered {
		owner := contract.OwnerOrg()
		_, ok := view.Org(owner)
		return owner, ok
	}
	ids := view.OrgIDs()
	if len(ids) != 1 {
		return "", false
	}
	return ids[0], true
}

func methodAuthorized(snapshot *policybundle.CatalogSnapshot, org *runtimepolicy.OrgView, name string) bool {
	method, known := snapshot.Method(name)
	if !known || method.Canonical != name || !org.GroupAllowsMethod(name) {
		return false
	}
	for _, claim := range method.RequiredClaims {
		mask := uint8(0)
		switch claim {
		case "admin":
			mask = policycore.ClaimAdmin
		case "deploy":
			mask = policycore.ClaimDeploy
		case "upgrade":
			mask = policycore.ClaimUpgrade
		default:
			return false
		}
		if org.UnionClaims()&mask == 0 {
			return false
		}
	}
	return true
}

func (e *Engine) Call(ctx context.Context, assertion, explicitOrg string, rawRequest []byte) Response {
	return e.call(ctx, assertion, explicitOrg, rawRequest, nil)
}

func (e *Engine) call(ctx context.Context, assertion, explicitOrg string, rawRequest []byte, observation *OperationResult) Response {
	ctx, cancel, operationErr := e.startNative(ctx, observation)
	if operationErr != nil {
		return responseError(nil, -32002, "execution unavailable")
	}
	defer cancel()
	parse := parseRequest
	if e != nil && e.snapshot != nil && simulationProfile(e.snapshot.Metadata().Profile) {
		parse = parseSimulationRequest
	}
	req, requestError := parse(rawRequest)
	if requestError != nil {
		out := responseError(req.id, requestError.Code, requestError.Message)
		return observation.failure(InvalidCompletion, out)
	}
	observation.method(EthCall)
	if e == nil || e.snapshot == nil || ctx.Err() != nil || (e.raw != nil && e.raw.closed.Load()) {
		return responseError(req.id, -32002, "execution unavailable")
	}
	view, err := e.factory.Build(assertion)
	if err != nil {
		return observation.failure(UnauthenticatedCompletion, denied(req.id))
	}
	observation.accept(view)
	if len(view.OrgIDs()) == 0 {
		return observation.failure(DeniedCompletion, denied(req.id))
	}
	current := e.currentPass(view)
	var orgID string
	var ok bool
	if req.call.Creation() {
		orgID = explicitOrg
		if orgID == "" {
			ids := view.OrgIDs()
			if len(ids) == 1 {
				orgID = ids[0]
			}
		}
		_, ok = view.Org(orgID)
	} else {
		if current != nil {
			orgID, ok, err = current.selectOrg(ctx, explicitOrg, req.call.To())
			if err != nil {
				return responseError(req.id, -32002, "execution unavailable")
			}
		} else {
			orgID, ok = selectedOrganization(view, explicitOrg, req.call)
		}
	}
	if !ok {
		return observation.failure(DeniedCompletion, denied(req.id))
	}
	observation.selectOrg(orgID)
	org, _ := view.Org(orgID)
	if req.block.Historical() && !org.IsOrgAdmin() {
		return observation.failure(DeniedCompletion, denied(req.id))
	}
	if !methodAuthorized(e.snapshot, org, "eth_call") {
		return observation.failure(DeniedCompletion, denied(req.id))
	}
	ref, err := org.SelectCredentialRef("eth_call")
	if err != nil {
		return observation.failure(DeniedCompletion, denied(req.id))
	}
	client, err := e.clients[orgID].WithCredential(ref)
	if err != nil {
		return responseError(req.id, -32002, "execution unavailable")
	}
	var wallet nativeadmission.WalletSnapshot
	if req.call.FromSupplied() || e.needsWallets {
		if e.wallets == nil {
			return observation.failure(DeniedCompletion, denied(req.id))
		}
		wallet, err = e.wallets.Load(ctx, view.ActorID())
		if err != nil || wallet.ActorID() != view.ActorID() {
			return observation.failure(UnavailableCompletion, denied(req.id))
		}
		if req.call.FromSupplied() && !wallet.Contains(req.call.From()) {
			return observation.failure(DeniedCompletion, denied(req.id))
		}
	}
	if ctx.Err() != nil || view.RequireLive() != nil {
		return observation.failure(DeniedCompletion, denied(req.id))
	}
	var execution *rpcexecution.CallExecution
	var scopeSourceErr error
	if simulationProfile(e.snapshot.Metadata().Profile) {
		execution, err = client.AcquireSimulationCall(ctx, req.call, req.block, func(destination common.Address) bool {
			var actual string
			var matched bool
			if current != nil {
				actual, matched, scopeSourceErr = current.selectOrg(ctx, explicitOrg, destination)
			} else {
				actual, matched = selectedAddressOrganization(view, explicitOrg, destination)
			}
			return matched && actual == orgID && ctx.Err() == nil && view.RequireLive() == nil
		})
	} else {
		acquire := client.AcquireCall
		if e.snapshot.Metadata().Profile == policybundle.RuntimeLifecycleProfileID {
			acquire = client.AcquireLifecycleCall
		}
		execution, err = acquire(ctx, req.call, req.block)
	}
	if err != nil {
		var category *rpcexecution.Error
		if scopeSourceErr == nil && errors.As(err, &category) && category.Code == rpcexecution.RootScopeDenied {
			return observation.failure(DeniedCompletion, denied(req.id))
		}
		return responseError(req.id, -32002, "execution unavailable")
	}
	if req.call.Creation() {
		creation, known := execution.CreationContext(0)
		if !known || !creation.Address.Known {
			return responseError(req.id, -32002, "execution unavailable")
		}
		var actual string
		var matched bool
		if current != nil {
			actual, matched, err = current.selectOrg(ctx, explicitOrg, creation.Address.Value)
			if err != nil {
				return responseError(req.id, -32002, "execution unavailable")
			}
		} else {
			actual, matched = selectedAddressOrganization(view, explicitOrg, creation.Address.Value)
		}
		if !matched || actual != orgID {
			return observation.failure(DeniedCompletion, denied(req.id))
		}
	}
	if view.RequireLive() != nil {
		return observation.failure(DeniedCompletion, denied(req.id))
	}
	native := e.native
	if current != nil {
		if current.collect(ctx, execution) != nil {
			return responseError(req.id, -32002, "execution unavailable")
		}
		if current.requireExecution(ctx, client) != nil {
			return responseError(req.id, -32002, "execution unavailable")
		}
		native, err = current.engine()
		if err != nil {
			return observation.failure(DeniedCompletion, denied(req.id))
		}
	}
	decision := native.Check(ctx, view, orgID, execution, wallet)
	if !decision.Allowed {
		return observation.failure(nativeClass(decision), denied(req.id))
	}
	if _, bound := client.BoundNetwork(); bound {
		if observation != nil {
			// Retain only the small original source, not its execution tree or
			// raw mux while the real Recorder append may block.
			observation.callSource = client
			observation.current = current
		} else if current != nil && current.requireCall(ctx, e, client) != nil || current == nil && client.RequireBoundNetwork(ctx) != nil {
			return responseError(req.id, -32002, "execution unavailable")
		}
	}
	if ctx.Err() != nil || view.RequireLive() != nil {
		return observation.failure(DeniedCompletion, denied(req.id))
	}
	outcome, ok := execution.Tree().Outcome()
	if !ok {
		return responseError(req.id, -32002, "execution unavailable")
	}
	if outcome.RevertReason != "" && outcome.Error != "execution reverted" {
		return responseError(req.id, -32002, "execution unavailable")
	}
	if outcome.Error == "execution reverted" {
		observation.class(EvaluationFailedCompletion)
		out := responseError(req.id, 3, "execution reverted")
		out.Error.Data = "0x" + hex.EncodeToString(outcome.Output)
		return out
	}
	if outcome.Error != "" {
		return observation.failure(EvaluationFailedCompletion, responseError(req.id, -32000, "execution failed"))
	}
	observation.class(SuccessfulCompletion)
	result := "0x" + hex.EncodeToString(outcome.Output)
	return Response{JSONRPC: "2.0", ID: req.id, Result: &result}
}
