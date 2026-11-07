// Package rpcengine implements the authenticated native eth_call vertical
// slice. It neither imports the legacy server nor forwards a second eth_call.
package rpcengine

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"slices"

	"privacy-proxy/internal/identity"
	"privacy-proxy/internal/nativeadmission"
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
}

func New(snapshot *policybundle.CatalogSnapshot, bindings map[string]*rpcexecution.Client, wallets WalletResolver, clock identity.Clock) (*Engine, error) {
	if snapshot == nil || clock == nil {
		return nil, errors.New("invalid RPC engine configuration")
	}
	runtime, ok := snapshot.Runtime()
	metadata := snapshot.Metadata()
	if !ok || metadata.Profile != policybundle.RuntimeCallProfileID {
		return nil, errors.New("invalid RPC engine configuration")
	}
	factory, err := runtimepolicy.NewFactory(snapshot, clock)
	if err != nil {
		return nil, errors.New("invalid RPC engine configuration")
	}
	native, err := nativeadmission.New(snapshot, clock)
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
			if g.RpcCredential != nil {
				if _, err := client.WithCredential(g.RpcCredential.FromEnv); err != nil {
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
	contract, registered := view.Contract(call.To())
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

func (e *Engine) Call(ctx context.Context, assertion, explicitOrg string, rawRequest []byte) Response {
	req, requestError := parseRequest(rawRequest)
	if requestError != nil {
		out := responseError(req.id, requestError.Code, requestError.Message)
		return out
	}
	if e == nil || ctx.Err() != nil {
		return responseError(req.id, -32002, "execution unavailable")
	}
	view, err := e.factory.Build(assertion)
	if err != nil {
		return denied(req.id)
	}
	orgID, ok := selectedOrganization(view, explicitOrg, req.call)
	if !ok {
		return denied(req.id)
	}
	org, _ := view.Org(orgID)
	if req.block.Historical() && !org.IsOrgAdmin() {
		return denied(req.id)
	}
	method, known := e.snapshot.Method("eth_call")
	if !known || method.Canonical != "eth_call" || !org.GroupAllowsMethod("eth_call") {
		return denied(req.id)
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
			return denied(req.id)
		}
		if org.UnionClaims()&mask == 0 {
			return denied(req.id)
		}
	}
	ref, err := org.SelectCredentialRef("eth_call")
	if err != nil {
		return denied(req.id)
	}
	client, err := e.clients[orgID].WithCredential(ref)
	if err != nil {
		return responseError(req.id, -32002, "execution unavailable")
	}
	var wallet nativeadmission.WalletSnapshot
	if req.call.FromSupplied() || e.needsWallets {
		if e.wallets == nil {
			return denied(req.id)
		}
		wallet, err = e.wallets.Load(ctx, view.ActorID())
		if err != nil || wallet.ActorID() != view.ActorID() {
			return denied(req.id)
		}
		if req.call.FromSupplied() && !wallet.Contains(req.call.From()) {
			return denied(req.id)
		}
	}
	if ctx.Err() != nil || view.RequireLive() != nil {
		return denied(req.id)
	}
	execution, err := client.AcquireCall(ctx, req.call, req.block)
	if err != nil {
		return responseError(req.id, -32002, "execution unavailable")
	}
	if view.RequireLive() != nil {
		return denied(req.id)
	}
	decision := e.native.Check(ctx, view, orgID, execution, wallet)
	if !decision.Allowed {
		return denied(req.id)
	}
	if ctx.Err() != nil || view.RequireLive() != nil {
		return denied(req.id)
	}
	outcome, ok := execution.Tree().Outcome()
	if !ok {
		return responseError(req.id, -32002, "execution unavailable")
	}
	if outcome.RevertReason != "" && outcome.Error != "execution reverted" {
		return responseError(req.id, -32002, "execution unavailable")
	}
	if outcome.Error == "execution reverted" {
		out := responseError(req.id, 3, "execution reverted")
		out.Error.Data = "0x" + hex.EncodeToString(outcome.Output)
		return out
	}
	if outcome.Error != "" {
		return responseError(req.id, -32000, "execution failed")
	}
	result := "0x" + hex.EncodeToString(outcome.Output)
	return Response{JSONRPC: "2.0", ID: req.id, Result: &result}
}
