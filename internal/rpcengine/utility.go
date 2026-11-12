package rpcengine

import (
	"context"
	"encoding/json"
	"errors"
	"sort"
	"strconv"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"privacy-proxy/internal/policybundle"
	"privacy-proxy/internal/policycore"
	"privacy-proxy/internal/rpcenvelope"
	"privacy-proxy/internal/rpcexecution"
	"privacy-proxy/internal/rpcmethoddata"
	"privacy-proxy/internal/runtimepolicy"
)

type ExecutionUtilityOptions struct {
	Limits      rpcexecution.UtilityLimits
	NodeSigning bool
}
type executionUtilityEngine struct {
	options ExecutionUtilityOptions
	methods map[string]string
}

func (e *Engine) initExecutionUtilities(options ExecutionUtilityOptions) error {
	if e == nil || e.current == nil || e.snapshot.Metadata().Profile != policybundle.RuntimeCreationObservedProfileID {
		return errOperation
	}
	if options.Limits == (rpcexecution.UtilityLimits{}) {
		options.Limits = rpcexecution.DefaultUtilityLimits()
	}
	if !options.Limits.Valid() {
		return errOperation
	}
	u := &executionUtilityEngine{options: options, methods: map[string]string{}}
	for _, decl := range e.snapshot.Methods() {
		switch decl.Canonical {
		case "eth_estimateGas", "eth_createAccessList":
		case "eth_sendTransaction":
			if !options.NodeSigning {
				continue
			}
		default:
			continue
		}
		canonical, builtin := rpcmethoddata.CanonicalBuiltin(decl.Name)
		if builtin && (canonical != decl.Canonical || decl.Name != canonical) || !builtin && !metadataAliasAllowed(decl.Name) {
			return errOperation
		}
		u.methods[decl.Name] = decl.Canonical
	}
	for _, o := range e.snapshot.Organizations() {
		for _, id := range e.snapshot.GroupIDs(o.ID) {
			g, _ := e.snapshot.Group(o.ID, id)
			for _, name := range g.AllowedMethods {
				if u.methods[name] == "" {
					continue
				}
				ref := ""
				if g.RpcCredential != nil {
					ref = g.RpcCredential.FromEnv
				}
				if _, err := e.clients[o.ID].WithCredential(ref); err != nil {
					return errOperation
				}
			}
		}
	}
	e.utilities = u
	return nil
}
func (e *Engine) UtilityOperationBinding() TraceOperationBinding {
	if e == nil || e.utilities == nil {
		return TraceOperationBinding{}
	}
	b := e.OperationBinding()
	out := TraceOperationBinding{Environment: b.Environment, ChainID: b.ChainID, Profile: b.Profile, NetworkKey: b.NetworkKey, ManifestDigest: b.ManifestDigest, OrganizationIDs: b.OrganizationIDs}
	for name := range e.utilities.methods {
		out.Methods = append(out.Methods, name)
	}
	sort.Strings(out.Methods)
	return out
}
func (e *Engine) utilityAllowed(org *runtimepolicy.OrgView, name string) bool {
	if e == nil || e.utilities == nil || e.utilities.methods[name] == "" || org == nil || !org.GroupAllowsMethod(name) {
		return false
	}
	decl, ok := e.snapshot.Method(name)
	if !ok || decl.Canonical != e.utilities.methods[name] {
		return false
	}
	for _, claim := range decl.RequiredClaims {
		mask := map[string]uint8{"admin": policycore.ClaimAdmin, "deploy": policycore.ClaimDeploy, "upgrade": policycore.ClaimUpgrade}[claim]
		if mask == 0 || org.UnionClaims()&mask == 0 {
			return false
		}
	}
	return true
}

type utilityRequest struct {
	id                json.RawMessage
	notification      bool
	method, canonical string
	call              rpcexecution.Call
	block             rpcexecution.BlockSelector
	metadata          []any
	present           bool
}

func (e *Engine) parseUtility(raw []byte) (utilityRequest, int) {
	q := utilityRequest{id: json.RawMessage("null")}
	env, err := rpcenvelope.ParseRaw(raw, rpcenvelope.DefaultLimits())
	if err != nil {
		return q, -32600
	}
	q.id, q.notification = env.IDJSON()
	q.notification = !q.notification
	if q.notification {
		q.id = json.RawMessage("null")
	}
	if v := env.VersionJSON(); len(v) > 0 {
		var s string
		if json.Unmarshal(v, &s) != nil || s != "2.0" {
			return q, -32600
		}
	}
	q.method = env.Method()
	if name, ok := rpcmethoddata.CanonicalBuiltin(q.method); ok {
		q.method = name
	}
	if e == nil || e.utilities == nil || e.utilities.methods[q.method] == "" {
		return q, -32601
	}
	q.canonical = e.utilities.methods[q.method]
	v, err := readClientTraceParams(env.ParamsJSON())
	if err != nil {
		return q, -32602
	}
	params, ok := v.([]any)
	if !ok || len(params) < 1 || len(params) > 2 {
		return q, -32602
	}
	b, _ := json.Marshal(params[0])
	q.call, err = rpcexecution.NormalizeSimulationCall(b)
	if err != nil {
		return q, -32602
	}
	var block []byte
	if q.canonical == "eth_sendTransaction" {
		root, err := readClientTraceParams(raw)
		if err != nil {
			return q, -32600
		}
		object, ok := root.(map[string]any)
		if !ok {
			return q, -32600
		}
		for _, name := range []string{"visibleTo", "privateFor"} {
			if v, ok := object[name]; ok {
				q.present = true
				q.metadata = append(q.metadata, v)
			}
		}
		if len(params) == 2 {
			options, ok := params[1].(map[string]any)
			if !ok || len(options) != 1 {
				return q, -32602
			}
			v, ok := options["visibleTo"]
			if !ok {
				return q, -32602
			}
			q.present = true
			q.metadata = append(q.metadata, v)
		}
	} else if len(params) == 2 {
		block, _ = json.Marshal(params[1])
	}
	q.block, err = rpcexecution.ParseBlockSelector(block)
	if err != nil {
		return q, -32602
	}
	return q, 0
}

func (e *Engine) UtilityObserved(parent context.Context, assertion, selected string, raw []byte) *TraceOperationResult {
	r := &TraceOperationResult{owner: e, id: json.RawMessage("null"), metadata: TraceOperationMetadata{Method: "rpc.invalid_request", Class: UnavailableCompletion}}
	if e == nil || e.utilities == nil || parent == nil || e.raw == nil || e.raw.closed.Load() {
		return r.fail(UnavailableCompletion, -32002)
	}
	holder := &OperationResult{}
	ctx, cancel, err := e.startNative(parent, holder)
	if err != nil {
		return r.fail(UnavailableCompletion, -32002)
	}
	defer cancel()
	r.fence = holder.fence
	q, code := e.parseUtility(raw)
	r.id, r.notification = q.id, q.notification
	if code != 0 {
		return r.fail(InvalidCompletion, code)
	}
	r.metadata.Method = q.method
	view, err := e.factory.Build(assertion)
	if err != nil {
		return r.fail(UnauthenticatedCompletion, -32001)
	}
	r.view = view
	r.metadata.ActorID = view.ActorID()
	r.metadata.PolicyDigest = view.Metadata().ManifestDigest
	current := e.currentPass(view)
	r.current = current
	var org string
	var ok bool
	if q.call.Creation() {
		org = selected
		if org == "" {
			ids := view.OrgIDs()
			if len(ids) == 1 {
				org = ids[0]
			}
		}
		_, ok = view.Org(org)
	} else {
		org, ok, err = current.selectOrg(ctx, selected, q.call.To())
	}
	if err != nil {
		return r.fail(UnavailableCompletion, -32002)
	}
	o, mapped := view.Org(org)
	if !ok || !mapped || !e.utilityAllowed(o, q.method) {
		return r.fail(DeniedCompletion, -32001)
	}
	r.metadata.OrganizationID = org
	if q.block.Historical() {
		admin := false
		for _, id := range view.OrgIDs() {
			v, _ := view.Org(id)
			admin = admin || v.IsOrgAdmin()
		}
		if !admin {
			return r.fail(DeniedCompletion, -32001)
		}
	}
	ref, err := o.SelectCredentialRef(q.method)
	if err != nil {
		return r.fail(DeniedCompletion, -32001)
	}
	client, err := e.clients[org].WithCredential(ref)
	if err != nil {
		return r.fail(UnavailableCompletion, -32002)
	}
	wallet, err := e.wallets.Load(ctx, view.ActorID())
	if err != nil || wallet.ActorID() != view.ActorID() {
		return r.fail(UnavailableCompletion, -32002)
	}
	r.walletVersion = wallet.Version()
	if q.call.FromSupplied() && !wallet.Contains(q.call.From()) {
		return r.fail(DeniedCompletion, -32001)
	}
	if q.canonical == "eth_sendTransaction" {
		return e.nodeOwnedObserved(ctx, q, view, org, ref, wallet, r)
	}
	session, err := client.NewUtilitySession(ctx, q.call, q.block, e.utilities.options.Limits)
	if err != nil {
		return r.fail(UnavailableCompletion, -32002)
	}
	qualify := func(gas uint64, list *types.AccessList, capture bool) (*rpcexecution.CallExecution, error) {
		x, err := session.Probe(ctx, gas, list, capture, func(target common.Address) bool {
			actual, yes, err := current.selectOrg(ctx, org, target)
			return err == nil && yes && actual == org && ctx.Err() == nil && view.RequireLive() == nil
		})
		if err != nil {
			return nil, err
		}
		if err = current.collect(ctx, x); err != nil {
			return nil, err
		}
		if err = current.requireExecution(ctx, session.DeliveryCheckpoint().Client()); err != nil {
			return nil, err
		}
		native, err := current.engine()
		if err != nil {
			return nil, err
		}
		if !native.Check(ctx, view, org, x, wallet).Allowed {
			return nil, errUtilityDenied
		}
		return x, nil
	}
	var projection []byte
	if q.canonical == "eth_estimateGas" {
		gas, err := estimateChecked(session.GasCap(), func(gas uint64) (*rpcexecution.CallExecution, error) { return qualify(gas, nil, false) })
		if err != nil {
			if err == errUtilityDenied {
				return r.fail(DeniedCompletion, -32001)
			}
			return r.fail(EvaluationFailedCompletion, -32000)
		}
		projection, _ = json.Marshal("0x" + strconv.FormatUint(gas, 16))
	} else {
		x, err := qualify(session.GasCap(), nil, true)
		if err != nil {
			return utilityError(r, err)
		}
		list, err := x.AccessList()
		if err != nil {
			return r.fail(UnavailableCompletion, -32002)
		}
		filtered := types.AccessList{}
		native, err := current.engine()
		if err != nil {
			return r.fail(UnavailableCompletion, -32002)
		}
		for _, entry := range list {
			if entry.Address == q.call.From() && len(entry.StorageKeys) == 0 {
				continue
			}
			if err := current.lookupNeeded(ctx, entry.Address, true); err != nil {
				return r.fail(UnavailableCompletion, -32002)
			}
			native, err = current.engine()
			if err != nil {
				return r.fail(UnavailableCompletion, -32002)
			}
			plain, admin := native.UtilityReadAccess(view, org, entry.Address, x)
			if !plain {
				if len(entry.StorageKeys) == 0 && wallet.Contains(entry.Address) {
					filtered = append(filtered, entry)
				}
				continue
			}
			keys := []common.Hash{}
			if methodAuthorized(e.snapshot, o, "eth_getStorageAt") {
				for _, key := range entry.StorageKeys {
					if admin || stateInfrastructureSlots[key.Hex()] {
						keys = append(keys, key)
					}
				}
			}
			filtered = append(filtered, types.AccessTuple{Address: entry.Address, StorageKeys: keys})
		}
		// Use exactly the privacy-filtered list, not the original unfiltered
		// footprint, for the real second execution and its reported gas use.
		x, err = qualify(session.GasCap(), &filtered, false)
		if err != nil {
			return utilityError(r, err)
		}
		records := x.Tree().Records()
		if len(records) == 0 {
			return r.fail(UnavailableCompletion, -32002)
		}
		out := map[string]any{"accessList": filtered, "gasUsed": "0x" + strconv.FormatUint(records[0].GasUsed, 16)}
		if records[0].Error != "" {
			out["error"] = "execution failed"
			r.metadata.Class = EvaluationFailedCompletion
		}
		projection, _ = json.Marshal(out)
	}
	if len(projection)+len(q.id)+128 > MaxObservedResponseBytes || ctx.Err() != nil || view.RequireLive() != nil {
		return r.fail(UnavailableCompletion, -32002)
	}
	r.projection = projection
	r.utility = session.DeliveryCheckpoint()
	r.source = r.utility.Client()
	if r.metadata.Class != EvaluationFailedCompletion {
		r.metadata.Class = SuccessfulCompletion
	}
	return r
}

var errUtilityDenied = errors.New("utility policy denied")

func utilityError(r *TraceOperationResult, err error) *TraceOperationResult {
	if err == errUtilityDenied {
		return r.fail(DeniedCompletion, -32001)
	}
	return r.fail(UnavailableCompletion, -32002)
}
func estimateChecked(cap uint64, probe func(uint64) (*rpcexecution.CallExecution, error)) (uint64, error) {
	x, err := probe(cap)
	if err != nil {
		return 0, err
	}
	records := x.Tree().Records()
	if len(records) == 0 || records[0].Error != "" {
		return 0, errOperation
	}
	hi := cap
	lo := uint64(20999)
	if records[0].GasUsed > 21000 && records[0].GasUsed <= cap {
		lo = records[0].GasUsed - 1
	}
	for lo+1 < hi {
		if hi-lo <= hi/100 {
			return hi, nil
		}
		mid := lo + (hi-lo)/2
		x, err = probe(mid)
		if err != nil {
			return 0, err
		}
		records = x.Tree().Records()
		if len(records) == 0 {
			return 0, errOperation
		}
		if records[0].Error != "" {
			lo = mid
		} else {
			hi = mid
		}
	}
	return hi, nil
}
