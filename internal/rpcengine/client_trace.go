package rpcengine

import (
	"context"
	"encoding/json"
	"github.com/ethereum/go-ethereum/common"
	"privacy-proxy/internal/executionfacts"
	"privacy-proxy/internal/nativeadmission"
	"privacy-proxy/internal/policybundle"
	"privacy-proxy/internal/policycore"
	"privacy-proxy/internal/rpcexecution"
	"privacy-proxy/internal/rpcmethoddata"
	"privacy-proxy/internal/runtimepolicy"
	"privacy-proxy/internal/tracer"
	"sort"
	"strings"
)

type TraceOperationBinding struct {
	Environment, ChainID, Profile, NetworkKey string
	ManifestDigest                            policybundle.Digest
	Methods, OrganizationIDs                  []string
}

func (e *Engine) TraceOperationBinding() TraceOperationBinding {
	if e == nil || e.raw == nil || e.raw.closed.Load() || e.current == nil {
		return TraceOperationBinding{}
	}
	b := e.OperationBinding()
	out := TraceOperationBinding{Environment: b.Environment, ChainID: b.ChainID, Profile: b.Profile, NetworkKey: b.NetworkKey, ManifestDigest: b.ManifestDigest, OrganizationIDs: b.OrganizationIDs}
	for name := range e.traceMethods {
		out.Methods = append(out.Methods, name)
	}
	sort.Strings(out.Methods)
	return out
}
func (e *Engine) initClientTrace() error {
	if e.current == nil {
		return nil
	}
	e.traceMethods = map[string]bool{}
	for _, m := range e.snapshot.Methods() {
		if m.Canonical != "debug_traceCall" {
			continue
		}
		c, builtin := rpcmethoddata.CanonicalBuiltin(m.Name)
		if builtin && (c != "debug_traceCall" || m.Name != c) || !builtin && !metadataAliasAllowed(m.Name) {
			return errOperation
		}
		e.traceMethods[m.Name] = true
	}
	enabled := false
	for _, o := range e.snapshot.Organizations() {
		for _, id := range e.snapshot.GroupIDs(o.ID) {
			g, _ := e.snapshot.Group(o.ID, id)
			for _, name := range g.AllowedMethods {
				if !e.traceMethods[name] {
					continue
				}
				if !clientTraceLimits(e.clients[o.ID].AcquisitionLimits()) {
					return errOperation
				}
				enabled = true
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
	if !enabled {
		e.traceMethods = nil
	}
	return nil
}
func (e *Engine) traceMethodAuthorized(org *runtimepolicy.OrgView, name string) bool {
	m, known := e.snapshot.Method(name)
	if !known || m.Canonical != "debug_traceCall" || !org.GroupAllowsMethod(name) {
		return false
	}
	// Alias claims were compiled from the canonical declaration by policybundle.
	for _, claim := range m.RequiredClaims {
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
func (e *Engine) TraceCallObserved(ctx context.Context, assertion, selectedOrg string, raw []byte) *TraceOperationResult {
	r := &TraceOperationResult{owner: e, id: json.RawMessage("null"), metadata: TraceOperationMetadata{Method: "rpc.invalid_request", Class: UnavailableCompletion}}
	// Reuse original fence construction, never a canceled acquisition child.
	holder := &OperationResult{}
	child, cancel, err := e.startNative(ctx, holder)
	if err != nil {
		return r.fail(UnavailableCompletion, -32002)
	}
	defer cancel()
	r.fence = holder.fence
	ctx = child
	q, code := e.parseClientTrace(raw)
	r.id = q.id
	r.notification = q.notification
	if code != 0 {
		return r.fail(InvalidCompletion, code)
	}
	r.metadata.Method = q.method
	if clientTraceMulticall(q.call.To(), q.call.Input()) {
		return r.fail(DeniedCompletion, -32001)
	}
	if e == nil || e.current == nil || e.raw == nil || e.raw.closed.Load() {
		return r.fail(UnavailableCompletion, -32002)
	}
	view, err := e.factory.Build(assertion)
	if err != nil {
		return r.fail(UnauthenticatedCompletion, -32001)
	}
	r.view = view
	r.metadata.ActorID = view.ActorID()
	current := e.currentPass(view)
	orgID, ok := selectedOrg, false
	if q.call.Creation() {
		if orgID == "" {
			ids := view.OrgIDs()
			if len(ids) == 1 {
				orgID = ids[0]
			}
		}
		_, ok = view.Org(orgID)
	} else {
		orgID, ok, err = current.selectOrg(ctx, selectedOrg, q.call.To())
		if err != nil {
			return r.fail(UnavailableCompletion, -32002)
		}
	}
	if !ok {
		return r.fail(DeniedCompletion, -32001)
	}
	org, _ := view.Org(orgID)
	r.metadata.OrganizationID = orgID
	r.metadata.PolicyDigest = view.Metadata().ManifestDigest
	if q.block.Historical() {
		admin := false
		for _, id := range view.OrgIDs() {
			o, _ := view.Org(id)
			admin = admin || o.IsOrgAdmin()
		}
		if !admin {
			return r.fail(DeniedCompletion, -32001)
		}
	}
	if !e.traceMethodAuthorized(org, q.method) {
		return r.fail(DeniedCompletion, -32001)
	}
	ref, err := org.SelectCredentialRef(q.method)
	if err != nil {
		return r.fail(DeniedCompletion, -32001)
	}
	client, err := e.clients[orgID].WithCredential(ref)
	if err != nil {
		return r.fail(UnavailableCompletion, -32002)
	}
	var wallets nativeadmission.WalletSnapshot
	if q.call.FromSupplied() || e.native.ClientTraceNeedsWallets(view, orgID) {
		if e.wallets == nil {
			return r.fail(UnavailableCompletion, -32002)
		}
		wallets, err = e.wallets.Load(ctx, view.ActorID())
		if err != nil || wallets.ActorID() != view.ActorID() {
			return r.fail(UnavailableCompletion, -32002)
		}
		if q.call.FromSupplied() && !wallets.Contains(q.call.From()) {
			return r.fail(DeniedCompletion, -32001)
		}
	}
	execution, err := client.AcquireSimulationCall(ctx, q.call, q.block, func(a common.Address) bool {
		actual, matched, scopeErr := current.selectOrg(ctx, selectedOrg, a)
		return scopeErr == nil && matched && actual == orgID && ctx.Err() == nil && view.RequireLive() == nil
	})
	if err != nil {
		return r.fail(UnavailableCompletion, -32002)
	}
	if q.call.Creation() {
		c, known := execution.CreationContext(0)
		if !known || !c.Address.Known {
			return r.fail(UnavailableCompletion, -32002)
		}
		actual, matched, err := current.selectOrg(ctx, selectedOrg, c.Address.Value)
		if err != nil {
			return r.fail(UnavailableCompletion, -32002)
		}
		if !matched || actual != orgID {
			return r.fail(DeniedCompletion, -32001)
		}
	}
	if current.collect(ctx, execution) != nil {
		return r.fail(UnavailableCompletion, -32002)
	}
	// All same-org storage grant lookups, including fallback associations, are
	// deduplicated in the same original point-read cache as native execution.
	for _, record := range execution.Tree().Records() {
		a := record.StorageAddress.Value
		if record.Kind == executionfacts.SelfDestruct || record.Kind == executionfacts.Create || record.Kind == executionfacts.Create2 {
			a = record.To.Value
		}
		if a != (common.Address{}) && !clientTracePublic(a) {
			if current.lookupNeeded(ctx, a, true) != nil {
				return r.fail(UnavailableCompletion, -32002)
			}
		}
	}

	if current.requireExecution(ctx, client) != nil {
		return r.fail(UnavailableCompletion, -32002)
	}
	native, err := current.engine()
	if err != nil {
		return r.fail(UnavailableCompletion, -32002)
	}
	if !native.CheckClientTrace(ctx, view, orgID, execution, wallets).Allowed {
		return r.fail(DeniedCompletion, -32001)
	}
	readable := map[string]bool{}
	if methodAuthorized(e.snapshot, org, "eth_getStorageAt") {
		facts, err := native.ClientTracePrivateStorage(view, orgID, execution)
		if err != nil {
			return r.fail(UnavailableCompletion, -32002)
		}
		for a, yes := range facts {
			readable[strings.ToLower(a.Hex())] = yes
		}
	}
	childJSON, err := execution.CallTraceJSON()
	if err != nil {
		return r.fail(UnavailableCompletion, -32002)
	}
	budget := MaxObservedResponseBytes - len(r.id) - 128
	sanitized, _, err := tracer.ParseStrictCallTraceBounded(childJSON, budget)
	if err != nil {
		return r.fail(UnavailableCompletion, -32002)
	}
	projection, err := tracer.RedactStrictCallTraceBounded(sanitized, readable, budget)
	if err != nil {
		return r.fail(UnavailableCompletion, -32002)
	}
	outcome, known := execution.Tree().Outcome()
	if !known {
		return r.fail(UnavailableCompletion, -32002)
	}
	// No raw child/mux/execution is reachable from the observed delivery result.
	r.projection = projection
	r.source = client
	r.current = current
	if wallets.Version() != "" {
		r.walletVersion = wallets.Version()
	}
	r.metadata.Class = SuccessfulCompletion
	if outcome.Error != "" {
		r.metadata.Class = EvaluationFailedCompletion
	}
	if ctx.Err() != nil || view.RequireLive() != nil {
		return r.fail(UnavailableCompletion, -32002)
	}
	return r
}

func clientTracePublic(a common.Address) bool {
	for _, b := range a[:19] {
		if b != 0 {
			return false
		}
	}
	return a[19] > 0 && a[19] <= 9
}
func clientTraceMulticall(a common.Address, input []byte) bool {
	known := false
	for _, s := range []string{"0xca11bde05977b3631167028862be2a173976ca11", "0x5ba1e12693dc8f9c48aad8770482f4739beed696", "0xeefba1e63905ef1d7acba5a8513c70307c1ce441"} {
		known = known || a == common.HexToAddress(s)
	}
	if !known || len(input) < 4 {
		return false
	}
	for _, s := range []string{"252dba42", "82ad56cb", "174dea71", "c3077fa9", "bce38bd7", "399542e9"} {
		if common.Bytes2Hex(input[:4]) == s {
			return true
		}
	}
	return false
}

// Client constructors allow independently selected engineering limits for old
// purposes. N2's public size/work contract is lower-only against its defaults.
func clientTraceLimits(l rpcexecution.Limits) bool {
	d := rpcexecution.DefaultLimits()
	a, b := l.Trace, d.Trace
	return l.MaxMuxBytes <= d.MaxMuxBytes && l.MaxPrestateAccounts <= d.MaxPrestateAccounts && l.MaxCodeBytesPerAccount <= d.MaxCodeBytesPerAccount && l.MaxTotalCodeBytes <= d.MaxTotalCodeBytes && l.MaxAnchoredCodeLookups <= d.MaxAnchoredCodeLookups && l.AcquisitionTimeout <= d.AcquisitionTimeout && a.MaxRawBytes <= b.MaxRawBytes && a.MaxRecords <= b.MaxRecords && a.MaxDepth <= b.MaxDepth && a.MaxInputBytes <= b.MaxInputBytes && a.MaxAggregateInputBytes <= b.MaxAggregateInputBytes && a.MaxTextBytes <= b.MaxTextBytes && a.MaxLogs <= b.MaxLogs && a.MaxAggregateLogBytes <= b.MaxAggregateLogBytes
}
