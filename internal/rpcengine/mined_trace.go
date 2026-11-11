package rpcengine

import (
	"context"
	"encoding/json"
	"slices"
	"sort"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	share "privacy-proxy/internal/admissionsharedata"
	"privacy-proxy/internal/executionfacts"
	"privacy-proxy/internal/policybundle"
	"privacy-proxy/internal/policycore"
	"privacy-proxy/internal/readprivacy"
	"privacy-proxy/internal/rpcexecution"
	"privacy-proxy/internal/rpcmethoddata"
	"privacy-proxy/internal/runtimepolicy"
	"privacy-proxy/internal/tracer"
)

type MinedTraceOptions struct {
	Limits        rpcexecution.MinedTraceLimits
	Shares        share.ShareReader
	ShareExpected share.ShareBinding
}
type minedTraceEngine struct {
	options  MinedTraceOptions
	profile  readprivacy.ReadProfile
	identity *share.ReaderIdentity
	methods  map[string]bool
}
type nativeExecutionEvidence interface {
	Anchor() rpcexecution.Anchor
	Tree() *executionfacts.Tree
	FrameCode(int) (rpcexecution.CodeInfo, bool)
	RuntimeCodeAt(int, common.Address) (rpcexecution.CodeInfo, bool)
	CreationContext(int) (rpcexecution.CreationContext, bool)
}

func NewCreationObservedWithMinedTrace(snapshot *policybundle.CatalogSnapshot, options RawOptions, mined MinedTraceOptions) (*Engine, error) {
	return newRawConfigured(snapshot, options, policybundle.RuntimeCreationObservedProfileID, &mined)
}
func (e *Engine) initMinedTrace(options MinedTraceOptions) error {
	if e == nil || e.current == nil || e.raw == nil {
		return errOperation
	}
	if options.Limits == (rpcexecution.MinedTraceLimits{}) {
		options.Limits = rpcexecution.DefaultMinedTraceLimits()
	}
	if !options.Limits.Valid() {
		return errOperation
	}
	profile, err := readprivacy.ParseReadProfile(e.raw.readProfile)
	if err != nil {
		return errOperation
	}
	m := &minedTraceEngine{options: options, profile: profile, methods: map[string]bool{}}
	if options.Shares == nil {
		if !profile.Strict() || options.ShareExpected != (share.ShareBinding{}) {
			return errOperation
		}
	} else {
		r := options.Shares.Metadata()
		if !options.ShareExpected.Valid() || options.ShareExpected.Network != e.network || r.Binding != options.ShareExpected || r.Binding.State.Generation != e.current.metadata.Binding.State.Generation || [32]byte(r.Binding.State.Coverage) != [32]byte(e.current.metadata.Binding.State.Coverage) || r.Mode != "reader" || !r.Identity.Valid() {
			return errOperation
		}
		m.identity = r.Identity
	}
	for _, decl := range e.snapshot.Methods() {
		if decl.Canonical != "debug_traceTransaction" {
			continue
		}
		canonical, builtin := rpcmethoddata.CanonicalBuiltin(decl.Name)
		if builtin && (canonical != "debug_traceTransaction" || canonical != decl.Name) || !builtin && !metadataAliasAllowed(decl.Name) {
			return errOperation
		}
		m.methods[decl.Name] = true
	}
	enabled := false
	for _, o := range e.snapshot.Organizations() {
		for _, id := range e.snapshot.GroupIDs(o.ID) {
			g, _ := e.snapshot.Group(o.ID, id)
			for _, name := range g.AllowedMethods {
				if !m.methods[name] {
					continue
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
		m.methods = nil
	}
	e.mined = m
	return nil
}
func (e *Engine) MinedTraceOperationBinding() TraceOperationBinding {
	if e == nil || e.mined == nil || e.raw == nil || e.raw.closed.Load() {
		return TraceOperationBinding{}
	}
	b := e.OperationBinding()
	out := TraceOperationBinding{Environment: b.Environment, ChainID: b.ChainID, Profile: b.Profile, NetworkKey: b.NetworkKey, ManifestDigest: b.ManifestDigest, OrganizationIDs: b.OrganizationIDs}
	for name := range e.mined.methods {
		out.Methods = append(out.Methods, name)
	}
	sort.Strings(out.Methods)
	return out
}
func (e *Engine) minedMethodAuthorized(org *runtimepolicy.OrgView, name string) bool {
	decl, ok := e.snapshot.Method(name)
	if !ok || decl.Canonical != "debug_traceTransaction" || !org.GroupAllowsMethod(name) {
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

func (e *Engine) TraceTransactionObserved(parent context.Context, assertion, selectedOrg string, raw []byte) *MinedTraceOperationResult {
	r := &MinedTraceOperationResult{owner: e, id: json.RawMessage("null"), metadata: TraceOperationMetadata{Method: "rpc.invalid_request", Class: UnavailableCompletion}}
	if e == nil || e.mined == nil || e.current == nil || e.raw == nil || e.raw.closed.Load() || parent == nil {
		return r.fail(UnavailableCompletion, -32002)
	}
	fence, err := share.NewFence(parent, e.current.limits.Timeout)
	if err != nil {
		return r.fail(UnavailableCompletion, -32002)
	}
	ctx, cancel, err := fence.Bind(parent)
	if err != nil {
		return r.fail(UnavailableCompletion, -32002)
	}
	defer cancel()
	deadline, _ := ctx.Deadline()
	r.fence = &nativeOperationFence{deadline, parent}
	r.shareFence = fence
	q, code := e.parseMinedTrace(raw)
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
	if selectedOrg == "" {
		ids := view.OrgIDs()
		if len(ids) == 1 {
			selectedOrg = ids[0]
		}
	}
	org, ok := view.Org(selectedOrg)
	if !ok || !e.minedMethodAuthorized(org, q.method) {
		return r.fail(DeniedCompletion, -32001)
	}
	r.metadata.OrganizationID = selectedOrg
	ref, err := org.SelectCredentialRef(q.method)
	if err != nil {
		return r.fail(DeniedCompletion, -32001)
	}
	client, err := e.clients[selectedOrg].WithCredential(ref)
	if err != nil {
		return r.hidden(UnavailableCompletion)
	}
	wallet, err := e.wallets.Load(ctx, view.ActorID())
	if err != nil || wallet.ActorID() != view.ActorID() {
		return r.hidden(UnavailableCompletion)
	}
	r.walletVersion = wallet.Version()
	envelope, err := client.AcquireMinedEnvelope(ctx, q.hash, e.mined.options.Limits)
	if err != nil {
		return r.hidden(UnavailableCompletion)
	}
	tx := envelope.Transaction()
	to, call := tx.To()
	target := to
	if !call {
		target = crypto.CreateAddress(tx.From(), tx.Nonce())
	}
	current := e.currentPass(view)
	r.current = current
	if err := current.lookup(ctx, target); err != nil {
		return r.hidden(UnavailableCompletion)
	}
	native, err := current.engine()
	if err != nil {
		return r.hidden(UnavailableCompletion)
	}
	owner, err := native.CurrentOwner(view, target)
	if err != nil {
		return r.hidden(UnavailableCompletion)
	}
	if owner != "" && owner != selectedOrg {
		return r.hidden(DeniedCompletion)
	}
	participant := wallet.Contains(tx.From()) || call && wallet.Contains(to)
	admin := call && native.CurrentAddressAdminCandidate(view, selectedOrg, to)
	listed := false
	if !e.mined.profile.Strict() && !participant && !admin {
		pass, err := e.readMinedShare(ctx, fence, q.hash)
		if err != nil {
			return r.hidden(UnavailableCompletion)
		}
		r.shares = pass
		if row, ok := pass.Share(q.hash); ok {
			listed = slices.Contains(row.Recipients, view.ActorID())
		}
	}
	if !participant && (e.mined.profile.Strict() || !admin && !listed) {
		return r.hidden(DeniedCompletion)
	}
	if !e.mined.profile.Strict() && call && clientTraceMulticall(to, tx.Input()) {
		return r.hidden(DeniedCompletion)
	}
	execution, err := envelope.AcquireTrace(ctx, e.mined.profile.Strict())
	if err != nil {
		return r.hidden(UnavailableCompletion)
	}
	if current.collectMined(ctx, execution) != nil {
		return r.hidden(UnavailableCompletion)
	}
	if !e.mined.profile.Strict() {
		for _, record := range execution.Tree().Records() {
			a := record.StorageAddress.Value
			if record.Kind == executionfacts.Create || record.Kind == executionfacts.Create2 || record.Kind == executionfacts.SelfDestruct {
				a = record.To.Value
			}
			if a != (common.Address{}) && !clientTracePublic(a) {
				if current.lookupNeeded(ctx, a, true) != nil {
					return r.hidden(UnavailableCompletion)
				}
			}
		}
	}
	if execution.RequireEvaluationCurrent(ctx, current.head) != nil {
		return r.hidden(UnavailableCompletion)
	}
	native, err = current.engine()
	if err != nil {
		return r.hidden(UnavailableCompletion)
	}
	if e.mined.profile.Strict() {
		if native.CheckMinedParticipantTop(ctx, view, selectedOrg, execution, wallet) != nil {
			return r.hidden(DeniedCompletion)
		}
	} else {
		if !participant && !listed && !native.MinedTargetAdmin(view, selectedOrg, execution) {
			return r.hidden(DeniedCompletion)
		}
		if !native.CheckMinedClientTrace(ctx, view, selectedOrg, execution, wallet).Allowed {
			return r.hidden(DeniedCompletion)
		}
	}
	readable := map[string]bool{}
	if !e.mined.profile.Strict() && methodAuthorized(e.snapshot, org, "eth_getStorageAt") {
		facts, err := native.MinedTracePrivateStorage(view, selectedOrg, execution)
		if err != nil {
			return r.hidden(UnavailableCompletion)
		}
		for a, yes := range facts {
			readable[strings.ToLower(a.Hex())] = yes
		}
	}
	child, err := execution.CallTraceJSON()
	if err != nil {
		return r.hidden(UnavailableCompletion)
	}
	max := MaxObservedResponseBytes - len(r.id) - 128
	sanitized, _, err := tracer.ParseStrictCallTraceBounded(child, max)
	if err != nil {
		return r.hidden(UnavailableCompletion)
	}
	projection := sanitized
	if !e.mined.profile.Strict() {
		projection, err = tracer.RedactStrictCallTraceBounded(sanitized, readable, max)
		if err != nil {
			return r.hidden(UnavailableCompletion)
		}
	}
	checkpoint, err := execution.DeliveryCheckpoint()
	if err != nil {
		return r.hidden(UnavailableCompletion)
	}
	outcome, ok := execution.Tree().Outcome()
	if !ok {
		return r.hidden(UnavailableCompletion)
	}
	r.checkpoint = checkpoint
	r.projection = projection
	r.metadata.Class = SuccessfulCompletion
	if outcome.Error != "" {
		r.metadata.Class = EvaluationFailedCompletion
	}
	if ctx.Err() != nil || fence.Check() != nil || view.RequireLive() != nil {
		return r.hidden(UnavailableCompletion)
	}
	return r
}

func (e *Engine) readMinedShare(ctx context.Context, fence share.Fence, hash common.Hash) (*share.SharePass, error) {
	if e == nil || e.mined == nil || e.mined.options.Shares == nil {
		return nil, errOperation
	}
	m := e.mined.options.Shares.Metadata()
	if m.Binding != e.mined.options.ShareExpected || m.Mode != "reader" || m.Identity != e.mined.identity {
		return nil, errOperation
	}
	q, err := share.PrepareShareQuery([]common.Hash{hash}, fence, share.MaxChargedBytes)
	if err != nil {
		return nil, err
	}
	pass, err := e.mined.options.Shares.Read(ctx, q)
	if err != nil || pass.ValidateFor(e.mined.identity, m.Binding) != nil || !slices.Equal(pass.Query().Hashes, q.Hashes) {
		return nil, errOperation
	}
	return pass, nil
}
