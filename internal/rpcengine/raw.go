package rpcengine

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"privacy-proxy/internal/admission"
	"privacy-proxy/internal/guardbridge"
	"privacy-proxy/internal/identity"
	"privacy-proxy/internal/nodeapproval"
	"privacy-proxy/internal/policybundle"
	"privacy-proxy/internal/rpcexecution"
	"privacy-proxy/internal/transactioninput"
	"privacy-proxy/internal/walletadapter"
	"privacy-proxy/internal/walletops"
)

const MaxRawRefsPerOrg = 8
const MaxRawBindings = 64
const MaxProducerLanes = 256
const MaxRetainedApprovals = 1_000_000

type rawBudget struct{ bindings, lanes, retained int }

func (b *rawBudget) add(refs, lanesEach, retainedEach int) bool {
	if refs < 1 || refs > MaxRawRefsPerOrg || refs > MaxRawBindings-b.bindings || lanesEach < 0 || retainedEach < 0 || lanesEach > (MaxProducerLanes-b.lanes)/refs || retainedEach > (MaxRetainedApprovals-b.retained)/refs {
		return false
	}
	b.bindings += refs
	b.lanes += refs * lanesEach
	b.retained += refs * retainedEach
	return true
}

// RawNodeOptions is trusted immutable startup configuration. Mode comes from
// the approved runtime source; these options cannot choose a fallback mode.
type RawNodeOptions struct {
	Binding     rpcexecution.NodeBinding
	Transport   http.RoundTripper
	Limits      rpcexecution.Limits
	HashMode    uint8
	Seed        []byte
	KeyID       string
	ApprovalTTL time.Duration
	MaxBatch    int
	Delivery    nodeapproval.DeliveryOptions
}

type RawOptions struct {
	CallClients   map[string]*rpcexecution.Client
	RawNodes      map[string]RawNodeOptions
	Wallets       *walletadapter.Resolver
	WalletBinding walletops.ServiceBinding
	WalletState   walletops.ExpectedState
	Admission     *admission.Service
	Clock         identity.Clock
}

type rawBinding struct {
	client *rpcexecution.Client
	pair   *guardbridge.Pair
}
type rawEngine struct {
	readProfile string
	wallets     *walletadapter.Resolver
	admission   *admission.Service
	bindings    map[string]map[string]rawBinding
	once        sync.Once
	closed      atomic.Bool
}

func neededRawRefs(snapshot *policybundle.CatalogSnapshot) map[string][]string {
	out := map[string][]string{}
	for _, org := range snapshot.Organizations() {
		catalog, _ := snapshot.NativeCatalog(org.ID)
		seen := map[string]bool{}
		for group := range catalog.Groups {
			g, _ := snapshot.Group(org.ID, group)
			if !slices.Contains(g.AllowedMethods, "eth_sendTransaction") {
				continue
			}
			ref := ""
			if g.RpcCredential != nil {
				ref = g.RpcCredential.FromEnv
			}
			seen[ref] = true
		}
		if len(seen) != 0 {
			refs := []string{}
			for ref := range seen {
				refs = append(refs, ref)
			}
			sort.Strings(refs)
			out[org.ID] = refs
		}
	}
	return out
}

func deliveryOptions(n RawNodeOptions) nodeapproval.BoundDeliveryOptions {
	return nodeapproval.BoundDeliveryOptions{Seed: n.Seed, KeyID: n.KeyID, TTL: n.ApprovalTTL, MaxBatch: n.MaxBatch, Delivery: n.Delivery}
}

// NewRaw constructs the same-snapshot verifier and native engine, then the
// finite source-derived node bindings. It never accepts a preverified principal
// or an externally constructed approval service/receipt as policy permission.
func NewRaw(snapshot *policybundle.CatalogSnapshot, options RawOptions) (*Engine, error) {
	return newRaw(snapshot, options, policybundle.RuntimeRawSendProfileID)
}

// NewMultiOrg mounts the same simulation/raw consumers with explicitly selected
// native-v3 authority. It does not activate other RPC methods or lifecycle paths.
func NewMultiOrg(snapshot *policybundle.CatalogSnapshot, options RawOptions) (*Engine, error) {
	return newRaw(snapshot, options, policybundle.RuntimeMultiOrgProfileID)
}

func newRaw(snapshot *policybundle.CatalogSnapshot, options RawOptions, expectedProfile string) (*Engine, error) {
	bad := func() (*Engine, error) { return nil, errors.New("invalid raw RPC configuration") }
	if snapshot == nil || options.Admission == nil || options.Wallets == nil || options.Clock == nil || !options.WalletState.Valid() {
		return bad()
	}
	meta := snapshot.Metadata()
	runtime, ok := snapshot.Runtime()
	if !ok || meta.Profile != expectedProfile {
		return bad()
	}
	_, rawSource := runtime.RawSource()
	_, multiOrgSource := runtime.MultiOrgSource()
	if (expectedProfile == policybundle.RuntimeRawSendProfileID && !rawSource) || (expectedProfile == policybundle.RuntimeMultiOrgProfileID && !multiOrgSource) {
		return bad()
	}
	compliance, ok := snapshot.Compliance()
	if !ok {
		return bad()
	}
	financial := options.Admission.Metadata()
	profile := rpcexecution.SignedCallProfileID
	if runtime.RawSubmissionMode() == policybundle.RawSubmissionGuardV1 {
		profile = rpcexecution.GuardRetainedProfileID
	}
	wb := options.WalletBinding
	network := admission.NetworkBinding{Environment: wb.Environment, ChainID: wb.ChainID, GenesisHash: wb.GenesisHash, DeploymentID: wb.DeploymentID}
	key, err := network.Key()
	if err != nil || financial.ManifestDigest.String() != string(meta.ManifestDigest) || financial.ComplianceDigest.String() != compliance.Digest() || financial.EvidenceProfile != profile || financial.Network != network || financial.NetworkKey != key || network.Environment != meta.Environment || network.ChainID != meta.ChainID {
		return bad()
	}
	namespace, err := wb.Namespace()
	walletMeta := options.Wallets.Metadata()
	if err != nil || walletMeta.Namespace != namespace || walletMeta.ExpectedState != options.WalletState {
		return bad()
	}
	refs := neededRawRefs(snapshot)
	if len(refs) != len(options.RawNodes) {
		return bad()
	}
	prepared := map[string]map[string]*rpcexecution.Client{}
	budget := rawBudget{}
	for org, needed := range refs {
		if len(needed) < 1 || len(needed) > MaxRawRefsPerOrg {
			return bad()
		}
		n, exists := options.RawNodes[org]
		if !exists || n.Binding.OrganizationID != org || n.Binding.ChainID != meta.ChainID || n.Binding.Profile != profile {
			return bad()
		}
		callClient := options.CallClients[org]
		if callClient == nil {
			return bad()
		}
		callMetadata := callClient.Metadata()
		if callMetadata.PragueStartInclusive != n.Binding.PragueStartInclusive || callMetadata.PragueEndExclusive != n.Binding.PragueEndExclusive {
			return bad()
		}
		client, err := rpcexecution.NewClient(n.Transport, n.Binding, n.Limits)
		if err != nil {
			return bad()
		}
		prepared[org] = map[string]*rpcexecution.Client{}
		for _, ref := range needed {
			selected, err := client.WithCredential(ref)
			if err != nil {
				return bad()
			}
			prepared[org][ref] = selected
		}
		if runtime.RawSubmissionMode() == policybundle.RawSubmissionGuardV1 {
			if (n.HashMode != nodeapproval.HashStrict && n.HashMode != nodeapproval.HashCalls) || nodeapproval.ValidateBoundDelivery(deliveryOptions(n)) != nil {
				return bad()
			}
			if !budget.add(len(needed), len(n.Delivery.Targets), n.Delivery.RetainMax) {
				return bad()
			}
		} else if n.HashMode != 0 || len(n.Seed) != 0 || n.KeyID != "" || n.ApprovalTTL != 0 || n.MaxBatch != 0 || len(n.Delivery.Targets) != 0 || n.Delivery.Timeout != 0 || n.Delivery.MaxInFlight != 0 || n.Delivery.RetainMax != 0 {
			return bad()
		} else if !budget.add(len(needed), 0, 0) {
			return bad()
		}
	}
	e, err := newEngine(snapshot, options.CallClients, options.Wallets, options.Clock, expectedProfile)
	if err != nil {
		return nil, err
	}
	e.raw = &rawEngine{readProfile: runtime.ReadProfile(), wallets: options.Wallets, admission: options.Admission, bindings: map[string]map[string]rawBinding{}}
	// Source bindings and aggregate budgets are checked before producer startup.
	for org, needed := range refs {
		n := options.RawNodes[org]
		e.raw.bindings[org] = map[string]rawBinding{}
		for _, ref := range needed {
			binding := rawBinding{client: prepared[org][ref]}
			if runtime.RawSubmissionMode() == policybundle.RawSubmissionGuardV1 {
				pair, err := guardbridge.NewDeliveryPair(n.Binding, ref, n.Transport, n.HashMode, n.Limits, deliveryOptions(n))
				if err != nil {
					e.Close()
					return bad()
				}
				binding.pair = pair
			}
			e.raw.bindings[org][ref] = binding
		}
	}
	return e, nil
}

// Close drains the already accepted Guard work under each existing lane limit.
// The finite independent pairs close concurrently, avoiding multiplied drains.
func (e *Engine) Close() {
	if e == nil || e.raw == nil {
		return
	}
	e.raw.closed.Store(true)
	e.raw.once.Do(func() {
		var done sync.WaitGroup
		for _, org := range e.raw.bindings {
			for _, binding := range org {
				if binding.pair != nil {
					done.Add(1)
					go func(p *guardbridge.Pair) { defer done.Done(); p.Close() }(binding.pair)
				}
			}
		}
		done.Wait()
	})
}

func rawFailure(id json.RawMessage, err error) Response {
	if errors.Is(err, admission.ErrUnauthorized) || errors.Is(err, admission.ErrForbidden) || errors.Is(err, admission.ErrConflict) {
		return denied(id)
	}
	return responseError(id, -32002, "unavailable")
}
func outcomeUnknown(id json.RawMessage, tx transactioninput.VerifiedTransaction) Response {
	out := responseError(id, -32004, "submission outcome unknown")
	out.Error.Data = map[string]string{"transactionHash": tx.Hash().Hex()}
	return out
}

func (e *Engine) SubmitRaw(ctx context.Context, assertion, explicitOrg string, raw []byte) Response {
	req, parseError := parseRawRequest(raw)
	if parseError != nil {
		return responseError(req.id, parseError.Code, parseError.Message)
	}
	if e == nil || e.raw == nil {
		return responseError(req.id, -32601, "method not found")
	}
	if e.raw.readProfile == "strict" && req.present {
		return responseError(req.id, -32602, "visibleTo is not supported on this network")
	}
	entries, valid := req.entries()
	if !valid {
		return responseError(req.id, -32602, "invalid params")
	}
	if ctx.Err() != nil || e.raw.closed.Load() {
		return responseError(req.id, -32002, "unavailable")
	}
	view, err := e.factory.Build(assertion)
	if err != nil {
		return denied(req.id)
	}
	tx, err := transactioninput.DecodeRaw(req.rawHex, e.snapshot.Metadata().ChainID, transactioninput.ProtectedEVMProfile(), transactioninput.DefaultLimits())
	if err != nil {
		return responseError(req.id, -32602, "invalid params")
	}
	to, hasTo := tx.Destination()
	if tx.Creation() || !hasTo {
		return responseError(req.id, -32002, "unavailable")
	}
	orgID, ok := selectedAddressOrganization(view, explicitOrg, to)
	if !ok {
		return denied(req.id)
	}
	org, _ := view.Org(orgID)
	if !methodAuthorized(e.snapshot, org, "eth_sendTransaction") {
		return denied(req.id)
	}
	ref, err := org.SelectCredentialRef("eth_sendTransaction")
	if err != nil {
		return denied(req.id)
	}
	binding, ok := e.raw.bindings[orgID][ref]
	if !ok {
		return responseError(req.id, -32002, "unavailable")
	}
	if binding.pair != nil && (!binding.pair.Ready() || tx.Type() == 1) {
		return responseError(req.id, -32002, "unavailable")
	}
	wallet, err := e.raw.wallets.Load(ctx, view.ActorID())
	if err != nil || wallet.ActorID() != view.ActorID() {
		return responseError(req.id, -32002, "unavailable")
	}
	if len(entries) > 0 && (!wallet.Contains(tx.Signer()) || len(tx.Input()) == 0) {
		return denied(req.id)
	}
	audience, err := e.raw.wallets.ResolveRecipients(ctx, entries)
	if err != nil {
		return denied(req.id)
	}
	actors := audience.Actors()
	sort.Strings(actors)
	if ctx.Err() != nil || view.RequireLive() != nil {
		return denied(req.id)
	}
	var execution *rpcexecution.CallExecution
	var prepared *guardbridge.QualifiedPrepared
	if binding.pair != nil {
		prepared, err = binding.pair.AcquireSigned(ctx, tx)
		if err == nil {
			execution = prepared.Execution()
		}
	} else {
		execution, err = binding.client.AcquireSigned(ctx, tx)
	}
	if err != nil {
		return responseError(req.id, -32002, "unavailable")
	}
	if !e.native.CheckSigned(ctx, view, orgID, execution, wallet).Allowed {
		return denied(req.id)
	}
	if len(actors) > 0 {
		code, known := execution.Code(to)
		if !known || !code.HasCode() || code.Precompile() || code.Delegated() {
			return denied(req.id)
		}
	}
	input := admission.TrustedRawInput{View: view, OrganizationID: orgID, Transaction: tx, Execution: execution, WalletSnapshot: wallet, Audience: actors}
	result, err := e.raw.admission.CheckAndRecordRaw(ctx, input)
	if err != nil {
		return rawFailure(req.id, err)
	}
	if result == nil {
		return responseError(req.id, -32002, "unavailable")
	}
	if !result.Decision().Allowed {
		return responseError(req.id, -32003, "transaction blocked by compliance policy")
	}
	receipt, ok := result.Receipt()
	if !ok || !receipt.Matches(input) {
		return responseError(req.id, -32002, "unavailable")
	}
	if ctx.Err() != nil || e.raw.closed.Load() {
		return responseError(req.id, -32002, "unavailable")
	}
	if err := receipt.RequirePublishable(); err != nil {
		return rawFailure(req.id, err)
	}
	if binding.pair != nil {
		if err := binding.pair.EnqueueQualified(prepared); err != nil {
			return responseError(req.id, -32002, "unavailable")
		}
		_, err = binding.pair.BroadcastRaw(ctx, tx)
	} else {
		_, err = binding.client.BroadcastRaw(ctx, tx)
	}
	if err != nil {
		return outcomeUnknown(req.id, tx)
	}
	hash := tx.Hash().Hex()
	return Response{JSONRPC: "2.0", ID: req.id, Result: &hash}
}
