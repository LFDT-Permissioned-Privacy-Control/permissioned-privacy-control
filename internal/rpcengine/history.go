package rpcengine

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"

	"github.com/ethereum/go-ethereum/common"
	"privacy-proxy/internal/historyfacts"
	"privacy-proxy/internal/identity"
	"privacy-proxy/internal/networkidentity"
	"privacy-proxy/internal/policybundle"
	"privacy-proxy/internal/rpcenvelope"
	"privacy-proxy/internal/rpcexecution"
	"privacy-proxy/internal/rpchistorypolicy"
	"privacy-proxy/internal/rpcmethoddata"
	"privacy-proxy/internal/walletadapter"
	"privacy-proxy/internal/walletops"
)

var errHistory = errors.New("invalid history operation")

type HistoryBindingKey struct{ OrganizationID, CredentialRef string }
type HistoryConfig struct {
	Snapshot      *policybundle.CatalogSnapshot
	Policy        *rpchistorypolicy.Definition
	Network       networkidentity.Binding
	Default       *rpcexecution.HistoryReadClient
	Clients       map[HistoryBindingKey]*rpcexecution.HistoryReadClient
	Wallets       *walletadapter.Resolver
	WalletBinding walletops.ServiceBinding
	WalletState   walletops.ExpectedState
	Shares        historyfacts.ShareReader
	ShareExpected historyfacts.ShareBinding
	QueryLimits   rpcexecution.HistoryReadLimits
	Clock         identity.Clock
}
type historyDeclaration struct {
	info    policybundle.MethodInfo
	method  rpcexecution.HistoryMethod
	builtin bool
}
type HistoryEngine struct {
	snapshot      *policybundle.CatalogSnapshot
	policy        *rpchistorypolicy.Policy
	facts         *historyfacts.Factory
	network       networkidentity.Binding
	key           [32]byte
	defaultClient *rpcexecution.HistoryReadClient
	clients       map[HistoryBindingKey]*rpcexecution.HistoryReadClient
	methods       map[string]historyDeclaration
	limits        rpcexecution.HistoryReadLimits
}

func historyDigestText(d rpchistorypolicy.Digest) policybundle.Digest {
	return policybundle.Digest("sha256:" + hex.EncodeToString(d[:]))
}
func NewHistory(c HistoryConfig) (*HistoryEngine, error) {
	if c.Snapshot == nil || !c.Snapshot.HistoryConsumerEnabled() || c.Policy == nil || c.Default == nil || c.Clock == nil {
		return nil, errHistory
	}
	key, err := c.Network.Key()
	m := c.Snapshot.Metadata()
	if err != nil || m.Profile != policybundle.RuntimeCreationObservedProfileID || m.Environment != c.Network.Environment || m.ChainID != c.Network.ChainID || m.ManifestDigest != historyDigestText(c.Policy.ManifestDigest()) {
		return nil, errHistory
	}
	if _, err = rpcexecution.ParseHistoryReadQuery(rpcexecution.HistoryLogs, []byte(`[{}]`), c.QueryLimits); err != nil {
		return nil, errHistory
	}
	actual := c.Snapshot.Methods()
	methods := make([]rpchistorypolicy.Method, len(actual))
	for i, m := range actual {
		methods[i] = rpchistorypolicy.Method{Name: m.Name, Canonical: m.Canonical, RequiredClaims: m.RequiredClaims}
	}
	policy, err := rpchistorypolicy.Bind(c.Policy, c.Policy.ManifestDigest(), m.MethodCatalogVersion, methods)
	if err != nil {
		return nil, errHistory
	}
	facts, err := historyfacts.New(historyfacts.Config{Snapshot: c.Snapshot, Clock: c.Clock, Network: c.Network, Wallets: c.Wallets, WalletBinding: c.WalletBinding, WalletState: c.WalletState, Shares: c.Shares, ShareExpected: c.ShareExpected, Timeout: c.QueryLimits.Timeout, MaxBytes: c.QueryLimits.MaxChargedBytes})
	if err != nil {
		return nil, errHistory
	}
	e := &HistoryEngine{snapshot: c.Snapshot, policy: policy, facts: facts, network: c.Network, key: key, defaultClient: c.Default, clients: map[HistoryBindingKey]*rpcexecution.HistoryReadClient{}, methods: map[string]historyDeclaration{}, limits: c.QueryLimits}
	for _, m := range policy.HistoryMethods() {
		method, ok := rpcexecution.HistoryMethodNamed(m.Canonical)
		builtin := m.Name == m.Canonical
		if !ok || len(m.Name) > 100 || !builtin && !metadataAliasAllowed(m.Name) {
			return nil, errHistory
		}
		e.methods[m.Name] = historyDeclaration{policybundle.MethodInfo{Name: m.Name, Canonical: m.Canonical, RequiredClaims: m.RequiredClaims}, method, builtin}
	}
	for method := rpcexecution.HistoryTransactionByHash; method <= rpcexecution.HistoryBlockReceipts; method++ {
		d, ok := e.methods[method.String()]
		if !ok || !d.builtin || d.method != method {
			return nil, errHistory
		}
	}
	valid := func(client *rpcexecution.HistoryReadClient, org, ref string) bool {
		if client == nil || client.Bounds() != c.QueryLimits {
			return false
		}
		s := client.Source()
		return s.Organization == org && s.CredentialRef == ref && s.Network.Environment == c.Network.Environment && s.Network.ChainID == c.Network.ChainID && s.Network.Genesis.Hex() == c.Network.GenesisHash && s.Network.Deployment == c.Network.DeploymentID && [32]byte(s.Network.Key) == key
	}
	if !valid(c.Default, "", "") {
		return nil, errHistory
	}
	needed := map[HistoryBindingKey]bool{}
	for _, org := range c.Snapshot.Organizations() {
		for _, id := range c.Snapshot.GroupIDs(org.ID) {
			g, ok := c.Snapshot.Group(org.ID, id)
			if !ok {
				return nil, errHistory
			}
			for _, name := range g.AllowedMethods {
				if _, ok := e.methods[name]; !ok {
					continue
				}
				ref := ""
				if g.RpcCredential != nil {
					ref = g.RpcCredential.FromEnv
				}
				needed[HistoryBindingKey{org.ID, ref}] = true
			}
		}
	}
	if len(needed) != len(c.Clients) {
		return nil, errHistory
	}
	for key := range needed {
		client := c.Clients[key]
		if !valid(client, key.OrganizationID, key.CredentialRef) {
			return nil, errHistory
		}
		e.clients[key] = client
	}
	return e, nil
}
func (e *HistoryEngine) RequiresHistoryConsumer() bool {
	return e != nil && e.snapshot != nil && e.snapshot.HistoryConsumerEnabled()
}
func (e *Engine) RequiresHistoryConsumer() bool {
	return e != nil && e.snapshot != nil && e.snapshot.HistoryConsumerEnabled()
}
func (e *StateEngine) RequiresHistoryConsumer() bool {
	return e != nil && e.snapshot != nil && e.snapshot.HistoryConsumerEnabled()
}
func (e *MetadataEngine) RequiresHistoryConsumer() bool {
	return e != nil && e.snapshot != nil && e.snapshot.HistoryConsumerEnabled()
}
func (e *HistoryEngine) SharesSnapshot(native *Engine) bool {
	return e != nil && native != nil && e.snapshot == native.snapshot && e.network == native.network
}
func (e *HistoryEngine) SharesMetadataSnapshot(other *MetadataEngine) bool {
	return e != nil && other != nil && e.snapshot == other.snapshot && e.network == other.network
}
func (e *HistoryEngine) SharesStateSnapshot(other *StateEngine) bool {
	return e != nil && other != nil && e.snapshot == other.snapshot && e.network == other.network
}
func (e *HistoryEngine) OperationBinding() MetadataOperationBinding {
	if e == nil || e.snapshot == nil || e.policy == nil {
		return MetadataOperationBinding{}
	}
	m := e.snapshot.Metadata()
	b := MetadataOperationBinding{Environment: m.Environment, ChainID: m.ChainID, Profile: m.Profile, NetworkKey: "sha256:" + hex.EncodeToString(e.key[:]), ManifestDigest: m.ManifestDigest, PolicyDigest: historyDigestText(e.policy.Digest())}
	for name := range e.methods {
		b.Methods = append(b.Methods, name)
	}
	for _, org := range e.snapshot.Organizations() {
		b.OrganizationIDs = append(b.OrganizationIDs, org.ID)
	}
	sort.Strings(b.Methods)
	sort.Strings(b.OrganizationIDs)
	return b
}

func (e *HistoryEngine) QueryObserved(ctx context.Context, assertion MetadataAssertion, selectedOrg string, body []byte) *HistoryOperationResult {
	r := &HistoryOperationResult{owner: e, id: json.RawMessage("null"), metadata: HistoryOperationMetadata{Method: "rpc.invalid_request", Class: UnavailableCompletion}}
	if e == nil || e.policy == nil || ctx == nil || ctx.Err() != nil {
		return r.fail(UnavailableCompletion, -32002)
	}
	r.metadata.PolicyDigest = historyDigestText(e.policy.Digest())
	env, err := rpcenvelope.ParseRaw(body, rpcenvelope.DefaultLimits())
	if err != nil || env.Method() == "" {
		return r.fail(InvalidCompletion, -32600)
	}
	version := bytes.TrimSpace(env.VersionJSON())
	if len(version) > 0 && !bytes.Equal(version, []byte("null")) && !bytes.Equal(version, []byte(`"2.0"`)) {
		var v string
		if json.Unmarshal(version, &v) != nil || v != "2.0" {
			return r.fail(InvalidCompletion, -32600)
		}
	}
	id, present := env.IDJSON()
	if present {
		r.id = id
	} else {
		r.notification = true
	}
	name := env.Method()
	if canonical, builtin := rpcmethoddata.CanonicalBuiltin(name); builtin {
		name = canonical
	}
	declaration, known := e.methods[name]
	if !known {
		return r.fail(InvalidCompletion, -32601)
	}
	r.metadata.Method, r.metadata.Canonical = name, declaration.method
	q, err := rpcexecution.ParseHistoryReadQuery(declaration.method, env.ParamsJSON(), e.limits)
	if err != nil {
		return r.fail(InvalidCompletion, -32602)
	}
	client := e.defaultClient
	if assertion.kind == 1 {
		if !declaration.builtin || len(declaration.info.RequiredClaims) > 0 || !e.policy.AllowsAnonymous(name) {
			return r.fail(UnauthenticatedCompletion, -32001)
		}
		r.anonymous = true
	} else {
		if assertion.kind != 2 {
			return r.fail(UnauthenticatedCompletion, -32001)
		}
		current, err := e.facts.Begin(ctx, assertion.token, selectedOrg, name)
		if err != nil {
			return r.fail(DeniedCompletion, -32001)
		}
		r.current = current
		r.metadata.ActorID, r.metadata.OrganizationID = current.OriginalView().ActorID(), current.Organization()
		client = e.clients[HistoryBindingKey{current.Organization(), current.CredentialRef()}]
		if client == nil {
			return r.fail(UnavailableCompletion, -32002)
		}
	}
	r.client = client
	var observation *rpcexecution.HistoryReadObservation
	if r.current != nil {
		d, done := r.current.OriginalFence()
		observation, err = client.AcquireReservedWithin(ctx, q, rpcexecution.HistoryOperationFence{Deadline: d, Done: done}, r.current.ChargedBytes())
	} else {
		observation, err = client.Acquire(ctx, q)
	}
	if err != nil {
		return r.fail(UnavailableCompletion, -32002)
	}
	r.observation = observation
	if err = observation.ReserveWorkingBytes(observation.RenderWorkingBytes()); err != nil {
		return r.fail(UnavailableCompletion, -32002)
	}
	renderer, err := newHistoryRender(r.current, observation)
	if err != nil {
		return r.fail(UnavailableCompletion, -32002)
	}
	if r.current != nil && !r.current.Profile().Strict() && historyMethodConsumesShares(q.Method()) {
		// Reserve BOTH the retained original share pass and a complete fresh
		// bounded recheck before first SQL. The original pass carries that same
		// lower allowance; no final read restarts a larger decode budget.
		allowance := observation.RemainingWorkingBytes() / 2
		if allowance <= 0 || observation.ReserveWorkingBytes(2*allowance) != nil {
			return r.fail(UnavailableCompletion, -32002)
		}
		txs := observation.Transactions()
		hashes := make([]common.Hash, 0, len(txs))
		for _, t := range txs {
			hashes = append(hashes, t.Transaction.Hash())
		}
		r.current, err = r.current.WithSharesWithin(ctx, hashes, allowance)
		if err != nil {
			return r.fail(UnavailableCompletion, -32002)
		}
		renderer.current = r.current
	}
	result, err := renderer.renderRPC(observation, q)
	if err != nil {
		return r.fail(UnavailableCompletion, -32002)
	}
	if len(result) == 0 || int64(len(result)) > e.limits.MaxResultBytes {
		return r.fail(UnavailableCompletion, -32002)
	}
	r.result = result
	r.metadata.Class = SuccessfulCompletion
	if r.PreflightFor(e) != nil {
		return r.fail(UnavailableCompletion, -32002)
	}
	return r
}

// Block/count envelopes use participation only. Their source and wallet gates
// remain required, but no admitted-share pass participates in their decision.
// Receipt arrays can still consume shares when rendering their filtered logs.
func historyMethodConsumesShares(method rpcexecution.HistoryMethod) bool {
	switch method {
	case rpcexecution.HistoryBlockByHash, rpcexecution.HistoryBlockByNumber, rpcexecution.HistoryBlockCountByHash, rpcexecution.HistoryBlockCountByNumber:
		return false
	default:
		return true
	}
}
