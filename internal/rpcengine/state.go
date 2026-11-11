package rpcengine

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strconv"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"privacy-proxy/internal/creationfacts"
	"privacy-proxy/internal/identity"
	"privacy-proxy/internal/networkidentity"
	"privacy-proxy/internal/policybundle"
	"privacy-proxy/internal/policycore"
	"privacy-proxy/internal/rpcenvelope"
	"privacy-proxy/internal/rpcexecution"
	"privacy-proxy/internal/rpcmetadatapolicy"
	"privacy-proxy/internal/rpcmethoddata"
	"privacy-proxy/internal/rpcstatepolicy"
	"privacy-proxy/internal/runtimepolicy"
	"privacy-proxy/internal/walletadapter"
	"privacy-proxy/internal/walletops"
)

type StateBindingKey struct{ OrganizationID, CredentialRef string }
type StateConfig struct {
	Snapshot           *policybundle.CatalogSnapshot
	Policy             *rpcstatepolicy.Definition
	Network            networkidentity.Binding
	Default            *rpcexecution.StateClient
	Clients            map[StateBindingKey]*rpcexecution.StateClient
	Associations       creationfacts.CurrentAddressReader
	AssociationBinding creationfacts.AddressReadBinding
	Wallets            *walletadapter.Resolver
	WalletBinding      walletops.ServiceBinding
	WalletState        walletops.ExpectedState
	QueryLimits        rpcexecution.StateLimits
	Clock              identity.Clock
}
type stateDeclaration struct {
	info    policybundle.MethodInfo
	method  rpcexecution.StateMethod
	builtin bool
}
type StateEngine struct {
	snapshot            *policybundle.CatalogSnapshot
	factory             *runtimepolicy.Factory
	policy              *rpcstatepolicy.Policy
	network             networkidentity.Binding
	key                 [32]byte
	defaultClient       *rpcexecution.StateClient
	clients             map[StateBindingKey]*rpcexecution.StateClient
	methods             map[string]stateDeclaration
	preregistered       map[common.Address]string
	owners              map[common.Address]string
	associations        creationfacts.CurrentAddressReader
	associationMetadata creationfacts.AddressReaderMetadata
	wallets             *walletadapter.Resolver
	limits              rpcexecution.StateLimits
}

func stateMethod(name string) rpcexecution.StateMethod {
	for m := rpcexecution.StateBalance; m <= rpcexecution.StateNonce; m++ {
		if m.String() == name {
			return m
		}
	}
	return rpcexecution.InvalidStateMethod
}
func stateBoundsWithin(a, b rpcexecution.StateLimits) bool {
	return a.Timeout > 0 && a.Timeout <= b.Timeout && a.MaxParamsBytes > 0 && a.MaxParamsBytes <= b.MaxParamsBytes && a.MaxResultBytes > 0 && a.MaxResultBytes <= b.MaxResultBytes && a.MaxCodeBytes > 0 && a.MaxCodeBytes <= b.MaxCodeBytes && a.MaxStorageKeys > 0 && a.MaxStorageKeys <= b.MaxStorageKeys && a.MaxProofNodesPerProof > 0 && a.MaxProofNodesPerProof <= b.MaxProofNodesPerProof && a.MaxTotalProofNodes > 0 && a.MaxTotalProofNodes <= b.MaxTotalProofNodes && a.MaxProofNodeBytes > 0 && a.MaxProofNodeBytes <= b.MaxProofNodeBytes && a.MaxTotalProofBytes > 0 && a.MaxTotalProofBytes <= b.MaxTotalProofBytes
}
func NewState(c StateConfig) (*StateEngine, error) {
	if c.Snapshot == nil || c.Policy == nil || c.Default == nil || c.Clock == nil {
		return nil, errMetadata
	}
	key, err := c.Network.Key()
	meta := c.Snapshot.Metadata()
	if err != nil || meta.Profile != policybundle.RuntimeCreationObservedProfileID || meta.Environment != c.Network.Environment || meta.ChainID != c.Network.ChainID || meta.ManifestDigest != metadataDigestText(c.Policy.ManifestDigest()) {
		return nil, errMetadata
	}
	if _, err := rpcexecution.ParseStateQuery(rpcexecution.StateBalance, []byte(`["0x0000000000000000000000000000000000000000"]`), c.QueryLimits); err != nil {
		return nil, errMetadata
	}
	actual := c.Snapshot.Methods()
	methods := make([]rpcmetadatapolicy.Method, len(actual))
	for i, m := range actual {
		methods[i] = rpcmetadatapolicy.Method{Name: m.Name, Canonical: m.Canonical, RequiredClaims: m.RequiredClaims}
	}
	policy, err := rpcstatepolicy.Bind(c.Policy, c.Policy.ManifestDigest(), meta.MethodCatalogVersion, methods)
	if err != nil {
		return nil, errMetadata
	}
	factory, err := runtimepolicy.NewFactory(c.Snapshot, c.Clock)
	if err != nil {
		return nil, errMetadata
	}
	e := &StateEngine{snapshot: c.Snapshot, factory: factory, policy: policy, network: c.Network, key: key, defaultClient: c.Default, clients: map[StateBindingKey]*rpcexecution.StateClient{}, methods: map[string]stateDeclaration{}, preregistered: map[common.Address]string{}, associations: c.Associations, limits: c.QueryLimits}
	for _, m := range policy.Methods() {
		method := stateMethod(m.Canonical)
		builtin := m.Name == m.Canonical
		if method == rpcexecution.InvalidStateMethod || len(m.Name) > 100 || !builtin && !metadataAliasAllowed(m.Name) {
			return nil, errMetadata
		}
		e.methods[m.Name] = stateDeclaration{policybundle.MethodInfo{Name: m.Name, Canonical: m.Canonical, RequiredClaims: m.RequiredClaims}, method, builtin}
	}
	for m := rpcexecution.StateBalance; m <= rpcexecution.StateNonce; m++ {
		d, ok := e.methods[m.String()]
		if !ok || !d.builtin || d.method != m {
			return nil, errMetadata
		}
	}
	orgs := map[string]bool{}
	owners := map[common.Address]string{}
	for _, org := range c.Snapshot.Organizations() {
		orgs[org.ID] = true
		catalog, _ := c.Snapshot.NativeCatalog(org.ID)
		for address := range catalog.Contracts {
			owners[common.HexToAddress(address)] = org.ID
		}
	}
	runtime, ok := c.Snapshot.Runtime()
	if !ok {
		return nil, errMetadata
	}
	observedSource, observed := runtime.CreationObservedSource()
	if !observed {
		return nil, errMetadata
	}
	for _, scope := range observedSource.AddressScopes {
		address := common.HexToAddress(scope.Address)
		if owner, known := owners[address]; known && owner != scope.OrganizationID {
			return nil, errMetadata
		}
		owners[address] = scope.OrganizationID
	}
	for _, entry := range c.Policy.PreRegisteredAddresses() {
		address := common.HexToAddress(entry.Address)
		if !orgs[entry.OrganizationID] {
			return nil, errMetadata
		}
		if owner, known := owners[address]; known && owner != entry.OrganizationID {
			return nil, errMetadata
		}
		e.preregistered[address] = entry.OrganizationID
		owners[address] = entry.OrganizationID
	}
	e.owners = owners
	validClient := func(client *rpcexecution.StateClient) bool {
		if client == nil {
			return false
		}
		s := client.Source()
		return s.Network == c.Network && s.NetworkKey == key && s.Profile == "rpc-state/v1" && stateBoundsWithin(client.Bounds(), c.QueryLimits)
	}
	if !validClient(c.Default) {
		return nil, errMetadata
	}
	needed := map[StateBindingKey]bool{}
	for _, org := range c.Snapshot.Organizations() {
		for _, id := range c.Snapshot.GroupIDs(org.ID) {
			group, ok := c.Snapshot.Group(org.ID, id)
			if !ok {
				return nil, errMetadata
			}
			for _, name := range group.AllowedMethods {
				if _, ok := e.methods[name]; !ok {
					continue
				}
				ref := ""
				if group.RpcCredential != nil {
					ref = group.RpcCredential.FromEnv
				}
				needed[StateBindingKey{org.ID, ref}] = true
			}
		}
	}
	if len(needed) != len(c.Clients) {
		return nil, errMetadata
	}
	for binding := range needed {
		client := c.Clients[binding]
		if !validClient(client) || client.Source().CredentialRef != binding.CredentialRef {
			return nil, errMetadata
		}
		e.clients[binding] = client
	}
	if c.Associations == nil {
		if c.AssociationBinding != (creationfacts.AddressReadBinding{}) {
			return nil, errMetadata
		}
	} else {
		e.associationMetadata = c.Associations.Metadata()
		b := c.AssociationBinding
		n := b.Network
		if !b.Valid() || e.associationMetadata.Binding != b || !e.associationMetadata.Identity.Valid() || n.Key != creationfacts.Digest(key) || n.Environment != c.Network.Environment || n.ChainID != c.Network.ChainID || n.Genesis.Hex() != c.Network.GenesisHash || n.Deployment != c.Network.DeploymentID {
			return nil, errMetadata
		}
	}
	if c.Policy.LinkedWalletBasicsEnabled() {
		if c.Wallets == nil || !c.WalletState.Valid() || c.Associations == nil {
			return nil, errMetadata
		}
		b := c.WalletBinding
		if b.Environment != c.Network.Environment || b.ChainID != c.Network.ChainID || b.GenesisHash != c.Network.GenesisHash || b.DeploymentID != c.Network.DeploymentID {
			return nil, errMetadata
		}
		namespace, err := b.Namespace()
		metadata := c.Wallets.Metadata()
		if err != nil || metadata.Namespace != namespace || metadata.ExpectedState != c.WalletState {
			return nil, errMetadata
		}
		e.wallets = c.Wallets
	} else if c.Wallets != nil || c.WalletBinding != (walletops.ServiceBinding{}) || c.WalletState != (walletops.ExpectedState{}) {
		return nil, errMetadata
	}
	return e, nil
}
func (e *StateEngine) SharesSnapshot(native *Engine) bool {
	return e != nil && native != nil && e.snapshot == native.snapshot && native.OperationBinding().Profile == policybundle.RuntimeCreationObservedProfileID
}
func (e *StateEngine) SharesMetadataSnapshot(metadata *MetadataEngine) bool {
	return e != nil && metadata != nil && e.snapshot == metadata.snapshot
}
func (e *StateEngine) OperationBinding() MetadataOperationBinding {
	if e == nil || e.snapshot == nil || e.policy == nil {
		return MetadataOperationBinding{}
	}
	m := e.snapshot.Metadata()
	b := MetadataOperationBinding{Environment: m.Environment, ChainID: m.ChainID, Profile: m.Profile, NetworkKey: "sha256:" + hex.EncodeToString(e.key[:]), ManifestDigest: m.ManifestDigest, PolicyDigest: metadataDigestText(e.policy.Digest())}
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
func stateMethodGranted(org *runtimepolicy.OrgView, name string, d stateDeclaration) bool {
	if org == nil || !org.GroupAllowsMethod(name) {
		return false
	}
	for _, claim := range d.info.RequiredClaims {
		var mask uint8
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
func anyStateOrgAdmin(view *runtimepolicy.View) bool {
	for _, id := range view.OrgIDs() {
		org, _ := view.Org(id)
		if org.IsOrgAdmin() {
			return true
		}
	}
	return false
}
func staticPrecompile(address common.Address) bool {
	for _, b := range address[:19] {
		if b != 0 {
			return false
		}
	}
	return address[19] >= 1 && address[19] <= 9
}

var stateInfrastructureSlots = map[string]bool{
	"0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc": true,
	"0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103": true,
	"0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50": true,
	"0xc8fcad8db84d3cc18b4c41d551ea0ee66dd599cde068d998e57d5e09332c131c": true,
}

func stateInfraKey(key rpcexecution.StateStorageKey) bool {
	text := strings.ToLower(strings.TrimSpace(key.Original))
	if !strings.HasPrefix(text, "0x") {
		text = "0x" + text
	}
	return key.InputBytes == 32 && stateInfrastructureSlots[text]
}
func positiveStateAccount(p rpcexecution.ProofAccountPresence) bool {
	return p.AccountProofNodes > 0 && (p.NonceNonzero || p.BalanceNonzero || p.CodeHash != (common.Hash{}) && p.CodeHash != types.EmptyCodeHash || p.StorageHash != (common.Hash{}) && p.StorageHash != types.EmptyRootHash)
}
func (e *StateEngine) QueryObserved(ctx context.Context, assertion MetadataAssertion, selected string, body []byte) *StateOperationResult {
	r := &StateOperationResult{owner: e, id: json.RawMessage("null"), metadata: StateOperationMetadata{Method: "rpc.invalid_request", Class: UnavailableCompletion}}
	if e == nil || e.policy == nil || ctx == nil || ctx.Err() != nil {
		return r.fail(UnavailableCompletion, -32002)
	}
	r.metadata.PolicyDigest = metadataDigestText(e.policy.Digest())
	env, err := rpcenvelope.ParseRaw(body, rpcenvelope.DefaultLimits())
	if err != nil || env.Method() == "" {
		return r.fail(InvalidCompletion, -32600)
	}
	version := bytes.TrimSpace(env.VersionJSON())
	if len(version) > 0 && !bytes.Equal(version, []byte("null")) {
		var v string
		if json.Unmarshal(version, &v) != nil || v != "2.0" {
			return r.fail(InvalidCompletion, -32600)
		}
	}
	if id, present := env.IDJSON(); present {
		r.id = id
	} else {
		r.notification = true
	}
	name := env.Method()
	if canonical, known := rpcmethoddata.CanonicalBuiltin(name); known {
		name = canonical
	}
	d, known := e.methods[name]
	if !known {
		return r.fail(InvalidCompletion, -32601)
	}
	r.metadata.Method, r.metadata.Canonical = name, d.method
	q, err := rpcexecution.ParseStateQuery(d.method, env.ParamsJSON(), e.limits)
	if err != nil {
		return r.fail(InvalidCompletion, -32602)
	}
	r.query = q
	client := e.defaultClient
	if assertion.kind == 1 {
		if !d.builtin || !e.policy.AllowsAnonymous(name) || q.Block().HistoricalInput() || d.method == rpcexecution.StateStorage || d.method == rpcexecution.StateProof {
			return r.fail(UnauthenticatedCompletion, -32001)
		}
		r.anonymous = true
	} else {
		if assertion.kind != 2 {
			return r.fail(UnauthenticatedCompletion, -32001)
		}
		view, err := e.factory.Build(assertion.token)
		if err != nil {
			return r.fail(UnauthenticatedCompletion, -32001)
		}
		r.view = view
		r.metadata.ActorID = view.ActorID()
		ids := view.OrgIDs()
		if len(ids) == 0 {
			return r.fail(DeniedCompletion, -32001)
		}
		if q.Block().HistoricalInput() && !anyStateOrgAdmin(view) {
			return r.fail(DeniedCompletion, -32001)
		}
		contract, registered := view.Contract(q.Target())
		owner := e.owners[q.Target()]
		if owner != "" {
			if _, member := view.Org(owner); !member {
				return r.fail(DeniedCompletion, -32001)
			}
		}
		orgID := selected
		if orgID == "" {
			if owner != "" {
				orgID = owner
			} else if len(ids) == 1 {
				orgID = ids[0]
			}
		}
		var org *runtimepolicy.OrgView
		if orgID != "" {
			var mapped bool
			org, mapped = view.Org(orgID)
			if !mapped || !stateMethodGranted(org, name, d) {
				return r.fail(DeniedCompletion, -32001)
			}
			r.metadata.OrganizationID = orgID
		} else {
			possible := false
			for _, id := range ids {
				o, _ := view.Org(id)
				possible = possible || stateMethodGranted(o, name, d)
			}
			if !possible {
				return r.fail(DeniedCompletion, -32001)
			}
		}
		authorized, admin := false, false
		walletEligible := e.wallets != nil && (d.method == rpcexecution.StateBalance || d.method == rpcexecution.StateNonce)
		if registered && orgID == owner && contract.Associated() {
			authorized, admin = true, contract.AdminForRead()
		}
		if !registered && e.preregistered[q.Target()] != "" && orgID == owner && org != nil && (org.IsOrgAdmin() || org.UnionClaims()&(policycore.ClaimAdmin|policycore.ClaimDeploy) != 0) {
			authorized = true
		}
		if !registered && owner == "" && staticPrecompile(q.Target()) && orgID != "" {
			authorized = true
		}
		if !authorized && e.associations != nil {
			pass, err := e.associations.ReadAddressAssociations(ctx, q.Target())
			if err != nil || pass.ValidateFor(e.associationMetadata.Identity, e.associationMetadata.Binding, q.Target()) != nil {
				return r.fail(UnavailableCompletion, -32002)
			}
			r.association = pass
			candidates := pass.Candidates()
			namespaces, actors, births := map[string]bool{}, map[string]bool{}, map[string]bool{}
			for _, candidate := range candidates {
				namespaces[candidate.Namespace] = true
				if candidate.Kind == "WALLET" {
					actors[candidate.WalletActor] = true
				}
				births[candidate.Inclusion.Hash.Hex()+candidate.TransactionHash.Hex()+":"+strconv.Itoa(candidate.Record)] = true
			}
			if len(births) > 1 || len(actors) > 1 {
				return r.fail(DeniedCompletion, -32001)
			}
			if owner == "" {
				if len(namespaces) > 1 || len(namespaces) == 0 && !walletEligible {
					return r.fail(DeniedCompletion, -32001)
				}
				for namespace := range namespaces {
					owner = namespace
				}
				if _, member := view.Org(owner); owner != "" && !member {
					return r.fail(DeniedCompletion, -32001)
				}
			}
			if orgID == "" {
				if owner == "" {
					return r.fail(DeniedCompletion, -32001)
				}
				orgID = owner
				org, _ = view.Org(orgID)
				if !stateMethodGranted(org, name, d) {
					return r.fail(DeniedCompletion, -32001)
				}
				r.metadata.OrganizationID = orgID
			}
			if !registered && len(namespaces) == 1 && namespaces[owner] && owner == orgID && org != nil && org.IsOrgAdmin() {
				authorized, admin = true, true
			}
			if actors[view.ActorID()] && owner != "" {
				authorized = true
			}
			if !authorized && walletEligible && len(namespaces) > 1 {
				return r.fail(DeniedCompletion, -32001)
			}
		}
		if !authorized && walletEligible && org != nil && (owner == "" || owner == orgID) {
			wallet, err := e.wallets.Load(ctx, view.ActorID())
			if err != nil {
				return r.fail(UnavailableCompletion, -32002)
			}
			if wallet.ActorID() != view.ActorID() || !wallet.Contains(q.Target()) {
				return r.fail(DeniedCompletion, -32001)
			}
			r.wallet = &wallet
			authorized = true
		}
		if !authorized || org == nil {
			return r.fail(DeniedCompletion, -32001)
		}
		if d.method == rpcexecution.StateProof && !admin {
			return r.fail(DeniedCompletion, -32001)
		}
		if d.method == rpcexecution.StateStorage && !admin {
			for _, key := range q.StorageKeys() {
				if !stateInfraKey(key) {
					return r.fail(DeniedCompletion, -32001)
				}
			}
		}
		ref, err := org.SelectCredentialRef(name)
		if err != nil {
			return r.fail(DeniedCompletion, -32001)
		}
		client = e.clients[StateBindingKey{orgID, ref}]
		if client == nil {
			return r.fail(UnavailableCompletion, -32002)
		}
		if view.RequireLive() != nil {
			return r.fail(UnauthenticatedCompletion, -32001)
		}
	}
	r.source = client.Source()
	r.client = client
	observation, err := client.Query(ctx, q)
	if err != nil {
		return r.fail(UnavailableCompletion, -32002)
	}
	r.observation = observation
	if r.preflightObservation() != nil {
		return r.fail(UnavailableCompletion, -32002)
	}
	r.metadata.Class = SuccessfulCompletion
	if r.notification {
		r.observation = nil
		r.completedNotification = true
	}
	return r
}
