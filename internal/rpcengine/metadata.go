package rpcengine

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"
	"strings"

	"privacy-proxy/internal/identity"
	"privacy-proxy/internal/networkidentity"
	"privacy-proxy/internal/policybundle"
	"privacy-proxy/internal/policycore"
	"privacy-proxy/internal/rpcenvelope"
	"privacy-proxy/internal/rpcexecution"
	"privacy-proxy/internal/rpcmetadatapolicy"
	"privacy-proxy/internal/rpcmethoddata"
	"privacy-proxy/internal/runtimepolicy"
)

type MetadataBindingKey struct{ OrganizationID, CredentialRef string }
type MetadataConfig struct {
	Snapshot    *policybundle.CatalogSnapshot
	Policy      *rpcmetadatapolicy.Definition
	Network     networkidentity.Binding
	Default     *rpcexecution.MetadataClient
	Clients     map[MetadataBindingKey]*rpcexecution.MetadataClient
	QueryLimits rpcexecution.MetadataLimits
	Clock       identity.Clock
}
type metadataDeclaration struct {
	info    policybundle.MethodInfo
	method  rpcexecution.MetadataMethod
	builtin bool
	orgFree bool
}
type MetadataEngine struct {
	snapshot      *policybundle.CatalogSnapshot
	factory       *runtimepolicy.Factory
	policy        *rpcmetadatapolicy.Policy
	network       networkidentity.Binding
	key           [32]byte
	defaultClient *rpcexecution.MetadataClient
	clients       map[MetadataBindingKey]*rpcexecution.MetadataClient
	methods       map[string]metadataDeclaration
	limits        rpcexecution.MetadataLimits
}

var errMetadata = errors.New("invalid metadata operation")

func metadataMethod(name string) rpcexecution.MetadataMethod {
	for m := rpcexecution.MetadataAccounts; m <= rpcexecution.MetadataKeccak; m++ {
		if m.String() == name {
			return m
		}
	}
	return rpcexecution.InvalidMetadataMethod
}
func orgFreeMetadata(method rpcexecution.MetadataMethod) bool {
	switch method {
	case rpcexecution.MetadataBlockNumber, rpcexecution.MetadataChainID, rpcexecution.MetadataGasPrice, rpcexecution.MetadataListening, rpcexecution.MetadataNetworkVersion, rpcexecution.MetadataClientVersion:
		return true
	}
	return false
}
func metadataAliasAllowed(name string) bool {
	if _, builtin := rpcmethoddata.CanonicalBuiltin(name); builtin || rpcmethoddata.IsBlocked(name) {
		return false
	}
	name = strings.ToLower(name)
	for _, prefix := range []string{"eth_", "net_", "web3_", "engine_"} {
		if strings.HasPrefix(name, prefix) {
			return false
		}
	}
	return true
}
func metadataBoundsWithin(a, b rpcexecution.MetadataLimits) bool {
	return a.Timeout > 0 && a.Timeout <= b.Timeout && a.MaxParamsBytes > 0 && a.MaxParamsBytes <= b.MaxParamsBytes && a.MaxResultBytes > 0 && a.MaxResultBytes <= b.MaxResultBytes && a.MaxAccounts > 0 && a.MaxAccounts <= b.MaxAccounts && a.MaxHistoryBlocks > 0 && a.MaxHistoryBlocks <= b.MaxHistoryBlocks && a.MaxPercentiles > 0 && a.MaxPercentiles <= b.MaxPercentiles
}
func metadataDigestText(d rpcmetadatapolicy.Digest) policybundle.Digest {
	return policybundle.Digest("sha256:" + hex.EncodeToString(d[:]))
}

func NewMetadata(c MetadataConfig) (*MetadataEngine, error) {
	if c.Snapshot == nil || c.Policy == nil || c.Clock == nil || c.Default == nil {
		return nil, errMetadata
	}
	key, err := c.Network.Key()
	meta := c.Snapshot.Metadata()
	if err != nil || meta.Profile != policybundle.RuntimeCreationObservedProfileID || meta.Environment != c.Network.Environment || meta.ChainID != c.Network.ChainID || string(meta.ManifestDigest) != string(metadataDigestText(c.Policy.ManifestDigest())) {
		return nil, errMetadata
	}
	if _, err := rpcexecution.ParseMetadataQuery(rpcexecution.MetadataChainID, nil, c.QueryLimits); err != nil {
		return nil, errMetadata
	}
	actual := c.Snapshot.Methods()
	methods := make([]rpcmetadatapolicy.Method, len(actual))
	for i, m := range actual {
		methods[i] = rpcmetadatapolicy.Method{Name: m.Name, Canonical: m.Canonical, RequiredClaims: m.RequiredClaims}
	}
	policy, err := rpcmetadatapolicy.Bind(c.Policy, c.Policy.ManifestDigest(), meta.MethodCatalogVersion, methods)
	if err != nil {
		return nil, errMetadata
	}
	factory, err := runtimepolicy.NewFactory(c.Snapshot, c.Clock)
	if err != nil {
		return nil, errMetadata
	}
	e := &MetadataEngine{snapshot: c.Snapshot, factory: factory, policy: policy, network: c.Network, key: key, defaultClient: c.Default, clients: map[MetadataBindingKey]*rpcexecution.MetadataClient{}, methods: map[string]metadataDeclaration{}, limits: c.QueryLimits}
	for _, m := range policy.MetadataMethods() {
		method := metadataMethod(m.Canonical)
		builtin := m.Name == m.Canonical
		if method == rpcexecution.InvalidMetadataMethod || len(m.Name) > 100 || !builtin && !metadataAliasAllowed(m.Name) {
			return nil, errMetadata
		}
		e.methods[m.Name] = metadataDeclaration{policybundle.MethodInfo{Name: m.Name, Canonical: m.Canonical, RequiredClaims: m.RequiredClaims}, method, builtin, builtin && orgFreeMetadata(method)}
	}
	for method := rpcexecution.MetadataAccounts; method <= rpcexecution.MetadataKeccak; method++ {
		declaration, ok := e.methods[method.String()]
		if !ok || !declaration.builtin || declaration.method != method {
			return nil, errMetadata
		}
	}
	validClient := func(client *rpcexecution.MetadataClient) bool {
		if client == nil {
			return false
		}
		s := client.Source()
		return s.Network == c.Network && s.NetworkKey == key && s.Profile == "rpc-metadata/v1" && metadataBoundsWithin(client.Bounds(), c.QueryLimits)
	}
	if !validClient(c.Default) {
		return nil, errMetadata
	}
	needed := map[MetadataBindingKey]bool{}
	for _, org := range c.Snapshot.Organizations() {
		for _, id := range c.Snapshot.GroupIDs(org.ID) {
			g, ok := c.Snapshot.Group(org.ID, id)
			if !ok {
				return nil, errMetadata
			}
			for _, name := range g.AllowedMethods {
				declaration, ok := e.methods[name]
				if !ok || declaration.orgFree {
					continue
				}
				ref := ""
				if g.RpcCredential != nil {
					ref = g.RpcCredential.FromEnv
				}
				needed[MetadataBindingKey{org.ID, ref}] = true
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
	return e, nil
}

type MetadataAssertion struct {
	kind  uint8
	token string
}

func MetadataAuthorization(values []string) MetadataAssertion {
	if len(values) == 0 {
		return MetadataAssertion{kind: 1}
	}
	if len(values) == 1 {
		parts := strings.Split(values[0], " ")
		if len(parts) == 2 && strings.EqualFold(parts[0], "Bearer") && parts[1] != "" {
			return MetadataAssertion{kind: 2, token: parts[1]}
		}
	}
	return MetadataAssertion{}
}

func (e *MetadataEngine) SharesSnapshot(native *Engine) bool {
	return e != nil && e.snapshot != nil && native != nil && native.snapshot == e.snapshot && native.OperationBinding().Profile == policybundle.RuntimeCreationObservedProfileID
}

type MetadataOperationBinding struct {
	Environment, ChainID, Profile, NetworkKey string
	ManifestDigest, PolicyDigest              policybundle.Digest
	Methods, OrganizationIDs                  []string
}

func (e *MetadataEngine) OperationBinding() MetadataOperationBinding {
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

func (e *MetadataEngine) QueryObserved(ctx context.Context, assertion MetadataAssertion, selectedOrg string, body []byte) *MetadataOperationResult {
	r := &MetadataOperationResult{owner: e, id: json.RawMessage("null"), metadata: MetadataOperationMetadata{Method: "rpc.invalid_request", Class: UnavailableCompletion}}
	if e == nil || e.policy == nil || ctx == nil || ctx.Err() != nil {
		return r.fail(UnavailableCompletion, -32002)
	}
	r.metadata.PolicyDigest = metadataDigestText(e.policy.Digest())
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
	q, err := rpcexecution.ParseMetadataQuery(declaration.method, env.ParamsJSON(), e.limits)
	if err != nil {
		return r.fail(InvalidCompletion, -32602)
	}
	client := e.defaultClient
	if assertion.kind == 1 {
		if !declaration.builtin || !e.policy.AllowsAnonymous(name) {
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
		r.view, r.metadata.ActorID = view, view.ActorID()
		if !declaration.orgFree {
			org := selectedOrg
			if org == "" {
				ids := view.OrgIDs()
				if len(ids) != 1 {
					return r.fail(DeniedCompletion, -32001)
				}
				org = ids[0]
			}
			ov, ok := view.Org(org)
			if !ok {
				return r.fail(DeniedCompletion, -32001)
			}
			r.metadata.OrganizationID = org
			if !ov.GroupAllowsMethod(name) {
				return r.fail(DeniedCompletion, -32001)
			}
			for _, claim := range declaration.info.RequiredClaims {
				var mask uint8
				switch claim {
				case "admin":
					mask = policycore.ClaimAdmin
				case "deploy":
					mask = policycore.ClaimDeploy
				case "upgrade":
					mask = policycore.ClaimUpgrade
				default:
					return r.fail(DeniedCompletion, -32001)
				}
				if ov.UnionClaims()&mask == 0 {
					return r.fail(DeniedCompletion, -32001)
				}
			}
			ref, err := ov.SelectCredentialRef(name)
			if err != nil {
				return r.fail(DeniedCompletion, -32001)
			}
			client = e.clients[MetadataBindingKey{org, ref}]
			if client == nil {
				return r.fail(UnavailableCompletion, -32002)
			}
		}
		if view.RequireLive() != nil {
			return r.fail(UnauthenticatedCompletion, -32001)
		}
	}
	r.source = client.Source()
	observation, err := client.Query(ctx, q)
	if err != nil {
		return r.fail(UnavailableCompletion, -32002)
	}
	r.observation = observation
	if err := r.preflightObservation(); err != nil {
		return r.fail(UnavailableCompletion, -32002)
	}
	r.metadata.Class = SuccessfulCompletion
	if r.notification {
		r.observation = nil
		r.completedNotification = true
	}
	return r
}
