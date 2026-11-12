package v2demo

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/ethereum/go-ethereum/crypto"
	"privacy-proxy/internal/brokerpolicy"
	"privacy-proxy/internal/compliancepolicy"
	dp "privacy-proxy/internal/disclosurepolicy"
	"privacy-proxy/internal/identity"
	vs "privacy-proxy/internal/operational/v2server"
	"privacy-proxy/internal/policybundle"
	"privacy-proxy/internal/policycore"
	"privacy-proxy/internal/policyprofiles"
)

// This is an ordinary application contract ABI, not policy EVM bytecode.
const ContractABI = `[{"type":"function","name":"value","inputs":[],"outputs":[{"name":"","type":"uint256"}],"stateMutability":"view"},{"type":"function","name":"set","inputs":[{"name":"subject","type":"address"},{"name":"next","type":"uint256"}],"outputs":[],"stateMutability":"nonpayable"},{"type":"event","name":"Changed","inputs":[{"name":"subject","type":"address","indexed":true},{"name":"value","type":"uint256","indexed":false}],"anonymous":false}]`

type Persona struct {
	ID        string `json:"id"`
	HolderDID string `json:"holderDid"`
	RoleValue *int   `json:"roleValue"`
	ProfileID string `json:"profileId"`
}
type WalletMetadata struct {
	Version        int       `json:"version"`
	TestOnly       bool      `json:"testOnly"`
	Network        string    `json:"network"`
	ChainID        string    `json:"chainId"`
	StateContract  string    `json:"stateContract"`
	StateRPCURL    string    `json:"stateRpcUrl"`
	IssuerDID      string    `json:"issuerDid"`
	VerifierDID    string    `json:"verifierDid"`
	ContextURL     string    `json:"contextUrl"`
	ContextPath    string    `json:"contextPath"`
	ContextSHA256  string    `json:"contextSHA256"`
	CredentialType string    `json:"credentialType"`
	CircuitID      string    `json:"circuitId"`
	Personas       []Persona `json:"personas"`
}

func walletMetadata(s State) (WalletMetadata, []byte, error) {
	var m WalletMetadata
	directory := s.WalletOutput
	if directory == "" {
		directory = s.file("wallet-state")
	}
	b, e := os.ReadFile(filepath.Join(directory, "metadata.json"))
	if e != nil {
		return m, nil, e
	}
	if e = json.Unmarshal(b, &m); e != nil {
		return m, nil, e
	}
	if m.Version != 1 || !m.TestOnly || len(m.Personas) != 4 || m.ContextPath != "role-context.json" || m.StateRPCURL != s.WalletOrigin()+"/rpc" || m.CircuitID != "credentialAtomicQuerySigV2" || m.CredentialType != "BankRole" {
		return m, nil, ErrInvalid
	}
	context, e := os.ReadFile(filepath.Join(directory, "role-context.json"))
	if e != nil || string(policybundle.RawDigest(context)) != m.ContextSHA256 {
		return m, nil, ErrInvalid
	}
	ids := []string{"admin", "deployer", "reader", "outsider"}
	for i, p := range m.Personas {
		if p.ID != ids[i] || p.ProfileID != "demo-"+p.ID || (i < 3 && (p.RoleValue == nil || *p.RoleValue != i+1)) || (i == 3 && p.RoleValue != nil) {
			return m, nil, ErrInvalid
		}
	}
	return m, context, nil
}
func identitySource(s State, m WalletMetadata) (identity.SourceCatalog, error) {
	raw, e := base64.RawURLEncoding.DecodeString(s.Secrets["DEMO_ACCESS_PRIVATE"])
	if e != nil || len(raw) != 64 {
		return identity.SourceCatalog{}, ErrInvalid
	}
	private := ed25519.PrivateKey(raw)
	source := identity.SourceCatalog{APIVersion: identity.APIVersion, Kind: identity.CatalogKind, Issuers: []identity.Issuer{{ID: "demo-ops", Issuer: s.OPSOrigin(), Audience: "core", Keys: []identity.PublicKey{{Kid: "demo-access", Alg: "EdDSA", Kty: "OKP", Crv: "Ed25519", X: base64.RawURLEncoding.EncodeToString(private.Public().(ed25519.PublicKey))}}, AllowedProfiles: []string{}}}, Profiles: []identity.Profile{}, Mappings: []identity.Mapping{}}
	for i, who := range m.Personas {
		profile := identity.Profile{ID: who.ProfileID, Kind: identity.PrivadoIdentity, VerifierID: m.VerifierDID, Network: m.Network, IdentityStateContract: m.StateContract}
		if i < 3 {
			profile.Kind = identity.PrivadoRole
			profile.AllowedCredentialIssuers = []string{m.IssuerDID}
			profile.Context = m.ContextURL
			profile.ContextDigest = m.ContextSHA256
			profile.Type = m.CredentialType
			profile.CircuitID = m.CircuitID
			profile.Predicates = []identity.Predicate{{ID: who.ID, Field: "role", Operator: "eq", Value: fmt.Sprint(*who.RoleValue)}}
			source.Mappings = append(source.Mappings, identity.Mapping{ID: "demo-" + who.ID, ProfileID: who.ProfileID, OrganizationID: Organization, PrincipalKind: identity.Human, Fact: identity.Fact{Kind: "privado.predicate", Value: who.ID}, GroupIDs: []string{[]string{Admin, Deployer, Reader}[i]}})
		}
		source.Profiles = append(source.Profiles, profile)
		source.Issuers[0].AllowedProfiles = append(source.Issuers[0].AllowedProfiles, profile.ID)
	}
	return source, nil
}
func prepare(ctx context.Context, s State, name string, draft policybundle.Draft, docs map[string]any, extra map[string][]byte, options policybundle.Options) (*policybundle.CatalogSnapshot, vs.Selection, error) {
	source := s.file("private/authoring/" + name)
	if e := os.MkdirAll(source, 0700); e != nil {
		return nil, vs.Selection{}, e
	}
	for file, value := range docs {
		if _, e := writeJSON(filepath.Join(source, file), value); e != nil {
			return nil, vs.Selection{}, e
		}
	}
	for file, raw := range extra {
		if _, e := writeBytes(filepath.Join(source, file), raw); e != nil {
			return nil, vs.Selection{}, e
		}
	}
	if _, e := writeJSON(filepath.Join(source, "draft.json"), draft); e != nil {
		return nil, vs.Selection{}, e
	}
	artifact, e := policybundle.PrepareDirectory(ctx, policybundle.DraftSelection{Directory: source}, options)
	if e != nil {
		return nil, vs.Selection{}, e
	}
	output := s.file("bundles/" + name + "-" + strings.TrimPrefix(string(artifact.ManifestDigest()), "sha256:"))
	if e = os.MkdirAll(output, 0700); e != nil {
		return nil, vs.Selection{}, e
	}
	for _, file := range artifact.Files() {
		full := filepath.Join(output, file.Path)
		if old, e := os.ReadFile(full); e == nil {
			if string(old) != string(file.Bytes) {
				return nil, vs.Selection{}, ErrInvalid
			}
			continue
		}
		if _, e = writeBytes(full, file.Bytes); e != nil {
			return nil, vs.Selection{}, e
		}
	}
	if _, e = writeBytes(filepath.Join(output, "manifest.json"), artifact.ManifestBytes()); e != nil {
		return nil, vs.Selection{}, e
	}
	selection := vs.Selection{Directory: output, ManifestDigest: string(artifact.ManifestDigest()), Environment: Environment, ChainID: ChainID}
	snapshot, e := policybundle.LoadDirectory(ctx, policybundle.Selection{Directory: output, ExpectedManifestDigest: artifact.ManifestDigest(), ExpectedEnvironment: Environment, ExpectedChainID: ChainID}, options)
	return snapshot, selection, e
}
func bundleDocuments(draft *policybundle.Draft, docs map[string]any, groups []policybundle.Group, contracts []policybundle.Contract, policy *policycore.Policy) {
	for _, item := range []struct {
		kind policybundle.Kind
		name string
		spec any
	}{{policybundle.Groups, "groups", policybundle.GroupsSpec{Groups: groups}}, {policybundle.ContractRegistry, "registry", policybundle.RegistrySpec{Contracts: contracts}}, {policybundle.ExecutionRules, "execution", policybundle.ExecutionSpec{Policy: policy}}} {
		file := item.name + ".json"
		draft.Documents = append(draft.Documents, policybundle.DraftDocument{Kind: item.kind, OrganizationID: Organization, Path: file})
		docs[file] = map[string]any{"apiVersion": policybundle.DocumentAPIVersion, "kind": item.kind, "organizationId": Organization, "spec": item.spec}
	}
}
func baseDraft(profile, evaluator string) policybundle.Draft {
	return policybundle.Draft{APIVersion: policybundle.DraftAPIVersion, Kind: policybundle.DraftKind, Environment: Environment, ChainID: ChainID, EvaluatorVersion: evaluator, Profile: profile, SourceRevision: "isolated-local-demo", Organizations: []policybundle.Organization{{ID: Organization, Slug: "demo-bank", Name: "Demo Bank"}}, Documents: []policybundle.DraftDocument{}, IdentityCatalog: &policybundle.DraftIdentity{Path: "identity.json"}}
}
func bundles(ctx context.Context, s State) (*policybundle.CatalogSnapshot, *policybundle.CatalogSnapshot, vs.Selection, vs.Selection, error) {
	var empty vs.Selection
	m, contextBytes, e := walletMetadata(s)
	if e != nil {
		return nil, nil, empty, empty, e
	}
	ids, e := identitySource(s, m)
	if e != nil {
		return nil, nil, empty, empty, e
	}
	brokerOptions, brokerDescription, e := policyprofiles.Options(policybundle.BrokerMultiProfileID)
	if e != nil {
		return nil, nil, empty, empty, e
	}
	brokerDraft := baseDraft(policybundle.BrokerMultiProfileID, brokerDescription.EvaluatorVersion)
	brokerDraft.AuthCatalog = &policybundle.DraftIdentity{Path: "auth.json"}
	auth := brokerpolicy.SourceV2{APIVersion: brokerpolicy.MultiAPIVersion, Kind: brokerpolicy.Kind, IssuerID: "demo-ops", AccessKeyID: "demo-access", WebOrigin: s.OPSOrigin(), CompletionURI: s.OPSOrigin() + "/auth/complete", AzureProfiles: []brokerpolicy.AzureBinding{}, PrivadoProfiles: []brokerpolicy.PrivadoBinding{}, PrivadoNetworks: []brokerpolicy.PrivadoNetwork{{Network: m.Network, ChainID: m.ChainID, StateContract: m.StateContract, RPCURL: m.StateRPCURL, AllowPrivate: true}}, PinnedDocuments: []brokerpolicy.PinnedDocumentRef{{URL: m.ContextURL, Path: "role-context.json", SHA256: m.ContextSHA256}}, RenewalKeys: []brokerpolicy.KeyRef{{ID: "demo-mac", FromEnv: "OPS_BROKER_REFRESH_DEMO", Active: true}}, EncryptionKeys: []brokerpolicy.KeyRef{{ID: "demo-aes", FromEnv: "OPS_BROKER_ENCRYPTION_DEMO", Active: true}}}
	for _, p := range m.Personas {
		auth.PrivadoProfiles = append(auth.PrivadoProfiles, brokerpolicy.PrivadoBinding{ProfileID: p.ProfileID})
	}
	brokerDocs := map[string]any{"identity.json": ids, "auth.json": auth}
	brokerGroups := []policybundle.Group{}
	for i, id := range []string{Admin, Deployer, Reader} {
		brokerGroups = append(brokerGroups, policybundle.Group{ID: id, Slug: []string{"admin", "deployer", "reader"}[i], Name: []string{"Admin", "Deployer", "Reader"}[i], Claims: []string{}, AllowedMethods: []string{"eth_call"}})
	}
	bundleDocuments(&brokerDraft, brokerDocs, brokerGroups, []policybundle.Contract{}, &policycore.Policy{APIVersion: policycore.NativeV2APIVersion, Kind: policycore.Kind, Org: Organization, NestedCalls: policycore.NestedCallsRequireOwnRule, Bindings: []policycore.Binding{}})
	broker, brokerSelection, e := prepare(ctx, s, "broker", brokerDraft, brokerDocs, map[string][]byte{"role-context.json": contextBytes}, brokerOptions)
	if e != nil {
		return nil, nil, empty, empty, e
	}
	options, description, e := policyprofiles.DeliveryOptions(policybundle.RuntimeCreationObservedProfileID)
	if e != nil {
		return nil, nil, empty, empty, e
	}
	draft := baseDraft(policybundle.RuntimeCreationObservedProfileID, description.EvaluatorVersion)
	draft.RuntimeCatalog = &policybundle.DraftRuntime{Path: "runtime.json"}
	draft.ComplianceCatalog = &policybundle.DraftIdentity{Path: "compliance.json"}
	draft.DisclosureCatalog = &policybundle.DraftIdentity{Path: "disclosure.json"}
	// V1-compatible signed raw submission uses the eth_sendTransaction
	// capability. NodeSigning=false separately leaves the unsigned node-owned
	// handler unmounted; removing this capability would deny raw submission.
	methods := append([]string{}, options.Methods.Assignable...)
	groups := []policybundle.Group{{ID: Admin, Slug: "admin", Name: "Admin", IsOrgAdmin: true, Claims: []string{}, AllowedMethods: methods}, {ID: Deployer, Slug: "deployer", Name: "Deployer", Claims: []string{"admin", "deploy"}, AllowedMethods: methods}, {ID: Reader, Slug: "reader", Name: "Reader", Claims: []string{}, AllowedMethods: []string{"eth_call", "eth_getCode", "eth_getLogs", "eth_getTransactionByHash", "eth_getTransactionReceipt", "eth_chainId", "eth_blockNumber", "eth_getBalance", "eth_getTransactionCount", "web3_clientVersion"}}}
	event := policybundle.EventRule{Topic0: crypto.Keccak256Hash([]byte("Changed(address,uint256)")).Hex(), Name: "Changed", ParamRules: []policybundle.ParamRule{}}
	contract := policybundle.Contract{ID: "55555555-5555-4555-8555-555555555555", Address: s.TargetContract, Name: "Demo Ledger", ABI: json.RawMessage(ContractABI), AllowVisibleToUnlock: true, ReadGrants: []policybundle.ReadGrant{}}
	for i, group := range []string{Admin, Deployer, Reader} {
		if group == Reader && !s.ReaderGrant {
			continue
		}
		contract.ReadGrants = append(contract.ReadGrants, policybundle.ReadGrant{ID: fmt.Sprintf("66666666-6666-4666-8666-%012d", i+1), GroupID: group, EventRules: policybundle.EventRules{Mode: "allowlist", Rules: []policybundle.EventRule{event}}})
	}
	bindings := []policycore.Binding{}
	for _, id := range []string{Admin, Deployer, Reader} {
		allow := []policycore.FrameRule{{StorageAddress: s.TargetContract, Selector: "*"}}
		if id != Reader {
			allow = append(allow, policycore.FrameRule{TargetClass: "create", Selector: "*", CallTypes: []policycore.CallType{policycore.CallTypeCreate, policycore.CallTypeCreate2}})
		}
		bindings = append(bindings, policycore.Binding{Group: id, Allow: allow})
	}
	runtime := policybundle.RuntimeCreationObservedSource{APIVersion: policybundle.RuntimeCreationObservedAPIVersion, Kind: policybundle.RuntimeKind, ReadProfile: "standard", IntraOrgGrantTracing: false, SharedInfrastructure: []policybundle.SharedInfrastructure{}, AddressScopes: []policybundle.AddressScope{}, NodeEvidenceProfile: policybundle.RuntimeSimulationNodeEvidenceProfileID, RawSubmissionMode: policybundle.RawSubmissionOPSPreflight, CreationAttribution: policybundle.CreationAttribution{Factories: []policybundle.FactoryAttribution{}}, CaptureReadinessProfile: "same-node-caught-up/v1"}
	compliance := compliancepolicy.Source{APIVersion: compliancepolicy.APIVersion, Kind: compliancepolicy.Kind, Organizations: []compliancepolicy.OrganizationPolicy{{OrganizationID: Organization, RecordMaxSeconds: 86400, PriceMaxAgeSeconds: 600, Spec: compliancepolicy.SourceSpec{Settings: compliancepolicy.SourceSettings{Currency: "usd", ThresholdFiat: 100, UnknownPricePolicy: "forbidden", EnforcementMode: "enforce"}, AddressThresholds: []compliancepolicy.SourceThreshold{}, TokenPrices: []compliancepolicy.SourceTokenPrice{}}}}, Sanctions: []compliancepolicy.SourceSanction{}}
	now := s.CreatedAt
	disclosure := dp.Source{APIVersion: dp.APIVersion, Kind: dp.Kind, Rules: []dp.RuleSource{{ID: "demo-auditor", DataOrganizationID: Organization, Viewers: dp.Viewers{Groups: []dp.GroupRef{{OrganizationID: Organization, GroupID: Admin}}, Actors: []string{}}, Targets: dp.Targets{Mode: "all-in-data-org", Actors: []string{}}, Resources: []dp.Resource{dp.AddressHistory, dp.Transactions, dp.ActivityLogs, dp.ActivitySummary, dp.SanctionsReport, dp.ComplianceReport}, Addresses: dp.Addresses{Mode: "all-target-addresses", Values: []string{}}, DataTime: dp.Interval{Start: now - 86400, End: now + 86400*365}, MaxLevel: dp.Full, Validity: dp.Validity{NotBefore: now - 60, ExpiresAt: now + 86400*365}, MaxCaseSeconds: 1200}}}
	docs := map[string]any{"identity.json": ids, "runtime.json": runtime, "compliance.json": compliance, "disclosure.json": disclosure}
	bundleDocuments(&draft, docs, groups, []policybundle.Contract{contract}, &policycore.Policy{APIVersion: policycore.NativeV4APIVersion, Kind: policycore.Kind, Org: Organization, NestedCalls: policycore.NestedCallsRequireOwnRule, Bindings: bindings})
	core, coreSelection, e := prepare(ctx, s, "core", draft, docs, nil, options)
	return core, broker, coreSelection, brokerSelection, e
}
