package policybundle

import (
	"encoding/hex"
	"encoding/json"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"privacy-proxy/internal/creationfacts"
	"privacy-proxy/internal/pricefeedpolicy"
)

const RuntimeAPIVersion = "ops.runtime-policy/v1alpha1"
const RuntimeRawAPIVersion = "ops.runtime-policy/v1alpha2"
const RuntimeMultiOrgAPIVersion = "ops.runtime-policy/v1alpha3"
const RuntimeLifecycleAPIVersion = "ops.runtime-policy/v1alpha4"
const RuntimeSimulationAPIVersion = "ops.runtime-policy/v1alpha5"
const RuntimeKind = "RuntimePolicy"
const RuntimeNodeEvidenceProfileID = "geth-prague-call/v1"
const RuntimeLifecycleNodeEvidenceProfileID = "geth-prague-lifecycle-call/v1"
const RuntimeSimulationNodeEvidenceProfileID = "geth-prague-simulation/v1"
const RawSubmissionGuardV1 = "guard-v1"
const RawSubmissionOPSPreflight = "ops-preflight"

type RuntimeCatalogRef struct {
	Path   string `json:"path"`
	SHA256 Digest `json:"sha256"`
}
type RuntimeCatalogIdentity struct {
	RuntimeCatalogRef
	SemanticDigest Digest
	PriceFeed      *PriceFeedIdentity `json:",omitempty"`
}
type PriceFeedIdentity struct {
	SourceDigest, PlanDigest, ComplianceDigest string
}
type SharedInfrastructure struct {
	Address  string  `json:"address"`
	CodeHash *string `json:"codeHash,omitempty" optional:"true"`
}
type AddressScope struct {
	Address        string `json:"address"`
	OrganizationID string `json:"organizationId"`
}
type RuntimeSource struct {
	APIVersion           string                 `json:"apiVersion"`
	Kind                 string                 `json:"kind"`
	ReadProfile          string                 `json:"readProfile"`
	IntraOrgGrantTracing bool                   `json:"intraOrgGrantTracing"`
	SharedInfrastructure []SharedInfrastructure `json:"sharedInfrastructure"`
	AddressScopes        []AddressScope         `json:"addressScopes"`
	NodeEvidenceProfile  string                 `json:"nodeEvidenceProfile"`
}

// RuntimeRawSource is a distinct closed wire shape. Its approved submission
// mode cannot disappear through an older source projection or environment.
type RuntimeRawSource struct {
	APIVersion           string                 `json:"apiVersion"`
	Kind                 string                 `json:"kind"`
	ReadProfile          string                 `json:"readProfile"`
	IntraOrgGrantTracing bool                   `json:"intraOrgGrantTracing"`
	SharedInfrastructure []SharedInfrastructure `json:"sharedInfrastructure"`
	AddressScopes        []AddressScope         `json:"addressScopes"`
	NodeEvidenceProfile  string                 `json:"nodeEvidenceProfile"`
	RawSubmissionMode    string                 `json:"rawSubmissionMode"`
}

// RuntimeMultiOrgSource is the first closed v3 wire shape. An absent feed does
// not authorize an environment-selected endpoint; explicit null is invalid.
type RuntimeMultiOrgSource struct {
	APIVersion           string                  `json:"apiVersion"`
	Kind                 string                  `json:"kind"`
	ReadProfile          string                  `json:"readProfile"`
	IntraOrgGrantTracing bool                    `json:"intraOrgGrantTracing"`
	SharedInfrastructure []SharedInfrastructure  `json:"sharedInfrastructure"`
	AddressScopes        []AddressScope          `json:"addressScopes"`
	NodeEvidenceProfile  string                  `json:"nodeEvidenceProfile"`
	RawSubmissionMode    string                  `json:"rawSubmissionMode"`
	PriceFeed            *pricefeedpolicy.Source `json:"priceFeed,omitempty" optional:"true"`
}

// RuntimeLifecycleSource keeps the same closed fields under a distinct v4 tag.
// It is never exposed through an older source accessor.
type RuntimeLifecycleSource RuntimeMultiOrgSource

// RuntimeSimulationSource selects unsigned creation without older projection.
type RuntimeSimulationSource RuntimeMultiOrgSource

func positiveChain64(raw string) bool {
	n, err := strconv.ParseUint(raw, 10, 64)
	return err == nil && n > 0 && strconv.FormatUint(n, 10) == raw
}

func decodeRuntimeSource(raw []byte, depth int) (*RuntimeSource, *RuntimeRawSource, *RuntimeMultiOrgSource, *RuntimeLifecycleSource, *RuntimeSimulationSource, *RuntimeCreationIntentSource, *RuntimeCreationObservedSource, error) {
	value, err := strictValue(raw, depth)
	if err != nil {
		return nil, nil, nil, nil, nil, nil, nil, err
	}
	object, ok := value.(map[string]any)
	if !ok {
		return nil, nil, nil, nil, nil, nil, nil, fail(InvalidSchema, "", "", "runtimeCatalog", "runtime source must be an object")
	}
	switch object["apiVersion"] {
	case RuntimeAPIVersion:
		var source RuntimeSource
		if err := decodeSource(raw, &source, depth); err != nil {
			return nil, nil, nil, nil, nil, nil, nil, err
		}
		return &source, nil, nil, nil, nil, nil, nil, nil
	case RuntimeRawAPIVersion:
		var source RuntimeRawSource
		if err := decodeSource(raw, &source, depth); err != nil {
			return nil, nil, nil, nil, nil, nil, nil, err
		}
		return nil, &source, nil, nil, nil, nil, nil, nil
	case RuntimeMultiOrgAPIVersion:
		var source RuntimeMultiOrgSource
		if err := decodeSource(raw, &source, depth); err != nil {
			return nil, nil, nil, nil, nil, nil, nil, err
		}
		return nil, nil, &source, nil, nil, nil, nil, nil
	case RuntimeLifecycleAPIVersion:
		var source RuntimeLifecycleSource
		if err := decodeSource(raw, &source, depth); err != nil {
			return nil, nil, nil, nil, nil, nil, nil, err
		}
		return nil, nil, nil, &source, nil, nil, nil, nil
	case RuntimeSimulationAPIVersion:
		var source RuntimeSimulationSource
		if err := decodeSource(raw, &source, depth); err != nil {
			return nil, nil, nil, nil, nil, nil, nil, err
		}
		return nil, nil, nil, nil, &source, nil, nil, nil
	case RuntimeCreationIntentAPIVersion:
		var source RuntimeCreationIntentSource
		if err := decodeSource(raw, &source, depth); err != nil {
			return nil, nil, nil, nil, nil, nil, nil, err
		}
		return nil, nil, nil, nil, nil, &source, nil, nil
	case RuntimeCreationObservedAPIVersion:
		var source RuntimeCreationObservedSource
		if err := decodeSource(raw, &source, depth); err != nil {
			return nil, nil, nil, nil, nil, nil, nil, err
		}
		return nil, nil, nil, nil, nil, nil, &source, nil
	default:
		return nil, nil, nil, nil, nil, nil, nil, fail(InvalidSchema, "", "", "apiVersion", "unsupported runtime source version")
	}
}

// RuntimeCatalog is approved immutable source. Its static scopes never enter
// the registered-contract/native execution or operational ownership indexes.
type RuntimeCatalog struct {
	source                 RuntimeSource
	rawSource              *RuntimeRawSource
	multiOrgSource         *RuntimeMultiOrgSource
	lifecycleSource        *RuntimeLifecycleSource
	simulationSource       *RuntimeSimulationSource
	creationIntentSource   *RuntimeCreationIntentSource
	creationObservedSource *RuntimeCreationObservedSource
	feedDefinition         pricefeedpolicy.Definition
	feedPlan               pricefeedpolicy.Plan
	digest                 Digest
}

// Source returns only detached v1; v2/v3 catalogs return zero, preserving tags.
func (r *RuntimeCatalog) Source() RuntimeSource {
	if r == nil || r.rawSource != nil || r.multiOrgSource != nil || r.lifecycleSource != nil || r.simulationSource != nil || r.creationIntentSource != nil || r.creationObservedSource != nil {
		return RuntimeSource{}
	}
	s := r.source
	s.AddressScopes = slices.Clone(s.AddressScopes)
	s.SharedInfrastructure = cloneShared(s.SharedInfrastructure)
	return s
}

func cloneShared(in []SharedInfrastructure) []SharedInfrastructure {
	out := slices.Clone(in)
	for i := range out {
		if out[i].CodeHash != nil {
			h := *out[i].CodeHash
			out[i].CodeHash = &h
		}
	}
	return out
}

func (r *RuntimeCatalog) RawSource() (RuntimeRawSource, bool) {
	if r == nil || r.rawSource == nil {
		return RuntimeRawSource{}, false
	}
	s := *r.rawSource
	s.SharedInfrastructure = cloneShared(s.SharedInfrastructure)
	s.AddressScopes = slices.Clone(s.AddressScopes)
	return s, true
}

func (r *RuntimeCatalog) MultiOrgSource() (RuntimeMultiOrgSource, bool) {
	if r == nil || r.multiOrgSource == nil {
		return RuntimeMultiOrgSource{}, false
	}
	s := *r.multiOrgSource
	s.SharedInfrastructure = cloneShared(s.SharedInfrastructure)
	s.AddressScopes = slices.Clone(s.AddressScopes)
	if s.PriceFeed != nil {
		feed := r.feedDefinition.Source()
		s.PriceFeed = &feed
	}
	return s, true
}

func (r *RuntimeCatalog) LifecycleSource() (RuntimeLifecycleSource, bool) {
	if r == nil || r.lifecycleSource == nil {
		return RuntimeLifecycleSource{}, false
	}
	s := *r.lifecycleSource
	s.SharedInfrastructure = cloneShared(s.SharedInfrastructure)
	s.AddressScopes = slices.Clone(s.AddressScopes)
	if s.PriceFeed != nil {
		feed := r.feedDefinition.Source()
		s.PriceFeed = &feed
	}
	return s, true
}

func (r *RuntimeCatalog) SimulationSource() (RuntimeSimulationSource, bool) {
	if r == nil || r.simulationSource == nil {
		return RuntimeSimulationSource{}, false
	}
	s := *r.simulationSource
	s.SharedInfrastructure = cloneShared(s.SharedInfrastructure)
	s.AddressScopes = slices.Clone(s.AddressScopes)
	if s.PriceFeed != nil {
		feed := r.feedDefinition.Source()
		s.PriceFeed = &feed
	}
	return s, true
}

func (r *RuntimeCatalog) PriceFeed() (pricefeedpolicy.Definition, pricefeedpolicy.Plan, bool) {
	if r == nil || !r.feedDefinition.Valid() || !r.feedPlan.Valid() {
		return pricefeedpolicy.Definition{}, pricefeedpolicy.Plan{}, false
	}
	return r.feedDefinition, r.feedPlan, true
}

func (r *RuntimeCatalog) RawSubmissionMode() string {
	if r != nil && r.creationObservedSource != nil {
		return r.creationObservedSource.RawSubmissionMode
	}
	if r != nil && r.creationIntentSource != nil {
		return r.creationIntentSource.RawSubmissionMode
	}
	if r != nil && r.simulationSource != nil {
		return r.simulationSource.RawSubmissionMode
	}
	if r != nil && r.lifecycleSource != nil {
		return r.lifecycleSource.RawSubmissionMode
	}
	if r != nil && r.multiOrgSource != nil {
		return r.multiOrgSource.RawSubmissionMode
	}
	if r == nil || r.rawSource == nil {
		return ""
	}
	return r.rawSource.RawSubmissionMode
}
func (r *RuntimeCatalog) SharedInfrastructure() []SharedInfrastructure {
	if r != nil && r.creationObservedSource != nil {
		return cloneShared(r.creationObservedSource.SharedInfrastructure)
	}
	if r.creationIntentSource != nil {
		return cloneShared(r.creationIntentSource.SharedInfrastructure)
	}
	if r.simulationSource != nil {
		return cloneShared(r.simulationSource.SharedInfrastructure)
	}
	if r.lifecycleSource != nil {
		return cloneShared(r.lifecycleSource.SharedInfrastructure)
	}
	if r.multiOrgSource != nil {
		return cloneShared(r.multiOrgSource.SharedInfrastructure)
	}
	if r.rawSource != nil {
		return cloneShared(r.rawSource.SharedInfrastructure)
	}
	return cloneShared(r.source.SharedInfrastructure)
}
func (r *RuntimeCatalog) Digest() Digest { return r.digest }
func (r *RuntimeCatalog) NodeEvidenceProfile() string {
	if r != nil && r.creationObservedSource != nil {
		return r.creationObservedSource.NodeEvidenceProfile
	}
	if r != nil && r.creationIntentSource != nil {
		return r.creationIntentSource.NodeEvidenceProfile
	}
	if r.simulationSource != nil {
		return r.simulationSource.NodeEvidenceProfile
	}
	if r.lifecycleSource != nil {
		return r.lifecycleSource.NodeEvidenceProfile
	}
	if r.multiOrgSource != nil {
		return r.multiOrgSource.NodeEvidenceProfile
	}
	if r.rawSource != nil {
		return r.rawSource.NodeEvidenceProfile
	}
	return r.source.NodeEvidenceProfile
}

func (r *RuntimeCatalog) IntraOrgGrantTracing() bool {
	if r != nil && r.creationObservedSource != nil {
		return r.creationObservedSource.IntraOrgGrantTracing
	}
	if r != nil && r.creationIntentSource != nil {
		return r.creationIntentSource.IntraOrgGrantTracing
	}
	if r.simulationSource != nil {
		return r.simulationSource.IntraOrgGrantTracing
	}
	if r.lifecycleSource != nil {
		return r.lifecycleSource.IntraOrgGrantTracing
	}
	if r.multiOrgSource != nil {
		return r.multiOrgSource.IntraOrgGrantTracing
	}
	if r.rawSource != nil {
		return r.rawSource.IntraOrgGrantTracing
	}
	return r.source.IntraOrgGrantTracing
}

func (r *RuntimeCatalog) ReadProfile() string {
	if r != nil && r.creationObservedSource != nil {
		return r.creationObservedSource.ReadProfile
	}
	if r != nil && r.creationIntentSource != nil {
		return r.creationIntentSource.ReadProfile
	}
	if r.simulationSource != nil {
		return r.simulationSource.ReadProfile
	}
	if r.lifecycleSource != nil {
		return r.lifecycleSource.ReadProfile
	}
	if r.multiOrgSource != nil {
		return r.multiOrgSource.ReadProfile
	}
	if r.rawSource != nil {
		return r.rawSource.ReadProfile
	}
	return r.source.ReadProfile
}
func (s *CatalogSnapshot) Runtime() (*RuntimeCatalog, bool) { return s.runtime, s.runtime != nil }

func (b *catalogBuilder) compileRuntime(limits Limits) error {
	if b.runtimeSource == nil && b.runtimeRawSource == nil && b.runtimeMultiOrgSource == nil && b.runtimeLifecycleSource == nil && b.runtimeSimulationSource == nil && b.runtimeCreationIntentSource == nil && b.runtimeCreationObservedSource == nil {
		return nil
	}
	bad := func(field, message string) error { return fail(InvalidSchema, "", "", field, message) }
	var s RuntimeSource
	var feed pricefeedpolicy.Definition
	modern := b.runtimeMultiOrgSource
	lifecycle := b.runtimeLifecycleSource != nil
	simulation := b.runtimeSimulationSource != nil
	observed := b.runtimeCreationObservedSource != nil
	intent := b.runtimeCreationIntentSource != nil || observed
	expectedProfile, expectedVersion, expectedEvidence := RuntimeMultiOrgProfileID, RuntimeMultiOrgAPIVersion, RuntimeNodeEvidenceProfileID
	if lifecycle {
		if modern != nil {
			return bad("runtimeCatalog", "multiple runtime source variants")
		}
		view := RuntimeMultiOrgSource(*b.runtimeLifecycleSource)
		modern = &view
		expectedProfile, expectedVersion, expectedEvidence = RuntimeLifecycleProfileID, RuntimeLifecycleAPIVersion, RuntimeLifecycleNodeEvidenceProfileID
	}
	if simulation {
		if modern != nil {
			return bad("runtimeCatalog", "multiple runtime source variants")
		}
		view := RuntimeMultiOrgSource(*b.runtimeSimulationSource)
		modern = &view
		expectedProfile, expectedVersion, expectedEvidence = RuntimeSimulationProfileID, RuntimeSimulationAPIVersion, RuntimeSimulationNodeEvidenceProfileID
	}
	if intent {
		if modern != nil {
			return bad("runtimeCatalog", "multiple runtime source variants")
		}
		var view RuntimeMultiOrgSource
		if observed {
			if b.runtimeCreationIntentSource != nil || b.runtimeCreationObservedSource.CaptureReadinessProfile != creationfacts.CaptureProfile {
				return bad("captureReadinessProfile", "unsupported capture readiness profile")
			}
			view = b.runtimeCreationObservedSource.commonSource()
		} else {
			view = b.runtimeCreationIntentSource.commonSource()
		}
		modern = &view
		expectedProfile, expectedVersion, expectedEvidence = RuntimeCreationIntentProfileID, RuntimeCreationIntentAPIVersion, RuntimeSimulationNodeEvidenceProfileID
		if observed {
			expectedProfile, expectedVersion = RuntimeCreationObservedProfileID, RuntimeCreationObservedAPIVersion
		}
	}
	if modern != nil {
		r := modern
		if b.runtimeSource != nil || b.runtimeRawSource != nil || b.profile.id != expectedProfile || r.APIVersion != expectedVersion || (r.RawSubmissionMode != RawSubmissionGuardV1 && r.RawSubmissionMode != RawSubmissionOPSPreflight) {
			return bad("runtimeCatalog", "unsupported runtime source/profile or raw mode")
		}
		if r.PriceFeed != nil {
			var err error
			feed, err = pricefeedpolicy.Normalize(*r.PriceFeed)
			if err != nil {
				return bad("priceFeed", "invalid approved price-feed source")
			}
		}
		s = RuntimeSource{RuntimeAPIVersion, r.Kind, r.ReadProfile, r.IntraOrgGrantTracing, r.SharedInfrastructure, r.AddressScopes, r.NodeEvidenceProfile}
	} else if b.runtimeRawSource != nil {
		r := b.runtimeRawSource
		if b.runtimeSource != nil || b.profile.id != RuntimeRawSendProfileID || r.APIVersion != RuntimeRawAPIVersion || (r.RawSubmissionMode != RawSubmissionGuardV1 && r.RawSubmissionMode != RawSubmissionOPSPreflight) {
			return bad("runtimeCatalog", "unsupported runtime source/profile or raw mode")
		}
		s = RuntimeSource{RuntimeAPIVersion, r.Kind, r.ReadProfile, r.IntraOrgGrantTracing, r.SharedInfrastructure, r.AddressScopes, r.NodeEvidenceProfile}
	} else {
		if b.profile.id != RuntimeCallProfileID {
			return bad("runtimeCatalog", "runtime source version does not match profile")
		}
		s = *b.runtimeSource
	}
	if s.APIVersion != RuntimeAPIVersion || s.Kind != RuntimeKind || (s.ReadProfile != "standard" && s.ReadProfile != "strict") || s.NodeEvidenceProfile != expectedEvidence {
		return bad("runtimeCatalog", "unsupported runtime schema/profile")
	}
	if len(s.SharedInfrastructure) > min(4096, limits.MaxContractsPerOrg) || len(s.AddressScopes) > min(4096, limits.MaxContractsPerOrg) {
		return fail(LimitExceeded, "", "", "runtimeCatalog", "runtime address budget exceeded")
	}
	orgs := map[string]bool{}
	for _, org := range b.snapshot.organizations {
		orgs[org.ID] = true
	}
	seen := map[common.Address]bool{}
	for i := range s.SharedInfrastructure {
		item := &s.SharedInfrastructure[i]
		if !common.IsHexAddress(item.Address) || len(item.Address) != 42 || !strings.HasPrefix(item.Address, "0x") {
			return bad("sharedInfrastructure.address", "invalid shared address")
		}
		a := common.HexToAddress(item.Address)
		if a == (common.Address{}) || seen[a] {
			return bad("sharedInfrastructure.address", "zero or duplicate shared address")
		}
		seen[a] = true
		item.Address = addressKey(item.Address)
		if item.CodeHash != nil {
			hash := *item.CodeHash
			if len(hash) != 66 || !strings.HasPrefix(hash, "0x") || hash != strings.ToLower(hash) {
				return bad("sharedInfrastructure.codeHash", "noncanonical code hash")
			}
			if _, e := hex.DecodeString(hash[2:]); e != nil {
				return bad("sharedInfrastructure.codeHash", "invalid code hash")
			}
			copyHash := hash
			item.CodeHash = &copyHash
		}
	}
	b.runtimeScopes = map[string]string{}
	for i := range s.AddressScopes {
		item := &s.AddressScopes[i]
		if !common.IsHexAddress(item.Address) || len(item.Address) != 42 || !strings.HasPrefix(item.Address, "0x") || common.HexToAddress(item.Address) == (common.Address{}) || !orgs[item.OrganizationID] {
			return bad("addressScopes", "invalid scope address or organization")
		}
		item.Address = addressKey(item.Address)
		if _, duplicate := b.runtimeScopes[item.Address]; duplicate {
			return bad("addressScopes", "duplicate static scope address")
		}
		if owner, known := b.addresses[item.Address]; known && owner != item.OrganizationID {
			return fail(ReferenceFailure, "", item.OrganizationID, "addressScopes", "scope conflicts with registered owner")
		}
		b.runtimeScopes[item.Address] = item.OrganizationID
	}
	sort.Slice(s.SharedInfrastructure, func(i, j int) bool { return s.SharedInfrastructure[i].Address < s.SharedInfrastructure[j].Address })
	sort.Slice(s.AddressScopes, func(i, j int) bool { return s.AddressScopes[i].Address < s.AddressScopes[j].Address })
	raw, _ := json.Marshal(s)
	catalog := &RuntimeCatalog{source: s}
	if modern != nil {
		r := &RuntimeMultiOrgSource{APIVersion: expectedVersion, Kind: s.Kind, ReadProfile: s.ReadProfile, IntraOrgGrantTracing: s.IntraOrgGrantTracing, SharedInfrastructure: s.SharedInfrastructure, AddressScopes: s.AddressScopes, NodeEvidenceProfile: s.NodeEvidenceProfile, RawSubmissionMode: modern.RawSubmissionMode}
		if feed.Valid() {
			normalized := feed.Source()
			r.PriceFeed = &normalized
			catalog.feedDefinition = feed
			b.capabilities[CapabilityPriceFeed] = true
			if normalized.Credential != nil {
				b.secrets[normalized.Credential.FromEnv] = true
			}
		}
		catalog.source = RuntimeSource{}
		if intent {
			entries := b.runtimeCreationIntentSource
			var declarations []FactoryAttribution
			if observed {
				declarations = b.runtimeCreationObservedSource.CreationAttribution.Factories
			} else {
				declarations = entries.CreationAttribution.Factories
			}
			factories, err := b.normalizeCreationFactories(s.SharedInfrastructure, declarations)
			if err != nil {
				return err
			}
			if observed {
				owned := creationObservedSource(*r, factories)
				catalog.creationObservedSource = &owned
			} else {
				owned := creationIntentSource(*r, factories)
				catalog.creationIntentSource = &owned
			}
		} else if simulation {
			owned := RuntimeSimulationSource(*r)
			catalog.simulationSource = &owned
		} else if lifecycle {
			owned := RuntimeLifecycleSource(*r)
			catalog.lifecycleSource = &owned
		} else {
			catalog.multiOrgSource = r
		}
		if intent {
			if observed {
				raw, _ = json.Marshal(catalog.creationObservedSource)
			} else {
				raw, _ = json.Marshal(catalog.creationIntentSource)
			}
		} else {
			raw, _ = json.Marshal(r)
		}
	} else if b.runtimeRawSource != nil {
		r := &RuntimeRawSource{RuntimeRawAPIVersion, s.Kind, s.ReadProfile, s.IntraOrgGrantTracing, s.SharedInfrastructure, s.AddressScopes, s.NodeEvidenceProfile, b.runtimeRawSource.RawSubmissionMode}
		catalog.source, catalog.rawSource = RuntimeSource{}, r
		raw, _ = json.Marshal(r)
	}
	if mode := catalog.RawSubmissionMode(); mode != "" {
		if mode == RawSubmissionGuardV1 {
			b.capabilities[CapabilityGuardDelivery] = true
		} else {
			b.capabilities[CapabilitySignedCall] = true
		}
	}
	digest := RawDigest(raw)
	catalog.digest = digest
	b.snapshot.runtime = catalog
	b.snapshot.metadata.RuntimeCatalog = &RuntimeCatalogIdentity{RuntimeCatalogRef: *b.runtimeRef, SemanticDigest: digest}
	if len(s.SharedInfrastructure) > 0 {
		b.capabilities[CapabilitySharedCode] = true
	}
	if len(s.AddressScopes) > 0 {
		b.capabilities[CapabilityAddressScopes] = true
	}
	return nil
}

// BuildPlan runs after compileCompliance against this same private snapshot.
// No partially normalized catalog is published if either stage fails.
func (b *catalogBuilder) compileRuntimePriceFeed() error {
	runtime := b.snapshot.runtime
	if runtime == nil || !runtime.feedDefinition.Valid() {
		return nil
	}
	plan, err := pricefeedpolicy.BuildPlan(runtime.feedDefinition, b.snapshot.compliance)
	if err != nil || len(plan.Requests()) == 0 {
		return fail(InvalidSchema, "", "", "priceFeed", "feed plan does not match approved compliance source")
	}
	runtime.feedPlan = plan
	b.snapshot.metadata.RuntimeCatalog.PriceFeed = &PriceFeedIdentity{SourceDigest: runtime.feedDefinition.Digest(), PlanDigest: plan.Digest(), ComplianceDigest: plan.CatalogDigest()}
	return nil
}
