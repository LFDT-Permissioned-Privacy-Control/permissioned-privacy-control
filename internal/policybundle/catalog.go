package policybundle

import (
	"context"
	"encoding/json"
	"slices"
	"sort"

	"github.com/ethereum/go-ethereum/common"

	"privacy-proxy/internal/identity"
	"privacy-proxy/internal/policycore"
)

// CatalogSnapshot owns all backing state. Its foundation metadata is explicitly
// validation-only; this type has no Ready or activation method.
type CatalogSnapshot struct {
	metadata      BundleMetadata
	organizations []Organization
	groups        map[string]map[string]Group
	contracts     map[string]map[common.Address]Contract
	execution     map[string]*policycore.Validated
	requirements  Requirements
	identity      *identity.Catalog
	methods       methodIndex
	runtime       *RuntimeCatalog
}

func (s *CatalogSnapshot) Metadata() BundleMetadata {
	m := s.metadata
	m.Documents = slices.Clone(m.Documents)
	if m.IdentityCatalog != nil {
		copied := *m.IdentityCatalog
		m.IdentityCatalog = &copied
	}
	if m.RuntimeCatalog != nil {
		copied := *m.RuntimeCatalog
		m.RuntimeCatalog = &copied
	}
	return m
}

func (s *CatalogSnapshot) Identity() (*identity.Catalog, bool) { return s.identity, s.identity != nil }
func (s *CatalogSnapshot) Organizations() []Organization       { return slices.Clone(s.organizations) }
func (s *CatalogSnapshot) Group(org, id string) (Group, bool) {
	g, ok := s.groups[org][id]
	return cloneGroup(g), ok
}
func (s *CatalogSnapshot) Contract(org string, address common.Address) (Contract, bool) {
	c, ok := s.contracts[org][address]
	return cloneContract(c), ok
}
func (s *CatalogSnapshot) Execution(org string) (*policycore.Validated, bool) {
	v, ok := s.execution[org]
	return v, ok
}
func (s *CatalogSnapshot) Requirements() Requirements {
	return Requirements{slices.Clone(s.requirements.Capabilities), slices.Clone(s.requirements.SecretRefs)}
}
func (s *CatalogSnapshot) NativeCatalog(org string) (policycore.Catalog, bool) {
	groups, ok := s.groups[org]
	if !ok {
		return policycore.Catalog{}, false
	}
	c := policycore.Catalog{Org: org, Groups: make(map[string]struct{}, len(groups)), Contracts: make(map[string]policycore.ContractInfo, len(s.contracts[org]))}
	for id := range groups {
		c.Groups[id] = struct{}{}
	}
	for _, contract := range s.contracts[org] {
		c.Contracts[contract.Address] = policycore.ContractInfo{ABI: string(contract.ABI)}
	}
	return c, true
}

func cloneGroup(g Group) Group {
	g.AllowedMethods = slices.Clone(g.AllowedMethods)
	g.Claims = slices.Clone(g.Claims)
	if g.RpcCredential != nil {
		ref := *g.RpcCredential
		g.RpcCredential = &ref
	}
	return g
}
func cloneContract(c Contract) Contract {
	c.ABI = slices.Clone(c.ABI)
	c.ReadGrants = slices.Clone(c.ReadGrants)
	for i := range c.ReadGrants {
		rules := &c.ReadGrants[i].EventRules
		rules.Rules = slices.Clone(rules.Rules)
		for j := range rules.Rules {
			rules.Rules[j].ParamRules = slices.Clone(rules.Rules[j].ParamRules)
		}
	}
	return c
}

type catalogBuilder struct {
	profile        ValidationProfile
	snapshot       *CatalogSnapshot
	policies       map[string]*policycore.Policy
	capabilities   map[string]bool
	secrets        map[string]bool
	addresses      map[string]string
	groupOwners    map[string]string
	resourceIDs    map[string]bool
	addressRefs    []eventAddressRef
	identitySource *identity.SourceCatalog
	identityRef    *IdentityCatalogRef
	identityLimits identity.Limits
	runtimeSource  *RuntimeSource
	runtimeRef     *RuntimeCatalogRef
	runtimeScopes  map[string]string
	limits         Limits
}

func newCatalogBuilder(m Manifest, digest Digest, o Options) *catalogBuilder {
	s := &CatalogSnapshot{metadata: BundleMetadata{ManifestDigest: digest, Environment: m.Environment, ChainID: m.ChainID, EvaluatorVersion: m.EvaluatorVersion, Profile: m.Profile, MethodCatalogVersion: o.Methods.Version, SourceRevision: m.SourceRevision}, organizations: slices.Clone(m.Organizations), groups: map[string]map[string]Group{}, contracts: map[string]map[common.Address]Contract{}, execution: map[string]*policycore.Validated{}}
	sort.Slice(s.organizations, func(i, j int) bool { return s.organizations[i].ID < s.organizations[j].ID })
	for _, org := range m.Organizations {
		s.groups[org.ID] = map[string]Group{}
		s.contracts[org.ID] = map[common.Address]Contract{}
	}
	b := &catalogBuilder{profile: o.Profile, snapshot: s, policies: map[string]*policycore.Policy{}, capabilities: map[string]bool{CapabilityNativeValidate: true}, secrets: map[string]bool{}, addresses: map[string]string{}, groupOwners: map[string]string{}, resourceIDs: map[string]bool{}, identityLimits: o.IdentityLimits, limits: o.Limits}
	if o.Profile.id == RuntimeCallProfileID {
		for _, capability := range []string{CapabilityRuntimeCall, CapabilityPrincipal, CapabilityFrames, CapabilityAnchoredCode, CapabilityClassification, CapabilityOwnership} {
			b.capabilities[capability] = true
		}
	}
	return b
}

func (b *catalogBuilder) add(wire wireDocument, spec any, ref DocumentRef, methods methodIndex, limits Limits) error {
	org := wire.OrganizationID
	switch v := spec.(type) {
	case *GroupsSpec:
		if err := normalizeGroups(v, org, methods, limits); err != nil {
			return err
		}
		for _, g := range v.Groups {
			if owner, exists := b.groupOwners[g.ID]; exists && owner != org {
				return fail(ReferenceFailure, Groups, org, "id", "group ID belongs to another organization")
			}
			b.groupOwners[g.ID] = org
			b.snapshot.groups[org][g.ID] = g
			if len(g.AllowedMethods) > 0 || len(g.Claims) > 0 || g.IsOrgAdmin || g.IsOrgReadonlyAdmin {
				b.capabilities[CapabilityPrincipal] = true
			}
			if g.RpcCredential != nil {
				b.capabilities[CapabilityRPCCredential] = true
				b.secrets[g.RpcCredential.FromEnv] = true
			}
		}
	case *RegistrySpec:
		refs, err := normalizeRegistry(v, org, limits)
		if err != nil {
			return err
		}
		b.addressRefs = append(b.addressRefs, refs...)
		for _, c := range v.Contracts {
			if owner, exists := b.addresses[c.Address]; exists && owner != org {
				return fail(ReferenceFailure, ContractRegistry, org, "address", "contract address has ambiguous organization ownership")
			}
			b.addresses[c.Address] = org
			if b.resourceIDs[c.ID] {
				return fail(ReferenceFailure, ContractRegistry, org, "id", "duplicate registry resource ID")
			}
			b.resourceIDs[c.ID] = true
			for _, grant := range c.ReadGrants {
				if b.resourceIDs[grant.ID] {
					return fail(ReferenceFailure, ContractRegistry, org, "readGrants.id", "duplicate registry resource ID")
				}
				b.resourceIDs[grant.ID] = true
				if grant.EventRules.Mode != "none" {
					b.capabilities[CapabilityPrincipal] = true
				}
				for _, rule := range grant.EventRules.Rules {
					for _, param := range rule.ParamRules {
						if param.MustBe == "self" {
							b.capabilities[CapabilityLinkedWallets] = true
						}
					}
				}
			}
			if c.AllowVisibleToUnlock {
				return fail(UnsupportedFeature, ContractRegistry, org, "allowVisibleToUnlock", "privacy.visible-to-history requires a later history/runtime profile")
			}
			if c.EventsAllowDynamicPayload {
				b.capabilities[CapabilityDynamicPayload] = true
			}
			b.snapshot.contracts[org][common.HexToAddress(c.Address)] = c
		}
	case *ExecutionSpec:
		if len(v.Policy.Bindings) > limits.MaxGroupsPerOrg {
			return fail(LimitExceeded, ExecutionRules, org, "policy.bindings", "native binding budget exceeded")
		}
		count := 0
		for _, binding := range v.Policy.Bindings {
			if len(binding.Allow) > limits.MaxNativeRulesPerOrg-count {
				return fail(LimitExceeded, ExecutionRules, org, "policy.bindings.allow", "native rule budget exceeded")
			}
			count += len(binding.Allow)
		}
		b.policies[org] = v.Policy
	}
	raw, err := json.Marshal(spec)
	if err != nil {
		return fail(InvalidSchema, wire.Kind, org, "spec", "cannot canonicalize source")
	}
	wire.Spec = raw
	canonical, err := json.Marshal(wire)
	if err != nil {
		return fail(InvalidSchema, wire.Kind, org, "document", "cannot canonicalize document")
	}
	identity := DocumentIdentity{DocumentRef: ref, SemanticDigest: RawDigest(canonical)}
	if v, ok := spec.(*ExecutionSpec); ok {
		digest, err := policycore.CanonicalDigest(v.Policy)
		if err != nil {
			return fail(InvalidSchema, wire.Kind, org, "policy", "cannot identify native policy")
		}
		identity.PolicyDigest = digest
	}
	b.snapshot.metadata.Documents = append(b.snapshot.metadata.Documents, identity)
	return nil
}

func (b *catalogBuilder) finish(ctx context.Context) (*CatalogSnapshot, error) {
	if err := b.compileRuntime(b.limits); err != nil {
		return nil, err
	}
	for _, org := range b.snapshot.organizations {
		if err := canceled(ctx); err != nil {
			return nil, err
		}
		for _, c := range b.snapshot.contracts[org.ID] {
			for _, grant := range c.ReadGrants {
				if _, ok := b.snapshot.groups[org.ID][grant.GroupID]; !ok {
					return nil, fail(ReferenceFailure, ContractRegistry, org.ID, "readGrants.groupId", "grant does not resolve to a group in the same organization")
				}
			}
		}
		catalog, _ := b.snapshot.NativeCatalog(org.ID)
		validate := policycore.Validate
		if b.profile.id == NativeV2ProfileID || b.profile.id == RuntimeCallProfileID {
			validate = policycore.ValidateNativeV2
		}
		v, err := validate(b.policies[org.ID], catalog)
		if err != nil {
			return nil, fail(InvalidSchema, ExecutionRules, org.ID, "policy", err.Error())
		}
		if err := b.inferNative(v.Policy(), org.ID); err != nil {
			return nil, err
		}
		b.snapshot.execution[org.ID] = v
	}
	for _, ref := range b.addressRefs {
		if err := canceled(ctx); err != nil {
			return nil, err
		}
		owner, known := b.addresses[ref.address]
		if known && owner != ref.org {
			return nil, fail(ReferenceFailure, ContractRegistry, ref.org, "paramRules.must_be", "address literal belongs to another organization")
		}
		if !known {
			if b.profile.id != RuntimeCallProfileID {
				return nil, fail(UnsupportedFeature, ContractRegistry, ref.org, "paramRules.must_be", "unregistered EOA literal requires a later operational validation profile")
			}
			if scopedOwner, scoped := b.runtimeScopes[ref.address]; !scoped || scopedOwner != ref.org {
				return nil, fail(UnsupportedFeature, ContractRegistry, ref.org, "paramRules.must_be", "unregistered EOA literal requires explicit same-org static scope")
			}
		}
	}
	if err := b.compileIdentity(); err != nil {
		return nil, err
	}
	for name := range b.capabilities {
		b.snapshot.requirements.Capabilities = append(b.snapshot.requirements.Capabilities, name)
	}
	sort.Strings(b.snapshot.requirements.Capabilities)
	for name := range b.secrets {
		b.snapshot.requirements.SecretRefs = append(b.snapshot.requirements.SecretRefs, name)
	}
	sort.Strings(b.snapshot.requirements.SecretRefs)
	if err := canceled(ctx); err != nil {
		return nil, err
	}
	return b.snapshot, nil
}

func (b *catalogBuilder) inferNative(p *policycore.Policy, org string) error {
	runtime := b.profile.id == RuntimeCallProfileID
	unsupported := func(field, requirement string) error {
		return fail(UnsupportedFeature, ExecutionRules, org, field, requirement+" requires a later runtime profile")
	}
	for _, binding := range p.Bindings {
		if len(binding.Allow) > 0 {
			b.capabilities[CapabilityPrincipal] = true
			b.capabilities[CapabilityFrames] = true
		}
		for _, r := range binding.Allow {
			if r.Selector != "*" {
				b.capabilities[CapabilityCalldata] = true
			}
			if r.TargetClass != "" {
				if !runtime {
					return unsupported("targetClass", "inputs.classification/ownership ("+r.TargetClass+")")
				}
				switch r.TargetClass {
				case "org", "shared", "eoa", "precompile":
				default:
					return unsupported("targetClass", "deployment/lifecycle qualification ("+r.TargetClass+")")
				}
				if r.TargetClass == "shared" {
					b.capabilities[CapabilitySharedCode] = true
				}
			}
			if r.AllowUpgrade {
				if !runtime {
					return unsupported("allowUpgrade", "inputs.upgrade-facts")
				}
				b.capabilities[CapabilityUpgradeFacts] = true
			}
			for _, ct := range r.CallTypes {
				if ct != policycore.CallTypeCall && ct != policycore.CallTypeStaticCall && !(runtime && (ct == policycore.CallTypeDelegateCall || ct == policycore.CallTypeCallCode)) {
					return unsupported("callTypes", "inputs.frame-kind ("+string(ct)+")")
				}
			}
			if r.MaxValue != nil {
				b.capabilities[CapabilityValue] = true
			}
			if r.MaxDepth != nil || r.MinDepth != nil {
				b.capabilities[CapabilityDepth] = true
			}
			if r.CallerAddress != "" {
				b.capabilities[CapabilityCaller] = true
			}
			for _, arg := range r.Args {
				b.capabilities[CapabilityCalldata] = true
				if arg.RecordParty != nil {
					return unsupported("recordParty", "inputs.live-record-getter")
				}
				if arg.AddressEquals != nil {
					switch arg.AddressEquals.Source {
					case policycore.AddressSourceSigner:
						b.capabilities[CapabilitySigner] = true
					case policycore.AddressSourcePrincipalLinked:
						b.capabilities[CapabilityLinkedWallets] = true
					}
				}
			}
		}
	}
	return nil
}
