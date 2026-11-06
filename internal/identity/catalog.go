package identity

import (
	"crypto/ed25519"
	"encoding/json"
	"slices"
	"sort"
)

type issuerTrust struct {
	audience string
	profiles map[string]bool
	keys     map[string]ed25519.PublicKey
}
type mappingKey struct {
	profile, org string
	kind         Kind
	fact         Fact
}
type Catalog struct {
	source         SourceCatalog
	digest         string
	profileDigests map[string]string
	profiles       map[string]Profile
	issuers        map[string]issuerTrust
	mappings       map[mappingKey][]string
	limits         Limits
}

func (c *Catalog) Digest() string { return c.digest }
func (c *Catalog) ProfileDigest(id string) (string, bool) {
	d, ok := c.profileDigests[id]
	return d, ok
}
func (c *Catalog) Source() SourceCatalog {
	raw, _ := json.Marshal(c.source)
	var s SourceCatalog
	_ = json.Unmarshal(raw, &s)
	return s
}
func (c *Catalog) HasMappings() bool { return len(c.mappings) > 0 }

// Compile snapshots source and referenced group pairs. The callback is never
// retained, including on principals created later from this catalog.
func Compile(source SourceCatalog, groups GroupIndex, limits Limits) (*Catalog, error) {
	if !limits.Valid() || groups == nil {
		return nil, invalid("options", "catalog")
	}
	if err := sourceBounds(source, limits); err != nil {
		return nil, err
	}
	raw, err := json.Marshal(source)
	if err != nil {
		return nil, invalid("encoding", "catalog")
	}
	s, err := Decode(raw, limits)
	if err != nil {
		return nil, err
	}
	if s.APIVersion != APIVersion || s.Kind != CatalogKind {
		return nil, invalid("version", "catalog")
	}
	c := &Catalog{source: s, profiles: map[string]Profile{}, profileDigests: map[string]string{}, issuers: map[string]issuerTrust{}, mappings: map[mappingKey][]string{}, limits: limits}
	for i := range s.Profiles {
		p := &s.Profiles[i]
		if err := validateProfile(p, limits); err != nil {
			return nil, err
		}
		if _, dup := c.profiles[p.ID]; dup {
			return nil, invalid("duplicate", "profiles.id")
		}
		c.profiles[p.ID] = *p
		c.profileDigests[p.ID], _ = digest(p)
	}
	issuerIDs, authorized := map[string]bool{}, map[string]bool{}
	for i := range s.Issuers {
		issuer := &s.Issuers[i]
		if !name(issuer.ID, limits.MaxSourceIDBytes) || issuerIDs[issuer.ID] || !https(issuer.Issuer, limits.MaxURLBytes, false) || !text(issuer.Audience, 256) || len(issuer.Keys) == 0 || !uniqueSort(issuer.AllowedProfiles) {
			return nil, invalid("issuer", "issuers")
		}
		issuerIDs[issuer.ID] = true
		if _, dup := c.issuers[issuer.Issuer]; dup {
			return nil, invalid("duplicate", "issuers.issuer")
		}
		trust := issuerTrust{audience: issuer.Audience, profiles: map[string]bool{}, keys: map[string]ed25519.PublicKey{}}
		for _, id := range issuer.AllowedProfiles {
			if _, ok := c.profiles[id]; !ok {
				return nil, invalid("reference", "issuers.allowedProfiles")
			}
			trust.profiles[id], authorized[id] = true, true
		}
		for _, key := range issuer.Keys {
			if !ascii(key.Kid, limits.MaxKidBytes) || key.Alg != "EdDSA" || key.Kty != "OKP" || key.Crv != "Ed25519" {
				return nil, invalid("key", "issuers.keys")
			}
			if _, dup := trust.keys[key.Kid]; dup {
				return nil, invalid("duplicate", "issuers.keys.kid")
			}
			decoded, err := decodeSegment(key.X, ed25519.PublicKeySize)
			if err != nil || len(decoded) != ed25519.PublicKeySize {
				return nil, invalid("key", "issuers.keys.x")
			}
			trust.keys[key.Kid] = ed25519.PublicKey(decoded)
		}
		sort.Slice(issuer.Keys, func(i, j int) bool { return issuer.Keys[i].Kid < issuer.Keys[j].Kid })
		c.issuers[issuer.Issuer] = trust
	}
	for id := range c.profiles {
		if !authorized[id] {
			return nil, invalid("reference", "profiles.issuer")
		}
	}
	seenIDs, checkedGroups := map[string]bool{}, map[[2]string]bool{}
	for i := range s.Mappings {
		m := &s.Mappings[i]
		p, ok := c.profiles[m.ProfileID]
		if !ok || !name(m.ID, limits.MaxSourceIDBytes) || seenIDs[m.ID] || !uuid(m.OrganizationID) || m.PrincipalKind != expectedKind(p) || !validFact(p, m.Fact, limits) || len(m.GroupIDs) == 0 || !uniqueSort(m.GroupIDs) {
			return nil, invalid("mapping", "mappings")
		}
		seenIDs[m.ID] = true
		key := mappingKey{m.ProfileID, m.OrganizationID, m.PrincipalKind, m.Fact}
		if _, dup := c.mappings[key]; dup {
			return nil, invalid("duplicate", "mappings.fact")
		}
		for _, id := range m.GroupIDs {
			pair := [2]string{m.OrganizationID, id}
			if !uuid(id) {
				return nil, invalid("group", "mappings.groupIds")
			}
			if !checkedGroups[pair] {
				if !groups.HasGroup(pair[0], pair[1]) {
					return nil, invalid("reference", "mappings.groupIds")
				}
				checkedGroups[pair] = true
			}
		}
		c.mappings[key] = slices.Clone(m.GroupIDs)
	}
	sort.Slice(s.Issuers, func(i, j int) bool { return s.Issuers[i].ID < s.Issuers[j].ID })
	sort.Slice(s.Profiles, func(i, j int) bool { return s.Profiles[i].ID < s.Profiles[j].ID })
	sort.Slice(s.Mappings, func(i, j int) bool { return s.Mappings[i].ID < s.Mappings[j].ID })
	c.source = s
	c.digest, err = digest(s)
	if err != nil {
		return nil, err
	}
	return c, nil
}

func uniqueSort(s []string) bool {
	sort.Strings(s)
	for i, v := range s {
		if v == "" || (i > 0 && s[i-1] == v) {
			return false
		}
	}
	return true
}
func sortPredicates(p []Predicate) { sort.Slice(p, func(i, j int) bool { return p[i].ID < p[j].ID }) }

func sourceBounds(s SourceCatalog, l Limits) error {
	if len(s.Issuers) > l.MaxIssuers || len(s.Profiles) > l.MaxProfiles || len(s.Mappings) > l.MaxMappings {
		return invalid("limit", "catalog")
	}
	bytes, keys, refs := 0, 0, 0
	add := func(values ...string) bool {
		for _, v := range values {
			if len(v) > l.MaxIdentityDocumentBytes-bytes {
				return false
			}
			bytes += len(v)
		}
		return true
	}
	if !add(s.APIVersion, s.Kind) {
		return invalid("limit", "catalog")
	}
	for _, issuer := range s.Issuers {
		if len(issuer.Keys) > l.MaxKeysPerIssuer || len(issuer.Keys) > l.MaxTotalKeys-keys || len(issuer.AllowedProfiles) > l.MaxProfiles {
			return invalid("limit", "issuers")
		}
		keys += len(issuer.Keys)
		if !add(issuer.ID, issuer.Issuer, issuer.Audience) {
			return invalid("limit", "issuers")
		}
		for _, id := range issuer.AllowedProfiles {
			if !add(id) {
				return invalid("limit", "issuers")
			}
		}
		for _, key := range issuer.Keys {
			if !add(key.Kid, key.Alg, key.Kty, key.Crv, key.X) {
				return invalid("limit", "issuers")
			}
		}
	}
	for _, p := range s.Profiles {
		if len(p.AllowedClientIDs) > l.MaxIdentityDocumentBytes/3 || len(p.AllowedCredentialIssuers) > l.MaxIdentityDocumentBytes/3 || len(p.Predicates) > l.MaxIdentityDocumentBytes/2 {
			return invalid("limit", "profiles")
		}
		if !add(p.ID, p.Kind, p.TenantID, p.Issuer, p.APIAudience, p.ClientID, p.DelegatedScope, p.FactSource, p.VerifierID, p.Network, p.IdentityStateContract, p.ContextDigest, p.Context, p.Type, p.CircuitID) {
			return invalid("limit", "profiles")
		}
		for _, values := range [][]string{p.AllowedClientIDs, p.AllowedCredentialIssuers} {
			for _, v := range values {
				if !add(v) {
					return invalid("limit", "profiles")
				}
			}
		}
		for _, v := range p.Predicates {
			if !add(v.ID, v.Field, v.Operator, v.Value) {
				return invalid("limit", "predicates")
			}
		}
	}
	for _, m := range s.Mappings {
		if len(m.GroupIDs) > l.MaxGroupsPerMapping || len(m.GroupIDs) > l.MaxTotalGroupReferences-refs {
			return invalid("limit", "mappings.groupIds")
		}
		refs += len(m.GroupIDs)
		if !add(m.ID, m.ProfileID, m.OrganizationID, string(m.PrincipalKind), m.Fact.Kind, m.Fact.Value) {
			return invalid("limit", "mappings")
		}
		for _, id := range m.GroupIDs {
			if !add(id) {
				return invalid("limit", "mappings.groupIds")
			}
		}
	}
	return nil
}
