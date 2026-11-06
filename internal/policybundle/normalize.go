package policybundle

import (
	"encoding/hex"
	"fmt"
	"math/big"
	"regexp"
	"slices"
	"sort"
	"strings"

	"github.com/ethereum/go-ethereum/common"
)

var slugPattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_-]{0,99}$`)
var methodPattern = regexp.MustCompile(`^(\*|[a-zA-Z][a-zA-Z0-9]*_([a-zA-Z][a-zA-Z0-9_]*))$`)
var filePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]*\.json$`)
var secretSuffix = regexp.MustCompile(`^[A-Z0-9_]{1,64}$`)

func boundedName(s string, n int) bool {
	return len(s) > 0 && len(s) <= n && strings.TrimSpace(s) == s && !strings.ContainsAny(s, "\x00\r\n\t")
}
func canonicalUUID(s string) bool {
	if len(s) != 36 || s != strings.ToLower(s) || s[8] != '-' || s[13] != '-' || s[18] != '-' || s[23] != '-' {
		return false
	}
	raw := strings.ReplaceAll(s, "-", "")
	if len(raw) != 32 {
		return false
	}
	decoded, err := hex.DecodeString(raw)
	if err != nil {
		return false
	}
	for _, v := range decoded {
		if v != 0 {
			return true
		}
	}
	return false
}
func chainID(s string) bool {
	if s == "" || len(s) > 78 || (len(s) > 1 && s[0] == '0') {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	n, ok := new(big.Int).SetString(s, 10)
	return ok && n.BitLen() <= 256
}
func sortUnique(s []string) error {
	sort.Strings(s)
	for i, v := range s {
		if v == "" || (i > 0 && s[i-1] == v) {
			return fmt.Errorf("arrays contain an empty or duplicate value")
		}
	}
	return nil
}
func knownClaim(s string) bool { return s == "admin" || s == "deploy" || s == "upgrade" }

func validateManifest(m Manifest, s Selection, o Options) error {
	if m.APIVersion != BundleAPIVersion || m.Kind != BundleKind {
		return fail(InvalidSchema, "", "", "manifest", "unsupported bundle version or kind")
	}
	if m.Environment != s.ExpectedEnvironment || m.ChainID != s.ExpectedChainID || m.EvaluatorVersion != o.Profile.evaluatorVersion || m.Profile != o.Profile.id {
		return fail(InvalidSelection, "", "", "manifest", "environment/chain/evaluator/profile does not match deployment selection")
	}
	if !boundedName(m.SourceRevision, 256) {
		return fail(InvalidSchema, "", "", "sourceRevision", "source revision must be bounded nonempty metadata")
	}
	if len(m.Organizations) > o.Limits.MaxOrganizations || len(m.Documents) > o.Limits.MaxDocuments {
		return fail(LimitExceeded, "", "", "manifest", "organization or document budget exceeded")
	}
	if (o.Profile.id == FoundationProfileID && m.IdentityCatalog != nil) || (o.Profile.id == IdentityProfileID && m.IdentityCatalog == nil) {
		return fail(UnsupportedFeature, "", "", "identityCatalog", "identity source is required only under the explicit identity profile")
	}
	if m.IdentityCatalog != nil && len(m.Documents) == o.Limits.MaxDocuments {
		return fail(LimitExceeded, "", "", "identityCatalog", "identity file exceeds document count budget")
	}
	orgs, slugs := map[string]bool{}, map[string]bool{}
	for _, org := range m.Organizations {
		if !canonicalUUID(org.ID) || orgs[org.ID] || !slugPattern.MatchString(org.Slug) || slugs[org.Slug] || !boundedName(org.Name, 256) {
			return fail(InvalidSchema, "", org.ID, "organizations", "invalid or duplicate organization identity")
		}
		orgs[org.ID], slugs[org.Slug] = true, true
	}
	paths, logical := map[string]bool{}, map[string]bool{}
	for _, ref := range m.Documents {
		if !orgs[ref.OrganizationID] {
			return fail(ReferenceFailure, ref.Kind, ref.OrganizationID, "documents", "undeclared organization")
		}
		if ref.Kind != Groups && ref.Kind != ContractRegistry && ref.Kind != ExecutionRules {
			return fail(UnsupportedFeature, ref.Kind, ref.OrganizationID, "kind", "unsupported document kind")
		}
		key := ref.OrganizationID + "/" + string(ref.Kind)
		if len(ref.Path) > 128 || !filePattern.MatchString(ref.Path) || ref.Path == "manifest.json" || paths[ref.Path] || logical[key] || !validDigest(ref.SHA256) {
			return fail(InvalidSchema, ref.Kind, ref.OrganizationID, "documents", "invalid/duplicate path, logical source or digest")
		}
		paths[ref.Path], logical[key] = true, true
	}
	for org := range orgs {
		for _, kind := range []Kind{Groups, ContractRegistry, ExecutionRules} {
			if !logical[org+"/"+string(kind)] {
				return fail(ReferenceFailure, kind, org, "documents", "each organization requires groups, registry and explicit execution source")
			}
		}
	}
	if ref := m.IdentityCatalog; ref != nil {
		if len(ref.Path) > 128 || !filePattern.MatchString(ref.Path) || ref.Path == "manifest.json" || paths[ref.Path] || !validDigest(ref.SHA256) {
			return fail(InvalidSchema, "", "", "identityCatalog", "invalid or colliding global identity file reference")
		}
	}
	return nil
}

func normalizeGroups(spec *GroupsSpec, org string, methods methodIndex, limits Limits) error {
	if len(spec.Groups) > limits.MaxGroupsPerOrg {
		return fail(LimitExceeded, Groups, org, "groups", "group budget exceeded")
	}
	ids, slugs, names := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for i := range spec.Groups {
		g := &spec.Groups[i]
		if !canonicalUUID(g.ID) || ids[g.ID] || !slugPattern.MatchString(g.Slug) || slugs[g.Slug] || !boundedName(g.Name, 256) || names[g.Name] || len(g.Description) > 4096 {
			return fail(InvalidSchema, Groups, org, "groups", "invalid or duplicate group identity or text")
		}
		ids[g.ID], slugs[g.Slug], names[g.Name] = true, true, true
		if g.IsOrgAdmin && g.IsOrgReadonlyAdmin {
			return fail(InvalidSchema, Groups, org, "groups", "admin roles are mutually exclusive")
		}
		if g.IsOrgAdmin && (len(g.Claims) != 0 || len(g.AllowedMethods) == 0) {
			return fail(InvalidSchema, Groups, org, "groups", "org-admin groups require methods and no claims")
		}
		if err := sortUnique(g.Claims); err != nil {
			return fail(InvalidSchema, Groups, org, "claims", err.Error())
		}
		for _, claim := range g.Claims {
			if !knownClaim(claim) {
				return fail(InvalidSchema, Groups, org, "claims", "unsupported claim")
			}
		}
		if slices.Contains(g.Claims, "admin") {
			g.Claims = []string{"admin", "deploy", "upgrade"}
		}
		if err := sortUnique(g.AllowedMethods); err != nil {
			return fail(InvalidSchema, Groups, org, "allowedMethods", err.Error())
		}
		for _, name := range g.AllowedMethods {
			if !methodPattern.MatchString(name) || (name != "*" && !methods.assignable[name]) {
				return fail(InvalidSchema, Groups, org, "allowedMethods", "unsupported exact RPC method")
			}
		}
		if slices.Contains(g.AllowedMethods, "*") {
			set := map[string]bool{}
			expanded := make([]string, 0, len(methods.wildcard)+len(g.AllowedMethods))
			for _, name := range append(slices.Clone(methods.wildcard), g.AllowedMethods...) {
				if name != "*" && !set[name] {
					expanded = append(expanded, name)
					set[name] = true
				}
			}
			sort.Strings(expanded)
			g.AllowedMethods = expanded
		}
		if !g.IsOrgAdmin {
			for _, name := range g.AllowedMethods {
				canonical := name
				if target, ok := methods.aliases[name]; ok {
					canonical = target
				}
				claim := methods.requiredClaims[canonical]
				if own := methods.requiredClaims[name]; own != "" && !slices.Contains(g.Claims, own) {
					return fail(InvalidSchema, Groups, org, "allowedMethods", "method requires a missing claim")
				}
				if claim != "" && !slices.Contains(g.Claims, claim) {
					return fail(InvalidSchema, Groups, org, "allowedMethods", "method requires a missing claim")
				}
			}
		}
		if g.RpcCredential != nil {
			prefix := "OPS_RPC_CREDENTIAL_" + strings.ToUpper(strings.ReplaceAll(org, "-", "")) + "_"
			if !strings.HasPrefix(g.RpcCredential.FromEnv, prefix) || !secretSuffix.MatchString(strings.TrimPrefix(g.RpcCredential.FromEnv, prefix)) {
				return fail(InvalidSchema, Groups, org, "rpcCredential.fromEnv", "secret reference is outside this organization's credential namespace")
			}
		}
	}
	sort.Slice(spec.Groups, func(i, j int) bool { return spec.Groups[i].ID < spec.Groups[j].ID })
	return nil
}

func addressKey(s string) string { return strings.ToLower(common.HexToAddress(s).Hex()) }
