package policybundle

import "sort"

// MethodInfo describes trusted method names and operational claim requirements.
// It does not prove that an RPC operation/filter handler exists or grant access.
type MethodInfo struct {
	Name           string
	Canonical      string
	RequiredClaims []string
}

func (s *CatalogSnapshot) Method(name string) (MethodInfo, bool) {
	if !s.methods.assignable[name] {
		return MethodInfo{}, false
	}
	canonical := name
	if target, ok := s.methods.aliases[name]; ok {
		canonical = target
	}
	claims := []string{}
	for _, method := range []string{name, canonical} {
		claim := s.methods.requiredClaims[method]
		if claim != "" && (len(claims) == 0 || claims[0] != claim) {
			claims = append(claims, claim)
		}
	}
	sort.Strings(claims)
	return MethodInfo{Name: name, Canonical: canonical, RequiredClaims: claims}, true
}

// Methods returns the actual selected method declarations, including aliases
// and their combined required claims. It creates no dispatch or grant.
func (s *CatalogSnapshot) Methods() []MethodInfo {
	if s == nil {
		return nil
	}
	methods := make([]MethodInfo, 0, len(s.methods.assignable))
	for name := range s.methods.assignable {
		method, _ := s.Method(name)
		methods = append(methods, method)
	}
	sort.Slice(methods, func(i, j int) bool { return methods[i].Name < methods[j].Name })
	return methods
}

// GroupIDs returns sorted detached identifiers without copying contract ABIs.
func (s *CatalogSnapshot) GroupIDs(orgID string) []string {
	if s == nil {
		return nil
	}
	groups := make([]string, 0, len(s.groups[orgID]))
	for id := range s.groups[orgID] {
		groups = append(groups, id)
	}
	sort.Strings(groups)
	return groups
}
