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
