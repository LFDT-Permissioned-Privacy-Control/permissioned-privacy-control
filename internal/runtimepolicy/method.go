package runtimepolicy

import (
	"slices"
	"sort"
)

// GroupAllowsMethod checks the exact raw-name grant only. Handler registration,
// global floors, claims, target authorization and response filtering still apply.
func (o *OrgView) GroupAllowsMethod(rawName string) bool {
	_, known := o.snapshot.Method(rawName)
	return known && o.methods[rawName]
}

func (o *OrgView) CredentialRefs(rawMethod string) []string {
	refs := []string{}
	seen := map[string]bool{}
	if rawMethod != "" {
		if _, known := o.snapshot.Method(rawMethod); !known {
			return refs
		}
	}
	for _, id := range o.groups {
		g := o.groupData[id]
		if rawMethod != "" && !slices.Contains(g.AllowedMethods, rawMethod) {
			continue
		}
		if g.RpcCredential != nil && !seen[g.RpcCredential.FromEnv] {
			seen[g.RpcCredential.FromEnv] = true
			refs = append(refs, g.RpcCredential.FromEnv)
		}
	}
	sort.Strings(refs)
	return refs
}

func (o *OrgView) SelectCredentialRef(rawMethod string) (string, error) {
	refs := o.CredentialRefs(rawMethod)
	if len(refs) > 1 {
		return "", &Error{AmbiguousCredential}
	}
	if len(refs) == 1 {
		return refs[0], nil
	}
	return "", nil
}
