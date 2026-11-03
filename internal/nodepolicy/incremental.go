package nodepolicy

import (
	"context"
	"reflect"
	"sort"
)

// FactChanges is what changed between a base generation and Version
// (RD-1411 §5.6): the affected keys of each kind and the current facts for
// exactly those keys. An affected key without a current fact was deleted.
// Policies are keyed by organisation: an affected organisation's artifacts
// are replaced as a whole. Full means the change log cannot describe the gap
// and the caller must export every fact.
type FactChanges struct {
	Version    uint64
	Full       bool
	Principals []string
	Groups     []string
	Contracts  []string
	PolicyOrgs []string
	Sanctions  []string // OrgID + ":" + Address
	Current    FactSet
}

// IncrementalFactSource is a FactSource that can also export only what
// changed since a base generation.
type IncrementalFactSource interface {
	ExportNodePolicyChanges(ctx context.Context, base Snapshot) (FactChanges, error)
}

// ApplyChanges patches base with c and returns the next generation and the
// delta from base to it. The delta is built from the affected keys only, and
// equals BuildDelta(base, baseDigest, next): an affected key whose facts did
// not change yields no entry. A current fact outside the affected keys, a
// duplicate, a version that is not newer or a Full change set is refused.
func ApplyChanges(base Snapshot, baseDigest string, header Header, c FactChanges) (Snapshot, Delta, error) {
	if c.Full || base.Version == 0 || c.Version <= base.Version || !hexDigest(baseDigest) || header.Network != base.Network {
		return Snapshot{}, Delta{}, ErrSnapshot
	}
	// Compare the cloned forms, exactly as BuildDelta does.
	base = cloneSnapshot(base)
	current := cloneSnapshot(Snapshot{Principals: c.Current.Principals, Groups: c.Current.Groups, Contracts: c.Current.Contracts, Policies: c.Current.Policies, Sanctions: c.Current.Sanctions})
	next := Snapshot{Header: header, Version: c.Version}
	d := Delta{Header: header, PreviousVersion: base.Version, PreviousDigest: baseDigest, Version: c.Version}
	in := func(keys []string) func(string) bool {
		set := make(map[string]bool, len(keys))
		for _, k := range keys {
			set[k] = true
		}
		return func(k string) bool { return set[k] }
	}
	var err error
	principals := in(c.Principals)
	if next.Principals, d.Upserts.Principals, d.Deletes.Principals, _, err = patchFacts(base.Principals, current.Principals, principalKey, func(p Principal) bool { return principals(p.ID) }); err != nil {
		return Snapshot{}, Delta{}, err
	}
	groups := in(c.Groups)
	if next.Groups, d.Upserts.Groups, d.Deletes.Groups, _, err = patchFacts(base.Groups, current.Groups, groupKey, func(g Group) bool { return groups(g.ID) }); err != nil {
		return Snapshot{}, Delta{}, err
	}
	contracts := in(c.Contracts)
	if next.Contracts, d.Upserts.Contracts, d.Deletes.Contracts, _, err = patchFacts(base.Contracts, current.Contracts, contractKey, func(x Contract) bool { return contracts(x.Address) }); err != nil {
		return Snapshot{}, Delta{}, err
	}
	orgs := in(c.PolicyOrgs)
	if next.Policies, d.Upserts.Policies, d.Deletes.Policies, _, err = patchFacts(base.Policies, current.Policies, policyKey, func(p PolicyArtifact) bool { return orgs(p.OrgID) }); err != nil {
		return Snapshot{}, Delta{}, err
	}
	sanctions := in(c.Sanctions)
	var removed []Sanction
	if next.Sanctions, d.Upserts.Sanctions, _, removed, err = patchFacts(base.Sanctions, current.Sanctions, sanctionKey, func(s Sanction) bool { return sanctions(sanctionKey(s)) }); err != nil {
		return Snapshot{}, Delta{}, err
	}
	d.Deletes.Sanctions = removed
	return next, d, nil
}

// patchFacts replaces the affected facts of base with current. It returns the
// patched list, the changed or new facts and the deleted keys (and facts),
// each sorted by key like diffFacts.
func patchFacts[T any](base, current []T, key func(T) string, affected func(T) bool) ([]T, []T, []string, []T, error) {
	now := make(map[string]T, len(current))
	for _, v := range current {
		k := key(v)
		if !affected(v) {
			return nil, nil, nil, nil, ErrSnapshot
		}
		if _, dup := now[k]; dup {
			return nil, nil, nil, nil, ErrSnapshot
		}
		now[k] = v
	}
	out := make([]T, 0, len(base)+len(current))
	before := map[string]T{}
	for _, v := range base {
		if affected(v) {
			before[key(v)] = v
			continue
		}
		out = append(out, v)
	}
	upserts := []T{}
	for _, v := range current {
		out = append(out, v)
		if was, ok := before[key(v)]; !ok || !reflect.DeepEqual(was, v) {
			upserts = append(upserts, v)
		}
	}
	deletes := []string{}
	removed := []T{}
	for k, v := range before {
		if _, ok := now[k]; !ok {
			deletes = append(deletes, k)
			removed = append(removed, v)
		}
	}
	sort.Slice(upserts, func(i, j int) bool { return key(upserts[i]) < key(upserts[j]) })
	sort.Strings(deletes)
	sort.Slice(removed, func(i, j int) bool { return key(removed[i]) < key(removed[j]) })
	return out, upserts, deletes, removed, nil
}
