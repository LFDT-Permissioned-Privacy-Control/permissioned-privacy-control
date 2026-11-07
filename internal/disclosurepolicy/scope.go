package disclosurepolicy

import (
	"encoding/json"
	"slices"
	"time"

	"privacy-proxy/internal/identity"
)

func NormalizeScope(scope Scope, limits Limits) (Scope, error) {
	if !limits.Valid() || !validInterval(scope.DataTime) {
		return Scope{}, ErrInvalid
	}
	if _, ok := levelRank(scope.Level); !ok {
		return Scope{}, ErrInvalid
	}
	var err error
	scope.TargetActors, err = actors(scope.TargetActors, limits.MaxActors, true)
	if err != nil {
		return Scope{}, err
	}
	scope.Resources, err = resources(scope.Resources)
	if err != nil {
		return Scope{}, err
	}
	scope.Addresses, err = addresses(scope.Addresses, limits)
	if err != nil {
		return Scope{}, err
	}
	raw, _ := json.Marshal(scope)
	if len(raw) > 96<<10 {
		return Scope{}, ErrInvalid
	}
	return scope, nil
}

// Eligible accepts only facts established by the caller's verified View. It
// does not fetch memberships and cannot confer actor validity by itself.
func (r *Rule) Eligible(actor string, groups []GroupRef, now time.Time) bool {
	if !identity.ValidActorID(actor) || !r.Active(now) {
		return false
	}
	s := r.source
	if len(s.Viewers.Actors) != 0 && !slices.Contains(s.Viewers.Actors, actor) {
		return false
	}
	for _, group := range groups {
		if slices.Contains(s.Viewers.Groups, group) {
			return true
		}
	}
	return false
}
func (r *Rule) Active(now time.Time) bool {
	return now.Unix() >= r.source.Validity.NotBefore && now.Unix() < r.source.Validity.ExpiresAt
}

// Covers checks all dimensions against this ONE rule. It does not establish
// that requested rows actually belong to the declared data organization/actors.
func (r *Rule) Covers(scope Scope) bool {
	q, err := NormalizeScope(scope, r.limits)
	if err != nil {
		return false
	}
	s := r.source
	if s.Targets.Mode == "actors" {
		for _, actor := range q.TargetActors {
			if !slices.Contains(s.Targets.Actors, actor) {
				return false
			}
		}
	}
	for _, resource := range q.Resources {
		if !slices.Contains(s.Resources, resource) {
			return false
		}
	}
	if s.Addresses.Mode == "list" {
		if q.Addresses.Mode != "list" {
			return false
		}
		for _, address := range q.Addresses.Values {
			if !slices.Contains(s.Addresses.Values, address) {
				return false
			}
		}
	}
	a, _ := levelRank(q.Level)
	b, _ := levelRank(s.MaxLevel)
	return a <= b && q.DataTime.Start >= s.DataTime.Start && q.DataTime.End <= s.DataTime.End
}

// ProtectedUntil applies the current duration ceiling without extending an
// already-issued case. Metadata administration has a separate access predicate.
func (r *Rule) ProtectedUntil(created, recordedExpiry time.Time) time.Time {
	return minTime(recordedExpiry, minTime(created.Add(time.Duration(r.source.MaxCaseSeconds)*time.Second), time.Unix(r.source.Validity.ExpiresAt, 0)))
}
func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

func (c *Catalog) Requirements() []string {
	set := map[string]bool{"catalog.native-validate": true, "identity.claims/v1": true, "inputs.verified-principal": true, "disclosure.rules/v1": true, "disclosure.case-state/v1": true, "secrets.disclosure-cursor/v1": true}
	for _, r := range c.rules {
		for _, resource := range r.source.Resources {
			switch resource {
			case ActivityLogs, ActivitySummary:
				set["data.audit-source/v1"] = true
			case Transactions, Events:
				set["data.chain-history/v1"] = true
				set["data.address-history/v1"] = true
			case AddressHistory:
				set["data.address-history/v1"] = true
			case SanctionsReport:
				set["data.address-history/v1"] = true
				set["data.sanctions-source/v1"] = true
			case ComplianceReport:
				set["data.audit-source/v1"] = true
				set["data.address-history/v1"] = true
				set["data.sanctions-source/v1"] = true
				set["data.compliance-source/v1"] = true
			}
		}
		if r.source.MaxLevel == Pseudonymous || r.source.MaxLevel == Full {
			set["secrets.disclosure-render/v1"] = true
		}
	}
	out := make([]string, 0, len(set))
	for name := range set {
		out = append(out, name)
	}
	slices.Sort(out)
	return out
}
