package disclosurepolicy

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"slices"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"

	"privacy-proxy/internal/identity"
)

type Catalog struct {
	digest string
	rules  map[string]*Rule
	ids    []string
}
type Rule struct {
	source RuleSource
	digest string
	limits Limits
}

func (c *Catalog) Digest() string               { return c.digest }
func (c *Catalog) Rule(id string) (*Rule, bool) { r, ok := c.rules[id]; return r, ok }
func (c *Catalog) RuleIDs() []string            { return slices.Clone(c.ids) }
func (r *Rule) Digest() string                  { return r.digest }
func (r *Rule) Source() RuleSource              { return cloneRule(r.source) }

func Compile(source Source, index OrganizationGroupIndex, limits Limits) (*Catalog, error) {
	if !limits.Valid() || index == nil || source.APIVersion != APIVersion || source.Kind != Kind || source.Rules == nil || len(source.Rules) > limits.MaxRules {
		return nil, ErrInvalid
	}
	canonical := Source{APIVersion: APIVersion, Kind: Kind, Rules: []RuleSource{}}
	catalog := &Catalog{rules: map[string]*Rule{}, ids: []string{}}
	for _, original := range source.Rules {
		rule := cloneRule(original)
		if !Text(rule.ID, 128) || !canonicalUUID(rule.DataOrganizationID) || !index.HasOrganization(rule.DataOrganizationID) || catalog.rules[rule.ID] != nil || rule.Viewers.Groups == nil || len(rule.Viewers.Groups) == 0 || len(rule.Viewers.Groups) > limits.MaxGroups || !validInterval(rule.DataTime) || !validValidity(rule.Validity) || rule.MaxCaseSeconds <= 0 || rule.MaxCaseSeconds > MaxCaseSeconds {
			return nil, ErrInvalid
		}
		if _, ok := levelRank(rule.MaxLevel); !ok {
			return nil, ErrInvalid
		}
		seen := map[GroupRef]bool{}
		for _, group := range rule.Viewers.Groups {
			if !canonicalUUID(group.OrganizationID) || !canonicalUUID(group.GroupID) || !index.HasGroup(group.OrganizationID, group.GroupID) || seen[group] {
				return nil, ErrInvalid
			}
			seen[group] = true
		}
		sort.Slice(rule.Viewers.Groups, func(i, j int) bool {
			a, b := rule.Viewers.Groups[i], rule.Viewers.Groups[j]
			if a.OrganizationID == b.OrganizationID {
				return a.GroupID < b.GroupID
			}
			return a.OrganizationID < b.OrganizationID
		})
		var err error
		rule.Viewers.Actors, err = actors(rule.Viewers.Actors, limits.MaxActors, false)
		if err != nil {
			return nil, err
		}
		rule.Targets.Actors, err = actors(rule.Targets.Actors, limits.MaxActors, rule.Targets.Mode == "actors")
		if err != nil {
			return nil, err
		}
		if (rule.Targets.Mode != "actors" && rule.Targets.Mode != "all-in-data-org") || (rule.Targets.Mode == "all-in-data-org" && len(rule.Targets.Actors) != 0) {
			return nil, ErrInvalid
		}
		rule.Addresses, err = addresses(rule.Addresses, limits)
		if err != nil {
			return nil, err
		}
		rule.Resources, err = resources(rule.Resources)
		if err != nil {
			return nil, err
		}
		catalog.rules[rule.ID] = &Rule{source: rule, digest: Digest(rule), limits: limits}
		catalog.ids = append(catalog.ids, rule.ID)
		canonical.Rules = append(canonical.Rules, rule)
	}
	sort.Strings(catalog.ids)
	sort.Slice(canonical.Rules, func(i, j int) bool { return canonical.Rules[i].ID < canonical.Rules[j].ID })
	raw, _ := json.Marshal(canonical)
	if len(raw) > limits.MaxDocumentBytes {
		return nil, ErrInvalid
	}
	catalog.digest = Digest(canonical)
	return catalog, nil
}

func Digest(value any) string {
	raw, err := json.Marshal(value)
	if err != nil {
		return ""
	}
	h := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(h[:])
}

// Text permits bounded human metadata, never terminal controls or invalid UTF8.
func Text(value string, maximum int) bool {
	if len(value) == 0 || len(value) > maximum || !utf8.ValidString(value) || strings.TrimSpace(value) != value {
		return false
	}
	for _, r := range value {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}
func canonicalUUID(value string) bool {
	v, err := uuid.Parse(value)
	return err == nil && v != uuid.Nil && v.String() == value
}
func validInterval(v Interval) bool {
	return v.Start >= 0 && v.End >= v.Start && v.End <= MaxUnixSeconds
}
func validValidity(v Validity) bool {
	return v.NotBefore >= 0 && v.ExpiresAt > v.NotBefore && v.ExpiresAt <= MaxUnixSeconds
}
func levelRank(level Level) (int, bool) {
	switch level {
	case Redacted:
		return 0, true
	case Pseudonymous:
		return 1, true
	case Full:
		return 2, true
	}
	return 0, false
}
func actors(values []string, maximum int, required bool) ([]string, error) {
	if values == nil || len(values) > maximum || (required && len(values) == 0) {
		return nil, ErrInvalid
	}
	out := slices.Clone(values)
	for _, value := range out {
		if !identity.ValidActorID(value) {
			return nil, ErrInvalid
		}
	}
	sort.Strings(out)
	for i := 1; i < len(out); i++ {
		if out[i] == out[i-1] {
			return nil, ErrInvalid
		}
	}
	return out, nil
}
func resources(values []Resource) ([]Resource, error) {
	if len(values) == 0 || len(values) > 7 {
		return nil, ErrInvalid
	}
	out := slices.Clone(values)
	slices.Sort(out)
	for i, value := range out {
		switch value {
		case ActivityLogs, Transactions, Events, AddressHistory, ActivitySummary, SanctionsReport, ComplianceReport:
		default:
			return nil, ErrInvalid
		}
		if i > 0 && out[i-1] == value {
			return nil, ErrInvalid
		}
	}
	return out, nil
}
func addresses(value Addresses, limits Limits) (Addresses, error) {
	if value.Values == nil || len(value.Values) > limits.MaxAddresses {
		return Addresses{}, ErrInvalid
	}
	out := Addresses{Mode: value.Mode, Values: slices.Clone(value.Values)}
	if out.Mode == "all-target-addresses" {
		if len(out.Values) != 0 {
			return Addresses{}, ErrInvalid
		}
		return out, nil
	}
	if out.Mode != "list" || len(out.Values) == 0 {
		return Addresses{}, ErrInvalid
	}
	for i, s := range out.Values {
		if len(s) != 42 || !strings.HasPrefix(s, "0x") {
			return Addresses{}, ErrInvalid
		}
		raw, err := hex.DecodeString(s[2:])
		if err != nil || len(raw) != 20 {
			return Addresses{}, ErrInvalid
		}
		out.Values[i] = "0x" + hex.EncodeToString(raw)
	}
	sort.Strings(out.Values)
	for i := 1; i < len(out.Values); i++ {
		if out.Values[i] == out.Values[i-1] {
			return Addresses{}, ErrInvalid
		}
	}
	return out, nil
}
func cloneRule(r RuleSource) RuleSource {
	r.Viewers.Groups = slices.Clone(r.Viewers.Groups)
	r.Viewers.Actors = slices.Clone(r.Viewers.Actors)
	r.Targets.Actors = slices.Clone(r.Targets.Actors)
	r.Resources = slices.Clone(r.Resources)
	r.Addresses.Values = slices.Clone(r.Addresses.Values)
	return r
}
