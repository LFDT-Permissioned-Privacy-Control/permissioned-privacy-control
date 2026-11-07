package disclosurepolicy_test

import (
	"encoding/json"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	p "privacy-proxy/internal/disclosurepolicy"
)

const (
	org   = "11111111-1111-1111-1111-111111111111"
	group = "22222222-2222-2222-2222-222222222222"
	actor = "ops:p1:h8r51EkUOmId9V9QsfRAB4s2CDMR3omEQA4OG8icGig"
	other = "ops:p1:YJi2G0ot_md1qvCZnNv3QI3Ow8n1RQ8zk0dYhw9dh3M"
)

type index struct{ enabled bool }

func (i *index) HasOrganization(s string) bool { return i.enabled && s == org }
func (i *index) HasGroup(o, g string) bool     { return i.enabled && o == org && g == group }
func source() p.Source {
	return p.Source{APIVersion: p.APIVersion, Kind: p.Kind, Rules: []p.RuleSource{{ID: "auditor", DataOrganizationID: org, Viewers: p.Viewers{Groups: []p.GroupRef{{OrganizationID: org, GroupID: group}}, Actors: []string{}}, Targets: p.Targets{Mode: "actors", Actors: []string{actor}}, Resources: []p.Resource{p.Transactions, p.ActivitySummary}, Addresses: p.Addresses{Mode: "all-target-addresses", Values: []string{}}, DataTime: p.Interval{Start: 100, End: 500}, MaxLevel: p.Pseudonymous, Validity: p.Validity{NotBefore: 900, ExpiresAt: 2000}, MaxCaseSeconds: 100}}}
}
func scope() p.Scope {
	return p.Scope{TargetActors: []string{actor}, Resources: []p.Resource{p.Transactions}, Addresses: p.Addresses{Mode: "all-target-addresses", Values: []string{}}, DataTime: p.Interval{Start: 120, End: 400}, Level: p.Redacted}
}
func compile(t *testing.T, s p.Source) *p.Catalog {
	t.Helper()
	c, err := p.Compile(s, &index{true}, p.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestWholeRuleCannotBorrowAnotherRulesTargetOrLevel(t *testing.T) {
	s := source()
	second := s.Rules[0]
	second.ID = "other-target-full"
	second.Targets.Actors = []string{other}
	second.MaxLevel = p.Full
	second.DataTime = p.Interval{Start: 600, End: 800}
	s.Rules = append(s.Rules, second)
	c := compile(t, s)
	a, _ := c.Rule("auditor")
	b, _ := c.Rule(second.ID)
	if !a.Covers(scope()) {
		t.Fatal("narrow original scope denied")
	}
	q := scope()
	q.TargetActors = []string{actor}
	q.DataTime = second.DataTime
	q.Level = p.Full
	if a.Covers(q) || b.Covers(q) {
		t.Fatal("crossed target/time/level granted")
	}
	q = scope()
	q.Resources = []p.Resource{p.ActivityLogs}
	if a.Covers(q) {
		t.Fatal("summary output implied raw log output")
	}
	q = scope()
	q.Level = p.Full
	if a.Covers(q) {
		t.Fatal("max level bypass")
	}
	q = scope()
	q.TargetActors = []string{other}
	if a.Covers(q) {
		t.Fatal("wrong target")
	}
}

func TestEligibilityImmutableSourceAndDurationTightening(t *testing.T) {
	s := source()
	idx := &index{true}
	c, err := p.Compile(s, idx, p.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	r, _ := c.Rule("auditor")
	idx.enabled = false
	s.Rules[0].Viewers.Groups[0].GroupID = "changed"
	now := time.Unix(1000, 0)
	groups := []p.GroupRef{{OrganizationID: org, GroupID: group}}
	if !r.Eligible(actor, groups, now) || r.Eligible(actor, nil, now) || r.Eligible(actor, groups, time.Unix(2000, 0)) || r.Eligible("azuread:abc", groups, now) {
		t.Fatal("eligibility callback/time/identity boundary failed")
	}
	copy := r.Source()
	copy.Targets.Actors[0] = other
	copy.Viewers.Groups[0].GroupID = "changed"
	ids := c.RuleIDs()
	ids[0] = "changed"
	if !r.Covers(scope()) || c.RuleIDs()[0] != "auditor" || r.Source().Viewers.Groups[0].GroupID != group {
		t.Fatal("mutable accessor changed catalog")
	}
	created := time.Unix(950, 0)
	if r.ProtectedUntil(created, time.Unix(1500, 0)).Unix() != 1050 {
		t.Fatal("current max duration not applied")
	}
	if r.ProtectedUntil(created, time.Unix(990, 0)).Unix() != 990 {
		t.Fatal("source widened original expiry")
	}
}

func TestExactDecodeBoundsAndCanonicalSetIdentity(t *testing.T) {
	s := source()
	raw, _ := json.Marshal(s)
	decoded, err := p.Decode(raw, p.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	c := compile(t, decoded)
	s.Rules[0].Resources = slices.Clone(s.Rules[0].Resources)
	slices.Reverse(s.Rules[0].Resources)
	if compile(t, s).Digest() != c.Digest() {
		t.Fatal("set order changed semantic digest")
	}
	for name, bad := range map[string][]byte{"duplicate": []byte(strings.Replace(string(raw), `"kind":"DisclosurePolicy"`, `"kind":"DisclosurePolicy","kind":"DisclosurePolicy"`, 1)), "wrongcase": []byte(strings.Replace(string(raw), `"maxLevel"`, `"MaxLevel"`, 1)), "null": []byte(strings.Replace(string(raw), `"actors":[]`, `"actors":null`, 1)), "unknown": append([]byte(`{"unknown":true,`), raw[1:]...)} {
		t.Run(name, func(t *testing.T) {
			if _, err := p.Decode(bad, p.DefaultLimits()); err == nil {
				t.Fatal("ambiguous source decoded")
			}
		})
	}
	limits := p.DefaultLimits()
	limits.MaxDocumentBytes = len(raw) - 1
	if _, err := p.Decode(raw, limits); err == nil {
		t.Fatal("byte budget bypass")
	}
	for name, mutate := range map[string]func(*p.RuleSource){"unknown org": func(r *p.RuleSource) { r.DataOrganizationID = group }, "unknown group": func(r *p.RuleSource) { r.Viewers.Groups[0].GroupID = org }, "empty resources": func(r *p.RuleSource) { r.Resources = []p.Resource{} }, "legacy target": func(r *p.RuleSource) { r.Targets.Actors = []string{"did:polygonid:polygon:amoy:abc"} }, "implicit wildcard": func(r *p.RuleSource) { r.Targets.Mode = "" }, "all mode nonempty": func(r *p.RuleSource) { r.Targets.Mode = "all-in-data-org" }, "duplicate parsed address": func(r *p.RuleSource) {
		r.Addresses = p.Addresses{Mode: "list", Values: []string{"0xaB11111111111111111111111111111111111111", "0xab11111111111111111111111111111111111111"}}
	}, "duration": func(r *p.RuleSource) { r.MaxCaseSeconds = p.MaxCaseSeconds + 1 }} {
		t.Run(name, func(t *testing.T) {
			q := source()
			mutate(&q.Rules[0])
			if _, err := p.Compile(q, &index{true}, p.DefaultLimits()); err == nil {
				t.Fatal("invalid source compiled")
			}
		})
	}
	q := scope()
	raw, _ = json.Marshal(q)
	normalized, err := p.DecodeScope(raw, p.DefaultLimits())
	if err != nil || !reflect.DeepEqual(q, normalized) {
		t.Fatal("scope round trip", err)
	}
}

func TestReportInputsDoNotRequireRawOutputEntitlements(t *testing.T) {
	s := source()
	s.Rules[0].Resources = []p.Resource{p.ComplianceReport}
	r := compile(t, s)
	requirements := r.Requirements()
	for _, required := range []string{"data.audit-source/v1", "data.address-history/v1", "data.sanctions-source/v1", "data.compliance-source/v1", "secrets.disclosure-render/v1"} {
		if !slices.Contains(requirements, required) {
			t.Fatal("missing report input", required)
		}
	}
	rule, _ := r.Rule("auditor")
	q := scope()
	q.Resources = []p.Resource{p.ComplianceReport}
	if !rule.Covers(q) {
		t.Fatal("report output denied")
	}
	q.Resources = []p.Resource{p.ActivityLogs}
	if rule.Covers(q) {
		t.Fatal("input dependency leaked raw output grant")
	}
}
