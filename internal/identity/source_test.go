package identity_test

import (
	"encoding/json"
	"strings"
	"testing"

	"privacy-proxy/internal/identity"
)

func TestClosedCatalogVariantsCrossReferencesAndSourceLimits(t *testing.T) {
	for name, edit := range map[string]func(*identity.SourceCatalog){
		"unknown kind": func(s *identity.SourceCatalog) { s.Profiles[0].Kind = "oidc-any/v1" }, "mixed variant": func(s *identity.SourceCatalog) { s.Profiles[0].Network = "polygon:amoy" }, "missing scope": func(s *identity.SourceCatalog) { s.Profiles[0].DelegatedScope = "" }, "wildcard Azure tenant": func(s *identity.SourceCatalog) {
			s.Profiles[0].Issuer = "https://login.microsoftonline.com/common/v2.0"
		}, "bad UUID": func(s *identity.SourceCatalog) { s.Profiles[0].APIAudience = "api://custom" },
		"private key": func(s *identity.SourceCatalog) { s.Issuers[0].Keys[0].Kty = "oct" }, "key alg": func(s *identity.SourceCatalog) { s.Issuers[0].Keys[0].Alg = "HS256" }, "key curve": func(s *identity.SourceCatalog) { s.Issuers[0].Keys[0].Crv = "Ed448" }, "key bytes": func(s *identity.SourceCatalog) { s.Issuers[0].Keys[0].X = "AQ" }, "duplicate kid": func(s *identity.SourceCatalog) { s.Issuers[0].Keys = append(s.Issuers[0].Keys, s.Issuers[0].Keys[0]) }, "duplicate issuer": func(s *identity.SourceCatalog) { s.Issuers = append(s.Issuers, s.Issuers[0]) }, "unapproved profile": func(s *identity.SourceCatalog) { s.Issuers[0].AllowedProfiles = []string{} }, "unknown approval": func(s *identity.SourceCatalog) {
			s.Issuers[0].AllowedProfiles = append(s.Issuers[0].AllowedProfiles, "unknown")
		}, "remote issuer hint": func(s *identity.SourceCatalog) { s.Issuers[0].Issuer = "https://user:secret@ops.test" },
		"unknown group": func(s *identity.SourceCatalog) { s.Mappings[0].GroupIDs = []string{oid} }, "cross org": func(s *identity.SourceCatalog) { s.Mappings[0].OrganizationID = oid }, "mapping kind": func(s *identity.SourceCatalog) { s.Mappings[0].PrincipalKind = identity.Service }, "unknown fact": func(s *identity.SourceCatalog) { s.Mappings[0].Fact.Kind = "ops.admin" }, "split mapping": func(s *identity.SourceCatalog) {
			m := s.Mappings[0]
			m.ID = "split"
			m.GroupIDs = []string{group2}
			s.Mappings = append(s.Mappings, m)
		}, "duplicate target": func(s *identity.SourceCatalog) { s.Mappings[0].GroupIDs = []string{group, group} }, "identity only mapping": func(s *identity.SourceCatalog) {
			s.Mappings[0].ProfileID = "did"
			s.Mappings[0].Fact = identity.Fact{Kind: "privado.predicate", Value: "banker"}
		},
		"generic circuit": func(s *identity.SourceCatalog) { s.Profiles[3].CircuitID = "arbitrary" }, "JSONPath": func(s *identity.SourceCatalog) { s.Profiles[3].Predicates[0].Field = "role.admin" }, "operator": func(s *identity.SourceCatalog) { s.Profiles[3].Predicates[0].Operator = "gt" }, "uint32 overflow": func(s *identity.SourceCatalog) { s.Profiles[3].Predicates[0].Value = "4294967296" }, "noncanonical integer": func(s *identity.SourceCatalog) { s.Profiles[3].Predicates[0].Value = "07" }, "invalid DID": func(s *identity.SourceCatalog) {
			s.Profiles[3].AllowedCredentialIssuers = []string{"did:iden3:polygon:amoy:0invalid"}
		}, "missing context pin": func(s *identity.SourceCatalog) { s.Profiles[3].ContextDigest = "" }, "identity query mix": func(s *identity.SourceCatalog) { s.Profiles[2].Predicates = s.Profiles[3].Predicates },
	} {
		t.Run(name, func(t *testing.T) {
			s := fixture()
			edit(&s)
			if c, e := identity.Compile(s, &groupIndex{}, identity.DefaultLimits()); e == nil || c != nil {
				t.Fatal("ambiguous or unsupported source accepted")
			}
		})
	}
	good := string(raw(t, fixture()))
	for name, bad := range map[string]string{
		"unknown field":    strings.Replace(good, `"apiVersion":`, `"users":[],"apiVersion":`, 1),
		"wrong case":       strings.Replace(good, `"tenantId":`, `"TenantId":`, 1),
		"missing field":    strings.Replace(good, `,"factSource":"appRoles"`, "", 1),
		"duplicate source": strings.Replace(good, `"kind":"IdentityCatalog"`, `"kind":"IdentityCatalog","kind":"IdentityCatalog"`, 1),
		"null array":       strings.Replace(good, `"allowedProfiles":["azure","service","did","role"]`, `"allowedProfiles":null`, 1),
		"trailing":         good + `{}`,
		"digest assertion": strings.Replace(good, `"kind":"azure-human/v1"`, `"kind":"azure-human/v1","profileDigest":"chosen"`, 1),
	} {
		t.Run(name, func(t *testing.T) {
			if bad == good {
				t.Fatal("negative fixture did not change source")
			}
			if _, e := identity.Decode([]byte(bad), identity.DefaultLimits()); e == nil {
				t.Fatal("source ambiguity accepted")
			}
		})
	}
	for name, change := range map[string]func(*identity.Limits){"document bytes": func(l *identity.Limits) { l.MaxIdentityDocumentBytes = len(good) - 1 }, "depth": func(l *identity.Limits) { l.MaxCatalogJSONDepth = 2 }, "issuers": func(l *identity.Limits) { l.MaxIssuers = 0 }, "profiles": func(l *identity.Limits) { l.MaxProfiles = 3 }, "mappings": func(l *identity.Limits) { l.MaxMappings = 2 }, "total keys": func(l *identity.Limits) { l.MaxTotalKeys = 0 }, "group refs": func(l *identity.Limits) { l.MaxTotalGroupReferences = 2 }, "source names": func(l *identity.Limits) { l.MaxSourceIDBytes = 2 }, "context bytes": func(l *identity.Limits) { l.MaxURLBytes = 10 }, "predicate decimal": func(l *identity.Limits) { l.MaxPredicateDecimalBytes = 0 }} {
		t.Run(name, func(t *testing.T) {
			l := identity.DefaultLimits()
			change(&l)
			if c, e := identity.Compile(fixture(), &groupIndex{}, l); e == nil || c != nil {
				t.Fatal("source cap ignored")
			}
		})
	}
	// Raw byte caps include formatting; exact boundary accepts, +1 rejects.
	l := identity.DefaultLimits()
	l.MaxIdentityDocumentBytes = len(good)
	if _, e := identity.Decode([]byte(good), l); e != nil {
		t.Fatal(e)
	}
	if _, e := identity.Decode([]byte(good+" "), l); e == nil {
		t.Fatal("raw source byte cap ignored")
	}
	var object map[string]any
	if e := json.Unmarshal([]byte(good), &object); e != nil {
		t.Fatal(e)
	}
	object["profiles"].([]any)[2].(map[string]any)["predicates"] = nil
	if _, e := identity.Decode(raw(t, object), identity.DefaultLimits()); e == nil {
		t.Fatal("null/inapplicable variant accepted")
	}
}
