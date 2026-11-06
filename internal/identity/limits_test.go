package identity_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"privacy-proxy/internal/identity"
)

func azureOnly() identity.SourceCatalog {
	s := fixture()
	s.Profiles = s.Profiles[:1]
	s.Mappings = s.Mappings[:1]
	s.Issuers[0].AllowedProfiles = []string{"azure"}
	return s
}

func TestTokenRawDecodedAndStructuralLimitsAtBoundary(t *testing.T) {
	defaults := identity.DefaultLimits()
	base := compile(t, azureOnly(), defaults)
	m := claims(t, base, "azure")
	compact := token(t, m)
	headerBytes := len(raw(t, map[string]any{"typ": "ops-access+jwt", "alg": "EdDSA", "kid": "k1"}))
	payloadBytes := len(raw(t, m))
	for _, tc := range []struct {
		name     string
		set      func(*identity.Limits, int)
		boundary int
	}{
		{"compact", func(l *identity.Limits, n int) { l.MaxCompactAccessBytes = n }, len(compact)},
		{"header", func(l *identity.Limits, n int) { l.MaxDecodedHeaderBytes = n }, headerBytes},
		{"payload", func(l *identity.Limits, n int) { l.MaxDecodedPayloadBytes = n }, payloadBytes},
		{"token depth", func(l *identity.Limits, n int) { l.MaxTokenJSONDepth = n }, 3},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, offset := range []int{0, -1} {
				l := defaults
				tc.set(&l, tc.boundary+offset)
				v := verifier(t, compile(t, azureOnly(), l))
				p, e := v.VerifyAccess(compact)
				if offset == 0 {
					if e != nil || p == nil {
						t.Fatal("boundary rejected", e)
					}
				} else if e == nil || p != nil {
					t.Fatal("boundary+1 input accepted")
				}
			}
		})
	}
	l := defaults
	l.MaxFacts = 1
	v := verifier(t, compile(t, azureOnly(), l))
	if _, e := v.VerifyAccess(compact); e != nil {
		t.Fatal(e)
	}
	extra := claims(t, base, "azure")
	extra["facts"] = []identity.Fact{{Kind: "azure.role", Value: "Reader"}, {Kind: "azure.role", Value: "unmapped"}}
	denied(t, v, token(t, extra))
	// Six UTF8 bytes are valid at six; a seventh byte rejects before mapping.
	l = defaults
	l.MaxFactValueBytes = 6
	v = verifier(t, compile(t, azureOnly(), l))
	if _, e := v.VerifyAccess(compact); e != nil {
		t.Fatal(e)
	}
	extra = claims(t, base, "azure")
	extra["facts"] = []identity.Fact{{Kind: "azure.role", Value: "Readers"}}
	denied(t, v, token(t, extra))
	for field, n := range map[string]int{"source_subject": defaults.MaxSourceSubjectBytes, "source_profile": defaults.MaxProfileIDBytes, "jti": 128, "iss": defaults.MaxURLBytes, "aud": 256, "identity_authority": defaults.MaxURLBytes} {
		t.Run(field, func(t *testing.T) {
			extra := claims(t, base, "azure")
			extra[field] = strings.Repeat("x", n+1)
			denied(t, verifier(t, base), token(t, extra))
		})
	}
	oversizedHeader := map[string]any{"typ": "ops-access+jwt", "alg": "EdDSA", "kid": strings.Repeat("k", defaults.MaxKidBytes+1)}
	denied(t, verifier(t, base), signRaw(t, raw(t, oversizedHeader), raw(t, m), privateKey()))
	deep := claims(t, base, "azure")
	deep["unknown"] = json.RawMessage(strings.Repeat("[", defaults.MaxTokenJSONDepth+1) + "0" + strings.Repeat("]", defaults.MaxTokenJSONDepth+1))
	denied(t, verifier(t, base), token(t, deep))
}

func TestCatalogCollectionAndAggregateLimitsUseCheckedBoundaries(t *testing.T) {
	s := azureOnly()
	for _, tc := range []struct {
		name string
		set  func(*identity.Limits)
	}{
		{"issuer", func(l *identity.Limits) { l.MaxIssuers = 1 }},
		{"key", func(l *identity.Limits) { l.MaxKeysPerIssuer = 1; l.MaxTotalKeys = 1 }},
		{"profile", func(l *identity.Limits) { l.MaxProfiles = 1 }},
		{"mapping", func(l *identity.Limits) { l.MaxMappings = 1 }},
		{"references", func(l *identity.Limits) { l.MaxGroupsPerMapping = 1; l.MaxTotalGroupReferences = 1 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			l := identity.DefaultLimits()
			tc.set(&l)
			compile(t, s, l)
			changed := azureOnly()
			switch tc.name {
			case "issuer":
				other := changed.Issuers[0]
				other.ID = "second"
				other.Issuer = "https://second.test"
				changed.Issuers = append(changed.Issuers, other)
			case "key":
				other := changed.Issuers[0].Keys[0]
				other.Kid = "k2"
				changed.Issuers[0].Keys = append(changed.Issuers[0].Keys, other)
			case "profile":
				p := changed.Profiles[0]
				p.ID = "second"
				changed.Profiles = append(changed.Profiles, p)
				changed.Issuers[0].AllowedProfiles = append(changed.Issuers[0].AllowedProfiles, "second")
			case "mapping":
				mapping := changed.Mappings[0]
				mapping.ID = "second"
				mapping.Fact.Value = "Other"
				changed.Mappings = append(changed.Mappings, mapping)
			case "references":
				changed.Mappings[0].GroupIDs = append(changed.Mappings[0].GroupIDs, group2)
			}
			if c, e := identity.Compile(changed, &groupIndex{}, l); e == nil || c != nil {
				t.Fatal("collection boundary+1 ignored")
			}
			if _, e := identity.Decode(raw(t, changed), l); e == nil {
				t.Fatal("decoded collection cap ignored before typed source")
			}
		})
	}
	// Valid source ID boundary and +1 are distinct from unknown-reference errors.
	for _, size := range []int{128, 129} {
		changed := azureOnly()
		id := strings.Repeat("a", size)
		changed.Profiles[0].ID = id
		changed.Issuers[0].AllowedProfiles[0] = id
		changed.Mappings[0].ProfileID = id
		c, e := identity.Compile(changed, &groupIndex{}, identity.DefaultLimits())
		if size == 128 && e != nil {
			t.Fatal(e)
		}
		if size == 129 && (e == nil || c != nil) {
			t.Fatal("profile ID cap ignored")
		}
	}
}

func TestDefaultFactAndHeaderCapsAcceptTheirExactBoundary(t *testing.T) {
	l := identity.DefaultLimits()
	c := compile(t, azureOnly(), l)
	v := verifier(t, c)
	facts := make([]identity.Fact, l.MaxFacts)
	for i := range facts {
		facts[i] = identity.Fact{Kind: "azure.role", Value: fmt.Sprintf("R%03d", i)}
	}
	m := claims(t, c, "azure")
	m["facts"] = facts
	if _, e := v.VerifyAccess(token(t, m)); e != nil {
		t.Fatal("default fact boundary rejected", e)
	}
	m["facts"] = append(facts, identity.Fact{Kind: "azure.role", Value: "extra"})
	denied(t, v, token(t, m))
	m = claims(t, c, "azure")
	m["facts"] = []identity.Fact{{Kind: "azure.role", Value: strings.Repeat("r", l.MaxFactValueBytes)}}
	if _, e := v.VerifyAccess(token(t, m)); e != nil {
		t.Fatal("default fact value boundary rejected", e)
	}
	m["facts"] = []identity.Fact{{Kind: "azure.role", Value: strings.Repeat("r", l.MaxFactValueBytes+1)}}
	denied(t, v, token(t, m))
	header := raw(t, map[string]any{"typ": "ops-access+jwt", "alg": "EdDSA", "kid": "k1"})
	header = append(header, bytes.Repeat([]byte{' '}, l.MaxDecodedHeaderBytes-len(header))...)
	if _, e := v.VerifyAccess(signRaw(t, header, raw(t, claims(t, c, "azure")), privateKey())); e != nil {
		t.Fatal("default header boundary rejected", e)
	}
	denied(t, v, signRaw(t, append(header, ' '), raw(t, claims(t, c, "azure")), privateKey()))
	// The compact cap would otherwise dominate this independent decoded cap.
	l.MaxCompactAccessBytes = 32768
	c = compile(t, azureOnly(), l)
	v = verifier(t, c)
	payload := raw(t, claims(t, c, "azure"))
	payload = append(payload, bytes.Repeat([]byte{' '}, l.MaxDecodedPayloadBytes-len(payload))...)
	header = raw(t, map[string]any{"typ": "ops-access+jwt", "alg": "EdDSA", "kid": "k1"})
	if _, e := v.VerifyAccess(signRaw(t, header, payload, privateKey())); e != nil {
		t.Fatal("decoded payload boundary rejected", e)
	}
	denied(t, v, signRaw(t, header, append(payload, ' '), privateKey()))
}

func TestOtherScalarCapsRespectSemanticAndConfiguredBoundaries(t *testing.T) {
	for _, tc := range []struct {
		name  string
		set   func(*identity.Limits)
		field string
		value string
	}{
		{"subject", func(l *identity.Limits) { l.MaxSourceSubjectBytes = 36 }, "source_subject", oid + "x"},
		{"profile", func(l *identity.Limits) { l.MaxProfileIDBytes = 5 }, "source_profile", "azurex"},
		{"kid", func(l *identity.Limits) { l.MaxKidBytes = 2 }, "kid", "k11"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			l := identity.DefaultLimits()
			tc.set(&l)
			c := compile(t, azureOnly(), l)
			v := verifier(t, c)
			if _, e := v.VerifyAccess(token(t, claims(t, c, "azure"))); e != nil {
				t.Fatal(e)
			}
			m := claims(t, c, "azure")
			if tc.field == "kid" {
				denied(t, v, signRaw(t, raw(t, map[string]any{"typ": "ops-access+jwt", "alg": "EdDSA", "kid": tc.value}), raw(t, m), privateKey()))
			} else {
				m[tc.field] = tc.value
				denied(t, v, token(t, m))
			}
		})
	}
	for _, size := range []int{128, 129} {
		s := azureOnly()
		s.Issuers[0].Keys[0].Kid = strings.Repeat("k", size)
		s.Mappings[0].ID = strings.Repeat("m", size)
		c, e := identity.Compile(s, &groupIndex{}, identity.DefaultLimits())
		if size == 128 && e != nil {
			t.Fatal(e)
		}
		if size == 129 && (e == nil || c != nil) {
			t.Fatal("source key/mapping ID cap ignored")
		}
	}
	l := identity.DefaultLimits()
	for _, size := range []int{l.MaxURLBytes, l.MaxURLBytes + 1} {
		s := fixture()
		s.Profiles[3].Context = "https://example.test/" + strings.Repeat("x", size-len("https://example.test/"))
		c, e := identity.Compile(s, &groupIndex{}, l)
		if size == l.MaxURLBytes && e != nil {
			t.Fatal(e)
		}
		if size > l.MaxURLBytes && (e == nil || c != nil) {
			t.Fatal("URL cap ignored")
		}
	}
	// uint32 has a stronger ten-digit semantic bound than the general decimal cap.
	s := fixture()
	s.Profiles[3].Predicates[0].Value = "4294967295"
	l.MaxPredicateDecimalBytes = 10
	compile(t, s, l)
	l.MaxPredicateDecimalBytes = 9
	if c, e := identity.Compile(s, &groupIndex{}, l); e == nil || c != nil {
		t.Fatal("predicate decimal cap ignored")
	}
}
