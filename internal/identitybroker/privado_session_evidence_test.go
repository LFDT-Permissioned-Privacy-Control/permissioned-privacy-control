package identitybroker

import (
	"encoding/json"
	"math"
	"reflect"
	"strings"
	"testing"
	"time"

	"privacy-proxy/internal/brokerpolicy"
	f "privacy-proxy/internal/brokertest"
	"privacy-proxy/internal/identity"
	"privacy-proxy/internal/identitybroker/privado"
)

func TestPrivadoSessionEvidenceRejectsMalformedSnapshots(t *testing.T) {
	now := time.Unix(1800000000, 0).UTC()
	snapshot := f.MultiSnapshot(t, func(ids *identity.SourceCatalog, _ *brokerpolicy.SourceV2) {
		for i := range ids.Profiles {
			if ids.Profiles[i].ID == f.PrivadoRoleProfile {
				ids.Profiles[i].Predicates = []identity.Predicate{
					{ID: "reader", Field: "role", Operator: "eq", Value: "7"},
					{ID: "writer", Field: "role", Operator: "eq", Value: "8", Optional: true},
				}
			}
		}
	})
	ids, _ := snapshot.Identity()
	broker, _ := snapshot.AuthBroker()
	// Only exercise snapshot validation. No opaque VerifiedProof is fabricated.
	s := &Service{multi: true, privado: &privado.Provider{}, identity: ids, broker: broker}
	digest, _ := ids.ProfileDigest(f.PrivadoRoleProfile)
	subject := f.PublicFixtureDID(t, 71)
	actor, err := ids.SourceActorID(identity.SourceIdentity{ProfileID: f.PrivadoRoleProfile, Kind: identity.Human, Authority: "privado", Subject: subject})
	if err != nil {
		t.Fatal(err)
	}
	family := Family{ProfileID: f.PrivadoRoleProfile, ProfileDigest: digest, Subject: subject, Actor: actor, AbsoluteExpiresAt: now.Add(time.Hour)}
	evidence := privadoSessionEvidence{ClaimsAsOf: now.Unix() - 20, VerifiedAt: now.Unix() - 10, NotAfter: now.Unix() + 100, Predicates: []uint32{1}}
	want := []identity.Fact{{Kind: "privado.predicate", Value: "reader"}}
	facts, err := s.privadoEvidenceFacts(family, evidence, now)
	if err != nil || !reflect.DeepEqual(facts, want) {
		t.Fatal("valid canonical subset rejected", facts, err)
	}
	// Authentic expiry is a separate state from malformed evidence. Validation
	// must still succeed so the caller can request a genuinely new proof.
	if _, err := s.privadoEvidenceFacts(family, evidence, time.Unix(evidence.NotAfter, 0)); err != nil {
		t.Fatal("valid expired snapshot treated as malformed", err)
	}
	for name, mutate := range map[string]func(*Family, *privadoSessionEvidence){
		"nil facts":                   func(_ *Family, e *privadoSessionEvidence) { e.Predicates = nil },
		"missing mandatory":           func(_ *Family, e *privadoSessionEvidence) { e.Predicates = []uint32{2} },
		"duplicate fact":              func(_ *Family, e *privadoSessionEvidence) { e.Predicates = []uint32{1, 1} },
		"unordered facts":             func(_ *Family, e *privadoSessionEvidence) { e.Predicates = []uint32{2, 1} },
		"zero index":                  func(_ *Family, e *privadoSessionEvidence) { e.Predicates = []uint32{0} },
		"unknown index":               func(_ *Family, e *privadoSessionEvidence) { e.Predicates = []uint32{1, 3} },
		"negative time":               func(_ *Family, e *privadoSessionEvidence) { e.ClaimsAsOf = -1 },
		"overflow time":               func(_ *Family, e *privadoSessionEvidence) { e.ClaimsAsOf = math.MaxInt64 },
		"verified before source":      func(_ *Family, e *privadoSessionEvidence) { e.VerifiedAt = e.ClaimsAsOf - 1 },
		"future verification":         func(_ *Family, e *privadoSessionEvidence) { e.VerifiedAt = now.Unix() + 1 },
		"expired before verification": func(_ *Family, e *privadoSessionEvidence) { e.NotAfter = e.VerifiedAt },
		"extended source age":         func(_ *Family, e *privadoSessionEvidence) { e.NotAfter = e.ClaimsAsOf + 301 },
		"extended family":             func(f *Family, e *privadoSessionEvidence) { f.AbsoluteExpiresAt = time.Unix(e.NotAfter-1, 0) },
		"changed profile":             func(family *Family, _ *privadoSessionEvidence) { family.ProfileID = f.PrivadoProfile },
		"changed digest":              func(f *Family, _ *privadoSessionEvidence) { f.ProfileDigest = Hash("changed").String() },
		"changed actor": func(f *Family, _ *privadoSessionEvidence) {
			f.Actor = "ops:p1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
		},
		"changed holder": func(family *Family, _ *privadoSessionEvidence) { family.Subject = f.PublicFixtureDID(t, 72) },
	} {
		t.Run(name, func(t *testing.T) {
			copyFamily, copyEvidence := family, evidence
			mutate(&copyFamily, &copyEvidence)
			if _, err := s.privadoEvidenceFacts(copyFamily, copyEvidence, now); err == nil {
				t.Fatal("malformed evidence accepted")
			}
		})
	}
}

func TestPrivadoSessionEvidenceEnvelopeVersionsAndCapacity(t *testing.T) {
	digest := Hash("public-test").String()
	provider := providerPlan{digest, digest, digest, digest}
	indices := make([]uint32, privado.MaxPredicates)
	for i := range indices {
		indices[i] = uint32(i + 1)
	}
	evidence := &privadoSessionEvidence{ClaimsAsOf: 1800000000, VerifiedAt: 1800000001, NotAfter: 1800000300, Predicates: indices}
	payload := privadoFamilyPayload{Version: 2, SourceAuthDigest: digest, Provider: provider, Evidence: evidence}
	raw, err := json.Marshal(payload)
	if err != nil || len(raw)+28 > 2048 {
		t.Fatal("maximum predicate snapshot exceeds existing authenticated family cap", len(raw), err)
	}
	decoded, err := decodePrivadoFamily(raw)
	if err != nil || !reflect.DeepEqual(decoded, payload) {
		t.Fatal("new family snapshot cannot round trip", err)
	}
	for name, malformed := range map[string]string{
		"v1 with evidence": strings.Replace(string(raw), `"version":2`, `"version":1`, 1),
		"unknown version":  strings.Replace(string(raw), `"version":2`, `"version":3`, 1),
		"duplicate time":   strings.Replace(string(raw), `"claimsAsOf":1800000000`, `"claimsAsOf":1800000000,"claimsAsOf":1800000001`, 1),
		"arbitrary facts":  strings.TrimSuffix(string(raw), "}") + `,"facts":[{"kind":"privado.predicate","value":"admin"}]}`,
		"null evidence":    strings.Replace(string(raw), string(mustJSON(t, evidence)), "null", 1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := decodePrivadoFamily([]byte(malformed)); err == nil {
				t.Fatal("malformed envelope accepted")
			}
		})
	}
	for _, version := range []uint8{1, 2} {
		without := privadoFamilyPayload{Version: version, SourceAuthDigest: digest, Provider: provider}
		_, err := decodePrivadoFamily(mustJSON(t, without))
		if (err == nil) != (version == 1) {
			t.Fatal("legacy continuity-only family or required v2 evidence mishandled", version, err)
		}
	}
}

func mustJSON(t *testing.T, value any) []byte {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
