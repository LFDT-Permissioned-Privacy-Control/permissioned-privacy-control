package identitybroker

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	f "privacy-proxy/internal/brokertest"
	"privacy-proxy/internal/identity"
	"privacy-proxy/internal/identitybroker/privado"
)

func TestPrivadoCanonicalMetadataCannotRestoreFactsOrExtendAge(t *testing.T) {
	d := Hash("public-test").String()
	m := providerPlan{d, d, d, d}
	nonce := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{42}, 32))
	payload := privadoChallengePayload{1, nonce, d, m, d}
	raw, e := json.Marshal(payload)
	if e != nil || len(raw) != 638 {
		t.Fatal("small envelope contract", len(raw), e)
	}
	if _, _, e := decodePrivadoChallenge(raw); e != nil {
		t.Fatal(e)
	}
	for _, bad := range []string{" " + string(raw), string(raw) + "\n", strings.Replace(string(raw), `"version":1`, `"version":1.0`, 1), strings.Replace(string(raw), `"version":1`, `"Version":1`, 1), strings.TrimSuffix(string(raw), "}") + `,"facts":[]}`, strings.TrimSuffix(string(raw), "}") + `,"sourceAuthDigest":"` + d + `"}`, strings.Replace(string(raw), nonce, base64.RawURLEncoding.EncodeToString(make([]byte, 32)), 1)} {
		if _, _, e := decodePrivadoChallenge([]byte(bad)); e == nil {
			t.Fatal("noncanonical/authority-bearing payload accepted")
		}
	}
	familyRaw, e := json.Marshal(privadoFamilyPayload{1, d, m})
	if e != nil || len(familyRaw) != 493 {
		t.Fatal("family envelope contract", len(familyRaw), e)
	}
	if _, e := decodePrivadoFamily(familyRaw); e != nil {
		t.Fatal(e)
	}
}
func TestPrivadoAEADBindsProviderRecipientCaptureAndOriginalTime(t *testing.T) {
	_, ring, e := newKeyrings(f.BrokerSource(), []SecretBinding{{"OPS_BROKER_REFRESH_TEST", bytes.Repeat([]byte{1}, 32)}}, []SecretBinding{{"OPS_BROKER_ENCRYPTION_TEST", bytes.Repeat([]byte{2}, 32)}}, f.SigningKey())
	if e != nil {
		t.Fatal(e)
	}
	now := time.Unix(1800000000, 0).UTC()
	scope := Scope{Hash("public-namespace"), ExpectedState{uuid.NewString()}}
	p := PrivadoChallengeRecord{ID: uuid.NewString(), Scope: scope, ProfileID: "role", ProfileDigest: Hash("profile").String(), Recipient: RecipientBinding{1}, Mode: privado.Login, EncryptionKeyID: ring.active, CreatedAt: now, ExpiresAt: now.Add(300 * time.Second)}
	raw := []byte("authenticated original context")
	p.Ciphertext, e = ring.seal(p.EncryptionKeyID, raw, privadoChallengeAAD(p))
	if e != nil {
		t.Fatal(e)
	}
	for _, change := range []func(*PrivadoChallengeRecord){func(p *PrivadoChallengeRecord) { p.Recipient = RecipientBinding{2} }, func(p *PrivadoChallengeRecord) { p.ID = uuid.NewString() }, func(p *PrivadoChallengeRecord) { p.ExpiresAt = p.ExpiresAt.Add(time.Second) }, func(p *PrivadoChallengeRecord) { p.Mode = privado.Renew }, func(p *PrivadoChallengeRecord) {
		p.ExpectedActorID = "ops:p1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	}} {
		copy := p
		change(&copy)
		if _, e = ring.open(copy.EncryptionKeyID, copy.Ciphertext, privadoChallengeAAD(copy), 2048); e == nil {
			t.Fatal("tampered context decrypted")
		}
	}
	family := Family{Provider: FamilyPrivado, ID: uuid.NewString(), RequestID: p.ID, Scope: scope, Actor: "ops:p1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", ProfileID: p.ProfileID, ProfileDigest: p.ProfileDigest, Authority: "privado", Subject: f.PublicFixtureDID(t, 71), Kind: identity.Human, Recipient: p.Recipient, Generation: 0, CurrentHandleHash: Hash("handle"), EncryptionKeyID: ring.active, CreatedAt: now, AbsoluteExpiresAt: now.Add(FamilyLifetime), LastRotatedAt: now}
	family.Ciphertext, e = ring.seal(family.EncryptionKeyID, raw, privadoFamilyAAD(family))
	if e != nil || !family.Valid() {
		t.Fatal("valid provider-tagged family", e)
	}
	revoked := family
	revoked.RevokedAt = &now
	if _, e = ring.open(revoked.EncryptionKeyID, revoked.Ciphertext, privadoFamilyAAD(revoked), 2048); e != nil {
		t.Fatal("revoke must preserve cipher, while DB state denies authorization", e)
	}
	family.Tenant = "00000000-0000-4000-8000-000000000001"
	if family.Valid() {
		t.Fatal("Privado family accepted fictitious Azure tenant")
	}
	family.Tenant = ""
	family.Provider = FamilyAzure
	if family.Valid() {
		t.Fatal("DID variant accepted as Azure UUID/OIDC family")
	}
}
