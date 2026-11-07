package identitybroker

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	f "privacy-proxy/internal/brokertest"
	d "privacy-proxy/internal/disclosuretest"
	"privacy-proxy/internal/identity"
)

func testRings(t *testing.T) (*keyring, *keyring) {
	t.Helper()
	mac, aes, err := newKeyrings(f.BrokerSource(), []SecretBinding{{"OPS_BROKER_REFRESH_TEST", bytes.Repeat([]byte{1}, 32)}}, []SecretBinding{{"OPS_BROKER_ENCRYPTION_TEST", bytes.Repeat([]byte{2}, 32)}}, f.SigningKey())
	if err != nil {
		t.Fatal(err)
	}
	return mac, aes
}
func TestCiphertextCannotMoveBetweenRowsOrRecipientBindings(t *testing.T) {
	_, ring := testRings(t)
	scope := Scope{Hash("namespace", []byte("one")), ExpectedState{uuid.NewString()}}
	p := Pending{ID: uuid.NewString(), Scope: scope, StateHash: Hash("state"), ProfileID: "azure", ProfileDigest: Hash("profile").String(), Recipient: RecipientBinding{1}, EncryptionKeyID: ring.active, CreatedAt: time.Unix(d.Now, 0), ExpiresAt: time.Unix(d.Now+300, 0)}
	raw, err := ring.seal(p.EncryptionKeyID, []byte(`{"nonce":"secret","pkceVerifier":"secret"}`), pendingAAD(p))
	if err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*Pending){func(p *Pending) { p.ID = uuid.NewString() }, func(p *Pending) { p.StateHash = Hash("other") }, func(p *Pending) { p.ProfileID = "service" }, func(p *Pending) { p.ProfileDigest = Hash("other").String() }, func(p *Pending) { p.Recipient = RecipientBinding{2} }, func(p *Pending) { p.Scope.State.RecoveryEpoch = uuid.NewString() }, func(p *Pending) { p.Scope.Namespace = Hash("other") }, func(p *Pending) { p.EncryptionKeyID = "other" }} {
		copy := p
		change(&copy)
		if _, err := ring.open(copy.EncryptionKeyID, raw, pendingAAD(copy), 2048); err == nil {
			t.Fatal("pending ciphertext moved")
		}
	}
	family := Family{ID: uuid.NewString(), Scope: scope, Actor: d.Actor(d.Subject), ProfileID: "azure", ProfileDigest: p.ProfileDigest, Authority: "https://login.microsoftonline.com/" + d.Tenant + "/v2.0", Tenant: d.Tenant, Subject: d.Subject, Kind: identity.Human, OIDCSubjectHash: Hash("oidc"), NonceHash: Hash("nonce"), Recipient: RecipientBinding{1}, Generation: 1, CurrentHandleHash: Hash("handle"), EncryptionKeyID: ring.active}
	family.Ciphertext, err = ring.seal(ring.active, []byte("provider-refresh-secret"), familyAAD(family))
	if err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*Family){func(f *Family) { f.ID = uuid.NewString() }, func(f *Family) { f.Actor = d.Actor(d.AdminSubject) }, func(f *Family) { f.Subject = d.AdminSubject }, func(f *Family) { f.Tenant = d.OtherOrg }, func(f *Family) { f.ProfileDigest = Hash("other").String() }, func(f *Family) { f.Recipient = RecipientBinding{2} }, func(f *Family) { f.Generation++ }, func(f *Family) { f.CurrentHandleHash = Hash("other") }, func(f *Family) { f.OIDCSubjectHash = Hash("other") }, func(f *Family) { f.NonceHash = Hash("other") }, func(f *Family) { v := int64(1); f.OriginalAuthTime = &v }, func(f *Family) { f.Scope.State.RecoveryEpoch = uuid.NewString() }} {
		copy := family
		change(&copy)
		// Even when the caller supplies the row's substituted recipient, AAD must
		// reject the stored ciphertext before a provider grant can take place.
		if _, err := ring.open(copy.EncryptionKeyID, copy.Ciphertext, familyAAD(copy), MaxFamilyCipherBytes); err == nil {
			t.Fatal("family ciphertext moved")
		}
	}
	if _, err := ring.open(ring.active, raw, familyAAD(family), 2048); err == nil {
		t.Fatal("cross-purpose ciphertext accepted")
	}
}
func TestRefreshProofIsClosedTypedCanonicalAndBoundBeforeSQL(t *testing.T) {
	ring, _ := testRings(t)
	jti, _ := randomToken()
	epoch := uuid.NewString()
	c := refreshClaims{Issuer: "https://ops.test", Audience: "ops-renewal", FamilyID: uuid.NewString(), Actor: d.Actor(d.Subject), ProfileID: "azure", ProfileDigest: Hash("profile").String(), Generation: 0, ID: jti, IssuedAt: d.Now, Expires: d.Now + 604800, Epoch: epoch}
	raw, err := ring.mintRefresh(c)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ring.parseRefresh(raw, c.Issuer, epoch, d.Now); err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(raw, ".")
	header, _ := base64.RawURLEncoding.DecodeString(parts[0])
	payload, _ := base64.RawURLEncoding.DecodeString(parts[1])
	sign := func(h, p string) string {
		input := base64.RawURLEncoding.EncodeToString([]byte(h)) + "." + base64.RawURLEncoding.EncodeToString([]byte(p))
		sig, _ := jwt.SigningMethodHS256.Sign(input, ring.mac[ring.active])
		return input + "." + base64.RawURLEncoding.EncodeToString(sig)
	}
	for _, bad := range []string{
		sign(strings.Replace(string(header), "ops-refresh+jwt", "ops-access+jwt", 1), string(payload)),
		sign(strings.Replace(string(header), "HS256", "HS512", 1), string(payload)),
		sign(string(header), strings.Replace(string(payload), `"gen":0`, `"gen":-0`, 1)),
		sign(string(header), strings.Replace(string(payload), `"gen":0`, `"gen":0.0`, 1)),
		sign(string(header), strings.Replace(string(payload), `"gen":0`, `"gen":9223372036854775808`, 1)),
		sign(string(header), strings.Replace(string(payload), `"gen":0`, `"gen":0,"gen":0`, 1)),
		sign(string(header), strings.Replace(string(payload), `"aud":"ops-renewal"`, `"aud":"core"`, 1)),
		sign(string(header), strings.TrimSuffix(string(payload), "}")+`,"admin":true}`),
		raw + "=", strings.Repeat("a", 4097),
	} {
		if _, err := ring.parseRefresh(bad, c.Issuer, epoch, d.Now); err == nil {
			t.Fatal("noncanonical/cross-purpose handle accepted")
		}
	}
	for _, args := range []struct {
		issuer, epoch string
		at            int64
	}{{"https://other.test", epoch, d.Now}, {c.Issuer, uuid.NewString(), d.Now}, {c.Issuer, epoch, c.Expires}, {c.Issuer, epoch, d.Now - 31}} {
		if _, err := ring.parseRefresh(raw, args.issuer, args.epoch, args.at); err == nil {
			t.Fatal("foreign/expired handle accepted")
		}
	}
}
