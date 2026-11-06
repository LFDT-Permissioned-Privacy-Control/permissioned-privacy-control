package identity_test

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"math"
	"slices"
	"strings"
	"testing"

	"privacy-proxy/internal/identity"
)

func TestAccessCryptographyAndTrustSubstitutionReject(t *testing.T) {
	c := compile(t, fixture(), identity.DefaultLimits())
	v := verifier(t, c)
	for name, edit := range map[string]func(map[string]any){
		"issuer": func(m map[string]any) { m["iss"] = "https://foreign.test" }, "audience": func(m map[string]any) { m["aud"] = "broker-renewal" }, "audience list": func(m map[string]any) { m["aud"] = []string{"ops-core"} },
		"source profile": func(m map[string]any) { m["source_profile"] = "unknown" }, "source digest": func(m map[string]any) { m["source_profile_digest"] = "sha256:" + strings.Repeat("0", 64) }, "principal kind": func(m map[string]any) { m["principal_kind"] = "service" },
		"source tenant": func(m map[string]any) { m["source_tenant"] = org }, "missing source tenant": func(m map[string]any) { delete(m, "source_tenant") }, "source authority": func(m map[string]any) { m["identity_authority"] = "https://evil.test" }, "subject swap": func(m map[string]any) { m["source_subject"] = org }, "actor injection": func(m map[string]any) { m["sub"] = "azuread:" + oid },
		"permission bits": func(m map[string]any) { m["admin"] = true }, "internal groups": func(m map[string]any) { m["groups"] = []string{group} }, "old refresh": func(m map[string]any) { m["family_id"] = "chosen-family" }, "overage": func(m map[string]any) { m["_claim_names"] = map[string]any{"groups": "src1"} },
		"fact kind": func(m map[string]any) { m["facts"] = []identity.Fact{{Kind: "ops.group", Value: group}} }, "wrong provider fact": func(m map[string]any) { m["facts"] = []identity.Fact{{Kind: "azure.group", Value: group}} }, "duplicate facts": func(m map[string]any) {
			m["facts"] = []identity.Fact{{Kind: "azure.role", Value: "Reader"}, {Kind: "azure.role", Value: "Reader"}}
		}, "null facts": func(m map[string]any) { m["facts"] = nil }, "missing facts": func(m map[string]any) { delete(m, "facts") },
	} {
		t.Run(name, func(t *testing.T) { m := claims(t, c, "azure"); edit(m); denied(t, v, token(t, m)) })
	}
	for name, edit := range map[string]func(map[string]any){"alg none": func(h map[string]any) { h["alg"] = "none" }, "HS fallback": func(h map[string]any) { h["alg"] = "HS256" }, "ES variant": func(h map[string]any) { h["alg"] = "ES256" }, "wrong typ": func(h map[string]any) { h["typ"] = "ops-refresh+jwt" }, "wrong kid": func(h map[string]any) { h["kid"] = "unknown" }, "empty kid": func(h map[string]any) { h["kid"] = "" }, "embedded key": func(h map[string]any) { h["jwk"] = map[string]any{} }, "remote key": func(h map[string]any) { h["jku"] = "https://evil.test" }, "cert hint": func(h map[string]any) { h["x5u"] = "https://evil.test" }} {
		t.Run(name, func(t *testing.T) {
			h := map[string]any{"alg": "EdDSA", "typ": "ops-access+jwt", "kid": "k1"}
			edit(h)
			denied(t, v, signRaw(t, raw(t, h), raw(t, claims(t, c, "azure")), privateKey()))
		})
	}
	wrong := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{2}, 32))
	denied(t, v, signRaw(t, raw(t, map[string]any{"alg": "EdDSA", "typ": "ops-access+jwt", "kid": "k1"}), raw(t, claims(t, c, "azure")), wrong))
	good := token(t, claims(t, c, "azure"))
	parts := strings.Split(good, ".")
	alphabet := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	last := strings.IndexByte(alphabet, parts[2][len(parts[2])-1])
	noncanonical := parts[2][:len(parts[2])-1] + string(alphabet[last+1]) // Same decoded signature bytes, nonzero unused bits.
	denied(t, v, parts[0]+"."+parts[1]+"."+noncanonical)
	for _, bad := range []string{good + ".extra", good + "=", strings.Join([]string{parts[0], parts[1], parts[2][:len(parts[2])-1]}, "."), parts[0] + ".." + parts[2], "." + parts[1] + "." + parts[2], strings.Replace(good, ".", "\n.", 1), parts[0] + "." + parts[1] + "." + base64.RawURLEncoding.EncodeToString(make([]byte, 65)), "not-a-token"} {
		denied(t, v, bad)
	}
	duplicate := strings.Replace(string(raw(t, claims(t, c, "azure"))), `"jti":"request-1"`, `"jti":"request-1","jti":"request-2"`, 1)
	denied(t, v, signRaw(t, raw(t, map[string]any{"typ": "ops-access+jwt", "alg": "EdDSA", "kid": "k1"}), []byte(duplicate), privateKey()))
	m := claims(t, c, "azure")
	m["facts"] = []identity.Fact{{Kind: "azure.role", Value: "reader"}}
	p, e := v.VerifyAccess(token(t, m))
	if e != nil || len(p.Groups(org)) != 0 {
		t.Fatal("unknown case-sensitive role granted or rejected as malformed", e)
	}
	for _, id := range []string{"did", "role"} {
		m := claims(t, c, id)
		m["facts"] = []identity.Fact{{Kind: "privado.predicate", Value: "not-declared"}}
		denied(t, v, token(t, m))
		m = claims(t, c, id)
		m["source_subject"] = "did:iden3:polygon:main:123456789ABCDEFGH"
		denied(t, v, token(t, m))
		m = claims(t, c, id)
		m["source_tenant"] = tenant
		denied(t, v, token(t, m))
	}
}

func TestAssertionFreshnessHasNoStackedWindowOrExpiryLeeway(t *testing.T) {
	c := compile(t, fixture(), identity.DefaultLimits())
	v := verifier(t, c)
	for name, edit := range map[string]func(map[string]any){
		"expired now": func(m map[string]any) { m["exp"] = now }, "issued future31": func(m map[string]any) { m["iat"] = now + 31 }, "nbf future31": func(m map[string]any) { m["nbf"], m["iat"] = now+31, now+31 }, "evidence future31": func(m map[string]any) { m["claims_as_of"], m["source_verified_at"], m["iat"] = now+31, now+31, now+31 },
		"stacked old claims": func(m map[string]any) { m["claims_as_of"] = now - 240; m["exp"] = now + 300 }, "source min bound": func(m map[string]any) { m["source_not_after"] = now + 299 }, "issuer min bound": func(m map[string]any) { m["exp"] = now + 301 }, "evidence after verify": func(m map[string]any) { m["claims_as_of"] = now + 1 }, "verify after issue": func(m map[string]any) { m["source_verified_at"] = now + 1 }, "nbf after issue": func(m map[string]any) { m["nbf"] = now + 1 }, "exp before issue": func(m map[string]any) { m["iat"] = now + 10; m["exp"] = now + 5 }, "timestamp overflow": func(m map[string]any) { m["iat"] = int64(math.MaxInt64) }, "negative": func(m map[string]any) { m["iat"] = -1 }, "float": func(m map[string]any) { m["iat"] = float64(now) + 0.5 }, "exponent": func(m map[string]any) { m["iat"] = json.Number("18e8") }, "quoted": func(m map[string]any) { m["iat"] = "1800000000" }, "negative zero": func(m map[string]any) { m["nbf"] = json.Number("-0") },
	} {
		t.Run(name, func(t *testing.T) { m := claims(t, c, "azure"); edit(m); denied(t, v, token(t, m)) })
	}
	m := claims(t, c, "azure")
	m["claims_as_of"] = now - 240
	m["exp"] = now + 60
	if _, e := v.VerifyAccess(token(t, m)); e != nil {
		t.Fatal("one-minute residual authority rejected", e)
	}
	m = claims(t, c, "azure")
	m["iat"], m["nbf"], m["claims_as_of"], m["source_verified_at"], m["exp"] = now+30, now+30, now+30, now+30, now+330
	p, e := v.VerifyAccess(token(t, m))
	if e != nil || p.ExpiresAt().Unix() != now+330 {
		t.Fatal("reviewed future-clock exposure changed", e)
	}
	m["exp"] = now + 331
	denied(t, v, token(t, m))
	m = claims(t, c, "did")
	m["source_not_after"] = now + 500
	denied(t, v, token(t, m))
	m = claims(t, c, "role")
	m["source_not_after"] = now + 299
	denied(t, v, token(t, m))
	m["exp"] = now + 299
	if _, e := v.VerifyAccess(token(t, m)); e != nil {
		t.Fatal("known proof expiry bound rejected", e)
	}
	// A public-key rotation does not alter the source profile digest.
	s := fixture()
	s.Issuers[0].Keys[0].X = base64.RawURLEncoding.EncodeToString(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{2}, 32)).Public().(ed25519.PublicKey))
	next := compile(t, s, identity.DefaultLimits())
	d, _ := c.ProfileDigest("azure")
	d2, _ := next.ProfileDigest("azure")
	if d != d2 || next.Digest() == c.Digest() {
		t.Fatal("profile and trust digest spaces mixed")
	}
	denied(t, verifier(t, next), token(t, claims(t, c, "azure")))
	if !slices.Equal(p.Facts(), []identity.Fact{{Kind: "azure.role", Value: "Reader"}}) {
		t.Fatal("verified facts changed")
	}
}
