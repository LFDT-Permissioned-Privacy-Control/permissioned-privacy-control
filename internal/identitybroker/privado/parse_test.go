package privado

import (
	"encoding/base64"
	"encoding/json"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

func compactParts(t *testing.T, compact string) []map[string]any {
	t.Helper()
	parts := strings.Split(compact, ".")
	out := make([]map[string]any, 3)
	for i, s := range parts {
		raw, e := base64.RawURLEncoding.DecodeString(s)
		if e != nil {
			t.Fatal(e)
		}
		decoder := json.NewDecoder(strings.NewReader(string(raw)))
		decoder.UseNumber()
		if decoder.Decode(&out[i]) != nil {
			t.Fatal("fixture decode")
		}
	}
	return out
}
func marshalCompact(t *testing.T, parts []map[string]any) string {
	t.Helper()
	out := []string{}
	for _, p := range parts {
		raw, e := json.Marshal(p)
		if e != nil {
			t.Fatal(e)
		}
		out = append(out, base64.RawURLEncoding.EncodeToString(raw))
	}
	return strings.Join(out, ".")
}
func TestClosedJWZPreflightRejectsAmbiguityBeforeSDK(t *testing.T) {
	p := fixtureProvider(t, nil)
	r := fixtureRequest(t, p, "privado")
	_, holder := fixtureDID(t, "polygon:mumbai", 13)
	token := unprovedCompact(t, r, holder)
	for name, change := range map[string]func([]map[string]any){
		"wrong media":         func(v []map[string]any) { v[0]["typ"] = "application/iden3comm-signed-json" },
		"plain outer wire":    func(v []map[string]any) { v[0]["typ"] = "application/iden3comm-plain-json" },
		"unknown inner label": func(v []map[string]any) { v[1]["typ"] = "application/iden3comm-signed-json" },
		"wrong critical type": func(v []map[string]any) { v[0]["crit"] = "circuitId" },
		"unknown critical":    func(v []map[string]any) { v[0]["crit"] = []string{"circuitId", "x"}; v[0]["x"] = true },
		"body case alias":     func(v []map[string]any) { v[1]["Body"] = v[1]["body"] },
		"wrong thread":        func(v []map[string]any) { v[1]["thid"] = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa" },
		"wrong challenge":     func(v []map[string]any) { v[1]["body"].(map[string]any)["message"] = "another public challenge" },
		"extra scope":         func(v []map[string]any) { v[1]["body"].(map[string]any)["scope"] = []any{map[string]any{}} },
		"nonfield signal":     func(v []map[string]any) { v[2]["pub_signals"].([]any)[2] = fr.Modulus().String() },
		"noncanonical number": func(v []map[string]any) { v[2]["pub_signals"].([]any)[2] = "00" },
		"proof dimension":     func(v []map[string]any) { v[2]["proof"].(map[string]any)["pi_b"] = []any{} },
	} {
		t.Run(name, func(t *testing.T) {
			parts := compactParts(t, token)
			change(parts)
			if _, e := parseCompact(marshalCompact(t, parts), sdkRequest(t, r), p.profiles["privado"], time.Now().Unix()); e == nil {
				t.Fatal("ambiguous input accepted")
			}
		})
	}
	header, _, _ := strings.Cut(token, ".")
	raw, _ := base64.RawURLEncoding.DecodeString(header)
	raw = append([]byte(`{"alg":"groth16",`), raw[1:]...)
	duplicate := base64.RawURLEncoding.EncodeToString(raw) + token[len(header):]
	for _, bad := range []string{duplicate, token + " ", strings.Repeat("a", MaxCompactBytes+1), "e30.e30.e30"} {
		if _, e := parseCompact(bad, sdkRequest(t, r), p.profiles["privado"], time.Now().Unix()); e == nil {
			t.Fatal("malformed compact accepted")
		}
	}
	for _, typ := range []string{"application/iden3-zkp-json", "application/iden3comm-plain-json"} {
		parts := compactParts(t, token)
		parts[1]["typ"] = typ
		if _, e := parseCompact(marshalCompact(t, parts), sdkRequest(t, r), p.profiles["privado"], time.Now().Unix()); e != nil {
			t.Fatal("known inner media label rejected", e)
		}
	}
}

func TestRoleSignalsOnlyRestrictLookupsAndPreserveOriginalAge(t *testing.T) {
	p := fixtureProvider(t, nil)
	r := fixtureRequest(t, p, "role")
	_, holder := fixtureDID(t, "polygon:mumbai", 13)
	parts := compactParts(t, unprovedCompact(t, r, holder))
	issuer, _ := fixtureDID(t, "polygon:mumbai", 12)
	user, _ := fixtureDID(t, "polygon:mumbai", 13)
	signals := []string{"0", user.BigInt().String(), "100", "1", issuer.BigInt().String(), "1", "200", strconv.FormatInt(r.Context.CreatedAt.Unix()-10, 10), "0", "0", "0", "0", "1", "7"}
	for len(signals) < 77 {
		signals = append(signals, "0")
	}
	proof := parts[2]["proof"]
	parts[1]["body"].(map[string]any)["scope"] = []any{map[string]any{"id": 1, "circuitId": "credentialAtomicQuerySigV2", "proof": proof, "pub_signals": signals}}
	parsed, err := parseCompact(marshalCompact(t, parts), sdkRequest(t, r), p.profiles["role"], time.Now().Unix())
	if err != nil {
		t.Fatal("bounded signal primitive", err)
	}
	if len(parsed.roles) != 2 || parsed.roles[stateKey{"polygon:mumbai", issuer.BigInt().String(), "100"}] || !parsed.roles[stateKey{"polygon:mumbai", issuer.BigInt().String(), "200"}] || parsed.claimsAsOf != r.Context.CreatedAt.Unix()-10 {
		t.Fatal("issuer roles or original proof age lost")
	}
	signals[6] = "100"
	parsed, err = parseCompact(marshalCompact(t, parts), sdkRequest(t, r), p.profiles["role"], time.Now().Unix())
	if err != nil || len(parsed.roles) != 1 || !parsed.roles[stateKey{"polygon:mumbai", issuer.BigInt().String(), "100"}] {
		t.Fatal("role-union currentness bypass")
	}
	for _, at := range []int64{r.Context.CreatedAt.Unix() - 31, time.Now().Unix() + 31, time.Now().Unix() - 301} {
		signals[7] = strconv.FormatInt(at, 10)
		if _, e := parseCompact(marshalCompact(t, parts), sdkRequest(t, r), p.profiles["role"], time.Now().Unix()); e == nil {
			t.Fatal("stale or future role timestamp")
		}
	}
}
