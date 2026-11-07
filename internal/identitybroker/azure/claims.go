// Package azure implements the bounded Microsoft provider adapter. Verified
// evidence is opaque; roles and groups come only from the own-API access token.
package azure

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/google/uuid"
	"privacy-proxy/internal/identity"
	"privacy-proxy/internal/strictjson"
)

const MaxCompactTokenBytes = 32 << 10
const maxProviderUnix = 253402300799 // UTC year9999; bound before SDK time construction.
var knownClaims = map[string]bool{"iss": true, "aud": true, "sub": true, "iat": true, "exp": true, "nbf": true, "oid": true, "tid": true, "azp": true, "ver": true, "idtyp": true, "scp": true, "roles": true, "groups": true, "hasgroups": true, "nonce": true, "auth_time": true, "_claim_names": true, "_claim_sources": true}

func jsonObject(raw []byte, depth int) (map[string]any, error) {
	if !utf8.Valid(raw) {
		return nil, ErrEvidence
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	value, err := strictjson.ReadValue(d, 0, depth)
	if err != nil {
		return nil, ErrEvidence
	}
	if _, err := d.Token(); err != io.EOF {
		return nil, ErrEvidence
	}
	object, ok := value.(map[string]any)
	if !ok {
		return nil, ErrEvidence
	}
	return object, nil
}
func jwtObject(compact string) (map[string]any, error) {
	if len(compact) == 0 || len(compact) > MaxCompactTokenBytes || strings.Count(compact, ".") != 2 {
		return nil, ErrEvidence
	}
	parts := strings.Split(compact, ".")
	limits := []int{4 << 10, 24 << 10, 24 << 10}
	decoded := make([][]byte, 3)
	for i, part := range parts {
		if part == "" || len(part) > base64.RawURLEncoding.EncodedLen(limits[i]) {
			return nil, ErrEvidence
		}
		raw, err := base64.RawURLEncoding.Strict().DecodeString(part)
		if err != nil || len(raw) > limits[i] || base64.RawURLEncoding.EncodeToString(raw) != part {
			return nil, ErrEvidence
		}
		decoded[i] = raw
	}
	header, err := jsonObject(decoded[0], 8)
	if err != nil {
		return nil, err
	}
	for key := range header {
		lower := strings.ToLower(key)
		if (lower == "alg" || lower == "kid" || lower == "typ") && key != lower {
			return nil, ErrEvidence
		}
	}
	if header["alg"] != "RS256" {
		return nil, ErrEvidence
	}
	kid, ok := header["kid"].(string)
	if !ok || !boundedText(kid, 128) {
		return nil, ErrEvidence
	}
	claims, err := jsonObject(decoded[1], 8)
	if err != nil {
		return nil, err
	}
	for key := range claims {
		lower := strings.ToLower(key)
		if knownClaims[lower] && key != lower {
			return nil, ErrEvidence
		}
	}
	return claims, nil
}
func boundedText(s string, max int) bool {
	if s == "" || len(s) > max || !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}
func integer(claims map[string]any, key string, required bool) (int64, bool, error) {
	value, exists := claims[key]
	if !exists && !required {
		return 0, false, nil
	}
	number, ok := value.(json.Number)
	if !ok || len(number) > 12 {
		return 0, false, ErrEvidence
	}
	v, err := strconv.ParseInt(string(number), 10, 64)
	if err != nil || v < 0 || v > maxProviderUnix || strconv.FormatInt(v, 10) != string(number) {
		return 0, false, ErrEvidence
	}
	return v, true, nil
}
func times(claims map[string]any, now int64) (int64, int64, error) {
	if now < 0 || now > maxProviderUnix-300 {
		return 0, 0, ErrEvidence
	}
	iat, _, err := integer(claims, "iat", true)
	if err != nil {
		return 0, 0, err
	}
	exp, _, err := integer(claims, "exp", true)
	if err != nil {
		return 0, 0, err
	}
	if iat > now+30 || exp <= now || iat >= exp {
		return 0, 0, ErrEvidence
	}
	if nbf, present, err := integer(claims, "nbf", false); err != nil || present && (nbf > now+30 || nbf >= exp) {
		return 0, 0, ErrEvidence
	}
	return iat, exp, nil
}
func canonicalUUID(value any) (string, error) {
	s, ok := value.(string)
	if !ok || len(s) > 64 {
		return "", ErrEvidence
	}
	id, err := uuid.Parse(s)
	if err != nil || id == uuid.Nil {
		return "", ErrEvidence
	}
	return id.String(), nil
}
func selectedFacts(claims map[string]any, profile identity.Profile) ([]identity.Fact, error) {
	key, kind := "roles", "azure.role"
	if profile.FactSource == "groupIds" {
		key, kind = "groups", "azure.group"
		if _, exists := claims["hasgroups"]; exists {
			return nil, ErrEvidence
		}
		if names, ok := claims["_claim_names"]; ok {
			object, ok := names.(map[string]any)
			if !ok {
				return nil, ErrEvidence
			}
			if _, present := object["groups"]; present {
				return nil, ErrEvidence
			}
		}
	}
	value, present := claims[key]
	if !present {
		return []identity.Fact{}, nil
	}
	values, ok := value.([]any)
	if !ok || len(values) > identity.DefaultLimits().MaxFacts {
		return nil, ErrEvidence
	}
	out := make([]identity.Fact, 0, len(values))
	seen := map[string]bool{}
	for _, value := range values {
		s, ok := value.(string)
		if !ok || !boundedText(s, identity.DefaultLimits().MaxFactValueBytes) {
			return nil, ErrEvidence
		}
		if kind == "azure.group" {
			var err error
			s, err = canonicalUUID(s)
			if err != nil {
				return nil, err
			}
		}
		if seen[s] {
			return nil, ErrEvidence
		}
		seen[s] = true
		out = append(out, identity.Fact{Kind: kind, Value: s})
	}
	return out, nil
}
