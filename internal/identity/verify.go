package identity

import (
	"encoding/base64"
	"encoding/json"
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"privacy-proxy/internal/strictjson"
)

type Clock func() time.Time
type Verifier struct {
	catalog *Catalog
	clock   Clock
}

func NewVerifier(c *Catalog, clock Clock) (*Verifier, error) {
	if c == nil || !c.limits.Valid() || clock == nil {
		return nil, invalid("options", "verifier")
	}
	return &Verifier{c, clock}, nil
}

func decodeSegment(segment string, limit int) ([]byte, error) {
	if segment == "" || len(segment) > base64.RawURLEncoding.EncodedLen(limit) || base64.RawURLEncoding.DecodedLen(len(segment)) > limit {
		return nil, invalid("limit", "segment")
	}
	for _, c := range segment {
		if !((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_' || c == '-') {
			return nil, invalid("base64", "segment")
		}
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(segment)
	if err != nil || base64.RawURLEncoding.EncodeToString(raw) != segment {
		return nil, invalid("base64", "segment")
	}
	return raw, nil
}

// VerifyAccess never uses token data to select an algorithm, remote endpoint or
// permission source. Unverified issuer/kid are exact immutable key lookups.
func (v *Verifier) VerifyAccess(compact string) (*RequestPrincipal, error) {
	l := v.catalog.limits
	if len(compact) > l.MaxCompactAccessBytes || strings.Count(compact, ".") != 2 {
		return nil, invalid("format", "token")
	}
	headerPart, rest, _ := strings.Cut(compact, ".")
	payloadPart, signaturePart, _ := strings.Cut(rest, ".")
	if len(signaturePart) != base64.RawURLEncoding.EncodedLen(64) {
		return nil, invalid("signature", "token")
	}
	headerRaw, err := decodeSegment(headerPart, l.MaxDecodedHeaderBytes)
	if err != nil {
		return nil, err
	}
	payloadRaw, err := decodeSegment(payloadPart, l.MaxDecodedPayloadBytes)
	if err != nil {
		return nil, err
	}
	signature, err := decodeSegment(signaturePart, 64)
	if err != nil || len(signature) != 64 {
		return nil, invalid("signature", "token")
	}
	headerValue, err := jsonValue(headerRaw, l.MaxTokenJSONDepth)
	if err != nil {
		return nil, err
	}
	var header accessHeader
	if err := strictjson.ExactDecode(headerValue, &header); err != nil || header.Alg != "EdDSA" || header.Typ != "ops-access+jwt" || !ascii(header.Kid, l.MaxKidBytes) {
		return nil, invalid("header", "token")
	}
	payloadValue, err := jsonValue(payloadRaw, l.MaxTokenJSONDepth)
	if err != nil {
		return nil, err
	}
	object, ok := payloadValue.(map[string]any)
	if !ok {
		return nil, invalid("claims", "token")
	}
	if err := claimBounds(object, l); err != nil {
		return nil, err
	}
	var claims accessClaims
	if err := strictjson.ExactDecode(object, &claims); err != nil {
		return nil, invalid("claims", "token")
	}
	trust, ok := v.catalog.issuers[claims.Issuer]
	if !ok || claims.Audience != trust.audience || !trust.profiles[claims.SourceProfile] {
		return nil, invalid("trust", "token")
	}
	key, ok := trust.keys[header.Kid]
	if !ok {
		return nil, invalid("key", "token")
	}
	profile, ok := v.catalog.profiles[claims.SourceProfile]
	if !ok || claims.SourceProfileDigest != v.catalog.profileDigests[claims.SourceProfile] || claims.PrincipalKind != expectedKind(profile) {
		return nil, invalid("profile", "token")
	}
	actor, err := claimIdentity(claims, profile, l)
	if err != nil {
		return nil, err
	}
	if claims.Subject != actor {
		return nil, invalid("subject", "token")
	}
	seen := map[Fact]bool{}
	for _, fact := range claims.Facts {
		if !validFact(profile, fact, l) || seen[fact] {
			return nil, invalid("facts", "token")
		}
		seen[fact] = true
	}
	if profile.Kind == PrivadoIdentity && len(claims.Facts) != 0 {
		return nil, invalid("facts", "token")
	}
	if err := claimTimes(claims, v.clock().Unix()); err != nil {
		return nil, err
	}
	if err := jwt.SigningMethodEdDSA.Verify(headerPart+"."+payloadPart, signature, key); err != nil {
		return nil, invalid("signature", "token")
	}
	return &RequestPrincipal{actor: actor, kind: claims.PrincipalKind, expires: time.Unix(claims.Expires, 0), facts: claims.Facts, profile: claims.SourceProfile, catalog: v.catalog}, nil
}

func claimBounds(object map[string]any, l Limits) error {
	facts, ok := object["facts"].([]any)
	if !ok || len(facts) > l.MaxFacts {
		return invalid("limit", "facts")
	}
	for _, item := range facts {
		fact, ok := item.(map[string]any)
		if !ok {
			return invalid("facts", "token")
		}
		value, ok := fact["value"].(string)
		if !ok || len(value) > l.MaxFactValueBytes {
			return invalid("limit", "facts.value")
		}
	}
	for field, max := range map[string]int{"source_subject": l.MaxSourceSubjectBytes, "source_profile": l.MaxProfileIDBytes, "jti": 128, "iss": l.MaxURLBytes, "aud": 256, "identity_authority": l.MaxURLBytes} {
		s, ok := object[field].(string)
		if !ok || !text(s, max) {
			return invalid("limit", "claims")
		}
	}
	if s, _ := object["jti"].(string); !ascii(s, 128) {
		return invalid("claims", "jti")
	}
	for _, field := range []string{"iat", "nbf", "exp", "source_verified_at", "claims_as_of", "source_not_after"} {
		value, exists := object[field]
		if !exists && field == "source_not_after" {
			continue
		}
		number, ok := value.(json.Number)
		if !ok || !decimal(string(number)) {
			return invalid("time", "claims")
		}
		if _, err := strconv.ParseInt(string(number), 10, 64); err != nil {
			return invalid("time", "claims")
		}
	}
	return nil
}

func claimIdentity(c accessClaims, p Profile, l Limits) (string, error) {
	if p.Kind == AzureHuman || p.Kind == AzureService {
		if c.SourceNotAfter == nil {
			return "", invalid("source-identity", "token")
		}
	}
	if p.Kind == PrivadoIdentity && c.SourceNotAfter != nil {
		return "", invalid("source-identity", "token")
	}
	return sourceActorID(SourceIdentity{ProfileID: c.SourceProfile, Kind: c.PrincipalKind, Authority: c.IdentityAuthority, Subject: c.SourceSubject, Tenant: c.SourceTenant}, p, l)
}

func claimTimes(c accessClaims, now int64) error {
	if now < 0 || now > math.MaxInt64-300 {
		return invalid("clock", "verifier")
	}
	for _, value := range []int64{c.IssuedAt, c.NotBefore, c.SourceVerifiedAt, c.ClaimsAsOf} {
		if value < 0 || value > now+30 || value > math.MaxInt64-300 {
			return invalid("time", "token")
		}
	}
	if c.NotBefore > c.IssuedAt || c.ClaimsAsOf > c.SourceVerifiedAt || c.SourceVerifiedAt > c.IssuedAt || c.Expires <= now || c.Expires <= c.IssuedAt || c.Expires > c.IssuedAt+300 || c.Expires > c.ClaimsAsOf+300 || (c.SourceNotAfter != nil && c.Expires > *c.SourceNotAfter) {
		return invalid("time", "token")
	}
	return nil
}
