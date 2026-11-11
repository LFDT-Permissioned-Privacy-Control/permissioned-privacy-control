package identitybroker

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"math"
	"strconv"
	"strings"

	"github.com/golang-jwt/jwt/v5"
	"privacy-proxy/internal/brokerpolicy"
	"privacy-proxy/internal/identity"
	"privacy-proxy/internal/strictjson"
)

type SecretBinding struct {
	FromEnv string
	Value   []byte
}
type keyring struct {
	active string
	mac    map[string][]byte
	aes    map[string]cipher.AEAD
	// Private equality checks at startup; no raw AES value or getter is retained.
	fingerprints map[string][32]byte
}

func newKeyrings(source brokerpolicy.Source, renewal, encryption []SecretBinding, signing ed25519.PrivateKey) (*keyring, *keyring, error) {
	return newCommonKeyrings(brokerpolicy.CommonSettings{RenewalKeys: source.RenewalKeys, EncryptionKeys: source.EncryptionKeys}, renewal, encryption, signing)
}
func newCommonKeyrings(source brokerpolicy.CommonSettings, renewal, encryption []SecretBinding, signing ed25519.PrivateKey) (*keyring, *keyring, error) {
	if len(signing) != ed25519.PrivateKeySize {
		return nil, nil, ErrInvalid
	}
	macKeys, err := bindKeys(source.RenewalKeys, renewal, false)
	if err != nil {
		return nil, nil, err
	}
	aesKeys, err := bindKeys(source.EncryptionKeys, encryption, true)
	if err != nil {
		return nil, nil, err
	}
	for _, a := range macKeys {
		for _, b := range aesKeys {
			if bytes.Equal(a, b) {
				return nil, nil, ErrInvalid
			}
		}
	}
	for _, keys := range []map[string][]byte{macKeys, aesKeys} {
		for _, key := range keys {
			if bytes.Equal(key, signing) || bytes.Equal(key, signing.Seed()) {
				return nil, nil, ErrInvalid
			}
		}
	}
	macRing, aesRing := &keyring{mac: macKeys}, &keyring{aes: map[string]cipher.AEAD{}, fingerprints: map[string][32]byte{}}
	for _, ref := range source.RenewalKeys {
		if ref.Active {
			macRing.active = ref.ID
		}
	}
	for _, ref := range source.EncryptionKeys {
		if ref.Active {
			aesRing.active = ref.ID
		}
		block, err := aes.NewCipher(aesKeys[ref.ID])
		if err != nil {
			return nil, nil, ErrInvalid
		}
		aead, err := cipher.NewGCM(block)
		if err != nil {
			return nil, nil, ErrInvalid
		}
		aesRing.aes[ref.ID] = aead
		aesRing.fingerprints[ref.ID] = sha256.Sum256(aesKeys[ref.ID])
	}
	return macRing, aesRing, nil
}
func bindKeys(refs []brokerpolicy.KeyRef, bindings []SecretBinding, encryption bool) (map[string][]byte, error) {
	if len(refs) != len(bindings) {
		return nil, ErrInvalid
	}
	values := map[string][]byte{}
	for _, binding := range bindings {
		if _, exists := values[binding.FromEnv]; exists {
			return nil, ErrInvalid
		}
		if encryption && len(binding.Value) != 32 || !encryption && (len(binding.Value) < 32 || len(binding.Value) > 128) || bytes.Equal(binding.Value, make([]byte, len(binding.Value))) {
			return nil, ErrInvalid
		}
		for _, previous := range values {
			if bytes.Equal(previous, binding.Value) {
				return nil, ErrInvalid
			}
		}
		values[binding.FromEnv] = bytes.Clone(binding.Value)
	}
	out := map[string][]byte{}
	for _, ref := range refs {
		key, ok := values[ref.FromEnv]
		if !ok {
			return nil, ErrInvalid
		}
		out[ref.ID] = key
	}
	return out, nil
}
func randomToken() (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", ErrUnavailable
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}
func randomTokenShape(raw string) bool {
	if len(raw) != 43 {
		return false
	}
	b, err := base64.RawURLEncoding.Strict().DecodeString(raw)
	return err == nil && len(b) == 32 && base64.RawURLEncoding.EncodeToString(b) == raw
}
func tokenHash(raw string) Digest { return Digest(sha256.Sum256([]byte(raw))) }
func (k *keyring) seal(keyID string, raw, aad []byte) ([]byte, error) {
	aead := k.aes[keyID]
	if aead == nil {
		return nil, ErrInvalid
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, ErrUnavailable
	}
	return aead.Seal(nonce, nonce, raw, aad), nil
}
func (k *keyring) open(keyID string, raw, aad []byte, max int) ([]byte, error) {
	aead := k.aes[keyID]
	if aead == nil || len(raw) < aead.NonceSize()+aead.Overhead() || len(raw) > max {
		return nil, ErrUnauthorized
	}
	out, err := aead.Open(nil, raw[:aead.NonceSize()], raw[aead.NonceSize():], aad)
	if err != nil {
		return nil, ErrUnauthorized
	}
	return out, nil
}
func pendingAAD(p Pending) []byte {
	return Pack("ops.broker.pending/v1", p.Scope.Namespace[:], []byte(p.Scope.State.RecoveryEpoch), []byte(p.ID), p.StateHash[:], []byte(p.ProfileID), []byte(p.ProfileDigest), p.Recipient[:], []byte(p.EncryptionKeyID))
}
func familyAAD(f Family) []byte {
	authTime := []byte{}
	if f.OriginalAuthTime != nil {
		authTime = []byte(strconv.FormatInt(*f.OriginalAuthTime, 10))
	}
	return Pack("ops.broker.family/v1", f.Scope.Namespace[:], []byte(f.Scope.State.RecoveryEpoch), []byte(f.ID), []byte(f.Actor), []byte(f.Authority), []byte(f.Tenant), []byte(f.Subject), []byte(f.Kind), []byte(f.ProfileID), []byte(f.ProfileDigest), []byte(strconv.FormatInt(f.Generation, 10)), f.CurrentHandleHash[:], []byte(f.EncryptionKeyID), f.OIDCSubjectHash[:], f.NonceHash[:], authTime, f.Recipient[:])
}

type pendingSecrets struct {
	Nonce        string `json:"nonce"`
	PKCEVerifier string `json:"pkceVerifier"`
}

func decodeClosed(raw []byte, out any, max int) error {
	if len(raw) > max {
		return ErrUnauthorized
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	value, err := strictjson.ReadValue(d, 0, 8)
	if err != nil {
		return ErrUnauthorized
	}
	if _, err := d.Token(); err != io.EOF {
		return ErrUnauthorized
	}
	if strictjson.ExactDecode(value, out) != nil {
		return ErrUnauthorized
	}
	return nil
}

type refreshHeader struct {
	Typ string `json:"typ"`
	Alg string `json:"alg"`
	Kid string `json:"kid"`
}
type refreshClaims struct {
	Issuer        string `json:"iss"`
	Audience      string `json:"aud"`
	FamilyID      string `json:"sid"`
	Actor         string `json:"sub"`
	ProfileID     string `json:"source_profile"`
	ProfileDigest string `json:"source_profile_digest"`
	Generation    int64  `json:"gen"`
	ID            string `json:"jti"`
	IssuedAt      int64  `json:"iat"`
	Expires       int64  `json:"exp"`
	Epoch         string `json:"epoch"`
}

func (k *keyring) mintRefresh(claims refreshClaims) (string, error) {
	header, err := json.Marshal(refreshHeader{"ops-refresh+jwt", "HS256", k.active})
	if err != nil {
		return "", ErrUnavailable
	}
	payload, err := json.Marshal(claims)
	if err != nil || len(payload) > 2048 {
		return "", ErrUnavailable
	}
	encoded := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
	sig, err := jwt.SigningMethodHS256.Sign(encoded, k.mac[k.active])
	if err != nil {
		return "", ErrUnavailable
	}
	return encoded + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}
func segment(raw string, max int) ([]byte, error) {
	if len(raw) == 0 || len(raw) > base64.RawURLEncoding.EncodedLen(max) {
		return nil, ErrUnauthorized
	}
	b, err := base64.RawURLEncoding.Strict().DecodeString(raw)
	if err != nil || len(b) > max || base64.RawURLEncoding.EncodeToString(b) != raw {
		return nil, ErrUnauthorized
	}
	return b, nil
}
func (k *keyring) parseRefresh(raw, issuer, epoch string, now int64) (refreshClaims, error) {
	var claims refreshClaims
	if len(raw) > 4096 || strings.Count(raw, ".") != 2 || now < 0 || now > math.MaxInt64-300 {
		return claims, ErrUnauthorized
	}
	parts := strings.Split(raw, ".")
	headerRaw, err := segment(parts[0], 512)
	if err != nil {
		return claims, err
	}
	payload, err := segment(parts[1], 2048)
	if err != nil {
		return claims, err
	}
	sig, err := segment(parts[2], 32)
	if err != nil || len(sig) != 32 {
		return claims, ErrUnauthorized
	}
	var header refreshHeader
	if decodeClosed(headerRaw, &header, 512) != nil || header.Typ != "ops-refresh+jwt" || header.Alg != "HS256" || k.mac[header.Kid] == nil {
		return claims, ErrUnauthorized
	}
	if jwt.SigningMethodHS256.Verify(parts[0]+"."+parts[1], sig, k.mac[header.Kid]) != nil {
		return claims, ErrUnauthorized
	}
	if decodeClosed(payload, &claims, 2048) != nil || claims.Issuer != issuer || claims.Audience != "ops-renewal" || claims.Epoch != epoch || !ValidUUID(claims.FamilyID) || !identity.ValidActorID(claims.Actor) || !validText(claims.ProfileID, 128) || claims.Generation < 0 || !randomTokenShape(claims.ID) || claims.IssuedAt < 0 || claims.IssuedAt > now+30 || claims.Expires <= now || claims.Expires <= claims.IssuedAt || claims.Expires-claims.IssuedAt > int64(FamilyLifetime.Seconds()) {
		return refreshClaims{}, ErrUnauthorized
	}
	// JSON integers accepted by encoding/json include -0. Require the exact
	// canonical integer spelling used by our own issuer before state access.
	var numbers map[string]json.RawMessage
	if json.Unmarshal(payload, &numbers) != nil {
		return refreshClaims{}, ErrUnauthorized
	}
	for field, value := range map[string]int64{"gen": claims.Generation, "iat": claims.IssuedAt, "exp": claims.Expires} {
		if string(bytes.TrimSpace(numbers[field])) != strconv.FormatInt(value, 10) {
			return refreshClaims{}, ErrUnauthorized
		}
	}
	if _, err := ParseDigest(claims.ProfileDigest); err != nil {
		return refreshClaims{}, ErrUnauthorized
	}
	return claims, nil
}
