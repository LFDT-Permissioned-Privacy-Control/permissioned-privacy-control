package v2server

import (
	"encoding/base64"
	"os"

	"privacy-proxy/internal/brokerpolicy"
	b "privacy-proxy/internal/identitybroker"
)

func secret(ref string) (string, error) {
	if !envName.MatchString(ref) {
		return "", ErrInvalid
	}
	value, ok := os.LookupEnv(ref)
	if !ok || value == "" {
		return "", ErrInvalid
	}
	return value, nil
}
func binarySecret(ref string, size int) ([]byte, error) {
	raw, e := secret(ref)
	if e != nil {
		return nil, e
	}
	value, e := base64.RawURLEncoding.Strict().DecodeString(raw)
	if e != nil || len(value) != size || base64.RawURLEncoding.EncodeToString(value) != raw {
		return nil, ErrInvalid
	}
	return value, nil
}
func keyBindings(refs []brokerpolicy.KeyRef) ([]b.SecretBinding, error) {
	values := make([]b.SecretBinding, 0, len(refs))
	for _, ref := range refs {
		value, e := binarySecret(ref.FromEnv, 32)
		if e != nil {
			return nil, e
		}
		values = append(values, b.SecretBinding{FromEnv: ref.FromEnv, Value: value})
	}
	return values, nil
}
