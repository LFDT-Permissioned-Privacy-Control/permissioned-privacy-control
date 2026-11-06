package policycore

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

// CanonicalDigest is the lowercase hex sha256 of a policy's canonical JSON.
// It identifies the complete approved document, even for a ForGroup view.
// This is the normalized model's digest, not a hash of submitted source bytes.
func CanonicalDigest(p *Policy) (string, error) {
	encoded, err := json.Marshal(p)
	if err != nil {
		return "", fmt.Errorf("policydsl: could not canonicalise the policy: %w", err)
	}
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:]), nil
}

// ABIDigest is the lowercase hex sha256 of a registered ABI's exact text.
func ABIDigest(abiText string) string {
	sum := sha256.Sum256([]byte(abiText))
	return hex.EncodeToString(sum[:])
}
