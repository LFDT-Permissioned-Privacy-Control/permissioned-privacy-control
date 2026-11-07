package identity

import (
	"encoding/base64"
	"strings"
)

// ValidActorID checks the canonical identifier syntax, not the holder's
// identity or authority. Those are established by VerifyAccess and its catalog.
func ValidActorID(actor string) bool {
	const prefix = "ops:p1:"
	if len(actor) != len(prefix)+43 || !strings.HasPrefix(actor, prefix) {
		return false
	}
	encoded := actor[len(prefix):]
	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	return err == nil && len(raw) == 32 && base64.RawURLEncoding.EncodeToString(raw) == encoded
}
