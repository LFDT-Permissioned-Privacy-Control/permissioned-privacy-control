package walletproof

import (
	"errors"
	"strings"
	"time"
	"unicode/utf8"
)

const MaxMessageBytes = 4096

type MessageFields struct {
	Origin, Namespace, Actor, Address, Nonce string
	IssuedAt, ExpiresAt                      time.Time
}

// Message formats already canonical identifiers. Callers validate their typed
// identity/network/address values; this layer also prevents delimiter injection.
func Message(f MessageFields) (string, error) {
	for _, s := range []string{f.Origin, f.Namespace, f.Actor, f.Address, f.Nonce} {
		if s == "" || len(s) > 2048 || !utf8.ValidString(s) {
			return "", errors.New("invalid wallet message")
		}
		for _, r := range s {
			if r < 0x20 || r == 0x7f {
				return "", errors.New("invalid wallet message")
			}
		}
	}
	if f.IssuedAt.Unix() < 0 || f.ExpiresAt.Unix() > 253402300799 || f.IssuedAt.Nanosecond() != 0 || f.ExpiresAt.Nanosecond() != 0 || !f.ExpiresAt.After(f.IssuedAt) || f.ExpiresAt.Sub(f.IssuedAt) > 5*time.Minute {
		return "", errors.New("invalid wallet message time")
	}
	message := strings.Join([]string{"OPS wallet link v1", "Service: " + f.Origin, "Network: " + f.Namespace, "Actor: " + f.Actor, "Address: " + f.Address, "Nonce: " + f.Nonce, "IssuedAt: " + f.IssuedAt.UTC().Format(time.RFC3339), "ExpiresAt: " + f.ExpiresAt.UTC().Format(time.RFC3339), "", "I authorize this wallet to be linked to this OPS identity. This does not authorize a transaction."}, "\n")
	if len(message) > MaxMessageBytes {
		return "", errors.New("invalid wallet message size")
	}
	return message, nil
}
