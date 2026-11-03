package db

import (
	"encoding/hex"
	"errors"
	"strings"
)

// ErrNodeSubmissionConflict: a transaction or created address is already
// bound to another principal or organisation.
var ErrNodeSubmissionConflict = errors.New("transaction is already bound to a different submission")

func validSubmissionHex(s string, size int) bool {
	if len(s) != 2+2*size || !strings.HasPrefix(s, "0x") || strings.ToLower(s) != s {
		return false
	}
	_, err := hex.DecodeString(s[2:])
	return err == nil
}
