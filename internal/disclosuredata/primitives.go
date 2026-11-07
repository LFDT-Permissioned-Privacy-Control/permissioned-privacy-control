package disclosuredata

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	p "privacy-proxy/internal/disclosurepolicy"
	"privacy-proxy/internal/identity"
)

func framed(parts ...[]byte) []byte {
	var out []byte
	for _, part := range parts {
		var n [4]byte
		binary.BigEndian.PutUint32(n[:], uint32(len(part)))
		out = append(out, n[:]...)
		out = append(out, part...)
	}
	return out
}
func hashParts(domain string, parts ...[]byte) Digest {
	all := [][]byte{[]byte(domain)}
	all = append(all, parts...)
	h := sha256.Sum256(framed(all...))
	return Digest("sha256:" + hex.EncodeToString(h[:]))
}
func digestValid(d Digest) bool {
	if len(d) != 71 || !strings.HasPrefix(string(d), "sha256:") {
		return false
	}
	b, e := hex.DecodeString(string(d)[7:])
	return e == nil && hex.EncodeToString(b) == string(d)[7:]
}
func digestBytes(d Digest) ([]byte, error) {
	if !digestValid(d) {
		return nil, ErrInvalid
	}
	b, _ := hex.DecodeString(string(d)[7:])
	return b, nil
}
func uuidValid(s string) bool {
	u, e := uuid.Parse(s)
	return e == nil && u != uuid.Nil && u.String() == s
}
func keyID(s string) bool {
	if len(s) < 1 || len(s) > 64 {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-') {
			return false
		}
	}
	return true
}
func countValid(s Count) bool {
	if len(s) == 0 || len(s) > 20 || len(s) > 1 && s[0] == '0' {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	_, e := strconv.ParseUint(string(s), 10, 64)
	return e == nil
}
func countValue(s Count) uint64 { v, _ := strconv.ParseUint(string(s), 10, 64); return v }
func amountValid(s Amount) bool {
	if len(s) == 0 || len(s) > 78 || len(s) > 1 && s[0] == '0' {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	v, ok := new(big.Int).SetString(string(s), 10)
	return ok && v.BitLen() <= 256
}
func text(s string, max int) bool { return p.Text(s, max) }
func utc(t time.Time) bool {
	return !t.IsZero() && t.Location() == time.UTC && t.Unix() >= 0 && t.Unix() <= p.MaxUnixSeconds && t.Nanosecond()%1000 == 0
}
func address(raw string) ([20]byte, error) {
	var out [20]byte
	if len(raw) != 42 || !strings.HasPrefix(raw, "0x") {
		return out, ErrInvalid
	}
	b, e := hex.DecodeString(raw[2:])
	if e != nil {
		return out, ErrInvalid
	}
	copy(out[:], b)
	return out, nil
}
func addressString(a [20]byte) string { return "0x" + hex.EncodeToString(a[:]) }
func hashString(a [32]byte) string    { return "0x" + hex.EncodeToString(a[:]) }
func actor(s string) bool             { return identity.ValidActorID(s) }
func cloneScope(s p.Scope) p.Scope {
	s.TargetActors = append([]string{}, s.TargetActors...)
	s.Resources = append([]p.Resource{}, s.Resources...)
	s.Addresses.Values = append([]string{}, s.Addresses.Values...)
	return s
}
func jsonBytes(v any) ([]byte, error) {
	b, e := json.Marshal(v)
	if e != nil {
		return nil, ErrInvalid
	}
	return b, nil
}
func validUTF8(s string) bool { return utf8.ValidString(s) }

func hasNull(v any) bool {
	if v == nil {
		return true
	}
	switch x := v.(type) {
	case map[string]any:
		for _, v := range x {
			if hasNull(v) {
				return true
			}
		}
	case []any:
		for _, v := range x {
			if hasNull(v) {
				return true
			}
		}
	}
	return false
}

func ValidCount(v Count) bool { return countValid(v) }
