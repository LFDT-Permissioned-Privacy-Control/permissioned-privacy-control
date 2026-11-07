package disclosurecase

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"io"
	"strings"
	"time"

	"privacy-proxy/internal/identity"
	"privacy-proxy/internal/strictjson"
)

type CursorKey struct {
	ID  string
	Key []byte
}
type CursorKeys struct {
	Active   CursorKey
	Previous *CursorKey
}
type cursorRing struct {
	active string
	keys   map[string]cipher.AEAD
}
type cursorPayload struct {
	Version      int    `json:"v"`
	Epoch        string `json:"storeEpoch"`
	Actor        string `json:"actorId"`
	Bundle       string `json:"bundleDigest"`
	Disclosure   string `json:"disclosureDigest"`
	Role         string `json:"role"`
	Organization string `json:"organizationId"`
	Query        string `json:"queryDigest"`
	LastTime     int64  `json:"lastTimeMicros"`
	LastID       string `json:"lastId"`
	Expires      int64  `json:"exp"`
}

func newCursorRing(source CursorKeys) (*cursorRing, error) {
	r := &cursorRing{active: source.Active.ID, keys: map[string]cipher.AEAD{}}
	keys := []CursorKey{source.Active}
	if source.Previous != nil {
		keys = append(keys, *source.Previous)
	}
	for _, key := range keys {
		if !cursorKeyID(key.ID) || len(key.Key) != 32 || r.keys[key.ID] != nil {
			return nil, ErrInvalid
		}
		block, err := aes.NewCipher(key.Key)
		if err != nil {
			return nil, ErrInvalid
		}
		aead, err := cipher.NewGCM(block)
		if err != nil {
			return nil, ErrInvalid
		}
		r.keys[key.ID] = aead
	}
	return r, nil
}
func cursorKeyID(s string) bool {
	if len(s) == 0 || len(s) > 64 {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-') {
			return false
		}
	}
	return true
}
func cursorAAD(id string) []byte {
	var out bytes.Buffer
	for _, s := range []string{"ops-disclosure-cursor", "dc1", id} {
		_ = binary.Write(&out, binary.BigEndian, uint32(len(s)))
		out.WriteString(s)
	}
	return out.Bytes()
}
func (r *cursorRing) seal(p cursorPayload) (string, error) {
	raw, err := json.Marshal(p)
	if err != nil || len(raw) > 2048 {
		return "", ErrInvalid
	}
	a := r.keys[r.active]
	nonce := make([]byte, a.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", ErrUnavailable
	}
	sealed := a.Seal(nonce, nonce, raw, cursorAAD(r.active))
	return "dc1." + r.active + "." + base64.RawURLEncoding.EncodeToString(sealed), nil
}
func (r *cursorRing) open(raw string, expected cursorPayload, now time.Time) (*Position, error) {
	if len(raw) > 4096 {
		return nil, ErrInvalid
	}
	parts := strings.Split(raw, ".")
	if len(parts) != 3 || parts[0] != "dc1" {
		return nil, ErrInvalid
	}
	a := r.keys[parts[1]]
	if a == nil {
		return nil, ErrInvalid
	}
	sealed, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || base64.RawURLEncoding.EncodeToString(sealed) != parts[2] || len(sealed) < a.NonceSize()+a.Overhead() {
		return nil, ErrInvalid
	}
	plaintext, err := a.Open(nil, sealed[:a.NonceSize()], sealed[a.NonceSize():], cursorAAD(parts[1]))
	if err != nil || len(plaintext) > 2048 {
		return nil, ErrInvalid
	}
	d := json.NewDecoder(bytes.NewReader(plaintext))
	d.UseNumber()
	value, err := strictjson.ReadValue(d, 0, 8)
	if err != nil {
		return nil, ErrInvalid
	}
	if _, err := d.Token(); err != io.EOF {
		return nil, ErrInvalid
	}
	var p cursorPayload
	if strictjson.ExactDecode(value, &p) != nil {
		return nil, ErrInvalid
	}
	if p.Version != 1 || !identity.ValidActorID(p.Actor) || !ValidUUID(p.LastID) || p.LastTime < 0 || p.Expires <= now.Unix() {
		return nil, ErrInvalid
	}
	if p.Epoch != expected.Epoch || p.Actor != expected.Actor || p.Bundle != expected.Bundle || p.Disclosure != expected.Disclosure || p.Role != expected.Role || p.Organization != expected.Organization || p.Query != expected.Query {
		return nil, ErrConflict
	}
	return &Position{time.UnixMicro(p.LastTime), p.LastID}, nil
}
