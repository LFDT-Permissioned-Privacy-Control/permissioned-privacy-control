package accesslog

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"strings"
	"time"

	"privacy-proxy/internal/strictjson"
)

type Key struct {
	ID    string
	Bytes []byte
}
type Keys struct {
	Active   Key
	Previous *Key
}
type cursorRing struct {
	active string
	keys   map[string]cipher.AEAD
}
type cursorState struct {
	Version                                                                      int `json:"v"`
	Actor, Profile, ProfileDigest, Bundle, Organization, Query, PopulationDigest string
	Cut                                                                          Cut
	Last                                                                         Position
	Expires                                                                      int64
}

func keyID(v string) bool {
	if len(v) < 1 || len(v) > 64 {
		return false
	}
	for _, c := range v {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-') {
			return false
		}
	}
	return true
}
func newCursor(keys Keys) (*cursorRing, error) {
	r := &cursorRing{active: keys.Active.ID, keys: map[string]cipher.AEAD{}}
	all := []Key{keys.Active}
	if keys.Previous != nil {
		all = append(all, *keys.Previous)
	}
	for _, k := range all {
		if !keyID(k.ID) || len(k.Bytes) != 32 || bytes.Equal(k.Bytes, make([]byte, 32)) || r.keys[k.ID] != nil {
			return nil, ErrInvalid
		}
		// A dedicated subkey and authenticated token domain prevent cross-use with
		// disclosure cursors even though the deployment supplies the same root ring.
		mac := hmac.New(sha256.New, k.Bytes)
		mac.Write([]byte("ops-access-log-cursor-key/v1"))
		block, e := aes.NewCipher(mac.Sum(nil))
		if e != nil {
			return nil, ErrInvalid
		}
		ae, e := cipher.NewGCM(block)
		if e != nil {
			return nil, ErrInvalid
		}
		r.keys[k.ID] = ae
	}
	return r, nil
}
func cursorAAD(id string) []byte { return []byte("ops-access-log-cursor/al1/" + id) }
func (r *cursorRing) seal(p cursorState) (string, error) {
	raw, e := json.Marshal(p)
	if e != nil || len(raw) > 4096 {
		return "", ErrUnavailable
	}
	a := r.keys[r.active]
	nonce := make([]byte, a.NonceSize())
	if _, e = rand.Read(nonce); e != nil {
		return "", ErrUnavailable
	}
	return "al1." + r.active + "." + base64.RawURLEncoding.EncodeToString(a.Seal(nonce, nonce, raw, cursorAAD(r.active))), nil
}
func (r *cursorRing) open(raw string, expected cursorState, now time.Time) (cursorState, error) {
	var p cursorState
	if len(raw) > 8192 {
		return p, ErrInvalid
	}
	parts := strings.Split(raw, ".")
	if len(parts) != 3 || parts[0] != "al1" {
		return p, ErrInvalid
	}
	a := r.keys[parts[1]]
	if a == nil {
		return p, ErrInvalid
	}
	sealed, e := base64.RawURLEncoding.DecodeString(parts[2])
	if e != nil || base64.RawURLEncoding.EncodeToString(sealed) != parts[2] || len(sealed) < a.NonceSize()+a.Overhead() {
		return p, ErrInvalid
	}
	plain, e := a.Open(nil, sealed[:a.NonceSize()], sealed[a.NonceSize():], cursorAAD(parts[1]))
	if e != nil || len(plain) > 4096 {
		return p, ErrInvalid
	}
	d := json.NewDecoder(bytes.NewReader(plain))
	d.UseNumber()
	v, e := strictjson.ReadValue(d, 0, 10)
	if e != nil {
		return p, ErrInvalid
	}
	if _, e = d.Token(); e != io.EOF {
		return p, ErrInvalid
	}
	if strictjson.ExactDecode(v, &p) != nil || p.Version != 1 {
		return p, ErrInvalid
	}
	if p.Expires <= now.Unix() {
		return p, ErrExpired
	}
	if p.Expires > now.Add(5*time.Minute).Unix() {
		return p, ErrInvalid
	}
	if p.Actor != expected.Actor || p.Profile != expected.Profile || p.ProfileDigest != expected.ProfileDigest || p.Bundle != expected.Bundle || p.Organization != expected.Organization || p.Query != expected.Query || p.PopulationDigest != expected.PopulationDigest {
		return p, ErrCursor
	}
	return p, nil
}
