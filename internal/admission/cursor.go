package admission

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strings"
	"time"
)

type CursorKey struct {
	ID  string
	Key []byte
}
type CursorKeyring struct {
	Active  CursorKey
	Overlap *CursorKey
}
type cursorRing struct {
	active string
	keys   map[string]cipher.AEAD
}

func newCursorRing(keys CursorKeyring) (*cursorRing, error) {
	if keys.Active.ID == "" && len(keys.Active.Key) == 0 && keys.Overlap == nil {
		return nil, nil
	}
	ring := &cursorRing{active: keys.Active.ID, keys: map[string]cipher.AEAD{}}
	list := []CursorKey{keys.Active}
	if keys.Overlap != nil {
		list = append(list, *keys.Overlap)
	}
	for _, key := range list {
		if !text(key.ID, 32, false) || strings.Contains(key.ID, ".") || len(key.Key) != 32 || bytes.Equal(key.Key, make([]byte, 32)) {
			return nil, ErrInvalid
		}
		if _, ok := ring.keys[key.ID]; ok {
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
		ring.keys[key.ID] = aead
	}
	return ring, nil
}

type pageCursor struct {
	Version                                                              int `json:"v"`
	Purpose, Network, Generation, Coverage, Org, Viewer, Manifest, Query string
	At                                                                   time.Time
	ID                                                                   string
	Expires                                                              int64
}

func (r *cursorRing) seal(c pageCursor) (string, error) {
	if r == nil {
		return "", ErrUnavailable
	}
	raw, err := json.Marshal(c)
	if err != nil || len(raw) > 2048 {
		return "", ErrInvalid
	}
	aead := r.keys[r.active]
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", ErrUnavailable
	}
	body := aead.Seal(nonce, nonce, raw, []byte("ops-admission-cursor/v1:"+r.active))
	return r.active + "." + base64.RawURLEncoding.EncodeToString(body), nil
}
func (r *cursorRing) open(raw string, expected pageCursor, now time.Time) (pageCursor, error) {
	if r == nil || len(raw) > 4096 {
		return pageCursor{}, ErrConflict
	}
	kid, body, ok := strings.Cut(raw, ".")
	aead, found := r.keys[kid]
	if !ok || !found {
		return pageCursor{}, ErrConflict
	}
	ciphertext, err := base64.RawURLEncoding.Strict().DecodeString(body)
	if err != nil || len(ciphertext) < aead.NonceSize()+aead.Overhead() {
		return pageCursor{}, ErrConflict
	}
	plain, err := aead.Open(nil, ciphertext[:aead.NonceSize()], ciphertext[aead.NonceSize():], []byte("ops-admission-cursor/v1:"+kid))
	if err != nil || len(plain) > 2048 {
		return pageCursor{}, ErrConflict
	}
	var c pageCursor
	if json.Unmarshal(plain, &c) != nil || c.Version != 1 || c.Purpose != expected.Purpose || c.Network != expected.Network || c.Generation != expected.Generation || c.Coverage != expected.Coverage || c.Org != expected.Org || c.Viewer != expected.Viewer || c.Manifest != expected.Manifest || c.Query != expected.Query || c.Expires <= now.Unix() {
		return pageCursor{}, ErrConflict
	}
	return c, nil
}
