package ssohttp

import (
	"bytes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"github.com/google/uuid"
	b "privacy-proxy/internal/identitybroker"
	m "privacy-proxy/internal/ssotransaction"
	"time"
)

type contextPayload struct {
	V           int    `json:"v"`
	ClientID    string `json:"clientId"`
	RedirectURI string `json:"redirectURI"`
	State       string `json:"state"`
}
type grantPayload struct {
	V             int    `json:"v"`
	AccessToken   string `json:"accessToken"`
	RenewalHandle string `json:"renewalHandle"`
}

func number(n int64) []byte {
	var out [8]byte
	binary.BigEndian.PutUint64(out[:], uint64(n))
	return out[:]
}
func uuidBytes(raw string) []byte {
	x, e := uuid.Parse(raw)
	if e != nil {
		return nil
	}
	return x[:]
}
func hashed(domain, raw string) m.Digest { return m.Digest(b.Hash(domain, []byte(raw))) }
func (h *Handler) contextAAD(p m.PendingRecord) []byte {
	return b.Pack("ops-sso-context/v1", h.runtimeDigest[:], uuidBytes(p.ID), p.Scope.Namespace[:], uuidBytes(p.Scope.Epoch), p.Scope.BrokerNamespace[:], uuidBytes(p.Scope.BrokerRecoveryEpoch), []byte(p.ClientID), p.ClientCatalogDigest[:], p.IdentityDigest[:], p.Recipient[:], p.StateHash[:], p.RedirectHash[:], p.PKCES256[:], []byte(p.ContextKeyID), number(int64(p.CreatedAt)), number(int64(p.ExpiresAt)))
}
func (h *Handler) grantAAD(p m.PendingRecord, v m.ReadyFields) []byte {
	ca := sha256.Sum256(h.contextAAD(p))
	cc := sha256.Sum256(p.ContextCiphertext)
	return b.Pack("ops-sso-grant/v1", ca[:], cc[:], []byte(v.GrantKeyID), v.CodeHash[:], number(int64(v.CodeExpiresAt)), []byte(v.ActorID), []byte(v.ProfileID), v.ProfileDigest[:], uuidBytes(v.FamilyID), number(v.FamilyGeneration), v.FamilyHandleHash[:], v.AccessDigest[:], number(int64(v.AccessExpiresAt)), number(int64(v.FamilyExpiresAt)), number(int64(v.PreparedAt)), v.CodeResponseDigest[:], number(int64(v.CodeResponseBytes)))
}
func seal(a cipher.AEAD, v any, aad []byte, max int) ([]byte, error) {
	// This is encrypted JSON, never HTML. Disable HTML escaping so every
	// supported 512-byte state fits, including '<', '>' and '&'. JSON quote
	// and backslash escaping still applies and is covered by maximum tests.
	var encoded bytes.Buffer
	encoder := json.NewEncoder(&encoded)
	encoder.SetEscapeHTML(false)
	e := encoder.Encode(v)
	plain := encoded.Bytes()
	if e != nil || len(plain)+a.NonceSize()+a.Overhead() > max {
		return nil, b.ErrInvalid
	}
	nonce := make([]byte, a.NonceSize())
	if _, e = rand.Read(nonce); e != nil {
		return nil, b.ErrUnavailable
	}
	return a.Seal(nonce, nonce, plain, aad), nil
}
func open(a cipher.AEAD, raw, aad []byte, out any, max int) error {
	if len(raw) < a.NonceSize()+a.Overhead() || len(raw) > max {
		return b.ErrUnauthorized
	}
	plain, e := a.Open(nil, raw[:a.NonceSize()], raw[a.NonceSize():], aad)
	if e != nil || closed(plain, out, max) != nil {
		return b.ErrUnauthorized
	}
	return nil
}
func ascii(s string, min, max int, space bool) bool {
	if len(s) < min || len(s) > max {
		return false
	}
	lo := byte(0x21)
	if space {
		lo = 0x20
	}
	for _, v := range []byte(s) {
		if v < lo || v > 0x7e {
			return false
		}
	}
	return true
}
func (h *Handler) openContext(r m.Record) (contextPayload, error) {
	p := r.Pending
	var out contextPayload
	if m.ValidateRecord(r) != nil || p.Scope != h.scope || p.ClientCatalogDigest != h.clientsDigest || p.IdentityDigest != h.identityDigest || p.ContextKeyID != h.runtime.ContextKey.ID {
		return out, b.ErrUnauthorized
	}
	if e := open(h.contextCipher, p.ContextCiphertext, h.contextAAD(p), &out, m.MaxContextCipherBytes); e != nil {
		return out, e
	}
	client, ok := h.clients.Client(p.ClientID)
	if !ok || out.V != 1 || out.ClientID != p.ClientID || !ascii(out.State, 1, 512, true) || !ascii(out.RedirectURI, 1, 2048, false) || hashed("ops-sso-state/v1", out.State) != p.StateHash || hashed("ops-sso-redirect/v1", out.RedirectURI) != p.RedirectHash {
		return out, b.ErrUnauthorized
	}
	found := false
	for _, u := range client.Source().RedirectURIs {
		found = found || u == out.RedirectURI
	}
	if !found {
		return out, b.ErrUnauthorized
	}
	at, e := h.now()
	if e != nil || m.Micros(at.UnixMicro()) < p.CreatedAt || m.Micros(at.UnixMicro()) >= p.ExpiresAt {
		return out, b.ErrUnauthorized
	}
	return out, nil
}
func (h *Handler) openGrant(r m.Record) (grantPayload, error) {
	var out grantPayload
	if r.Phase != m.Ready || r.Ready == nil || r.Ready.GrantKeyID != h.runtime.GrantKey.ID {
		return out, b.ErrUnauthorized
	}
	if e := open(h.grantCipher, r.Ready.GrantCiphertext, h.grantAAD(r.Pending, *r.Ready), &out, m.MaxGrantCipherBytes); e != nil {
		return out, e
	}
	if out.V != 1 || !ascii(out.AccessToken, 1, 16384, false) || !ascii(out.RenewalHandle, 1, 3500, false) || hashed("ops-sso-access/v1", out.AccessToken) != r.Ready.AccessDigest {
		return out, b.ErrUnauthorized
	}
	return out, nil
}
func micros(t time.Time) m.Micros { return m.Micros(t.UnixMicro()) }
