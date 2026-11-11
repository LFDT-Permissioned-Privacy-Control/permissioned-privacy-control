package ssohttp

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"io"
	"mime"
	"net/http"
	"net/url"
	b "privacy-proxy/internal/identitybroker"
	m "privacy-proxy/internal/ssotransaction"
	"strings"
)

func boundedBody(r *http.Request, media string, max int) ([]byte, error) {
	types := r.Header.Values("Content-Type")
	if len(types) != 1 || len(types[0]) > 128 || len(r.Header.Values("Content-Encoding")) != 0 || r.ContentLength > int64(max) || r.Body == nil {
		return nil, b.ErrInvalid
	}
	mt, params, e := mime.ParseMediaType(types[0])
	if e != nil || mt != media || len(params) > 1 {
		return nil, b.ErrInvalid
	}
	for k, v := range params {
		if k != "charset" || !strings.EqualFold(v, "utf-8") {
			return nil, b.ErrInvalid
		}
	}
	raw, e := io.ReadAll(io.LimitReader(r.Body, int64(max)+1))
	if e != nil || len(raw) > max {
		return nil, b.ErrInvalid
	}
	return raw, nil
}
func fields(raw string, required, optional []string, max int) (url.Values, error) {
	if len(raw) > max || strings.Contains(raw, ";") {
		return nil, b.ErrInvalid
	}
	v, e := url.ParseQuery(raw)
	if e != nil {
		return nil, b.ErrInvalid
	}
	allowed := map[string]bool{}
	for _, k := range required {
		allowed[k] = true
		if len(v[k]) != 1 || v[k][0] == "" {
			return nil, b.ErrInvalid
		}
	}
	for _, k := range optional {
		allowed[k] = true
	}
	for k, values := range v {
		if !allowed[k] || len(values) != 1 || values[0] == "" {
			return nil, b.ErrInvalid
		}
	}
	return v, nil
}
func (h *Handler) basic(r *http.Request) (string, error) {
	values := r.Header.Values("Authorization")
	if len(values) != 1 || len(values[0]) > 2048 {
		return "", b.ErrUnauthorized
	}
	scheme, encoded, ok := strings.Cut(values[0], " ")
	if !ok || !strings.EqualFold(scheme, "Basic") || encoded == "" || strings.ContainsAny(encoded, " \t\r\n,") {
		return "", b.ErrUnauthorized
	}
	wire, e := base64.StdEncoding.Strict().DecodeString(encoded)
	if e != nil || len(wire) > 1153 || base64.StdEncoding.EncodeToString(wire) != encoded {
		return "", b.ErrUnauthorized
	}
	id, secret, ok := strings.Cut(string(wire), ":")
	if !ok {
		return "", b.ErrUnauthorized
	}
	id, e = url.QueryUnescape(id)
	if e != nil {
		return "", b.ErrUnauthorized
	}
	secret, e = url.QueryUnescape(secret)
	if e != nil || !m.ValidName(id) || !ascii(secret, 32, 256, false) {
		return "", b.ErrUnauthorized
	}
	expected, ok := h.secrets[id]
	if !ok {
		return "", b.ErrUnauthorized
	}
	got := sha256.Sum256([]byte(secret))
	if h.secretLengths[id] != len(secret) || subtle.ConstantTimeCompare(expected[:], got[:]) != 1 {
		return "", b.ErrUnauthorized
	}
	return id, nil
}
func bearer(r *http.Request) (string, error) {
	v := r.Header.Values("Authorization")
	if len(v) != 1 || !strings.HasPrefix(v[0], "Bearer ") {
		return "", b.ErrUnauthorized
	}
	raw := strings.TrimPrefix(v[0], "Bearer ")
	if !ascii(raw, 1, 16384, false) || strings.Count(raw, ".") != 2 {
		return "", b.ErrUnauthorized
	}
	return raw, nil
}
func canonicalToken(raw string) bool {
	if len(raw) != 43 {
		return false
	}
	d, e := base64.RawURLEncoding.Strict().DecodeString(raw)
	return e == nil && len(d) == 32 && base64.RawURLEncoding.EncodeToString(d) == raw
}
func verifier(raw string) bool {
	if len(raw) < 43 || len(raw) > 128 {
		return false
	}
	for _, v := range []byte(raw) {
		if !(v >= 'a' && v <= 'z' || v >= 'A' && v <= 'Z' || v >= '0' && v <= '9' || strings.ContainsRune("-._~", rune(v))) {
			return false
		}
	}
	return true
}
