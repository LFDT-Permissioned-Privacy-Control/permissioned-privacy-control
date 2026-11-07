package identityhttp

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"mime"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	b "privacy-proxy/internal/identitybroker"
	"privacy-proxy/internal/strictjson"
)

const RecipientCookie = "__Host-ops-v2-recipient"
const RenewalCookie = "__Host-ops-v2-renewal"

type requestCookies struct{ recipient, renewal string }

func readCookies(r *http.Request) (requestCookies, error) {
	out := requestCookies{}
	n := 0
	seen := map[string]bool{}
	for _, header := range r.Header.Values("Cookie") {
		if len(header) > 16<<10-n {
			return out, b.ErrInvalid
		}
		n += len(header)
		for _, part := range strings.Split(header, ";") {
			name, value, found := strings.Cut(strings.TrimSpace(part), "=")
			if name != RecipientCookie && name != RenewalCookie {
				continue
			}
			if !found || seen[name] || value == "" {
				return out, b.ErrInvalid
			}
			seen[name] = true
			for _, v := range []byte(value) {
				if v < 0x21 || v > 0x7e || v == '"' || v == '\\' || v == ',' {
					return out, b.ErrInvalid
				}
			}
			if name == RecipientCookie {
				if _, err := recipient(value); err != nil {
					return out, err
				}
				out.recipient = value
			} else {
				if len(value) > 3500 {
					return out, b.ErrInvalid
				}
				out.renewal = value
			}
		}
	}
	return out, nil
}
func recipient(raw string) (b.RecipientBinding, error) {
	if len(raw) != 43 {
		return b.RecipientBinding{}, b.ErrInvalid
	}
	data, err := base64.RawURLEncoding.Strict().DecodeString(raw)
	if err != nil || len(data) != 32 || base64.RawURLEncoding.EncodeToString(data) != raw {
		return b.RecipientBinding{}, b.ErrInvalid
	}
	return b.RecipientBinding(sha256.Sum256(data)), nil
}
func newRecipient() (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", b.ErrUnavailable
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}
func cookie(name, value string, expires, now time.Time) (string, error) {
	if !expires.After(now) {
		return "", b.ErrUnauthorized
	}
	seconds := expires.Unix() - now.Unix()
	if seconds <= 0 || seconds > int64(b.FamilyLifetime.Seconds()) {
		return "", b.ErrUnauthorized
	}
	c := (&http.Cookie{Name: name, Value: value, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode, Expires: time.Unix(expires.Unix(), 0).UTC(), MaxAge: int(seconds)}).String()
	if len(c) > 4096 || c == "" {
		return "", b.ErrUnavailable
	}
	return c, nil
}
func expiredCookie(name string) string {
	return (&http.Cookie{Name: name, Value: "", Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode, Expires: time.Unix(1, 0).UTC(), MaxAge: -1}).String()
}
func decode(r *http.Request, out any, max int) error {
	types := r.Header.Values("Content-Type")
	if len(types) != 1 {
		return b.ErrInvalid
	}
	media, parameters, err := mime.ParseMediaType(types[0])
	if err != nil || media != "application/json" || len(parameters) > 1 {
		return b.ErrInvalid
	}
	for k, v := range parameters {
		if k != "charset" || !strings.EqualFold(v, "utf-8") {
			return b.ErrInvalid
		}
	}
	if len(r.Header.Values("Content-Encoding")) != 0 || r.ContentLength > int64(max) || r.Body == nil {
		return b.ErrInvalid
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, int64(max)+1))
	if err != nil || len(raw) > max || !utf8.Valid(raw) {
		return b.ErrInvalid
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	value, err := strictjson.ReadValue(d, 0, 8)
	if err != nil {
		return b.ErrInvalid
	}
	if _, err := d.Token(); err != io.EOF {
		return b.ErrInvalid
	}
	if strictjson.ExactDecode(value, out) != nil {
		return b.ErrInvalid
	}
	return nil
}
