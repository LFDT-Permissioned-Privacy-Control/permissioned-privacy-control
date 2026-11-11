package identityhttp

import (
	"net/http"
	b "privacy-proxy/internal/identitybroker"
	"time"
)

// CentralCookies exposes the existing exact central-cookie parser to owned
// operational handlers. These strings are credentials, never verified identity.
type CentralCookies struct{ Recipient, Renewal string }

func ReadCentralCookies(r *http.Request) (CentralCookies, error) {
	c, err := readCookies(r)
	return CentralCookies{c.recipient, c.renewal}, err
}
func CentralRecipientBinding(raw string) (b.RecipientBinding, error) { return recipient(raw) }
func CentralRecipientCookie(raw string, expires, now time.Time) (string, error) {
	if _, err := recipient(raw); err != nil {
		return "", err
	}
	return cookie(RecipientCookie, raw, expires, now)
}
