// Package identityhttp mounts the approved broker's browser and machine flows.
// It accepts no provider/store implementation from an HTTP request and owns no
// user directory, policy mutation or Core cookie authentication fallback.
package identityhttp

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"path"
	"strconv"
	"strings"
	"time"

	"privacy-proxy/internal/identity"
	b "privacy-proxy/internal/identitybroker"
	"privacy-proxy/internal/policybundle"
)

const Prefix = "/api/v2/auth/"
const MaxInFlight = 32

type Config struct {
	Snapshot *policybundle.CatalogSnapshot
	Service  *b.Service
	Clock    identity.Clock
}
type provider struct {
	ID            string        `json:"id"`
	Provider      string        `json:"provider"`
	PrincipalKind identity.Kind `json:"principalKind"`
}
type Handler struct {
	service                      *b.Service
	clock                        identity.Clock
	origin, host, completionPath string
	profiles                     []provider
	kinds                        map[string]string
	slots                        chan struct{}
}

func New(c Config) (*Handler, error) {
	if c.Snapshot == nil || c.Service == nil || c.Clock == nil {
		return nil, b.ErrInvalid
	}
	auth, ok := c.Snapshot.AuthBroker()
	if !ok {
		return nil, b.ErrInvalid
	}
	ids, ok := c.Snapshot.Identity()
	if !ok {
		return nil, b.ErrInvalid
	}
	meta, service := c.Snapshot.Metadata(), c.Service.Metadata()
	source := auth.Source()
	if meta.Profile != policybundle.BrokerProfileID || string(meta.ManifestDigest) != service.ManifestDigest || ids.Digest() != service.IdentityDigest || auth.Digest() != service.BrokerDigest || service.Binding.Origin != source.WebOrigin {
		return nil, b.ErrInvalid
	}
	u, err := url.Parse(source.WebOrigin)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Opaque != "" || u.Path != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.RawFragment != "" || u.String() != source.WebOrigin || strings.ToLower(u.Host) != u.Host || u.Port() == "443" {
		return nil, b.ErrInvalid
	}
	for _, r := range u.Host {
		if r < 0x21 || r > 0x7e || r == '%' || r == '\\' {
			return nil, b.ErrInvalid
		}
	}
	if u.Port() != "" {
		p, err := strconv.ParseUint(u.Port(), 10, 16)
		if err != nil || p == 0 || strconv.FormatUint(p, 10) != u.Port() {
			return nil, b.ErrInvalid
		}
	}
	if !canonicalHostname(u.Hostname()) {
		return nil, b.ErrInvalid
	}
	complete, err := url.Parse(source.CompletionURI)
	if err != nil || complete.Scheme+"://"+complete.Host != source.WebOrigin || complete.User != nil || complete.RawQuery != "" || complete.ForceQuery || complete.Fragment != "" || complete.Path == "" || !strings.HasPrefix(complete.Path, "/") || strings.HasPrefix(complete.Path, "//") || path.Clean(complete.Path) != complete.Path || strings.ContainsAny(source.CompletionURI, "%\\") {
		return nil, b.ErrInvalid
	}
	h := &Handler{service: c.Service, clock: c.Clock, origin: source.WebOrigin, host: u.Host, completionPath: complete.Path, kinds: map[string]string{}, slots: make(chan struct{}, MaxInFlight), profiles: []provider{}}
	for _, p := range auth.Profiles() {
		h.kinds[p.Definition.ID] = p.Definition.Kind
		if p.Definition.Kind == identity.AzureHuman {
			if p.Binding.RedirectURI != source.WebOrigin+"/auth/azure/callback" {
				return nil, b.ErrInvalid
			}
			h.profiles = append(h.profiles, provider{p.Definition.ID, "azure", identity.Human})
		}
	}
	return h, nil
}

func canonicalHostname(host string) bool {
	if ip, err := netip.ParseAddr(host); err == nil {
		return ip.Zone() == "" && !ip.Is4In6() && ip.String() == host
	}
	if strings.Contains(host, ":") || len(host) == 0 || len(host) > 253 {
		return false
	}
	labels := strings.Split(strings.TrimSuffix(host, "."), ".")
	last := labels[len(labels)-1]
	// Browser URL parsers interpret numeric endings as IPv4, including
	// abbreviated/octal/hex forms that net/url leaves untouched. Only canonical
	// IP spellings above are supported by this exact-Origin hosting contract.
	if last == "" || strings.HasPrefix(last, "0x") {
		return false
	}
	numeric := true
	for _, r := range last {
		numeric = numeric && r >= '0' && r <= '9'
	}
	if numeric {
		return false
	}
	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, r := range label {
			if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-') {
				return false
			}
		}
	}
	return true
}
func (h *Handler) Register(mux *http.ServeMux) { mux.Handle(Prefix, h) }
func headers(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
}
func failure(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = io.WriteString(w, `{"error":"`+code+`"}`+"\n")
}
func failService(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, b.ErrSessionChanged):
		failure(w, 409, "session_changed")
	case errors.Is(err, b.ErrInvalid):
		failure(w, 400, "invalid_request")
	case errors.Is(err, b.ErrUnauthorized), errors.Is(err, b.ErrRelogin):
		failure(w, 401, "reauthentication_required")
	default:
		failure(w, 503, "authentication_unavailable")
	}
}
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	headers(w)
	want := "POST"
	switch r.URL.Path {
	case Prefix + "providers":
		want = "GET"
	case Prefix + "azure/start", Prefix + "azure/complete", Prefix + "renew", Prefix + "logout", Prefix + "service/exchange":
	default:
		failure(w, 404, "not_found")
		return
	}
	if r.Method != want {
		w.Header().Set("Allow", want)
		failure(w, 405, "method_not_allowed")
		return
	}
	if r.Host != h.host {
		failure(w, 403, "forbidden")
		return
	}
	if r.URL.RawQuery != "" || r.URL.ForceQuery || r.URL.RawPath != "" && r.URL.RawPath != r.URL.Path {
		failure(w, 400, "invalid_request")
		return
	}
	machine := r.URL.Path == Prefix+"service/exchange"
	origins := r.Header.Values("Origin")
	if machine {
		if len(origins) != 0 {
			failure(w, 403, "forbidden")
			return
		}
	} else if want == "POST" || len(origins) > 0 {
		if len(origins) != 1 || origins[0] != h.origin {
			failure(w, 403, "forbidden")
			return
		}
	}
	cookies, err := readCookies(r)
	if err != nil {
		failure(w, 400, "invalid_request")
		return
	}
	if machine && (cookies.recipient != "" || cookies.renewal != "") {
		failure(w, 403, "forbidden")
		return
	}
	select {
	case h.slots <- struct{}{}:
		defer func() { <-h.slots }()
	default:
		failure(w, 503, "busy")
		return
	}
	switch r.URL.Path {
	case Prefix + "providers":
		if r.ContentLength != 0 || len(r.TransferEncoding) != 0 {
			failure(w, 400, "invalid_request")
			return
		}
		if r.Body != nil {
			raw, err := io.ReadAll(io.LimitReader(r.Body, 1))
			if err != nil || len(raw) != 0 {
				failure(w, 400, "invalid_request")
				return
			}
		}
		publish(w, r, map[string]any{"profiles": h.profiles, "completionPath": h.completionPath}, nil, func() error { return r.Context().Err() })
	case Prefix + "azure/start":
		h.start(w, r, cookies)
	case Prefix + "azure/complete":
		h.complete(w, r, cookies)
	case Prefix + "renew":
		h.renew(w, r, cookies)
	case Prefix + "logout":
		h.logout(w, r, cookies)
	case Prefix + "service/exchange":
		h.exchange(w, r)
	}
}
func publish(w http.ResponseWriter, r *http.Request, value any, cookies []string, gate func() error) {
	raw, err := json.Marshal(value)
	if err != nil || len(raw)+1 > 24<<10 {
		failure(w, 503, "authentication_unavailable")
		return
	}
	raw = append(raw, '\n')
	if err := gate(); err != nil {
		failService(w, err)
		return
	}
	if r.Context().Err() != nil {
		failure(w, 503, "authentication_unavailable")
		return
	}
	for _, cookie := range cookies {
		w.Header().Add("Set-Cookie", cookie)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(200)
	_, _ = w.Write(raw)
}
func (h *Handler) now() (time.Time, error) {
	at := h.clock().UTC()
	if at.Unix() < 0 || at.Unix() > 253402300799-int64(b.FamilyLifetime.Seconds()) {
		return time.Time{}, b.ErrUnavailable
	}
	return at, nil
}
func live(ctx context.Context, at, expires time.Time) error {
	if ctx.Err() != nil {
		return b.ErrUnavailable
	}
	if !at.Before(expires) {
		return b.ErrUnauthorized
	}
	return nil
}
