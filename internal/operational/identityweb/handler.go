// Package identityweb serves the immutable built V2 browser entry. The owner
// mounts it beside the selected broker, SSO and pure self handlers; it does not
// assemble a legacy SPA, user directory or authentication fallback.
package identityweb

import (
	"errors"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"

	"github.com/google/uuid"

	"privacy-proxy/internal/policybundle"
)

var ErrInvalid = errors.New("invalid V2 browser build or binding")

type Config struct {
	Snapshot *policybundle.CatalogSnapshot
	Files    fs.FS // frontend/dist-v2, built by npm run build:v2
}
type asset struct {
	body        []byte
	contentType string
}
type Handler struct {
	host   string
	pages  map[string]bool
	assets map[string]asset
	entry  []byte
}

// New copies only the bounded selected build into memory. Subsequent filesystem
// edits cannot replace a running instance's code or widen its public paths.
func New(c Config) (*Handler, error) {
	if c.Snapshot == nil || c.Files == nil || c.Snapshot.Metadata().Profile != policybundle.BrokerMultiProfileID {
		return nil, ErrInvalid
	}
	broker, ok := c.Snapshot.AuthBroker()
	if !ok {
		return nil, ErrInvalid
	}
	source := broker.CommonSettings()
	origin, err := url.Parse(source.WebOrigin)
	if err != nil || origin.Scheme != "https" || origin.Host == "" {
		return nil, ErrInvalid
	}
	complete, err := url.Parse(source.CompletionURI)
	if err != nil || complete.Scheme+"://"+complete.Host != source.WebOrigin || complete.RawQuery != "" || complete.Fragment != "" || !pagePath(complete.Path) || strings.HasPrefix(complete.Path, "/api/") || strings.HasPrefix(complete.Path, "/assets-v2/") || complete.Path == "/login" || complete.Path == "/auth/sso" || complete.Path == "/auth/azure/callback" || adminPage(complete.Path) {
		return nil, ErrInvalid
	}
	h := &Handler{host: origin.Host, pages: map[string]bool{"/login": true, "/auth/sso": true, "/auth/azure/callback": true, complete.Path: true}, assets: map[string]asset{}}
	for _, p := range adminPages {
		h.pages[p] = true
	}
	total, count := 0, 0
	err = fs.WalkDir(c.Files, ".", func(name string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.Type()&fs.ModeSymlink != 0 {
			return ErrInvalid
		}
		if d.IsDir() {
			if name == "." || name == "assets-v2" {
				return nil
			}
			return ErrInvalid
		}
		if !d.Type().IsRegular() || count >= 64 {
			return ErrInvalid
		}
		kind, limit := "", 2<<20
		switch {
		case name == "index-v2.html":
			kind, limit = "text/html; charset=utf-8", 256<<10
		case strings.HasPrefix(name, "assets-v2/") && path.Base(name) == strings.TrimPrefix(name, "assets-v2/"):
			switch path.Ext(name) {
			case ".js":
				kind = "text/javascript; charset=utf-8"
			case ".css":
				kind = "text/css; charset=utf-8"
			}
		}
		if kind == "" {
			return ErrInvalid
		}
		info, e := d.Info()
		if e != nil || info.Size() <= 0 || info.Size() > int64(limit) {
			return ErrInvalid
		}
		file, e := c.Files.Open(name)
		if e != nil {
			return ErrInvalid
		}
		body, e := io.ReadAll(io.LimitReader(file, int64(limit)+1))
		closeErr := file.Close()
		if e != nil || closeErr != nil || len(body) != int(info.Size()) || len(body) > limit {
			return ErrInvalid
		}
		count++
		total += len(body)
		if total > 8<<20 {
			return ErrInvalid
		}
		if name == "index-v2.html" {
			h.entry = body
		} else {
			h.assets["/"+name] = asset{body, kind}
		}
		return nil
	})
	if err != nil || len(h.entry) == 0 || len(h.assets) == 0 {
		return nil, ErrInvalid
	}
	return h, nil
}
func pagePath(value string) bool {
	return strings.HasPrefix(value, "/") && value != "/" && path.Clean(value) == value && !strings.ContainsAny(value, "%\\?# \t\r\n")
}

// Admin routes serve only the selected static entry. Authentication and actual
// operation authority still belong to the native client and API handlers.
// Keep this list exact: an unknown API or legacy path must never become a SPA.
var adminPages = []string{
	"/account", "/admin", "/admin/account", "/admin/rbac", "/admin/rbac/organizations", "/admin/rbac/groups",
	"/admin/rbac/contracts", "/admin/rbac/execution-policy", "/admin/rbac/configuration",
	"/admin/rbac/identity-profiles", "/admin/rbac/claim-mappings", "/admin/rbac/azure-tenants", "/admin/rbac/platform-configuration",
	"/admin/rbac/disclosure-source", "/admin/rbac/compliance-source",
	"/admin/identity/profiles", "/admin/identity/claim-mappings", "/admin/settings",
	"/admin/disclosure/rules", "/admin/compliance/policy", "/admin/configuration",
	"/admin/compliance", "/admin/disclosure", "/admin/disclosures", "/admin/logs", "/admin/diagnostics", "/disclosures",
}

func adminPage(value string) bool {
	for _, page := range adminPages {
		if value == page {
			return true
		}
	}
	return false
}

func adminQuery(value, raw string, force bool) bool {
	if raw == "" {
		return !force
	}
	if !adminPage(value) || value == "/admin" || value == "/admin/account" || value == "/account" {
		return false
	}
	// A single canonical organization selector is the only accepted query.
	// Reject percent aliases as well as duplicate or unrelated parameters.
	if len(raw) != len("org=")+36 || !strings.HasPrefix(raw, "org=") {
		return false
	}
	selected := strings.TrimPrefix(raw, "org=")
	id, err := uuid.Parse(selected)
	return err == nil && id != uuid.Nil && id.String() == selected
}

func (h *Handler) Register(mux *http.ServeMux) {
	for p := range h.pages {
		mux.Handle(p, h)
	}
	mux.Handle("/assets-v2/", h)
}
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; base-uri 'none'; frame-ancestors 'none'; form-action 'none'")
	if r.Host != h.host {
		http.Error(w, "forbidden", 403)
		return
	}
	if r.Method != "GET" {
		w.Header().Set("Allow", "GET")
		http.Error(w, "method not allowed", 405)
		return
	}
	if r.URL.RawPath != "" && r.URL.RawPath != r.URL.Path || r.ContentLength > 0 || r.URL.Fragment != "" || r.URL.RawFragment != "" || len(r.URL.RawQuery) > 32768 {
		http.Error(w, "invalid request", 400)
		return
	}
	if adminPage(r.URL.Path) && !adminQuery(r.URL.Path, r.URL.RawQuery, r.URL.ForceQuery) {
		http.Error(w, "invalid request", 400)
		return
	}
	body, kind := h.entry, "text/html; charset=utf-8"
	if !h.pages[r.URL.Path] {
		a, ok := h.assets[r.URL.Path]
		if !ok || r.URL.RawQuery != "" || r.URL.ForceQuery {
			http.NotFound(w, r)
			return
		}
		body, kind = a.body, a.contentType
	}
	deadline := time.Now().Add(5 * time.Second)
	if d, ok := r.Context().Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	rc := http.NewResponseController(w)
	if rc.SetReadDeadline(deadline) != nil || rc.SetWriteDeadline(deadline) != nil || r.Context().Err() != nil {
		http.Error(w, "browser unavailable", 503)
		return
	}
	w.Header().Set("Content-Type", kind)
	_, _ = w.Write(body)
}
