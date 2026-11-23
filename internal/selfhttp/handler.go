// Package selfhttp exposes verified own-session display facts from the same
// immutable policy snapshot used by Core. It owns no session or user store.
package selfhttp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	"privacy-proxy/internal/identity"
	"privacy-proxy/internal/policybundle"
	"privacy-proxy/internal/runtimepolicy"
)

const Path = "/api/v2/self"
const MaxResponseBytes = 512 << 10
const MaxOrganizations = 256

// Group rows are a bounded own-membership display, never an authorization set.
const MaxDisplayedGroups = 256

var ErrInvalid = errors.New("invalid self handler configuration")

type Config struct {
	Snapshot *policybundle.CatalogSnapshot
	Origin   string
	Clock    identity.Clock
}
type Organization struct {
	ID                 string  `json:"id"`
	Slug               string  `json:"slug"`
	Name               string  `json:"name"`
	IsOrgAdmin         bool    `json:"isOrgAdmin"`
	IsOrgReadonlyAdmin bool    `json:"isOrgReadonlyAdmin"`
	Groups             []Group `json:"groups"`
	GroupCount         int     `json:"groupCount"`
	GroupsTruncated    bool    `json:"groupsTruncated"`
}
type Group struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Slug string `json:"slug"`
}
type Response struct {
	ActorID             string         `json:"actorId"`
	PrincipalKind       identity.Kind  `json:"principalKind"`
	SourceProfile       string         `json:"sourceProfile"`
	SourceProfileDigest string         `json:"sourceProfileDigest"`
	ExpiresAt           int64          `json:"expiresAt"`
	Organizations       []Organization `json:"organizations"`
}
type Handler struct {
	factory  *runtimepolicy.Factory
	host     string
	orgs     map[string]policybundle.Organization
	snapshot *policybundle.CatalogSnapshot
}

func New(c Config) (*Handler, error) {
	if c.Snapshot == nil || c.Clock == nil {
		return nil, ErrInvalid
	}
	u, err := url.Parse(c.Origin)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Opaque != "" || u.Path != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.RawFragment != "" || u.String() != c.Origin || strings.ToLower(u.Host) != u.Host || strings.ContainsAny(u.Host, "%\\") || u.Port() == "443" || !canonicalHostname(u.Hostname()) {
		return nil, ErrInvalid
	}
	if p := u.Port(); p != "" {
		n, err := strconv.ParseUint(p, 10, 16)
		if err != nil || n == 0 || strconv.FormatUint(n, 10) != p {
			return nil, ErrInvalid
		}
	}
	authority := u.Hostname()
	if strings.Contains(authority, ":") {
		authority = "[" + authority + "]"
	}
	if u.Port() != "" {
		authority += ":" + u.Port()
	}
	if authority != u.Host {
		return nil, ErrInvalid
	}
	orgs := c.Snapshot.Organizations()
	if len(orgs) > MaxOrganizations {
		return nil, ErrInvalid
	}
	factory, err := runtimepolicy.NewFactory(c.Snapshot, c.Clock)
	if err != nil {
		return nil, ErrInvalid
	}
	h := &Handler{factory: factory, host: u.Host, orgs: map[string]policybundle.Organization{}, snapshot: c.Snapshot}
	for _, org := range orgs {
		h.orgs[org.ID] = org
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

func (h *Handler) Register(mux *http.ServeMux) {
	mux.Handle(Path, h)
}
func fail(w http.ResponseWriter, status int, code string) {
	w.WriteHeader(status)
	_, _ = io.WriteString(w, `{"error":"`+code+`"}`+"\n")
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if r.URL.Path != Path {
		fail(w, 404, "not_found")
		return
	}
	if r.Method != "GET" {
		w.Header().Set("Allow", "GET")
		fail(w, 405, "method_not_allowed")
		return
	}
	if r.Host != h.host || len(r.Header.Values("Origin")) > 1 || r.Header.Get("Origin") != "" && r.Header.Get("Origin") != "https://"+h.host {
		fail(w, 403, "forbidden")
		return
	}
	if r.URL.RawQuery != "" || r.URL.ForceQuery || r.URL.RawPath != "" && r.URL.RawPath != r.URL.Path || r.ContentLength > 0 {
		fail(w, 400, "invalid_request")
		return
	}
	deadline := time.Now().Add(5 * time.Second)
	if d, ok := r.Context().Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	rc := http.NewResponseController(w)
	if rc.SetReadDeadline(deadline) != nil || rc.SetWriteDeadline(deadline) != nil {
		fail(w, 503, "self_unavailable")
		return
	}
	ctx, cancel := context.WithDeadline(r.Context(), deadline)
	defer cancel()
	if raw, err := io.ReadAll(io.LimitReader(r.Body, 1)); err != nil || len(raw) != 0 {
		fail(w, 400, "invalid_request")
		return
	}
	values := r.Header.Values("Authorization")
	if len(values) != 1 {
		fail(w, 401, "invalid_access")
		return
	}
	scheme, token, ok := strings.Cut(values[0], " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") || len(token) == 0 || len(token) > 16384 || strings.ContainsAny(token, " \t\r\n,") {
		fail(w, 401, "invalid_access")
		return
	}
	view, err := h.factory.Build(token)
	if err != nil {
		fail(w, 401, "invalid_access")
		return
	}
	profile, digest := view.SourceProfile()
	response := Response{ActorID: view.ActorID(), PrincipalKind: view.Kind(), SourceProfile: profile, SourceProfileDigest: digest, ExpiresAt: view.ExpiresAt().Unix(), Organizations: []Organization{}}
	groupIDs := [][]string{}
	for _, id := range view.OrgIDs() {
		org, ok := view.Org(id)
		metadata, found := h.orgs[id]
		if !ok || !found {
			fail(w, 503, "self_unavailable")
			return
		}
		groups := org.Groups()
		groupIDs = append(groupIDs, groups)
		response.Organizations = append(response.Organizations, Organization{ID: id, Slug: metadata.Slug, Name: metadata.Name, IsOrgAdmin: org.IsOrgAdmin(), IsOrgReadonlyAdmin: org.IsOrgReadonlyAdmin(), Groups: []Group{}, GroupCount: len(groups), GroupsTruncated: len(groups) > 0})
	}
	if h.projectGroups(&response, groupIDs) != nil {
		fail(w, 503, "self_unavailable")
		return
	}
	var body bytes.Buffer
	if json.NewEncoder(&body).Encode(response) != nil || body.Len() > MaxResponseBytes || ctx.Err() != nil {
		fail(w, 503, "self_unavailable")
		return
	}
	// Verification and rendering never renew the original access evidence.
	if view.RequireLive() != nil {
		fail(w, 401, "invalid_access")
		return
	}
	_, _ = w.Write(body.Bytes())
}

// Reserve the complete organization/role/count frame first. Admit a stable
// prefix of each verified OrgView's groups within the existing encoded-byte
// budget, including JSON escaping and the final true -> false flag change.
// Large display populations never turn an otherwise valid identity into a
// login failure; the exact own count and truncation flag remain visible.
func (h *Handler) projectGroups(response *Response, ids [][]string) error {
	var base bytes.Buffer
	if json.NewEncoder(&base).Encode(response) != nil || base.Len() > MaxResponseBytes {
		return ErrInvalid
	}
	size, displayed := base.Len(), 0
	for i := range response.Organizations {
		org := &response.Organizations[i]
		for _, id := range ids[i] {
			if displayed == MaxDisplayedGroups {
				break
			}
			metadata, ok := h.snapshot.Group(org.ID, id)
			if !ok {
				return ErrInvalid
			}
			group := Group{ID: id, Name: metadata.Name, Slug: metadata.Slug}
			raw, err := json.Marshal(group)
			if err != nil {
				return ErrInvalid
			}
			delta := len(raw)
			if len(org.Groups) > 0 {
				delta++
			}
			complete := len(org.Groups)+1 == org.GroupCount
			if complete {
				delta++
			}
			if size+delta > MaxResponseBytes {
				break
			}
			org.Groups = append(org.Groups, group)
			org.GroupsTruncated = !complete
			size += delta
			displayed++
		}
	}
	return nil
}
