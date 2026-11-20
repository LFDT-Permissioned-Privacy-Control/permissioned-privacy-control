package selfhttp

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"privacy-proxy/internal/runtimepolicy"
)

const DiagnosticsPattern = "/api/v2/orgs/{orgId}/diagnostics"

var diagnosticsOrganization = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

type BuildIdentity struct {
	Version string `json:"version"`
	Commit  string `json:"commit"`
	BuiltAt string `json:"builtAt"`
}
type Observation struct {
	State     string     `json:"state"`
	SampledAt *time.Time `json:"sampledAt,omitempty"`
	LatencyMS *int64     `json:"latencyMs,omitempty"`
}
type DiagnosticsSample struct{ Readiness, Node Observation }
type DiagnosticsConfig struct {
	Config
	Build  BuildIdentity
	Sample func(context.Context, string) DiagnosticsSample
}
type DiagnosticsHandler struct {
	self   *Handler
	config DiagnosticsConfig
}
type DiagnosticsResponse struct {
	OrganizationID string        `json:"organizationId"`
	Build          BuildIdentity `json:"build"`
	Process        string        `json:"process"`
	ObservedAt     time.Time     `json:"observedAt"`
	Readiness      Observation   `json:"readiness"`
	Node           Observation   `json:"node"`
}

func NewDiagnostics(c DiagnosticsConfig) (*DiagnosticsHandler, error) {
	h, err := New(c.Config)
	if err != nil || c.Sample == nil {
		return nil, ErrInvalid
	}
	if !regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$`).MatchString(c.Build.Version) {
		c.Build.Version = "unknown"
	}
	if c.Build.Commit != "none" && !regexp.MustCompile(`^[0-9a-f]{7,64}$`).MatchString(c.Build.Commit) {
		c.Build.Commit = "unknown"
	}
	if at, err := time.Parse(time.RFC3339, c.Build.BuiltAt); err == nil {
		c.Build.BuiltAt = at.UTC().Format(time.RFC3339)
	} else {
		c.Build.BuiltAt = "unknown"
	}
	return &DiagnosticsHandler{self: h, config: c}, nil
}
func (h *DiagnosticsHandler) Register(mux *http.ServeMux) { mux.Handle(DiagnosticsPattern, h) }
func diagnosticRole(view *runtimepolicy.View, org string) bool {
	o, ok := view.Org(org)
	return ok && (o.IsOrgAdmin() || o.IsOrgReadonlyAdmin())
}
func validObservation(value Observation, node bool, now time.Time) bool {
	validState := value.State == "unknown" || value.State == "unavailable" || !node && value.State == "ready" || node && value.State == "connected"
	if !validState {
		return false
	}
	if value.State == "unknown" {
		return value.SampledAt == nil && value.LatencyMS == nil
	}
	if value.SampledAt == nil || value.SampledAt.IsZero() || value.SampledAt.After(now) || now.Sub(*value.SampledAt) > time.Second || value.SampledAt.Year() < 1970 || value.SampledAt.Year() > 9999 {
		return false
	}
	return value.LatencyMS == nil || node && *value.LatencyMS >= 0 && *value.LatencyMS <= 3000
}
func (h *DiagnosticsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	org := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/api/v2/orgs/"), "/diagnostics")
	if r.URL.Path != "/api/v2/orgs/"+org+"/diagnostics" || !diagnosticsOrganization.MatchString(org) || org == "00000000-0000-0000-0000-000000000000" {
		fail(w, 404, "not_found")
		return
	}
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		fail(w, 405, "method_not_allowed")
		return
	}
	if r.Host != h.self.host || len(r.Header.Values("Origin")) > 1 || r.Header.Get("Origin") != "" && r.Header.Get("Origin") != "https://"+h.self.host {
		fail(w, 403, "forbidden")
		return
	}
	if r.URL.RawQuery != "" || r.URL.ForceQuery || r.URL.RawPath != "" && r.URL.RawPath != r.URL.Path || r.ContentLength > 0 {
		fail(w, 400, "invalid_request")
		return
	}
	deadline := time.Now().Add(3 * time.Second)
	if d, ok := r.Context().Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	rc := http.NewResponseController(w)
	if rc.SetReadDeadline(deadline) != nil || rc.SetWriteDeadline(deadline) != nil {
		fail(w, 503, "diagnostics_unavailable")
		return
	}
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
	view, err := h.self.factory.Build(token)
	if err != nil || view.RequireLive() != nil {
		fail(w, 401, "invalid_access")
		return
	}
	if !diagnosticRole(view, org) {
		fail(w, 403, "forbidden")
		return
	}
	// The original evidence also bounds the socket publication deadline.
	if expiry := time.Now().Add(view.ExpiresAt().Sub(h.config.Clock())); expiry.Before(deadline) {
		deadline = expiry
		if rc.SetWriteDeadline(deadline) != nil {
			fail(w, 503, "diagnostics_unavailable")
			return
		}
	}
	ctx, cancel := context.WithDeadline(r.Context(), deadline)
	defer cancel()
	sample := h.config.Sample(ctx, org)
	if view.RequireLive() != nil {
		fail(w, 401, "invalid_access")
		return
	}
	if !diagnosticRole(view, org) {
		fail(w, 403, "forbidden")
		return
	}
	now := h.config.Clock().UTC()
	if ctx.Err() != nil || !validObservation(sample.Readiness, false, now) || !validObservation(sample.Node, true, now) {
		fail(w, 503, "diagnostics_unavailable")
		return
	}
	response := DiagnosticsResponse{org, h.config.Build, "running", now, sample.Readiness, sample.Node}
	var body bytes.Buffer
	if json.NewEncoder(&body).Encode(response) != nil || body.Len() > 4096 || ctx.Err() != nil {
		fail(w, 503, "diagnostics_unavailable")
		return
	}
	if view.RequireLive() != nil {
		fail(w, 401, "invalid_access")
		return
	}
	_, _ = w.Write(body.Bytes())
}
