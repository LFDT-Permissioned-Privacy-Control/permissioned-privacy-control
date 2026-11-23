package configurationviewer

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"privacy-proxy/internal/identity"
	"privacy-proxy/internal/policybundle"
	"privacy-proxy/internal/runtimepolicy"
	"privacy-proxy/internal/selfhttp"
)

type Config struct {
	Settings *Settings
	Snapshot *policybundle.CatalogSnapshot
	Origin   string
	Clock    identity.Clock
}
type observation struct {
	capture            *capture
	captured, lastUsed time.Time
	users              int
	cached             bool
}
type Handler struct {
	settings                 *Settings
	factory                  *runtimepolicy.Factory
	host                     string
	clock                    identity.Clock
	load                     func(context.Context, *Settings, string) (*capture, error)
	mu                       sync.Mutex
	cache                    map[string]*observation
	flights                  map[string]chan struct{}
	used, reserved, inflight int
}

func New(c Config) (*Handler, error) {
	if c.Settings.Validate() != nil {
		return nil, ErrInvalid
	}
	if _, e := selfhttp.New(selfhttp.Config{Snapshot: c.Snapshot, Origin: c.Origin, Clock: c.Clock}); e != nil {
		return nil, ErrInvalid
	}
	f, e := runtimepolicy.NewFactory(c.Snapshot, c.Clock)
	if e != nil {
		return nil, ErrInvalid
	}
	u, _ := url.Parse(c.Origin)
	h := &Handler{factory: f, host: u.Host, clock: c.Clock, load: captureSource, cache: map[string]*observation{}, flights: map[string]chan struct{}{}}
	if c.Settings != nil {
		copySettings := *c.Settings
		copySettings.Audience = cloneAudience(copySettings.Audience)
		copySettings.FolderAudiences = map[string]Audience{}
		for id, a := range c.Settings.FolderAudiences {
			copySettings.FolderAudiences[id] = cloneAudience(a)
		}
		known := map[string]bool{}
		for _, org := range c.Snapshot.Organizations() {
			known[org.ID] = true
		}
		for _, a := range append([]Audience{copySettings.Audience}, audiences(copySettings.FolderAudiences)...) {
			for _, org := range a.OwnerOrganizationIDs {
				if !known[org] {
					return nil, ErrInvalid
				}
			}
		}
		h.settings = &copySettings
	}
	return h, nil
}
func cloneAudience(a Audience) Audience {
	return Audience{slices.Clone(a.OwnerOrganizationIDs), slices.Clone(a.OperatorActorIDs)}
}
func audiences(m map[string]Audience) []Audience {
	out := []Audience{}
	for _, a := range m {
		out = append(out, a)
	}
	return out
}
func (h *Handler) Register(m *http.ServeMux) { m.Handle(Path, h); m.Handle(Path+"/", h) }
func fail(w http.ResponseWriter, status int, code string) {
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": code})
}
func (h *Handler) removeLocked(id string, e *observation) {
	if h.cache[id] == e {
		delete(h.cache, id)
		e.cached = false
		if e.users == 0 {
			h.used -= cap(e.capture.body)
		}
	}
}
func (h *Handler) evictLocked() bool {
	var oldest *observation
	key := ""
	for id, e := range h.cache {
		if e.users == 0 && (oldest == nil || e.lastUsed.Before(oldest.lastUsed)) {
			oldest = e
			key = id
		}
	}
	if oldest == nil {
		return false
	}
	h.removeLocked(key, oldest)
	return true
}
func (h *Handler) release(e *observation) {
	h.mu.Lock()
	defer h.mu.Unlock()
	e.users--
	if e.users == 0 && !e.cached {
		h.used -= cap(e.capture.body)
	}
}
func (h *Handler) observe(ctx context.Context, id string, force bool) (*observation, error) {
	for {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		h.mu.Lock()
		if e := h.cache[id]; e != nil && !force && time.Since(e.captured) < 10*time.Second {
			e.users++
			e.lastUsed = time.Now()
			h.mu.Unlock()
			if e.capture.unchanged(ctx, h.settings, id, false) == nil {
				return e, nil
			}
			h.mu.Lock()
			h.removeLocked(id, e)
			h.mu.Unlock()
			h.release(e)
			force = true
			continue
		}
		if done := h.flights[id]; done != nil {
			h.mu.Unlock()
			select {
			case <-done:
				force = false
				continue
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		if h.inflight >= 2 {
			h.mu.Unlock()
			return nil, errBusy
		}
		for h.used+h.reserved+captureReservation > maxBufferBytes {
			if !h.evictLocked() {
				h.mu.Unlock()
				return nil, errBusy
			}
		}
		done := make(chan struct{})
		h.flights[id] = done
		h.inflight++
		h.reserved += captureReservation
		h.mu.Unlock()
		var c *capture
		var err error
		for attempt := 0; attempt < 2; attempt++ {
			c, err = h.load(ctx, h.settings, id)
			if err == nil || ctx.Err() != nil {
				break
			}
		}
		h.mu.Lock()
		h.inflight--
		h.reserved -= captureReservation
		delete(h.flights, id)
		if old := h.cache[id]; old != nil {
			h.removeLocked(id, old)
		}
		if err == nil {
			for h.used+cap(c.body) > maxCacheBytes {
				if !h.evictLocked() {
					err = errBusy
					break
				}
			}
		}
		var result *observation
		if err == nil {
			result = &observation{capture: c, captured: time.Now(), lastUsed: time.Now(), users: 1, cached: true}
			h.cache[id] = result
			h.used += cap(c.body)
		}
		close(done)
		h.mu.Unlock()
		return result, err
	}
}
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	id := ""
	if r.URL.Path != Path {
		if !strings.HasPrefix(r.URL.Path, Path+"/") {
			fail(w, 404, "not_found")
			return
		}
		id = strings.TrimPrefix(r.URL.Path, Path+"/")
		if !sourceName.MatchString(id) {
			fail(w, 404, "not_found")
			return
		}
	}
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		fail(w, 405, "method_not_allowed")
		return
	}
	if r.Host != h.host || len(r.Header.Values("Origin")) > 1 || r.Header.Get("Origin") != "" && r.Header.Get("Origin") != "https://"+h.host {
		fail(w, 403, "forbidden")
		return
	}
	if r.URL.RawQuery != "" || r.URL.ForceQuery || r.URL.RawPath != "" && r.URL.RawPath != r.URL.Path || r.ContentLength > 0 || len(r.Header.Values("If-None-Match")) > 1 || len(r.Header.Values("Cache-Control")) > 1 {
		fail(w, 400, "invalid_request")
		return
	}
	tag := r.Header.Get("If-None-Match")
	if tag != "" && (len(tag) != 66 || tag[0] != '"' || tag[65] != '"' || !lowerHex(tag[1:65])) {
		fail(w, 400, "invalid_request")
		return
	}
	deadline := time.Now().Add(10 * time.Second)
	if d, ok := r.Context().Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	rc := http.NewResponseController(w)
	if rc.SetReadDeadline(deadline) != nil || rc.SetWriteDeadline(deadline) != nil {
		fail(w, 503, "configuration_viewer_unavailable")
		return
	}
	if raw, e := io.ReadAll(io.LimitReader(r.Body, 1)); e != nil || len(raw) != 0 {
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
	view, e := h.factory.Build(token)
	if e != nil || view.RequireLive() != nil {
		fail(w, 401, "invalid_access")
		return
	}
	if !anyAdmin(view) {
		fail(w, 403, "forbidden")
		return
	}
	if expiry := time.Now().Add(view.ExpiresAt().Sub(h.clock())); expiry.Before(deadline) {
		deadline = expiry
		if rc.SetWriteDeadline(deadline) != nil {
			fail(w, 503, "configuration_viewer_unavailable")
			return
		}
	}
	ctx, cancel := context.WithDeadline(r.Context(), deadline)
	defer cancel()
	if h.settings == nil {
		fail(w, 503, "configuration_viewer_unavailable")
		return
	}
	if id != "" && !permits(view, h.settings.audience(id)) {
		fail(w, 404, "not_found")
		return
	}
	if id == "" {
		all, e := listSources(ctx, h.settings)
		if e != nil {
			fail(w, 503, "configuration_viewer_unavailable")
			return
		}
		out := []Source{}
		for _, s := range all {
			if permits(view, h.settings.audience(s.ID)) {
				out = append(out, s)
			}
		}
		if view.RequireLive() != nil {
			fail(w, 401, "invalid_access")
			return
		}
		if ctx.Err() != nil {
			fail(w, 503, "configuration_viewer_unavailable")
			return
		}
		_ = json.NewEncoder(w).Encode(struct {
			Sources []Source `json:"sources"`
		}{out})
		return
	}
	observation, e := h.observe(ctx, id, r.Header.Get("Cache-Control") == "no-cache")
	if e != nil {
		status := 503
		code := "configuration_source_unavailable"
		if errors.Is(e, os.ErrNotExist) {
			status = 404
			code = "not_found"
		}
		fail(w, status, code)
		return
	}
	defer h.release(observation)
	if view.RequireLive() != nil {
		fail(w, 401, "invalid_access")
		return
	}
	if !permits(view, h.settings.audience(id)) {
		fail(w, 404, "not_found")
		return
	}
	if ctx.Err() != nil || observation.capture.unchanged(ctx, h.settings, id, false) != nil {
		h.mu.Lock()
		h.removeLocked(id, observation)
		h.mu.Unlock()
		fail(w, 503, "configuration_source_unavailable")
		return
	}
	if view.RequireLive() != nil {
		fail(w, 401, "invalid_access")
		return
	}
	w.Header().Set("ETag", observation.capture.tag)
	if tag == observation.capture.tag {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	w.Header().Set("Content-Length", strconv.Itoa(len(observation.capture.body)))
	_, _ = w.Write(observation.capture.body)
}
func lowerHex(v string) bool {
	for _, c := range v {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}
