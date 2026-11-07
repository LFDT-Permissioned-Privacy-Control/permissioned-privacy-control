// Package disclosurehttp mounts the finite V2 case administration routes. It
// mounts no data/report, user-directory or end-user approval endpoint.
package disclosurehttp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"privacy-proxy/internal/disclosurecase"
	"privacy-proxy/internal/strictjson"
)

type Handler struct{ service *disclosurecase.Service }

const MaxRawQueryBytes = 16 << 10

func New(service *disclosurecase.Service) (*Handler, error) {
	if service == nil {
		return nil, disclosurecase.ErrInvalid
	}
	return &Handler{service: service}, nil
}
func (h *Handler) Register(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/v1/disclosure/cases", h.wrap(h.create))
	mux.HandleFunc("GET /api/v1/disclosure/cases", h.wrap(h.list))
	mux.HandleFunc("GET /api/v1/disclosure/cases/{id}", h.wrap(h.get))
	mux.HandleFunc("POST /api/v1/disclosure/cases/{id}/revoke", h.wrap(h.revoke))
	mux.HandleFunc("GET /api/v1/disclosure/cases/{id}/audit", h.wrap(h.audit))
}

type operation func(context.Context, string, *http.Request) (*disclosurecase.Response, error)

func (h *Handler) wrap(op operation) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		// ServeMux normally matches HEAD against GET; the closed component
		// contract deliberately executes only its named GET/POST operations.
		if r.Method == http.MethodHead {
			w.Header().Set("Allow", "GET")
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		token, err := bearer(r)
		if err != nil {
			writeError(w, err)
			return
		}
		response, err := op(ctx, token, r)
		if err != nil {
			writeError(w, err)
			return
		}
		writer := &statusWriter{ResponseWriter: w, status: response.Status()}
		if _, err := response.WriteTo(writer); err != nil && !writer.wrote {
			writeError(w, err)
		}
	}
}

type statusWriter struct {
	http.ResponseWriter
	status int
	wrote  bool
}

func (w *statusWriter) Write(raw []byte) (int, error) {
	if !w.wrote {
		w.ResponseWriter.WriteHeader(w.status)
		w.wrote = true
	}
	return w.ResponseWriter.Write(raw)
}
func bearer(r *http.Request) (string, error) {
	values := r.Header.Values("Authorization")
	if len(values) != 1 || len(values[0]) > 32<<10 {
		return "", disclosurecase.ErrUnauthorized
	}
	scheme, token, ok := strings.Cut(values[0], " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") || token == "" || strings.ContainsAny(token, " \t\r\n,") {
		return "", disclosurecase.ErrUnauthorized
	}
	return token, nil
}
func writeError(w http.ResponseWriter, err error) {
	status, message := http.StatusServiceUnavailable, "disclosure service unavailable"
	switch {
	case errors.Is(err, disclosurecase.ErrUnauthorized):
		status, message = 401, "invalid or expired access"
	case errors.Is(err, disclosurecase.ErrNotFound):
		status, message = 404, "disclosure case not found"
	case errors.Is(err, disclosurecase.ErrConflict):
		status, message = 409, "disclosure context changed"
	case errors.Is(err, disclosurecase.ErrInvalid):
		status, message = 400, "invalid disclosure request"
	}
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(struct {
		Error string `json:"error"`
	}{message})
}
func decode(r *http.Request, out any) error {
	if r.ContentLength > disclosurecase.MaxRequestBytes {
		return disclosurecase.ErrInvalid
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, disclosurecase.MaxRequestBytes+1))
	if err != nil || len(raw) > disclosurecase.MaxRequestBytes || !utf8.Valid(raw) {
		return disclosurecase.ErrInvalid
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	value, err := strictjson.ReadValue(d, 0, 16)
	if err != nil {
		return disclosurecase.ErrInvalid
	}
	if _, err := d.Token(); err != io.EOF {
		return disclosurecase.ErrInvalid
	}
	if strictjson.ExactDecode(value, out) != nil {
		return disclosurecase.ErrInvalid
	}
	return nil
}
func query(r *http.Request, allowed ...string) error {
	if len(r.URL.RawQuery) > MaxRawQueryBytes {
		return disclosurecase.ErrInvalid
	}
	values, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		return disclosurecase.ErrInvalid
	}
	for name, list := range values {
		found := false
		for _, entry := range allowed {
			found = found || entry == name
		}
		if !found || len(list) != 1 {
			return disclosurecase.ErrInvalid
		}
	}
	return nil
}
func (h *Handler) create(ctx context.Context, token string, r *http.Request) (*disclosurecase.Response, error) {
	if query(r) != nil {
		return nil, disclosurecase.ErrInvalid
	}
	var request disclosurecase.CreateRequest
	if err := decode(r, &request); err != nil {
		return nil, err
	}
	return h.service.Create(ctx, token, request)
}
func (h *Handler) get(ctx context.Context, token string, r *http.Request) (*disclosurecase.Response, error) {
	if query(r) != nil {
		return nil, disclosurecase.ErrInvalid
	}
	return h.service.Get(ctx, token, r.PathValue("id"))
}
func (h *Handler) revoke(ctx context.Context, token string, r *http.Request) (*disclosurecase.Response, error) {
	if query(r) != nil {
		return nil, disclosurecase.ErrInvalid
	}
	var request struct {
		Reason string `json:"reason"`
	}
	if err := decode(r, &request); err != nil {
		return nil, err
	}
	return h.service.Revoke(ctx, token, r.PathValue("id"), request.Reason)
}
func limit(r *http.Request) (int, error) {
	raw := r.URL.Query().Get("limit")
	if raw == "" {
		return 0, nil
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < 1 || n > 100 || strconv.Itoa(n) != raw {
		return 0, disclosurecase.ErrInvalid
	}
	return n, nil
}
func (h *Handler) list(ctx context.Context, token string, r *http.Request) (*disclosurecase.Response, error) {
	if query(r, "role", "organizationId", "limit", "cursor") != nil {
		return nil, disclosurecase.ErrInvalid
	}
	n, err := limit(r)
	if err != nil {
		return nil, err
	}
	q := r.URL.Query()
	return h.service.List(ctx, token, disclosurecase.ListOptions{Role: q.Get("role"), Organization: q.Get("organizationId"), Cursor: q.Get("cursor"), Limit: n})
}
func (h *Handler) audit(ctx context.Context, token string, r *http.Request) (*disclosurecase.Response, error) {
	if query(r, "limit", "cursor") != nil {
		return nil, disclosurecase.ErrInvalid
	}
	n, err := limit(r)
	if err != nil {
		return nil, err
	}
	return h.service.Audit(ctx, token, r.PathValue("id"), r.URL.Query().Get("cursor"), n)
}
