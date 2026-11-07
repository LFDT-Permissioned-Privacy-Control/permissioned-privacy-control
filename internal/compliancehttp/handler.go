// Package compliancehttp mounts the finite native V2 operational compliance API.
// Policy, thresholds, sanctions and prices are read-only approved source views.
package compliancehttp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	a "privacy-proxy/internal/admission"
	"privacy-proxy/internal/strictjson"
)

const MaxRawQueryBytes = 16 << 10

type Handler struct{ service *a.Service }

func New(service *a.Service) (*Handler, error) {
	if !service.AdminReady() {
		return nil, a.ErrInvalid
	}
	return &Handler{service}, nil
}
func (h *Handler) Register(mux *http.ServeMux) {
	base := "/api/v2/orgs/{orgId}/compliance/"
	for _, section := range []string{"config", "tokens", "address-thresholds", "sanctions", "quotes"} {
		mux.HandleFunc("GET "+base+section, h.wrap(func(ctx context.Context, token string, r *http.Request) (*a.Response, error) {
			if _, err := query(r); err != nil {
				return nil, err
			}
			if err := empty(r); err != nil {
				return nil, err
			}
			return h.service.SelectedPolicy(ctx, token, r.PathValue("orgId"), section)
		}))
	}
	mux.HandleFunc("POST "+base+"travel-rule-records", h.wrap(h.create))
	mux.HandleFunc("GET "+base+"travel-rule-records", h.wrap(h.listRecords))
	mux.HandleFunc("GET "+base+"travel-rule-records/{recordId}", h.wrap(h.get))
	mux.HandleFunc("DELETE "+base+"travel-rule-records/{recordId}", h.wrap(h.delete))
	mux.HandleFunc("GET "+base+"events", h.wrap(h.listEvents))
	mux.HandleFunc("POST "+base+"preview", h.wrap(h.preview))
}

type operation func(context.Context, string, *http.Request) (*a.Response, error)

func (h *Handler) wrap(op operation) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		if r.Method == http.MethodHead {
			w.Header().Set("Allow", "GET")
			w.WriteHeader(405)
			return
		}
		values := r.Header.Values("Authorization")
		if len(values) != 1 || len(values[0]) > 32<<10 {
			writeError(w, a.ErrUnauthorized)
			return
		}
		scheme, token, ok := strings.Cut(values[0], " ")
		if !ok || !strings.EqualFold(scheme, "Bearer") || token == "" || strings.ContainsAny(token, " \t\r\n,") {
			writeError(w, a.ErrUnauthorized)
			return
		}
		if !a.ValidUUID(r.PathValue("orgId")) {
			writeError(w, a.ErrInvalid)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		response, err := op(ctx, token, r)
		if err != nil {
			writeError(w, err)
			return
		}
		writer := &statusWriter{ResponseWriter: w}
		if _, err := response.WriteTo(writer); err != nil && !writer.wrote {
			writeError(w, err)
		}
	}
}

type statusWriter struct {
	http.ResponseWriter
	wrote bool
}

func (w *statusWriter) Write(raw []byte) (int, error) {
	if !w.wrote {
		w.WriteHeader(200)
		w.wrote = true
	}
	return w.ResponseWriter.Write(raw)
}
func writeError(w http.ResponseWriter, err error) {
	status, message := 503, "compliance service unavailable"
	switch {
	case errors.Is(err, a.ErrUnauthorized):
		status, message = 401, "invalid or expired access"
	case errors.Is(err, a.ErrForbidden):
		status, message = 403, "compliance administration not authorized"
	case errors.Is(err, a.ErrNotFound):
		status, message = 404, "operational record not found"
	case errors.Is(err, a.ErrConflict):
		status, message = 409, "operational state conflict"
	case errors.Is(err, a.ErrInvalid):
		status, message = 400, "invalid compliance request"
	case errors.Is(err, a.ErrValuation):
		status, message = 422, "qualified valuation unavailable"
	}
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(struct {
		Error string `json:"error"`
	}{message})
}
func decode(r *http.Request, out any, max int) error {
	if r.ContentLength > int64(max) {
		return a.ErrInvalid
	}
	if typ := r.Header.Get("Content-Type"); typ != "" {
		parsed, _, err := mime.ParseMediaType(typ)
		if err != nil || parsed != "application/json" {
			return a.ErrInvalid
		}
	}
	if encoding := r.Header.Get("Content-Encoding"); encoding != "" && encoding != "identity" {
		return a.ErrInvalid
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, int64(max)+1))
	if err != nil || len(raw) > max || !utf8.Valid(raw) {
		return a.ErrInvalid
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	value, err := strictjson.ReadValue(d, 0, 20)
	if err != nil {
		return a.ErrInvalid
	}
	if _, err := d.Token(); err != io.EOF {
		return a.ErrInvalid
	}
	if strictjson.ExactDecode(value, out) != nil {
		return a.ErrInvalid
	}
	return nil
}
func empty(r *http.Request) error {
	if r.ContentLength > 0 {
		return a.ErrInvalid
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, 1))
	if err != nil || len(raw) != 0 {
		return a.ErrInvalid
	}
	return nil
}
func query(r *http.Request, allowed ...string) (url.Values, error) {
	if len(r.URL.RawQuery) > MaxRawQueryBytes {
		return nil, a.ErrInvalid
	}
	values, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		return nil, a.ErrInvalid
	}
	for name, list := range values {
		found := false
		for _, s := range allowed {
			found = found || s == name
		}
		if !found || len(list) != 1 {
			return nil, a.ErrInvalid
		}
	}
	return values, nil
}
func options(r *http.Request) (a.ListOptions, error) {
	q, err := query(r, "limit", "cursor")
	if err != nil {
		return a.ListOptions{}, err
	}
	if err := empty(r); err != nil {
		return a.ListOptions{}, err
	}
	out := a.ListOptions{Cursor: q.Get("cursor")}
	if raw := q.Get("limit"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 1 || n > 100 || strconv.Itoa(n) != raw {
			return out, a.ErrInvalid
		}
		out.Limit = n
	}
	return out, nil
}
func (h *Handler) create(ctx context.Context, token string, r *http.Request) (*a.Response, error) {
	if _, err := query(r); err != nil {
		return nil, err
	}
	var req a.CreateRecordRequest
	if err := decode(r, &req, a.MaxRequestBytes); err != nil {
		return nil, err
	}
	return h.service.CreateRecord(ctx, token, r.PathValue("orgId"), req)
}
func (h *Handler) get(ctx context.Context, token string, r *http.Request) (*a.Response, error) {
	if _, err := query(r); err != nil {
		return nil, err
	}
	if err := empty(r); err != nil {
		return nil, err
	}
	return h.service.GetRecord(ctx, token, r.PathValue("orgId"), r.PathValue("recordId"))
}
func (h *Handler) delete(ctx context.Context, token string, r *http.Request) (*a.Response, error) {
	if _, err := query(r); err != nil {
		return nil, err
	}
	if err := empty(r); err != nil {
		return nil, err
	}
	return h.service.DeleteUnused(ctx, token, r.PathValue("orgId"), r.PathValue("recordId"))
}
func (h *Handler) listRecords(ctx context.Context, token string, r *http.Request) (*a.Response, error) {
	opts, err := options(r)
	if err != nil {
		return nil, err
	}
	return h.service.ListRecords(ctx, token, r.PathValue("orgId"), opts)
}
func (h *Handler) listEvents(ctx context.Context, token string, r *http.Request) (*a.Response, error) {
	opts, err := options(r)
	if err != nil {
		return nil, err
	}
	return h.service.ListEvents(ctx, token, r.PathValue("orgId"), opts)
}
func (h *Handler) preview(ctx context.Context, token string, r *http.Request) (*a.Response, error) {
	if _, err := query(r); err != nil {
		return nil, err
	}
	var req a.PreviewRequest
	if err := decode(r, &req, a.MaxPreviewBytes); err != nil {
		return nil, err
	}
	return h.service.FinancialPreview(ctx, token, r.PathValue("orgId"), req)
}
