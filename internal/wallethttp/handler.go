// Package wallethttp exposes only authenticated self-service wallet operations.
package wallethttp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"privacy-proxy/internal/strictjson"
	"privacy-proxy/internal/walletops"
)

type Handler struct{ service *walletops.Service }

func New(service *walletops.Service) (*Handler, error) {
	if service == nil {
		return nil, walletops.ErrInvalid
	}
	return &Handler{service}, nil
}
func (h *Handler) Register(mux *http.ServeMux) {
	h.RegisterLinks(mux)
	mux.HandleFunc("POST /api/v2/eth/addresses/{address}/refresh-ens", h.wrap(h.ens))
}

// RegisterLinks mounts the four native ownership operations without the
// optional ENS resolver surface. The selected V2 composition uses this set.
func (h *Handler) RegisterLinks(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/v2/eth/link/challenge", h.wrap(h.issue))
	mux.HandleFunc("POST /api/v2/eth/link/verify", h.wrap(h.verify))
	mux.HandleFunc("GET /api/v2/eth/addresses", h.wrap(h.own))
	mux.HandleFunc("DELETE /api/v2/eth/addresses/{address}", h.wrap(h.unlink))
}

type operation func(context.Context, string, *http.Request) (*walletops.Response, error)

func (h *Handler) wrap(op operation) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		if r.Method == http.MethodHead {
			w.Header().Set("Allow", "GET")
			w.WriteHeader(405)
			return
		}
		if len(r.URL.RawQuery) > 4096 || r.URL.RawQuery != "" {
			writeError(w, walletops.ErrInvalid)
			return
		}
		values := r.Header.Values("Authorization")
		if len(values) != 1 || len(values[0]) > 32<<10 {
			writeError(w, walletops.ErrUnauthorized)
			return
		}
		scheme, token, ok := strings.Cut(values[0], " ")
		if !ok || !strings.EqualFold(scheme, "Bearer") || token == "" || strings.ContainsAny(token, " \t\r\n,") {
			writeError(w, walletops.ErrUnauthorized)
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
	status, message := 503, "wallet service unavailable"
	switch {
	case errors.Is(err, walletops.ErrUnauthorized):
		status, message = 401, "invalid or expired access"
	case errors.Is(err, walletops.ErrInvalid):
		status, message = 400, "invalid wallet request"
	case errors.Is(err, walletops.ErrNotFound):
		status, message = 404, "wallet link not found"
	case errors.Is(err, walletops.ErrConflict):
		status, message = 409, "wallet state conflict"
	}
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(struct {
		Error string `json:"error"`
	}{message})
}
func decode(r *http.Request, out any) error {
	if r.ContentLength > walletops.MaxRequestBytes {
		return walletops.ErrInvalid
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, walletops.MaxRequestBytes+1))
	if err != nil || len(raw) > walletops.MaxRequestBytes || !utf8.Valid(raw) {
		return walletops.ErrInvalid
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	v, err := strictjson.ReadValue(d, 0, 16)
	if err != nil {
		return walletops.ErrInvalid
	}
	if _, err := d.Token(); err != io.EOF {
		return walletops.ErrInvalid
	}
	if strictjson.ExactDecode(v, out) != nil {
		return walletops.ErrInvalid
	}
	return nil
}
func empty(r *http.Request) error {
	if r.ContentLength > 0 {
		return walletops.ErrInvalid
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, 1))
	if err != nil || len(raw) != 0 {
		return walletops.ErrInvalid
	}
	return nil
}
func (h *Handler) issue(ctx context.Context, token string, r *http.Request) (*walletops.Response, error) {
	var req walletops.ChallengeRequest
	if err := decode(r, &req); err != nil {
		return nil, err
	}
	return h.service.Issue(ctx, token, req)
}
func (h *Handler) verify(ctx context.Context, token string, r *http.Request) (*walletops.Response, error) {
	var req walletops.VerifyRequest
	if err := decode(r, &req); err != nil {
		return nil, err
	}
	return h.service.Verify(ctx, token, req)
}
func (h *Handler) own(ctx context.Context, token string, r *http.Request) (*walletops.Response, error) {
	if err := empty(r); err != nil {
		return nil, err
	}
	return h.service.Own(ctx, token)
}
func (h *Handler) unlink(ctx context.Context, token string, r *http.Request) (*walletops.Response, error) {
	if err := empty(r); err != nil {
		return nil, err
	}
	return h.service.Unlink(ctx, token, r.PathValue("address"))
}
func (h *Handler) ens(ctx context.Context, token string, r *http.Request) (*walletops.Response, error) {
	if err := empty(r); err != nil {
		return nil, err
	}
	return h.service.RefreshENS(ctx, token, r.PathValue("address"))
}
