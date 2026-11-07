package disclosurehttp

import (
	"context"
	"io"
	"mime"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	c "privacy-proxy/internal/disclosurecase"
	d "privacy-proxy/internal/disclosuredata"
)

func NewWithData(service *c.Service) (*Handler, error) {
	if service == nil || !service.DataEnabled() {
		return nil, c.ErrInvalid
	}
	return &Handler{service: service, data: true}, nil
}
func dataBoundary(r *http.Request) error {
	if len(r.Header.Values("Content-Encoding")) > 1 {
		return c.ErrInvalid
	}
	encoding := r.Header.Get("Content-Encoding")
	if encoding != "" && encoding != "identity" {
		return c.ErrInvalid
	}
	if r.ContentLength > c.MaxRequestBytes {
		return c.ErrInvalid
	}
	if r.Method == http.MethodPost {
		if len(r.Header.Values("Content-Type")) != 1 {
			return c.ErrInvalid
		}
		media, params, e := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if e != nil || media != "application/json" {
			return c.ErrInvalid
		}
		for k, v := range params {
			if k != "charset" || !strings.EqualFold(v, "utf-8") {
				return c.ErrInvalid
			}
		}
	}
	return nil
}
func dataDeadlines(w http.ResponseWriter) error {
	controller := http.NewResponseController(w)
	until := time.Now().Add(5 * time.Second)
	if controller.SetReadDeadline(until) != nil || controller.SetWriteDeadline(until) != nil {
		return c.ErrUnavailable
	}
	return nil
}
func (h *Handler) read(ctx context.Context, token string, r *http.Request) (*c.Response, error) {
	if r.URL.RawQuery != "" {
		return nil, c.ErrInvalid
	}
	raw, e := io.ReadAll(io.LimitReader(r.Body, d.MaxRequestBytes+1))
	if e != nil || len(raw) > d.MaxRequestBytes || !utf8.Valid(raw) {
		return nil, c.ErrInvalid
	}
	q, e := d.DecodeQuery(raw)
	if e != nil {
		return nil, e
	}
	return h.service.Read(ctx, token, r.PathValue("id"), q)
}
