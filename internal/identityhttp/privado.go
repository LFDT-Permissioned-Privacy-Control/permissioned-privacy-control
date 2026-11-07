package identityhttp

import (
	"io"
	"mime"
	"net/http"
	"strings"
	"time"

	"privacy-proxy/internal/identity"
	b "privacy-proxy/internal/identitybroker"
	"privacy-proxy/internal/identitybroker/privado"
)

func publicRoute(path string) (id, method string, ok bool) {
	for _, row := range []struct{ path, method string }{{Prefix + "privado/requests/", "GET"}, {Prefix + "privado/proofs/", "POST"}} {
		if strings.HasPrefix(path, row.path) {
			id := strings.TrimPrefix(path, row.path)
			if b.ValidUUID(id) {
				return id, row.method, true
			}
		}
	}
	return "", "", false
}
func (h *Handler) publicPrivado(w http.ResponseWriter, r *http.Request) bool {
	id, method, ok := publicRoute(r.URL.Path)
	if !ok {
		return false
	}
	if r.Host != h.host {
		failure(w, 403, "forbidden")
		return true
	}
	if r.URL.RawQuery != "" || r.URL.ForceQuery || r.URL.RawPath != "" && r.URL.RawPath != r.URL.Path {
		failure(w, 400, "invalid_request")
		return true
	}
	w.Header().Set("Access-Control-Allow-Origin", "*")
	if r.Method == "OPTIONS" {
		requested := r.Header.Values("Access-Control-Request-Method")
		if len(requested) != 1 || requested[0] != method || len(r.Header.Values("Access-Control-Request-Private-Network")) != 0 {
			failure(w, 403, "forbidden")
			return true
		}
		headers := r.Header.Values("Access-Control-Request-Headers")
		if len(headers) > 1 || len(headers) == 1 && strings.TrimSpace(headers[0]) != "" && !strings.EqualFold(strings.TrimSpace(headers[0]), "content-type") {
			failure(w, 403, "forbidden")
			return true
		}
		w.Header().Set("Access-Control-Allow-Methods", method)
		if len(headers) == 1 && strings.TrimSpace(headers[0]) != "" {
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		}
		w.WriteHeader(204)
		return true
	}
	if r.Method != method {
		w.Header().Set("Allow", method)
		failure(w, 405, "method_not_allowed")
		return true
	}
	release, ok := h.admit(w)
	if !ok {
		return true
	}
	defer release()
	ctx, cancel := httpOperation(r, w)
	defer cancel()
	if ctx == nil {
		return true
	}
	r = r.WithContext(ctx)
	// Deliberately never parse cookies/Authorization on these two public routes.
	if method == "GET" {
		if r.ContentLength != 0 || len(r.TransferEncoding) != 0 {
			failure(w, 400, "invalid_request")
			return true
		}
		if r.Body != nil {
			data, e := io.ReadAll(io.LimitReader(r.Body, 1))
			if e != nil || len(data) != 0 {
				failure(w, 400, "invalid_request")
				return true
			}
		}
		raw, e := h.service.PublicPrivadoRequest(r.Context(), id)
		if e != nil {
			failService(w, e)
			return true
		}
		if r.Context().Err() != nil {
			failService(w, b.ErrUnavailable)
			return true
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		_, _ = w.Write(raw)
		return true
	}
	types := r.Header.Values("Content-Type")
	if len(types) != 1 || len(r.Header.Values("Content-Encoding")) != 0 || r.Body == nil || r.ContentLength > privado.MaxCompactBytes {
		failService(w, b.ErrInvalid)
		return true
	}
	media, params, e := mime.ParseMediaType(types[0])
	if e != nil || media != "text/plain" || len(params) > 1 {
		failService(w, b.ErrInvalid)
		return true
	}
	for k, v := range params {
		if k != "charset" || !strings.EqualFold(v, "utf-8") {
			failService(w, b.ErrInvalid)
			return true
		}
	}
	data, e := io.ReadAll(io.LimitReader(r.Body, privado.MaxCompactBytes+1))
	if e != nil || len(data) == 0 || len(data) > privado.MaxCompactBytes {
		failService(w, b.ErrInvalid)
		return true
	}
	if e = h.service.OfferPrivadoProof(r.Context(), id, string(data)); e != nil {
		failService(w, e)
		return true
	}
	if r.Context().Err() != nil {
		failService(w, b.ErrUnavailable)
		return true
	}
	w.WriteHeader(http.StatusOK)
	return true
}
func (h *Handler) privadoStart(w http.ResponseWriter, r *http.Request, c requestCookies) {
	var request struct {
		ProfileID         string  `json:"profileId"`
		ExpectedHolderDID *string `json:"expectedHolderDid,omitempty" optional:"true"`
	}
	if decode(r, &request, 4<<10) != nil || h.kinds[request.ProfileID] != identity.PrivadoIdentity && h.kinds[request.ProfileID] != identity.PrivadoRole {
		failService(w, b.ErrInvalid)
		return
	}
	secret := c.recipient
	var e error
	if secret == "" {
		secret, e = newRecipient()
		if e != nil {
			failService(w, e)
			return
		}
	}
	binding, e := recipient(secret)
	if e != nil {
		failService(w, e)
		return
	}
	result, e := h.service.BeginPrivadoLogin(r.Context(), request.ProfileID, request.ExpectedHolderDID, binding)
	if e != nil {
		failService(w, e)
		return
	}
	now, e := h.now()
	if e != nil {
		failService(w, e)
		return
	}
	header, e := cookie(RecipientCookie, secret, now.Add(b.FamilyLifetime), now)
	if e != nil {
		failService(w, e)
		return
	}
	dto := struct {
		RequestID       string  `json:"requestId"`
		RequestURI      string  `json:"requestUri"`
		ExpiresAt       int64   `json:"expiresAt"`
		SourceProfile   string  `json:"sourceProfile"`
		ExpectedActorID *string `json:"expectedActorId"`
	}{result.RequestID, result.RequestURI, result.ExpiresAt.Unix(), result.SourceProfile, result.ExpectedActorID}
	publish(w, r, dto, []string{header}, func() error {
		now, e := h.now()
		if e != nil {
			return e
		}
		return live(r.Context(), now, result.ExpiresAt)
	})
}
func (h *Handler) privadoPreview(w http.ResponseWriter, r *http.Request, c requestCookies) {
	var request struct {
		RequestID string `json:"requestId"`
	}
	if decode(r, &request, 2<<10) != nil || !b.ValidUUID(request.RequestID) {
		failService(w, b.ErrInvalid)
		return
	}
	binding, e := recipient(c.recipient)
	if e != nil {
		failService(w, b.ErrUnauthorized)
		return
	}
	result, e := h.service.PreviewPrivado(r.Context(), request.RequestID, binding)
	if e != nil {
		failService(w, e)
		return
	}
	var dto any
	if result.Candidate == nil {
		dto = struct {
			Status        string `json:"status"`
			RequestID     string `json:"requestId"`
			SourceProfile string `json:"sourceProfile"`
			ExpiresAt     int64  `json:"expiresAt"`
		}{"waiting", result.RequestID, result.SourceProfile, result.ExpiresAt}
	} else {
		v := result.Candidate
		dto = struct {
			Status        string `json:"status"`
			RequestID     string `json:"requestId"`
			HolderDID     string `json:"holderDid"`
			Network       string `json:"network"`
			ActorID       string `json:"actorId"`
			SourceProfile string `json:"sourceProfile"`
			ProofDigest   string `json:"proofDigest"`
			VerifiedAt    int64  `json:"verifiedAt"`
			ExpiresAt     int64  `json:"expiresAt"`
		}{"candidate", result.RequestID, v.HolderDID, v.Network, v.ActorID, v.SourceProfile, v.ProofDigest, v.VerifiedAt, v.ExpiresAt}
	}
	publish(w, r, dto, nil, func() error {
		now, e := h.now()
		if e != nil {
			return e
		}
		return live(r.Context(), now, time.Unix(result.ExpiresAt, 0))
	})
}
func (h *Handler) privadoComplete(w http.ResponseWriter, r *http.Request, c requestCookies) {
	var request struct {
		RequestID         string  `json:"requestId"`
		ExpectedActorID   string  `json:"expectedActorId"`
		ExpectedHolderDID string  `json:"expectedHolderDid"`
		ProofDigest       string  `json:"proofDigest"`
		ExpectedSessionID *string `json:"expectedSessionId,omitempty" optional:"true"`
	}
	if decode(r, &request, 4<<10) != nil {
		failService(w, b.ErrInvalid)
		return
	}
	digest, e := b.ParseDigest(request.ProofDigest)
	if e != nil {
		failService(w, b.ErrInvalid)
		return
	}
	binding, e := recipient(c.recipient)
	if e != nil {
		failService(w, b.ErrUnauthorized)
		return
	}
	result, e := h.service.CompletePrivado(r.Context(), request.RequestID, binding, b.PrivadoConfirmation{ExpectedActorID: request.ExpectedActorID, ExpectedHolderDID: request.ExpectedHolderDID, ProofDigest: digest, ExpectedSessionID: request.ExpectedSessionID}, c.renewal)
	if e != nil {
		failService(w, e)
		return
	}
	h.publishBrowser(w, r, c, result)
}
