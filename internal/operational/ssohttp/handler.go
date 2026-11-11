package ssohttp

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"github.com/google/uuid"
	"io"
	"net/http"
	"net/url"
	"privacy-proxy/internal/identity"
	b "privacy-proxy/internal/identitybroker"
	"privacy-proxy/internal/identityhttp"
	"privacy-proxy/internal/operational/ssosql"
	"privacy-proxy/internal/runtimepolicy"
	m "privacy-proxy/internal/ssotransaction"
	"time"
)

const Prefix = "/api/v2/sso/"

type InspectRequest struct {
	Action string `json:"action"`
	FlowID string `json:"flowId"`
}
type CompleteRequest struct {
	Action            string `json:"action"`
	FlowID            string `json:"flowId"`
	ExpectedActorID   string `json:"expectedActorId"`
	ExpectedSessionID string `json:"expectedSessionId"`
}
type InspectResponse struct {
	ClientID    string `json:"clientId"`
	DisplayName string `json:"displayName"`
	ExpiresAt   int64  `json:"expiresAt"`
	Phase       string `json:"phase"`
}
type CompleteResponse struct {
	RedirectTo string `json:"redirectTo"`
}
type TokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int64  `json:"expires_in"`
}

func (h *Handler) Register(mux *http.ServeMux) {
	for _, p := range []string{"authorize", "flow", "token"} {
		mux.Handle(Prefix+p, h)
	}
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }
func (w *statusWriter) WriteHeader(n int) {
	if w.status == 0 {
		w.status = n
	}
	w.ResponseWriter.WriteHeader(n)
}
func (w *statusWriter) Write(raw []byte) (int, error) {
	if w.status == 0 {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(raw)
}
func fail(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = io.WriteString(w, `{"error":"`+code+`"}`+"\n")
}
func unavailable(w http.ResponseWriter, e error) {
	switch {
	case errors.Is(e, b.ErrUnauthorized), errors.Is(e, b.ErrRelogin), errors.Is(e, b.ErrSessionChanged):
		fail(w, 403, "access_denied")
	case errors.Is(e, ssosql.ErrNotFound), errors.Is(e, ssosql.ErrConflict), errors.Is(e, ssosql.ErrExpired):
		fail(w, 400, "invalid_grant")
	default:
		fail(w, 503, "temporarily_unavailable")
	}
}
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	sw := &statusWriter{ResponseWriter: w}
	w = sw
	label := "unknown"
	switch r.URL.Path {
	case Prefix + "authorize":
		label = "authorize"
	case Prefix + "flow":
		label = "flow"
	case Prefix + "token":
		label = "token"
	}
	defer func() {
		if sw.status >= 400 {
			h.log.WarnContext(r.Context(), "SSO request rejected", "route", label, "client", "unknown", "status", sw.status)
		}
	}()
	deadline := time.Now().Add(20 * time.Second)
	if d, ok := r.Context().Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	rc := http.NewResponseController(w)
	if rc.SetReadDeadline(deadline) != nil || rc.SetWriteDeadline(deadline) != nil {
		fail(w, 503, "temporarily_unavailable")
		return
	}
	ctx, cancel := context.WithDeadline(r.Context(), deadline)
	defer cancel()
	r = r.WithContext(ctx)
	if label == "unknown" {
		fail(w, 404, "invalid_request")
		return
	}
	want := "POST"
	if label == "authorize" {
		want = "GET"
	}
	if r.Method != want {
		w.Header().Set("Allow", want)
		fail(w, 405, "invalid_request")
		return
	}
	if r.Host != h.host {
		fail(w, 403, "access_denied")
		return
	}
	if r.URL.RawPath != "" && r.URL.RawPath != r.URL.Path || r.URL.ForceQuery || label != "authorize" && r.URL.RawQuery != "" {
		fail(w, 400, "invalid_request")
		return
	}
	origins := r.Header.Values("Origin")
	if label == "token" {
		if len(origins) != 0 || len(r.Header.Values("Cookie")) != 0 {
			fail(w, 403, "access_denied")
			return
		}
	} else if label == "flow" || len(origins) > 0 {
		if len(origins) != 1 || origins[0] != h.origin {
			fail(w, 403, "access_denied")
			return
		}
	}
	release, ok := h.broker.TryAdmitHTTP()
	if !ok {
		fail(w, 503, "temporarily_unavailable")
		return
	}
	defer release()
	switch label {
	case "authorize":
		h.authorize(w, r)
	case "flow":
		h.flow(w, r)
	case "token":
		h.token(w, r)
	}
}
func randomToken() (string, error) {
	raw := make([]byte, 32)
	if _, e := rand.Read(raw); e != nil {
		return "", b.ErrUnavailable
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}
func body(v any, max int) ([]byte, error) {
	raw, e := json.Marshal(v)
	if e != nil || len(raw)+1 > max {
		return nil, b.ErrUnavailable
	}
	return append(raw, '\n'), nil
}
func output(raw []byte) m.PreparedOutput {
	return m.PreparedOutput{Digest: m.Digest(sha256.Sum256(raw)), Bytes: uint32(len(raw))}
}
func send(w http.ResponseWriter, raw []byte) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(200)
	_, _ = w.Write(raw)
}
func (h *Handler) localGate(ctx context.Context, start, expiry time.Time, v *runtimepolicy.View) func() error {
	return func() error {
		if ctx.Err() != nil {
			return b.ErrUnavailable
		}
		at, e := h.now()
		if e != nil {
			return e
		}
		if at.Before(start) || !at.Before(expiry) {
			return b.ErrUnauthorized
		}
		if v != nil {
			return v.RequireLive()
		}
		return nil
	}
}
func receiptMatches(r ssosql.Receipt, id string, scope m.Scope, phase m.Phase) bool {
	c := r.Capture()
	return c.Valid() && c.ID == id && c.Scope == scope && c.Phase == phase
}
func (h *Handler) authorize(w http.ResponseWriter, r *http.Request) {
	if r.ContentLength != 0 || len(r.TransferEncoding) != 0 || len(r.Header.Values("Content-Encoding")) != 0 || len(r.Header.Values("Authorization")) != 0 {
		fail(w, 400, "invalid_request")
		return
	}
	if r.Body != nil {
		raw, e := io.ReadAll(io.LimitReader(r.Body, 1))
		if e != nil || len(raw) != 0 {
			fail(w, 400, "invalid_request")
			return
		}
	}
	q, e := fields(r.URL.RawQuery, []string{"client_id", "redirect_uri", "response_type", "state", "code_challenge", "code_challenge_method"}, []string{"response_mode"}, 8192)
	if e != nil || q.Get("response_type") != "code" || q.Get("code_challenge_method") != "S256" || q.Has("response_mode") && q.Get("response_mode") != "redirect" || !ascii(q.Get("state"), 1, 512, true) || !canonicalToken(q.Get("code_challenge")) {
		fail(w, 400, "invalid_request")
		return
	}
	client, ok := h.clients.Client(q.Get("client_id"))
	if !ok {
		fail(w, 400, "invalid_request")
		return
	}
	registered := false
	for _, u := range client.Source().RedirectURIs {
		registered = registered || u == q.Get("redirect_uri")
	}
	if !registered {
		fail(w, 400, "invalid_request")
		return
	}
	cookies, e := identityhttp.ReadCentralCookies(r)
	if e != nil {
		fail(w, 400, "invalid_request")
		return
	}
	recipient := cookies.Recipient
	if recipient == "" {
		recipient, e = randomToken()
		if e != nil {
			unavailable(w, e)
			return
		}
	}
	binding, e := identityhttp.CentralRecipientBinding(recipient)
	if e != nil {
		fail(w, 400, "invalid_request")
		return
	}
	at, e := h.now()
	if e != nil {
		unavailable(w, e)
		return
	}
	expires := at.Add(5 * time.Minute)
	cookie, e := identityhttp.CentralRecipientCookie(recipient, at.Add(b.FamilyLifetime), at)
	if e != nil {
		unavailable(w, e)
		return
	}
	id, e := uuid.NewRandom()
	if e != nil {
		unavailable(w, b.ErrUnavailable)
		return
	}
	challenge, _ := base64.RawURLEncoding.DecodeString(q.Get("code_challenge"))
	var pkce m.Digest
	copy(pkce[:], challenge)
	p := m.PendingRecord{ID: id.String(), Scope: h.scope, ClientID: client.Source().ID, ClientCatalogDigest: h.clientsDigest, IdentityDigest: h.identityDigest, Recipient: m.Digest(binding), StateHash: hashed("ops-sso-state/v1", q.Get("state")), RedirectHash: hashed("ops-sso-redirect/v1", q.Get("redirect_uri")), PKCES256: pkce, ContextKeyID: h.runtime.ContextKey.ID, CreatedAt: micros(at), ExpiresAt: micros(expires)}
	p.ContextCiphertext, e = seal(h.contextCipher, contextPayload{1, p.ClientID, q.Get("redirect_uri"), q.Get("state")}, h.contextAAD(p), m.MaxContextCipherBytes)
	if e != nil {
		unavailable(w, e)
		return
	}
	gate := h.localGate(r.Context(), at, expires, nil)
	receipt, e := h.store.InsertPending(r.Context(), p, gate)
	if e != nil {
		unavailable(w, e)
		return
	}
	if !receiptMatches(receipt, p.ID, p.Scope, m.Pending) {
		unavailable(w, b.ErrUnavailable)
		return
	}
	if e = gate(); e != nil {
		unavailable(w, e)
		return
	}
	w.Header().Add("Set-Cookie", cookie)
	w.Header().Set("Location", h.origin+"/auth/sso?flow="+p.ID)
	w.WriteHeader(http.StatusSeeOther)
}
func (h *Handler) flow(w http.ResponseWriter, r *http.Request) {
	raw, e := boundedBody(r, "application/json", 2048)
	if e != nil {
		fail(w, 400, "invalid_request")
		return
	}
	var action struct {
		Action string `json:"action"`
	}
	if json.Unmarshal(raw, &action) != nil {
		fail(w, 400, "invalid_request")
		return
	}
	var id string
	var expected b.ExpectedSession
	var jwt string
	switch action.Action {
	case "inspect":
		var req InspectRequest
		if closed(raw, &req, 2048) != nil || req.Action != "inspect" || !m.ValidUUID(req.FlowID) || len(r.Header.Values("Authorization")) != 0 {
			fail(w, 400, "invalid_request")
			return
		}
		id = req.FlowID
	case "complete":
		var req CompleteRequest
		if closed(raw, &req, 2048) != nil || req.Action != "complete" || !m.ValidUUID(req.FlowID) {
			fail(w, 400, "invalid_request")
			return
		}
		id = req.FlowID
		expected = b.ExpectedSession{ActorID: req.ExpectedActorID, SessionID: req.ExpectedSessionID}
		if !expected.Valid() {
			fail(w, 400, "invalid_request")
			return
		}
		jwt, e = bearer(r)
		if e != nil {
			fail(w, 403, "access_denied")
			return
		}
	default:
		fail(w, 400, "invalid_request")
		return
	}
	cookies, e := identityhttp.ReadCentralCookies(r)
	if e != nil {
		fail(w, 400, "invalid_request")
		return
	}
	binding, e := identityhttp.CentralRecipientBinding(cookies.Recipient)
	if e != nil {
		fail(w, 403, "access_denied")
		return
	}
	record, e := h.store.ReadFlow(r.Context(), id, m.Digest(binding))
	if e != nil {
		unavailable(w, e)
		return
	}
	payload, e := h.openContext(record)
	if e != nil {
		unavailable(w, e)
		return
	}
	if action.Action == "inspect" {
		client, _ := h.clients.Client(payload.ClientID)
		phase := "pending"
		if record.Phase == m.Ready {
			phase = "ready"
		} else if record.Phase != m.Pending {
			fail(w, 400, "invalid_grant")
			return
		}
		out, e := body(InspectResponse{payload.ClientID, client.Source().DisplayName, int64(record.Pending.ExpiresAt) / 1000000, phase}, 2048)
		if e != nil {
			unavailable(w, e)
			return
		}
		at, e := h.now()
		if e != nil {
			unavailable(w, e)
			return
		}
		if e = h.localGate(r.Context(), at, time.UnixMicro(int64(record.Pending.ExpiresAt)), nil)(); e != nil {
			unavailable(w, e)
			return
		}
		send(w, out)
		return
	}
	if record.Phase != m.Pending || cookies.Renewal == "" {
		fail(w, 400, "invalid_grant")
		return
	}
	h.complete(w, r, record, payload, jwt, cookies.Renewal, binding, expected)
}
func (h *Handler) verifiedSession(ctx context.Context, clientID, jwt, handle string, recipient b.RecipientBinding, expected b.ExpectedSession) (*runtimepolicy.View, *b.SessionBinding, b.SessionBindingMetadata, error) {
	v, e := h.factory.Build(jwt)
	if e != nil {
		return nil, nil, b.SessionBindingMetadata{}, b.ErrUnauthorized
	}
	client, ok := h.clients.Client(clientID)
	if !ok || h.eligible(client, v) != nil {
		return nil, nil, b.SessionBindingMetadata{}, b.ErrUnauthorized
	}
	session, e := h.broker.AuthenticateCurrentSession(ctx, handle, recipient, expected)
	if e != nil {
		return nil, nil, b.SessionBindingMetadata{}, e
	}
	meta, e := session.MetadataFor(h.broker)
	if e != nil {
		return nil, nil, meta, e
	}
	profile, digest := v.SourceProfile()
	if v.Kind() != identity.Human || v.ActorID() != meta.ActorID || profile != meta.ProfileID || digest != meta.ProfileDigest || !v.ExpiresAt().After(time.Unix(0, 0)) {
		return nil, nil, meta, b.ErrUnauthorized
	}
	return v, session, meta, nil
}
func (h *Handler) complete(w http.ResponseWriter, r *http.Request, record m.Record, payload contextPayload, jwt, handle string, recipient b.RecipientBinding, expected b.ExpectedSession) {
	v, session, meta, e := h.verifiedSession(r.Context(), payload.ClientID, jwt, handle, recipient, expected)
	if e != nil {
		unavailable(w, e)
		return
	}
	at, e := h.now()
	if e != nil {
		unavailable(w, e)
		return
	}
	expiry := minTime(at.Add(time.Minute), time.UnixMicro(int64(record.Pending.ExpiresAt)), v.ExpiresAt(), meta.AbsoluteExpiresAt)
	code, e := randomToken()
	if e != nil {
		unavailable(w, e)
		return
	}
	callback, e := url.Parse(payload.RedirectURI)
	if e != nil {
		unavailable(w, b.ErrUnauthorized)
		return
	}
	q := callback.Query()
	q.Set("code", code)
	q.Set("state", payload.State)
	callback.RawQuery = q.Encode()
	response, e := body(CompleteResponse{callback.String()}, 8192)
	if e != nil {
		unavailable(w, e)
		return
	}
	prepared := output(response)
	profileDigest, e := parseDigest(meta.ProfileDigest)
	if e != nil {
		unavailable(w, e)
		return
	}
	ready := m.ReadyFields{CodeHash: hashed("ops-sso-code/v1", code), CodeExpiresAt: micros(expiry), GrantKeyID: h.runtime.GrantKey.ID, ActorID: meta.ActorID, ProfileID: meta.ProfileID, ProfileDigest: profileDigest, FamilyID: meta.FamilyID, FamilyGeneration: meta.Generation, FamilyHandleHash: m.Digest(meta.HandleHash), AccessDigest: hashed("ops-sso-access/v1", jwt), AccessExpiresAt: micros(v.ExpiresAt()), FamilyExpiresAt: micros(meta.AbsoluteExpiresAt), PreparedAt: micros(at), CodeResponseDigest: prepared.Digest, CodeResponseBytes: prepared.Bytes}
	ready.GrantCiphertext, e = seal(h.grantCipher, grantPayload{1, jwt, handle}, h.grantAAD(record.Pending, ready), m.MaxGrantCipherBytes)
	if e != nil {
		unavailable(w, e)
		return
	}
	capture, e := m.CaptureRecord(record)
	if e != nil {
		unavailable(w, e)
		return
	}
	gate := h.localGate(r.Context(), at, expiry, v)
	receipt, e := h.store.PrepareReady(r.Context(), capture, ready, gate)
	if e != nil {
		unavailable(w, e)
		return
	}
	if !receiptMatches(receipt, record.Pending.ID, h.scope, m.Ready) {
		unavailable(w, b.ErrUnavailable)
		return
	}
	if e = h.broker.RecheckCurrentSession(r.Context(), session); e != nil {
		unavailable(w, e)
		return
	}
	if e = gate(); e != nil {
		unavailable(w, e)
		return
	}
	send(w, response)
}
func minTime(values ...time.Time) time.Time {
	out := values[0]
	for _, v := range values[1:] {
		if v.Before(out) {
			out = v
		}
	}
	return out
}
func (h *Handler) token(w http.ResponseWriter, r *http.Request) {
	id, e := h.basic(r)
	if e != nil {
		w.Header().Set("WWW-Authenticate", `Basic realm="ops-sso"`)
		fail(w, 401, "invalid_client")
		return
	}
	raw, e := boundedBody(r, "application/x-www-form-urlencoded", 8192)
	if e != nil {
		fail(w, 400, "invalid_request")
		return
	}
	form, e := fields(string(raw), []string{"grant_type", "code", "redirect_uri", "client_id", "code_verifier"}, nil, 8192)
	if e != nil || form.Get("grant_type") != "authorization_code" || form.Get("client_id") != id || !canonicalToken(form.Get("code")) || !verifier(form.Get("code_verifier")) || !ascii(form.Get("redirect_uri"), 1, 2048, false) {
		fail(w, 400, "invalid_request")
		return
	}
	record, e := h.store.LookupCode(r.Context(), hashed("ops-sso-code/v1", form.Get("code")))
	if e != nil {
		unavailable(w, e)
		return
	}
	payload, e := h.openContext(record)
	if e != nil {
		unavailable(w, e)
		return
	}
	if record.Pending.ClientID != id || payload.ClientID != id || payload.RedirectURI != form.Get("redirect_uri") || m.Digest(sha256.Sum256([]byte(form.Get("code_verifier")))) != record.Pending.PKCES256 {
		fail(w, 400, "invalid_grant")
		return
	}
	grant, e := h.openGrant(record)
	if e != nil {
		unavailable(w, e)
		return
	}
	ready := *record.Ready
	v, session, meta, e := h.verifiedSession(r.Context(), id, grant.AccessToken, grant.RenewalHandle, b.RecipientBinding(record.Pending.Recipient), b.ExpectedSession{ActorID: ready.ActorID, SessionID: ready.FamilyID})
	if e != nil {
		unavailable(w, e)
		return
	}
	profileDigest, e := parseDigest(meta.ProfileDigest)
	if e != nil || ready.ProfileID != meta.ProfileID || ready.ProfileDigest != profileDigest || ready.FamilyGeneration != meta.Generation || ready.FamilyHandleHash != m.Digest(meta.HandleHash) || ready.AccessExpiresAt != micros(v.ExpiresAt()) || ready.FamilyExpiresAt != micros(meta.AbsoluteExpiresAt) {
		fail(w, 400, "invalid_grant")
		return
	}
	at, e := h.now()
	if e != nil {
		unavailable(w, e)
		return
	}
	expiry := time.UnixMicro(int64(ready.CodeExpiresAt))
	remaining := int64(v.ExpiresAt().Sub(at) / time.Second)
	if remaining <= 0 {
		fail(w, 400, "invalid_grant")
		return
	}
	response, e := body(TokenResponse{grant.AccessToken, "Bearer", remaining}, 24<<10)
	if e != nil {
		unavailable(w, e)
		return
	}
	capture, e := m.CaptureRecord(record)
	if e != nil {
		unavailable(w, e)
		return
	}
	gate := h.localGate(r.Context(), at, expiry, v)
	receipt, e := h.store.Consume(r.Context(), capture, output(response), gate)
	if e != nil {
		unavailable(w, e)
		return
	}
	if !receiptMatches(receipt, record.Pending.ID, h.scope, m.Consumed) {
		unavailable(w, b.ErrUnavailable)
		return
	}
	if e = h.broker.RecheckCurrentSession(r.Context(), session); e != nil {
		unavailable(w, e)
		return
	}
	if e = gate(); e != nil {
		unavailable(w, e)
		return
	}
	send(w, response)
}
