package accesslog

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	a "privacy-proxy/internal/activitylog"
	"privacy-proxy/internal/activitymethoddata"
)

type Handler struct {
	service  *Service
	recorder *a.Recorder
	slots    chan struct{}
}

func NewHandler(s *Service, recorder *a.Recorder) (*Handler, error) {
	if s == nil || recorder == nil || recorder.Healthy() != nil || recorder.Metadata() != s.expected || !slices.Contains(recorder.Methods(), activitymethoddata.AdminAccessLogs) || !recorder.Bounds().Valid() {
		return nil, ErrInvalid
	}
	// A small per-route response-work bound lasts through final delivery. The
	// recorder's shared reservation remains the one audit-admission budget.
	return &Handler{s, recorder, make(chan struct{}, min(4, recorder.Bounds().InFlight))}, nil
}
func (h *Handler) Register(m *http.ServeMux) {
	m.HandleFunc("GET /api/v2/orgs/{orgId}/access-logs", h.serve)
}
func parseQuery(r *http.Request) (Query, string, error) {
	var q Query
	if len(r.URL.RawQuery) > 16<<10 || r.URL.RawPath != "" || r.URL.Fragment != "" || r.ContentLength > 0 {
		return q, "", ErrInvalid
	}
	body, e := io.ReadAll(io.LimitReader(r.Body, 1))
	if e != nil || len(body) > 0 {
		return q, "", ErrInvalid
	}
	v, e := url.ParseQuery(r.URL.RawQuery)
	if e != nil {
		return q, "", ErrInvalid
	}
	allowed := map[string]bool{"actorId": true, "method": true, "outcome": true, "from": true, "to": true, "requestReference": true, "limit": true, "cursor": true}
	for k, values := range v {
		if !allowed[k] || len(values) != 1 || values[0] == "" {
			return q, "", ErrInvalid
		}
	}
	q.ActorID = v.Get("actorId")
	q.Method = v.Get("method")
	q.Outcome = v.Get("outcome")
	q.RequestReference = v.Get("requestReference")
	q.Limit = 50
	if raw := v.Get("limit"); raw != "" {
		n, e := strconv.Atoi(raw)
		if e != nil || strconv.Itoa(n) != raw {
			return q, "", ErrInvalid
		}
		q.Limit = n
	}
	bound := func(raw string) (int64, error) {
		t, e := time.Parse(time.RFC3339Nano, raw)
		if e != nil || t.Before(time.Unix(0, 0)) {
			return 0, ErrInvalid
		}
		us := t.UnixMicro()
		if t.Nanosecond()%1000 != 0 {
			us++
		}
		return us, nil
	}
	q.FromMicros, e = bound(v.Get("from"))
	if e != nil {
		return q, "", e
	}
	q.ToMicros, e = bound(v.Get("to"))
	if e != nil || !q.Valid() {
		return q, "", ErrInvalid
	}
	return q, v.Get("cursor"), nil
}

type errorDTO struct {
	Code         string  `json:"code"`
	Message      string  `json:"message"`
	RetainedFrom *string `json:"retainedFrom,omitempty"`
}

func errorResponse(e error) (int, errorDTO) {
	status := 503
	out := errorDTO{Code: "source_unavailable", Message: "Activity source unavailable."}
	var retained *RetentionError
	switch {
	case errors.Is(e, ErrInvalid):
		status = 400
		out = errorDTO{Code: "invalid_request", Message: "Invalid access log query."}
	case errors.Is(e, errMethod):
		status = 405
		out = errorDTO{Code: "invalid_request", Message: "GET required."}
	case errors.Is(e, ErrUnauthorized):
		status = 401
		out = errorDTO{Code: "unauthenticated", Message: "Sign in again."}
	case errors.Is(e, ErrForbidden):
		status = 403
		out = errorDTO{Code: "forbidden", Message: "Organization administration required."}
	case errors.Is(e, ErrCursor):
		status = 409
		out = errorDTO{Code: "cursor_mismatch", Message: "The page no longer matches this request. Start again."}
	case errors.Is(e, ErrExpired):
		status = 409
		out = errorDTO{Code: "cursor_expired", Message: "The page expired. Start again."}
	case errors.As(e, &retained):
		status = 410
		at := asTime(retained.FromMicros)
		out = errorDTO{Code: "history_pruned", Message: "Requested history has been pruned.", RetainedFrom: &at}
	}
	return status, out
}
func writeError(w http.ResponseWriter, e error) {
	status, out := errorResponse(e)
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(struct {
		Error errorDTO `json:"error"`
	}{out})
}
func (h *Handler) serve(w http.ResponseWriter, r *http.Request) {
	w.Header().Del(a.RequestReferenceHeader)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	until := time.Now().Add(5 * time.Second)
	if deadline, ok := r.Context().Deadline(); ok && deadline.Before(until) {
		until = deadline
	}
	controller := http.NewResponseController(w)
	if controller.SetReadDeadline(until) != nil || controller.SetWriteDeadline(until) != nil {
		writeError(w, ErrUnavailable)
		return
	}
	select {
	case h.slots <- struct{}{}:
		defer func() { <-h.slots }()
	default:
		writeError(w, ErrUnavailable)
		return
	}
	slot, e := h.recorder.Reserve()
	if e != nil {
		writeError(w, ErrUnavailable)
		return
	}
	observed := &observation{}
	completed := false
	defer func() {
		if !completed {
			// Unexpected unwinding still retires this exact reservation once.
			// A panic during Complete is never retried by this fallback.
			_, _ = slot.Complete(a.Completion{Method: activitymethoddata.AdminAccessLogs, ActorID: observed.actor, DataOrganizationID: observed.org, PolicyDigest: observed.policy, TrustedIP: trustedPeer(r.RemoteAddr), HTTPStatus: 503, Outcome: a.Unavailable})
		}
	}()
	ctx, cancel := context.WithDeadline(r.Context(), until)
	defer cancel()
	response, selected := h.selectRead(ctx, r, observed)
	status, outcome := 200, a.Success
	if selected != nil {
		status, _ = errorResponse(selected)
		switch status {
		case 400, 405, 409:
			outcome = a.Invalid
		case 401:
			outcome = a.Unauthenticated
		case 403:
			outcome = a.Denied
		default:
			outcome = a.Unavailable
		}
	}
	if errors.Is(selected, errMethod) {
		w.Header().Set("Allow", "GET")
	}
	// selectRead has closed the original pinned transaction on every return.
	// Complete is exactly once, synchronous and deliberately not cancellable.
	// No filter/cursor/target value becomes audit metadata or a method label.
	completed = true
	receipt, e := slot.Complete(a.Completion{Method: activitymethoddata.AdminAccessLogs, ActorID: observed.actor, DataOrganizationID: observed.org, PolicyDigest: observed.policy, TrustedIP: trustedPeer(r.RemoteAddr), HTTPStatus: uint16(status), Outcome: outcome})
	if e != nil || receipt == nil || !a.CanonicalUUID(receipt.RecordID()) {
		writeError(w, ErrUnavailable)
		return
	}
	w.Header().Set(a.RequestReferenceHeader, receipt.RecordID())
	if h.recorder.Healthy() != nil || ctx.Err() != nil {
		writeError(w, ErrUnavailable)
		return
	}
	if observed.live != nil {
		if e = observed.live(); e != nil {
			writeError(w, e)
			return
		}
	}
	if selected != nil {
		writeError(w, selected)
		return
	}
	writer := &statusWriter{ResponseWriter: w}
	if _, e = response.WriteTo(writer); e != nil && !writer.wrote {
		writeError(w, e)
	}
}

var errMethod = errors.New("GET required")

func (h *Handler) selectRead(ctx context.Context, r *http.Request, observed *observation) (*Response, error) {
	if r.Method != http.MethodGet {
		return nil, errMethod
	}
	auth := r.Header.Values("Authorization")
	if len(auth) != 1 || len(auth[0]) > 32<<10 {
		return nil, ErrUnauthorized
	}
	scheme, token, ok := strings.Cut(auth[0], " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") || token == "" || strings.ContainsAny(token, " \t\r\n,") {
		return nil, ErrUnauthorized
	}
	q, cursor, e := parseQuery(r)
	if e != nil {
		return nil, e
	}
	return h.service.read(ctx, token, r.PathValue("orgId"), q, cursor, observed)
}

// Direct peer only. Forwarded/X-Forwarded-For headers never supply attribution.
func trustedPeer(remote string) string {
	host, _, e := net.SplitHostPort(remote)
	if e != nil {
		return ""
	}
	ip, e := netip.ParseAddr(host)
	if e != nil || ip.Zone() != "" {
		return ""
	}
	return ip.Unmap().String()
}

type statusWriter struct {
	http.ResponseWriter
	wrote bool
}

func (w *statusWriter) Write(p []byte) (int, error) {
	if !w.wrote {
		w.wrote = true
		w.WriteHeader(200)
	}
	return w.ResponseWriter.Write(p)
}
