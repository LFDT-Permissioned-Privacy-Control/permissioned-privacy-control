package rpcactivity

import (
	"context"
	"encoding/hex"
	"net/http"
	"slices"
	"strings"
	"time"

	"privacy-proxy/internal/activitylog"
	"privacy-proxy/internal/activitymethoddata"
	"privacy-proxy/internal/rpcengine"
)

// New composes all concrete consumers with the same recorder and in-flight
// lifetime. Explorer cannot create a sibling limiter or bypass RPC ownership.
func New(c Config) (*Service, error) {
	s, err := newHistoryService(c)
	if err != nil {
		return nil, err
	}
	if c.Explorer == nil {
		return s, nil
	}
	e := c.Explorer
	b := e.OperationBinding()
	h := c.History.OperationBinding()
	if c.History == nil || c.State == nil || c.Metadata == nil || !e.SharesHistory(c.History) || !e.SharesState(c.State) || !e.SharesMetadata(c.Metadata) || b.Profile != h.Profile || b.ManifestDigest != h.ManifestDigest || b.NetworkKey != h.NetworkKey || b.ChainID != h.ChainID || b.Environment != h.Environment || !slices.Equal(b.OrganizationIDs, h.OrganizationIDs) {
		return nil, ErrInvalid
	}
	for _, name := range b.Methods {
		if activitymethoddata.Classify(name) != activitymethoddata.Explorer || !slices.Contains(c.Recorder.Methods(), name) {
			return nil, ErrInvalid
		}
	}
	s.explorer = e
	return s, nil
}
func (s *Service) ExplorerHandler(selectedOrg string) (http.Handler, error) {
	if s == nil || s.explorer == nil || selectedOrg != "" && !slices.Contains(s.organizations, selectedOrg) {
		return nil, ErrInvalid
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { s.serveExplorer(w, r, selectedOrg) }), nil
}

var explorerBusy = []byte(`{"error":{"code":"unavailable"}}`)

func (s *Service) serveExplorer(w http.ResponseWriter, r *http.Request, org string) {
	deadline := time.Now().Add(20 * time.Second)
	if d, ok := r.Context().Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	controller := http.NewResponseController(w)
	if controller.SetWriteDeadline(deadline) != nil {
		write(w, 503, explorerBusy)
		return
	}
	select {
	case s.slots <- struct{}{}:
		defer func() { <-s.slots }()
	default:
		write(w, 503, explorerBusy)
		return
	}
	ctx, cancel := context.WithDeadline(r.Context(), deadline)
	defer cancel()
	slot, err := s.recorder.Reserve()
	if err != nil {
		write(w, 503, explorerBusy)
		return
	}
	if r.Method != http.MethodGet || r.URL.RawPath != "" || r.ContentLength != 0 || r.URL.Fragment != "" || len(r.URL.Path) > 1024 || len(r.URL.RawQuery) > 16<<10 {
		_, err = slot.Complete(activitylog.Completion{Method: "explorer.invalid_transport", TrustedIP: peer(r.RemoteAddr), HTTPStatus: 400, Outcome: activitylog.Invalid})
		if err != nil {
			write(w, 503, explorerBusy)
		} else {
			write(w, 400, []byte(`{"error":{"code":"invalid_request"}}`))
		}
		return
	}
	result := s.explorer.QueryHTTPObserved(ctx, rpcengine.MetadataAuthorization(r.Header.Values("Authorization")), org, r.URL.Path, r.URL.RawQuery)
	m, err := result.MetadataFor(s.explorer)
	if err != nil {
		_, _ = slot.Complete(activitylog.Completion{Method: "explorer.invalid_request", HTTPStatus: 503, Outcome: activitylog.Unavailable})
		write(w, 503, explorerBusy)
		return
	}
	c := activitylog.Completion{Method: m.Method, ActorID: m.ActorID, DataOrganizationID: m.OrganizationID, TrustedIP: peer(r.RemoteAddr), HTTPStatus: uint16(m.HTTPStatus), Outcome: category(m.Class)}
	if activitymethoddata.Classify(c.Method) != activitymethoddata.Explorer || len(m.PolicyDigest) != 71 || !strings.HasPrefix(string(m.PolicyDigest), "sha256:") {
		_, _ = slot.Complete(activitylog.Completion{Method: "explorer.invalid_request", HTTPStatus: 503, Outcome: activitylog.Unavailable})
		write(w, 503, explorerBusy)
		return
	}
	digest, err := hex.DecodeString(string(m.PolicyDigest)[7:])
	if err != nil || len(digest) != 32 {
		_, _ = slot.Complete(activitylog.Completion{Method: "explorer.invalid_request", HTTPStatus: 503, Outcome: activitylog.Unavailable})
		write(w, 503, explorerBusy)
		return
	}
	copy(c.PolicyDigest[:], digest)
	if _, err = slot.Complete(c); err != nil {
		write(w, 503, explorerBusy)
		return
	}
	body, err := result.MarshalResponseFor(s.explorer)
	if err != nil || s.recorder.Healthy() != nil || result.RequireDeliverable(ctx, s.explorer) != nil {
		write(w, 503, explorerBusy)
		return
	}
	write(w, m.HTTPStatus, body)
}
