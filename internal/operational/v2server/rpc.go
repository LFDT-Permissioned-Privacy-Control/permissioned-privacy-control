package v2server

import (
	"net/http"
	"privacy-proxy/internal/operational/rpcactivity"
)

func (s *Server) mountRPC(p *dataPlane) error {
	// One wrapper owns the N-slot, durable Append and output lifetime for all
	// operation families. Never mount Engine.Handler or an unfiltered node proxy.
	if p.recorder.CheckHealth() != nil {
		return ErrInvalid
	}
	service, e := rpcactivity.New(rpcactivity.Config{Engine: p.native, Metadata: p.metadata, State: p.state, History: p.history, Explorer: p.explorer, Recorder: p.recorder, Network: p.network})
	if e != nil {
		return e
	}
	explorer, e := service.ExplorerHandler(s.config.ExplorerOrganizationID)
	if e != nil {
		return e
	}
	s.handler.Handle("/api/v2/explorer/", explorer)

	selected, e := service.Handler("")
	if e != nil {
		return e
	}
	s.handler.Handle("POST /{$}", selected)
	s.handler.Handle("POST /rpc", selected)
	organizations := map[string]http.Handler{}
	for _, org := range s.core.Organizations() {
		h, e := service.Handler(org.ID)
		if e != nil {
			return e
		}
		organizations[org.ID] = h
	}
	s.handler.HandleFunc("POST /rpc/{org_id}", func(w http.ResponseWriter, r *http.Request) {
		h := organizations[r.PathValue("org_id")]
		if h == nil {
			w.Header().Set("Cache-Control", "no-store")
			http.NotFound(w, r)
			return
		}
		h.ServeHTTP(w, r)
	})
	return nil
}
