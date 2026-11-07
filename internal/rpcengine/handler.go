package rpcengine

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
)

// Handler is the single-request POST adapter for this partial integration.
// Final assembly must add global/concurrent backpressure before exposure.
func (e *Engine) Handler(selectedOrg string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			json.NewEncoder(w).Encode(responseError(nil, -32600, "invalid request"))
			return
		}
		raw, err := io.ReadAll(io.LimitReader(r.Body, MaxRequestBytes+1))
		if err != nil || len(raw) > MaxRequestBytes {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(responseError(nil, -32600, "invalid request"))
			return
		}
		assertion := ""
		if values := r.Header.Values("Authorization"); len(values) == 1 {
			parts := strings.Split(values[0], " ")
			if len(parts) == 2 && strings.EqualFold(parts[0], "Bearer") {
				assertion = parts[1]
			}
		}
		json.NewEncoder(w).Encode(e.Call(r.Context(), assertion, selectedOrg, raw))
	})
}
