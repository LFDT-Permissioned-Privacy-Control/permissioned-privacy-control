package identityhttp

import (
	"context"
	"net/http"
	"time"

	b "privacy-proxy/internal/identitybroker"
)

// A context alone cannot interrupt a stalled socket Body.Read. NewMulti
// requires a real net/http writer (or a wrapper exposing Unwrap) so both socket
// directions and the whole operation have the same absolute deadline.
func httpOperation(r *http.Request, w http.ResponseWriter) (context.Context, context.CancelFunc) {
	deadline := time.Now().Add(20 * time.Second)
	if d, ok := r.Context().Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	controller := http.NewResponseController(w)
	if controller.SetReadDeadline(deadline) != nil || controller.SetWriteDeadline(deadline) != nil {
		failService(w, b.ErrUnavailable)
		return nil, func() {}
	}
	ctx, cancel := context.WithDeadline(r.Context(), deadline)
	return ctx, cancel
}
