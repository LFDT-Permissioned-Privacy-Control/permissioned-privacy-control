package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus"

	"privacy-proxy/internal/apimodels"
	"privacy-proxy/internal/audit/buffer"
	"privacy-proxy/internal/audit/sealer"
	"privacy-proxy/internal/config"
)

// Review finding 6: once audit sealing has stopped, /ready answers 503 with a
// stable reason and the stopped gauge shows why; sealing that runs keeps the
// instance ready.
func TestReadyReportsStoppedAuditSealing(t *testing.T) {
	buf, err := buffer.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer buf.Close()
	if _, err := buf.Append([]byte(`{"e":"did:test:ready","m":"eth_call","s":200}`)); err != nil {
		t.Fatal(err)
	}
	chainHW := uint64(0)
	seal := func(context.Context, uint64, []byte) error { return nil }
	hw := func(context.Context) (uint64, error) { return chainHW, nil }
	sl := sealer.New(buf, seal, hw, sealer.Config{})
	s := &Server{config: &config.Config{}, auditSealer: sl}
	reg := prometheus.NewRegistry()
	registerAuditSealingMetrics(reg, sl)

	peer := "10.0.0.7:41000" // a management network (a kubelet probe)
	ready := func() (int, apimodels.ReadinessResponse) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest(http.MethodGet, "/ready", nil)
		c.Request.RemoteAddr = peer
		s.handleReady(c)
		var body apimodels.ReadinessResponse
		if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		return w.Code, body
	}
	if _, err := sl.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	if code, body := ready(); code != http.StatusOK || body.Reason != "" {
		t.Fatalf("sealing runs: %d %+v", code, body)
	}
	chainHW = 99 // rows in this buffer's own sequence space it never wrote
	if _, err := sl.Tick(context.Background()); err == nil {
		t.Fatal("the chain should be refused")
	}
	if code, body := ready(); code != http.StatusServiceUnavailable || body.Status != "not_ready" || body.Reason != ReasonAuditSealingStopped {
		t.Fatalf("refused chain: %d %+v", code, body)
	}
	peer = "203.0.113.9:41000" // the public internet learns only that it is not ready
	if code, body := ready(); code != http.StatusServiceUnavailable || body.Reason != "" {
		t.Fatalf("refused chain, public caller: %d %+v", code, body)
	}
	families, err := reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	stopped := map[string]float64{}
	for _, f := range families {
		if f.GetName() != "privacyproxy_audit_sealing_stopped" {
			continue
		}
		for _, m := range f.GetMetric() {
			stopped[m.GetLabel()[0].GetValue()] = m.GetGauge().GetValue()
		}
	}
	if stopped["chain_refused"] != 1 || stopped["stalled"] != 0 || len(stopped) != 2 {
		t.Fatalf("stopped gauge %v", stopped)
	}
}
