package server

import (
	"context"
	"encoding/json"
	"errors"
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

// Follow-up on finding 6: the audit buffer's volume running short of space
// makes the instance not ready (reason audit_buffer_low_space) before appends
// start failing; the floor is 1 GiB, or a quarter of a smaller volume.
func TestReadyReportsALowBufferVolume(t *testing.T) {
	const gib = uint64(1) << 30
	free, total := 10*gib, 100*gib
	s := &Server{config: &config.Config{}, auditBufferSpace: func() (uint64, uint64, error) { return free, total, nil }}
	ready := func() (int, apimodels.ReadinessResponse) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest(http.MethodGet, "/ready", nil)
		c.Request.RemoteAddr = "127.0.0.1:41000"
		s.handleReady(c)
		var body apimodels.ReadinessResponse
		if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		return w.Code, body
	}
	if code, _ := ready(); code != http.StatusOK {
		t.Fatalf("10 GiB free: %d", code)
	}
	free = gib - 1
	if code, body := ready(); code != http.StatusServiceUnavailable || body.Reason != ReasonAuditBufferLowSpace {
		t.Fatalf("under 1 GiB free: %d %+v", code, body)
	}
	free, total = 600<<20, 2*gib // a small volume: the floor is a quarter of it
	if code, _ := ready(); code != http.StatusOK {
		t.Fatalf("600 MiB free of 2 GiB: %d", code)
	}
	free = 400 << 20
	if code, _ := ready(); code != http.StatusServiceUnavailable {
		t.Fatalf("400 MiB free of 2 GiB: %d", code)
	}
}

func TestAuditBufferVolumeReadFailureRefusesReadiness(t *testing.T) {
	s := &Server{auditBufferSpace: func() (uint64, uint64, error) {
		return 0, 0, errors.New("volume unavailable")
	}}
	if got := s.auditReadinessReason(); got != ReasonAuditBufferUnavailable {
		t.Fatalf("unreadable volume: %q", got)
	}
	read := auditBufferVolumeSpace(t.TempDir())
	if free, total, err := read(); err != nil || total == 0 || free > total {
		t.Fatalf("real buffer volume: free=%d total=%d error=%v", free, total, err)
	}
}
