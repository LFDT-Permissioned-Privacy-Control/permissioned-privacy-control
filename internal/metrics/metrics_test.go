package metrics

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

// ---------------------------------------------------------------------------
// NormalizeRPCMethod
// ---------------------------------------------------------------------------

func TestNormalizeRPCMethod_KnownMethod(t *testing.T) {
	known := []string{
		"eth_blockNumber",
		"eth_call",
		"eth_getBalance",
		"eth_getLogs",
		"eth_getTransactionByHash",
		"eth_sendRawTransaction",
		"net_version",
		"web3_clientVersion",
		"debug_traceCall",
		"txpool_status",
	}
	for _, method := range known {
		t.Run(method, func(t *testing.T) {
			got := NormalizeRPCMethod(method)
			if got != method {
				t.Errorf("NormalizeRPCMethod(%q) = %q, want %q", method, got, method)
			}
		})
	}
}

func TestNormalizeRPCMethod_UnknownMethod(t *testing.T) {
	unknown := []string{
		"custom_method",
		"",
		"eth_fakeMethod",
		"admin_doSomething",
		"RANDOM_JUNK",
	}
	for _, method := range unknown {
		t.Run(method, func(t *testing.T) {
			got := NormalizeRPCMethod(method)
			if got != "other" {
				t.Errorf("NormalizeRPCMethod(%q) = %q, want %q", method, got, "other")
			}
		})
	}
}

func TestNormalizeRPCMethod_CaseInsensitiveLookup(t *testing.T) {
	// The method is looked up case-insensitively but the ORIGINAL casing is returned.
	got := NormalizeRPCMethod("ETH_BLOCKNUMBER")
	if got != "ETH_BLOCKNUMBER" {
		t.Errorf("NormalizeRPCMethod(%q) = %q, want ETH_BLOCKNUMBER", "ETH_BLOCKNUMBER", got)
	}

	got = NormalizeRPCMethod("Eth_Call")
	if got != "Eth_Call" {
		t.Errorf("NormalizeRPCMethod(%q) = %q, want Eth_Call", "Eth_Call", got)
	}
}

// ---------------------------------------------------------------------------
// New (Metrics constructor)
// ---------------------------------------------------------------------------

func TestNew_CreatesMetrics(t *testing.T) {
	m := New("v1.2.3")
	if m == nil {
		t.Fatal("New() returned nil")
	}
	if m.Registry == nil {
		t.Error("Registry should not be nil")
	}
	if m.HTTPRequestsTotal == nil {
		t.Error("HTTPRequestsTotal should not be nil")
	}
	if m.RPCRequestsTotal == nil {
		t.Error("RPCRequestsTotal should not be nil")
	}
	if m.RBACDecisionsTotal == nil {
		t.Error("RBACDecisionsTotal should not be nil")
	}
	if m.ComplianceDecisionsTotal == nil {
		t.Error("ComplianceDecisionsTotal should not be nil")
	}
	if m.AuthAttemptsTotal == nil {
		t.Error("AuthAttemptsTotal should not be nil")
	}
	if m.PendingDeployments == nil {
		t.Error("PendingDeployments should not be nil")
	}
}

// ---------------------------------------------------------------------------
// HTTPMiddleware
// ---------------------------------------------------------------------------

func TestHTTPMiddleware_RecordsMetrics(t *testing.T) {
	gin.SetMode(gin.TestMode)
	m := New("test")

	r := gin.New()
	r.Use(m.HTTPMiddleware())
	r.GET("/ping", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	req := httptest.NewRequest(http.MethodGet, "/ping", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestNewNoop_ReturnsValidMetrics(t *testing.T) {
	m := NewNoop()
	if m == nil {
		t.Fatal("NewNoop() returned nil")
	}
	if m.Registry == nil {
		t.Error("NewNoop Registry should not be nil")
	}
}

func TestHTTPMiddleware_UnmatchedRoute(t *testing.T) {
	gin.SetMode(gin.TestMode)
	m := New("test")

	r := gin.New()
	r.Use(m.HTTPMiddleware())
	// No routes registered — any request will be unmatched (404).

	req := httptest.NewRequest(http.MethodGet, "/unknown", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	// Default gin 404 for unmatched routes.
	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404 for unmatched route, got %d", w.Code)
	}
}
