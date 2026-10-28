package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"

	"privacy-proxy/internal/config"
	"privacy-proxy/internal/nodehttp"
)

// The dispatch points in docs/architecture/modules.toml each state the
// condition that keeps legacy-mode code out of a Reth-mode deployment. These
// tests pin those conditions.

func TestNewNodeApprovalsBuildsNothingInRethMode(t *testing.T) {
	t.Setenv("OPS_APPROVAL_TARGETS", "127.0.0.1:1")
	t.Setenv("OPS_APPROVAL_SEED_FILE", filepath.Join(t.TempDir(), "missing-seed"))
	reth := &config.Config{NodePolicy: config.NodePolicyConfig{Mode: "reth"}}
	approvals, budget, err := newNodeApprovals(reth, nodehttp.TransportConfig{}, nil, prometheus.NewRegistry())
	require.NoError(t, err)
	require.Nil(t, approvals)
	require.Nil(t, budget)

	// The same environment in legacy mode reaches the V1 constructors, which
	// fail on the missing seed: the mode guard decides, not the environment.
	_, _, err = newNodeApprovals(&config.Config{}, nodehttp.TransportConfig{}, nil, prometheus.NewRegistry())
	require.Error(t, err)
}

func TestLegacyRawTransactionGoesToTheNodePathWithNodePolicy(t *testing.T) {
	p, _, node, raw := nodeRPCFixture(t)
	result := p.legacyRawTransaction(context.Background(), nodeRPCRequest(t, "eth_sendRawTransaction", []any{raw}))
	require.Nil(t, result.Error)
	require.Len(t, node.submissions, 1, "the transaction went to the node path, not the legacy trace path")
}

func TestMountedCrossOrgOracleIsClosedInRethMode(t *testing.T) {
	gin.SetMode(gin.TestMode)
	s := &Server{config: &config.Config{
		CrossOrgAuthorizationOracleMode:  "verdict_only",
		CrossOrgAuthorizationOracleToken: "oracle-token",
		NodePolicy:                       config.NodePolicyConfig{Mode: "reth"},
	}}
	r := gin.New()
	s.mountCrossOrgOracle(r.Group("/api/v1"))
	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/cross-org-authorization-oracle", strings.NewReader(`{}`))
	req.RemoteAddr = "127.0.0.1:1234"
	req.Header.Set("X-Cross-Org-Authorization-Oracle-Token", "oracle-token")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	require.Equal(t, http.StatusNotFound, w.Code, w.Body.String())
}
