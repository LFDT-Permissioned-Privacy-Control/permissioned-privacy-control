package server

import (
	"context"
	"crypto/ed25519"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"privacy-proxy/internal/config"
	"privacy-proxy/internal/nodepolicy"
	"privacy-proxy/internal/server/middleware"
)

// evidenceNode answers ops_transactionStatus from a table.
type evidenceNode map[string]nodepolicy.TransactionStatus

func (n evidenceNode) TransactionStatus(_ context.Context, hash string) (nodepolicy.TransactionStatus, error) {
	if s, ok := n[hash]; ok {
		return s, nil
	}
	return nodepolicy.TransactionStatus{}, &nodepolicy.RejectedError{Code: -32000}
}

// G52: after a tracking-database loss, a named human organization
// administrator registers a finalized deployment of their own organization
// from the node's evidence, exactly once; another organization's deployment,
// a transaction that is not final or not a deployment, and non-admins are
// refused without revealing which.
func TestOwnershipRecoveryFromManifests(t *testing.T) {
	f := configurationAPI(t)
	s := f.server
	network := nodepolicy.Network{ChainID: 31337, DeploymentID: "recovery-test"}
	s.config.NodePolicy = config.NodePolicyConfig{Mode: "reth", ChainID: network.ChainID, DeploymentID: network.DeploymentID}
	s.rateLimiter = &noopRateLimiter{}
	var err error
	s.nodeExecution, err = newNodeExecutionBridge(s.db, nodeClientFixture{}, nodepolicy.Signer{KeyID: "test", PrivateKey: ed25519.NewKeyFromSeed(make([]byte, 32))}, network, time.Minute, nil)
	require.NoError(t, err)
	require.NoError(t, s.db.EnsureNodeTxEffectsFloor(t.Context(), network))
	deployer, err := s.db.GetUser(t.Context(), f.readonlyUserID)
	require.NoError(t, err)
	block := uint64(42)
	status := func(hash, org string, final bool, created ...string) nodepolicy.TransactionStatus {
		out := nodepolicy.TransactionStatus{TransactionHash: hash, PrincipalID: deployer.ID, OrgID: org, ContextID: uuid.NewString(),
			Execution: nodepolicy.ExecutionOutcome{Status: "included", FactsVersion: 3, BlockNumber: &block, Finalized: final, Created: []nodepolicy.CreatedContract{}}}
		for _, address := range created {
			out.Execution.Created = append(out.Execution.Created, nodepolicy.CreatedContract{Address: address, OrgID: org, PrincipalID: deployer.ID})
		}
		return out
	}
	hash := func(b byte) string { return "0x" + strings.Repeat(string("0123456789abcdef"[b%16])+"a", 32) }
	ours, foreign, pending, transfer := hash(1), hash(2), hash(3), hash(4)
	address := "0x" + strings.Repeat("c1", 20)
	s.nodeOwnershipEvidence = evidenceNode{
		ours:     status(ours, f.orgID, true, address),
		foreign:  status(foreign, uuid.NewString(), true, "0x"+strings.Repeat("c2", 20)),
		pending:  status(pending, f.orgID, false, "0x"+strings.Repeat("c3", 20)),
		transfer: status(transfer, f.orgID, true),
	}
	path := "/api/v1/admin/orgs/" + f.orgID + "/execution/ownership-recovery"
	recover := func(token, hash string) (int, string) {
		response := f.request(t, token, http.MethodPost, path, map[string]any{"transactionHash": hash})
		return response.Code, response.Body.String()
	}
	for _, refused := range []string{foreign, pending, transfer, hash(5)} {
		code, body := recover(f.admin, refused)
		require.Equal(t, http.StatusNotFound, code, body)
		require.Contains(t, body, "finalized deployment not found")
	}
	code, body := recover(f.readonly, ours)
	require.Equal(t, http.StatusForbidden, code, body)
	code, body = recover(f.service, ours)
	require.Equal(t, http.StatusForbidden, code, body)
	code, body = recover(f.admin, "0xABC")
	require.Equal(t, http.StatusBadRequest, code, body)

	code, body = recover(f.admin, ours)
	require.Equal(t, http.StatusOK, code, body)
	require.JSONEq(t, `{"transactionHash":"`+ours+`","registered":true,"conflicts":0}`, body)
	var owner string
	require.NoError(t, s.db.Conn().QueryRowContext(t.Context(), `SELECT org_id FROM contracts WHERE lower(address) = $1`, address).Scan(&owner))
	require.Equal(t, f.orgID, owner)
	limiter := middleware.NewRateLimiter(middleware.RateLimiterCleanupInterval)
	t.Cleanup(limiter.Stop)
	s.rateLimiter = limiter
	code, body = recover(f.admin, ours)
	require.Equal(t, http.StatusOK, code, body)
	require.JSONEq(t, `{"transactionHash":"`+ours+`","registered":false,"conflicts":0}`, body, "exactly once by marker")
	code, body = recover(f.admin, ours)
	require.Equal(t, http.StatusTooManyRequests, code, body, "rate limited per actor")
	var audited int
	require.NoError(t, s.db.Conn().QueryRowContext(t.Context(), `SELECT count(*) FROM rbac_audit_log WHERE action = 'recover_ownership' AND resource_id = $1 AND new_value::jsonb->>'transaction_hash' = $2`, f.orgID, ours).Scan(&audited))
	require.Equal(t, 2, audited)
}
