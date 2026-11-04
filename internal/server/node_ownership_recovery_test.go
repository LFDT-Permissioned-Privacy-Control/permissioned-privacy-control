package server

import (
	"context"
	"crypto/ed25519"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"privacy-proxy/internal/audit"
	"privacy-proxy/internal/config"
	"privacy-proxy/internal/nodepolicy"
	"privacy-proxy/internal/rbac"
	"privacy-proxy/internal/server/middleware"
)

// evidenceNode answers ops_transactionStatus from a table.
type evidenceNode map[string]nodepolicy.TransactionStatus

func (n evidenceNode) TransactionStatus(_ context.Context, hash string) (nodepolicy.TransactionStatus, error) {
	if s, ok := n[hash]; ok {
		return s, nil
	}
	if strings.HasPrefix(hash, "0x6") {
		return nodepolicy.TransactionStatus{}, &nodepolicy.RejectedError{Code: -32014} // N7: on no chain
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
	for _, refused := range []string{foreign, pending, transfer, hash(5), hash(6)} {
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

// failingAuditChain refuses every append: the RBAC audit store is unavailable.
type failingAuditChain struct{}

func (failingAuditChain) Append(func(string) (string, func(string) error, error)) (string, error) {
	return "", errors.New("rbac audit unavailable")
}

// The recovery's ownership and grant change commits together with its
// rbac_audit_log row or not at all: an audit failure answers an error and
// registers nothing (independent review, finding 5).
func TestOwnershipRecoveryCommitsOnlyWithItsAuditRow(t *testing.T) {
	f := configurationAPI(t)
	s := f.server
	network := nodepolicy.Network{ChainID: 31337, DeploymentID: "recovery-audit-test"}
	s.config.NodePolicy = config.NodePolicyConfig{Mode: "reth", ChainID: network.ChainID, DeploymentID: network.DeploymentID}
	s.rateLimiter = &noopRateLimiter{}
	var err error
	s.nodeExecution, err = newNodeExecutionBridge(s.db, nodeClientFixture{}, nodepolicy.Signer{KeyID: "test", PrivateKey: ed25519.NewKeyFromSeed(make([]byte, 32))}, network, time.Minute, nil)
	require.NoError(t, err)
	require.NoError(t, s.db.EnsureNodeTxEffectsFloor(t.Context(), network))
	deployer, err := s.db.GetUser(t.Context(), f.readonlyUserID)
	require.NoError(t, err)
	block := uint64(42)
	hash := "0x" + strings.Repeat("5a", 32)
	address := "0x" + strings.Repeat("c7", 20)
	s.nodeOwnershipEvidence = evidenceNode{hash: {TransactionHash: hash, PrincipalID: deployer.ID, OrgID: f.orgID, ContextID: uuid.NewString(),
		Execution: nodepolicy.ExecutionOutcome{Status: "included", FactsVersion: 3, BlockNumber: &block, Finalized: true,
			Created: []nodepolicy.CreatedContract{{Address: address, OrgID: f.orgID, PrincipalID: deployer.ID}}}}}
	path := "/api/v1/admin/orgs/" + f.orgID + "/execution/ownership-recovery"
	registered := func() int {
		var n int
		require.NoError(t, s.db.Conn().QueryRowContext(t.Context(), `SELECT count(*) FROM contracts WHERE lower(address) = $1`, address).Scan(&n))
		return n
	}
	audited := func() int {
		var n int
		require.NoError(t, s.db.Conn().QueryRowContext(t.Context(), `SELECT count(*) FROM rbac_audit_log WHERE action = 'recover_ownership' AND new_value::jsonb->>'transaction_hash' = $1`, hash).Scan(&n))
		return n
	}

	s.db.SetRBACAuditChain(failingAuditChain{})
	response := f.request(t, f.admin, http.MethodPost, path, map[string]any{"transactionHash": hash})
	require.Equal(t, http.StatusInternalServerError, response.Code, response.Body.String())
	require.NotContains(t, response.Body.String(), "rbac audit unavailable", "the error stays opaque")
	require.Zero(t, registered(), "nothing is registered without its audit row")
	require.Zero(t, audited())

	s.db.SetRBACAuditChain(audit.NewHashChain(""))
	response = f.request(t, f.admin, http.MethodPost, path, map[string]any{"transactionHash": hash})
	require.Equal(t, http.StatusOK, response.Code, response.Body.String())
	require.JSONEq(t, `{"transactionHash":"`+hash+`","registered":true,"conflicts":0}`, response.Body.String())
	require.Equal(t, 1, registered())
	require.Equal(t, 1, audited())
	var entryHash string
	require.NoError(t, s.db.Conn().QueryRowContext(t.Context(), `SELECT coalesce(entry_hash, '') FROM rbac_audit_log WHERE action = 'recover_ownership' AND new_value::jsonb->>'transaction_hash' = $1`, hash).Scan(&entryHash))
	require.NotEmpty(t, entryHash, "the row is linked into the audit hash chain")
}

// interferingChain is a real hash chain that runs interfere once between
// preparing an entry and writing it (a concurrent change between the
// recovery's preview and its write).
type interferingChain struct {
	inner     *audit.HashChain
	interfere func()
}

func (c *interferingChain) Append(build func(string) (string, func(string) error, error)) (string, error) {
	return c.inner.Append(func(prev string) (string, func(string) error, error) {
		content, write, err := build(prev)
		if err != nil {
			return content, write, err
		}
		return content, func(hash string) error {
			if c.interfere != nil {
				c.interfere()
				c.interfere = nil
			}
			return write(hash)
		}, nil
	})
}

// The audit row is written inside the change's transaction: a failing
// insert rolls the registration back, and a change between the recovery's
// preview and its write is re-prepared, so the one audit row describes what
// committed (code review of finding 5).
func TestOwnershipRecoveryAuditRowMatchesWhatCommitted(t *testing.T) {
	f := configurationAPI(t)
	s := f.server
	network := nodepolicy.Network{ChainID: 31337, DeploymentID: "recovery-race-test"}
	s.config.NodePolicy = config.NodePolicyConfig{Mode: "reth", ChainID: network.ChainID, DeploymentID: network.DeploymentID}
	s.rateLimiter = &noopRateLimiter{}
	var err error
	s.nodeExecution, err = newNodeExecutionBridge(s.db, nodeClientFixture{}, nodepolicy.Signer{KeyID: "test", PrivateKey: ed25519.NewKeyFromSeed(make([]byte, 32))}, network, time.Minute, nil)
	require.NoError(t, err)
	require.NoError(t, s.db.EnsureNodeTxEffectsFloor(t.Context(), network))
	deployer, err := s.db.GetUser(t.Context(), f.readonlyUserID)
	require.NoError(t, err)
	block := uint64(42)
	hash := "0x" + strings.Repeat("6b", 32)
	ours, raced := "0x"+strings.Repeat("c8", 20), "0x"+strings.Repeat("c9", 20)
	s.nodeOwnershipEvidence = evidenceNode{hash: {TransactionHash: hash, PrincipalID: deployer.ID, OrgID: f.orgID, ContextID: uuid.NewString(),
		Execution: nodepolicy.ExecutionOutcome{Status: "included", FactsVersion: 3, BlockNumber: &block, Finalized: true,
			Created: []nodepolicy.CreatedContract{{Address: ours, OrgID: f.orgID, PrincipalID: deployer.ID}, {Address: raced, OrgID: f.orgID, PrincipalID: deployer.ID}}}}}
	path := "/api/v1/admin/orgs/" + f.orgID + "/execution/ownership-recovery"
	ownerOf := func(address string) string {
		var owner string
		require.NoError(t, s.db.Conn().QueryRowContext(t.Context(), `SELECT coalesce(max(org_id::text), '') FROM contracts WHERE lower(address) = $1`, address).Scan(&owner))
		return owner
	}

	// The audit insert itself fails: nothing is registered.
	_, err = s.db.Conn().ExecContext(t.Context(), `ALTER TABLE rbac_audit_log ADD CONSTRAINT test_refuse_recovery CHECK (action <> 'recover_ownership') NOT VALID`)
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = s.db.Conn().ExecContext(context.Background(), `ALTER TABLE rbac_audit_log DROP CONSTRAINT IF EXISTS test_refuse_recovery`)
	})
	s.db.SetRBACAuditChain(audit.NewHashChain(""))
	response := f.request(t, f.admin, http.MethodPost, path, map[string]any{"transactionHash": hash})
	require.Equal(t, http.StatusInternalServerError, response.Code, response.Body.String())
	require.Equal(t, "", ownerOf(ours), "a failed audit insert rolls the registration back")
	_, err = s.db.Conn().ExecContext(t.Context(), `ALTER TABLE rbac_audit_log DROP CONSTRAINT test_refuse_recovery`)
	require.NoError(t, err)

	// Another organization takes one of the addresses between the preview
	// and the write: the step is prepared again and the audit row records
	// the refusal that committed.
	other := uuid.NewString()
	require.NoError(t, s.db.CreateOrganization(t.Context(), &rbac.Organization{ID: other, Slug: "race-" + other[:8], Name: "Race"}))
	s.db.SetRBACAuditChain(&interferingChain{inner: audit.NewHashChain(""), interfere: func() {
		require.NoError(t, s.db.CreateContract(context.Background(), &rbac.Contract{ID: uuid.NewString(), OrgID: other, Address: raced, Name: "raced"}))
	}})
	response = f.request(t, f.admin, http.MethodPost, path, map[string]any{"transactionHash": hash})
	require.Equal(t, http.StatusOK, response.Code, response.Body.String())
	require.JSONEq(t, `{"transactionHash":"`+hash+`","registered":true,"conflicts":1}`, response.Body.String())
	require.Equal(t, f.orgID, ownerOf(ours))
	require.Equal(t, other, ownerOf(raced))
	var rows int
	var conflicts string
	require.NoError(t, s.db.Conn().QueryRowContext(t.Context(), `SELECT count(*), max(new_value::jsonb->>'conflicts') FROM rbac_audit_log WHERE action = 'recover_ownership' AND new_value::jsonb->>'transaction_hash' = $1`, hash).Scan(&rows, &conflicts))
	require.Equal(t, 1, rows, "one audit row for one committed change")
	require.Equal(t, "1", conflicts, "the audit row describes what committed")
}
