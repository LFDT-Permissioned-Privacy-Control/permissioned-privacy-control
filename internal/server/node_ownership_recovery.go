package server

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"slices"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"privacy-proxy/internal/apimodels"
	"privacy-proxy/internal/auth"
	"privacy-proxy/internal/db"
	"privacy-proxy/internal/nodepolicy"
	"privacy-proxy/internal/rbac"
)

// nodeEvidence reads a transaction's finalized outcome from the node's block
// manifest (ops_transactionStatus on the recovery lane).
type nodeEvidence interface {
	TransactionStatus(context.Context, string) (nodepolicy.TransactionStatus, error)
}

// recoverNodeOwnership registers the contracts a finalized deployment created,
// from the node's evidence (plan §4.11, G52).
// @Summary Recover deployment ownership from node evidence
// @Description After the execution-tracking database was lost or recreated, a deployment that finalized meanwhile is not registered automatically. A named human with current full authority over the organization can register it from the node's finalized evidence: the node must report the transaction as included and final, deployed by a principal of this organization, within the node's evidence retention. Ownership is applied exactly once (a deployment already registered, by reconciliation or an earlier recovery, is not registered again), never below the replay floor, and never for an address another organization owns. Any transaction that is unknown, not final, not a deployment or not this organization's is answered with the same 404. The action is recorded in the RBAC audit log in the same transaction as the change: if the record cannot be written, nothing is registered and the request fails with 500.
// @Tags Admin: Configuration
// @Accept json
// @Produce json
// @Param org_id path string true "Organization UUID"
// @Param request body apimodels.NodeOwnershipRecoveryRequest true "Deployment transaction"
// @Success 200 {object} apimodels.NodeOwnershipRecoveryResponse
// @Failure 400 {object} apimodels.APIError
// @Failure 403 {object} apimodels.APIError
// @Failure 404 {object} apimodels.APIError
// @Failure 409 {object} apimodels.APIError "the deployment is older than the recovery window (replay floor)"
// @Failure 429 {object} apimodels.APIError
// @Failure 500 {object} apimodels.APIError "nothing was changed (for example the audit record could not be written)"
// @Failure 503 {object} apimodels.APIError
// @Security BearerAuth
// @Router /api/v1/admin/orgs/{org_id}/execution/ownership-recovery [post]
func (s *Server) recoverNodeOwnership(c *gin.Context) {
	c.Header("Cache-Control", "no-store")
	fail := func(code int, message string) { c.JSON(code, gin.H{"error": message}) }
	actor, ok := configurationRequestActor(c)
	if !ok {
		return
	}
	org := c.Param("org_id")
	if id, err := uuid.Parse(org); err != nil || id == uuid.Nil || id.String() != org {
		fail(http.StatusBadRequest, "invalid organization")
		return
	}
	if s.config == nil || !s.config.NodePolicy.Enabled() || s.nodeOwnershipEvidence == nil || s.nodeExecution == nil || s.rateLimiter == nil || s.db == nil {
		fail(http.StatusServiceUnavailable, "ownership recovery unavailable")
		return
	}
	if actor.PrincipalKind != string(auth.PrincipalHuman) {
		fail(http.StatusForbidden, "ownership recovery requires a named human organization administrator")
		return
	}
	ctx := c.Request.Context()
	_, orgs, err := s.db.IsOrgAdmin(ctx, actor.UserID)
	if err != nil || !slices.Contains(orgs, org) {
		fail(http.StatusForbidden, "ownership recovery requires current full organization authority")
		return
	}
	rps, daily := 1, 100
	if allowed, _ := s.rateLimiter.CheckAndIncrement("ownership-recovery:"+actor.ExternalID, &rps, &daily); !allowed {
		fail(http.StatusTooManyRequests, "ownership recovery limit reached")
		return
	}
	var req apimodels.NodeOwnershipRecoveryRequest
	decoder := json.NewDecoder(http.MaxBytesReader(c.Writer, c.Request.Body, 4096))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&req) != nil || decoder.Decode(new(any)) != io.EOF || !lowerTxHash(req.TransactionHash) {
		fail(http.StatusBadRequest, "invalid ownership recovery request")
		return
	}
	notFound := func() { fail(http.StatusNotFound, "finalized deployment not found") }
	status, err := s.nodeOwnershipEvidence.TransactionStatus(ctx, req.TransactionHash)
	if err != nil && !nodepolicy.NodeRefused(err) {
		fail(http.StatusServiceUnavailable, "ownership recovery unavailable") // no answer: nothing is known
		return
	}
	if err != nil {
		notFound() // unknown to the node, or beyond its evidence retention
		return
	}
	outcome := status.Execution
	if status.TransactionHash != req.TransactionHash || status.OrgID != org || outcome.Status != "included" || !outcome.Finalized || outcome.BlockNumber == nil || len(outcome.Created) == 0 {
		notFound()
		return
	}
	created := make([]string, 0, len(outcome.Created))
	for _, contract := range outcome.Created {
		created = append(created, contract.Address)
	}
	// The audited resource is the organization (rbac_audit_log ids are UUIDs);
	// the transaction and the created addresses are in the new value. The
	// row commits in the same transaction as the ownership and grant change,
	// or neither does.
	entry := func(result db.NodeTxEffectsResult) *rbac.AuditLogEntry {
		return auditEntry(c, "recover_ownership", "organization", org, "deployment ownership recovery", org, nil, map[string]any{
			"transaction_hash": req.TransactionHash, "deployer_principal_id": status.PrincipalID, "block_number": *outcome.BlockNumber,
			"created": created, "registered": result.OwnershipApplied, "conflicts": result.OwnershipConflicts,
		})
	}
	result, err := s.db.ApplyNodeTxEffectsAudited(ctx, s.nodeExecution.Network(), db.NodeTxEffects{TransactionHash: req.TransactionHash, PrincipalID: status.PrincipalID, OrgID: org, BlockNumber: *outcome.BlockNumber, Ownership: true, Created: outcome.Created}, entry)
	switch {
	case errors.Is(err, db.ErrBelowReplayFloor):
		fail(http.StatusConflict, "the deployment is older than the ownership recovery window")
		return
	case err != nil:
		slog.Error("ownership recovery failed; nothing was changed", "org_id", org, "tx", req.TransactionHash, "error", err)
		fail(http.StatusInternalServerError, "ownership recovery failed")
		return
	case result.Note == "organization_deleted":
		notFound()
		return
	}
	c.JSON(http.StatusOK, apimodels.NodeOwnershipRecoveryResponse{TransactionHash: req.TransactionHash, Registered: result.OwnershipApplied, Conflicts: result.OwnershipConflicts})
}

// lowerTxHash: a 0x-prefixed lowercase 32-byte hex hash.
func lowerTxHash(hash string) bool {
	if len(hash) != 66 || !strings.HasPrefix(hash, "0x") || strings.ToLower(hash) != hash {
		return false
	}
	_, err := hex.DecodeString(hash[2:])
	return err == nil
}
