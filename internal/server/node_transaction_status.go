package server

import (
	"database/sql"
	"encoding/hex"
	"errors"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"privacy-proxy/internal/apimodels"
	"privacy-proxy/internal/db"
	"privacy-proxy/internal/nodepolicy"
)

// getMyNodeTransactionStatus returns the caller's own durable execution state.
// @Summary My transaction execution status
// @Description Status for a transaction submitted by this named principal, with current organization membership and KYC required. Shared signing addresses do not share status access. pending, provisional (included in a block that is not final yet) and renewal_stopped (OPS will not renew its identity, but it may still settle; reconciliation_note names why, e.g. max_age, principal_banned, compliance_denied, nonce_conflict) are nonterminal: a provisional transaction can return to pending after a reorganization, and a renewal_stopped one can still be included while its last identity is valid. Wait for a final status rather than treating renewal_stopped as a failure. included and reverted (in a finalized block) and dropped (reported only once a finalized block used the transaction's nonce and the transaction itself was never included; an expired identity alone is never final) are final; reconciled means OPS bookkeeping for the final status is committed, and reconciliation_note effects_not_applied means a deployment or visibility effect was refused. Final statuses are kept for the configured retention (RETENTION_NODE_SUBMISSIONS), after which the transaction is not found. This endpoint never returns raw transactions, signing envelopes or visibility recipients.
// @Tags Profile
// @Produce json
// @Param hash path string true "Lowercase transaction hash"
// @Success 200 {object} apimodels.NodeTransactionProgress
// @Failure 401 {object} apimodels.APIError
// @Failure 404 {object} apimodels.APIError
// @Failure 429 {object} apimodels.APIError
// @Failure 500 {object} apimodels.APIError
// @Failure 503 {object} apimodels.APIError
// @Security BearerAuth
// @Router /api/v1/me/transactions/{hash}/execution [get]
func (s *Server) getMyNodeTransactionStatus(c *gin.Context) {
	c.Header("Cache-Control", "no-store")
	missing := func() { c.JSON(http.StatusNotFound, gin.H{"error": "transaction status not found"}) }
	if s.config == nil || !s.config.NodePolicy.Enabled() {
		missing()
		return
	}
	subject := c.GetString("subject")
	if subject == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "authentication required"})
		return
	}
	if s.rateLimiter == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "transaction status unavailable"})
		return
	}
	rps := 20
	if allowed, _ := s.rateLimiter.CheckAndIncrement("execution-status:"+subject, &rps, nil); !allowed {
		c.JSON(http.StatusTooManyRequests, gin.H{"error": "status request limit reached"})
		return
	}
	hash := c.Param("hash")
	if len(hash) != 66 || !strings.HasPrefix(hash, "0x") || strings.ToLower(hash) != hash {
		missing()
		return
	}
	if _, err := hex.DecodeString(hash[2:]); err != nil {
		missing()
		return
	}
	ctx := c.Request.Context()
	user, err := s.db.GetUserByExternalID(ctx, subject)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "transaction status unavailable"})
		return
	}
	if user == nil || user.Banned || !user.KYC {
		missing()
		return
	}
	if s.tracking == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "transaction status unavailable"})
		return
	}
	key, _ := hex.DecodeString(hash[2:])
	stored, err := s.tracking.runtime.LookupTracked(ctx, key)
	if errors.Is(err, sql.ErrNoRows) {
		missing()
		return
	}
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "transaction status unavailable"})
		return
	}
	if stored.PrincipalID.String() != user.ID {
		missing()
		return
	}
	memberships, err := s.db.ListUserMembershipsInOrg(ctx, user.ID, stored.OrgID.String())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "transaction status unavailable"})
		return
	}
	if len(memberships) == 0 {
		missing()
		return
	}
	c.JSON(http.StatusOK, nodeTransactionProgress(hash, stored))
}

// nodeTransactionProgress is the owner's view of a tracked transaction: the
// state, its block once included, and the final reason.
func nodeTransactionProgress(hash string, t db.TrackedTransaction) apimodels.NodeTransactionProgress {
	out := apimodels.NodeTransactionProgress{TransactionHash: hash, Status: db.TrackStateName(t.State), Reconciled: t.Final(), ReconciliationNote: db.TrackReasonName(t.Reason)}
	if t.ContextID != uuid.Nil {
		out.ContextID = t.ContextID.String()
	}
	switch t.State {
	case db.TrackProvisional, db.TrackIncluded, db.TrackReverted:
		status := "included"
		if t.State == db.TrackReverted {
			status = "reverted"
		}
		out.Execution = &nodepolicy.ExecutionOutcome{Status: status, BlockNumber: t.BlockNumber, Finalized: t.Final(), Created: []nodepolicy.CreatedContract{}}
	}
	return out
}
