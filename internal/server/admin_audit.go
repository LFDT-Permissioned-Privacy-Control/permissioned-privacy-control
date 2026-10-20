package server

import (
	"log/slog"

	"github.com/gin-gonic/gin"

	"privacy-proxy/internal/rbac"
)

// recordAuditAction writes an entry to rbac_audit_log for a successful
// admin mutation. Failures to write are logged but do NOT propagate — the
// mutation has already happened, and dropping a 200 because the audit
// table is unavailable would force the caller to re-issue (potentially
// double-mutating). Vanta / ISO 27001 evidence-completeness is handled
// by the audit retention worker's "rows pruned" tally and by alerting
// when the failure log volume crosses a threshold; per-write failure is
// recoverable through that channel.
//
// actorID may be empty (super-admin auth_method == "admin_token" has no
// user row); we still record actor_external_id ("__super_admin__" or
// the JWT subject) and the auth_method tag so downstream filtering can
// distinguish the two paths.
func (s *Server) recordAuditAction(
	c *gin.Context,
	action string,
	resourceType string,
	resourceID string,
	resourceName string,
	oldValue, newValue map[string]any,
) {
	s.recordAuditActionScoped(c, action, resourceType, resourceID, resourceName, "", oldValue, newValue)
}

// recordAuditActionScoped is the org-aware variant used by cross-org-sensitive
// resource types (group, contract, organization, grant, sanction, …). Pass
// the natural parent org_id of the affected resource so listAuditLogs can
// filter for JWT admins (security audit H1).
//
// orgID may be empty for resource types without a natural org (user,
// membership) — those entries are visible only to super-admin.
func (s *Server) recordAuditActionScoped(
	c *gin.Context,
	action string,
	resourceType string,
	resourceID string,
	resourceName string,
	orgID string,
	oldValue, newValue map[string]any,
) {
	if s.db == nil {
		return
	}

	authMethod := c.GetString("auth_method")
	actorExternalID := "__super_admin__"
	var actorID *string
	switch authMethod {
	case "jwt_admin":
		if subject := c.GetString("admin_subject"); subject != "" {
			actorExternalID = subject
		}
		if uid := c.GetString("admin_user_id"); uid != "" {
			actorID = &uid
		}
	case "operator_token":
		// The restricted operator/bootstrap token is a distinct principal from
		// the full super-admin token (RD-1132). Attribute its mutations to
		// "__operator__" so the audit trail does not misreport an operator
		// action as a super-admin one (change-management / actor fidelity).
		actorExternalID = "__operator__"
	}

	var orgIDPtr *string
	if orgID != "" {
		orgIDPtr = &orgID
	}

	entry := &rbac.AuditLogEntry{
		ActorID:         actorID,
		ActorExternalID: actorExternalID,
		Action:          action,
		ResourceType:    resourceType,
		ResourceID:      &resourceID,
		ResourceName:    resourceName,
		OrgID:           orgIDPtr,
		OldValue:        oldValue,
		NewValue:        newValue,
		IPAddress:       c.ClientIP(),
	}

	if err := s.db.CreateAuditLog(c.Request.Context(), entry); err != nil {
		slog.Error("audit log write failed",
			"action", action,
			"resource_type", resourceType,
			"resource_id", resourceID,
			"actor_external_id", actorExternalID,
			"err", err)
	}
}
