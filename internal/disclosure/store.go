package disclosure

import (
	"context"
	"time"
)

// Store defines the interface for disclosure data operations.
type Store interface {
	// Request operations
	CreateRequest(ctx context.Context, req *Request) error
	GetRequest(ctx context.Context, id string) (*Request, error)
	GetRequestWithDetails(ctx context.Context, id string) (*RequestWithDetails, error)
	UpdateRequestStatus(ctx context.Context, id string, status RequestStatus, decidedByUserID *string, reason string) error
	ListRequestsByTarget(ctx context.Context, targetUserID string, status *RequestStatus) ([]*Request, error)
	ListRequestsByRequester(ctx context.Context, requesterUserID string) ([]*Request, error)
	ListRequestsByOrg(ctx context.Context, orgID string, status *RequestStatus) ([]*Request, error)
	ListPendingRequestsForUser(ctx context.Context, targetUserID string) ([]*RequestWithDetails, error)
	ExpirePendingRequests(ctx context.Context) (int64, error) // Expire old pending requests
	DeleteRequest(ctx context.Context, id string) error       // Delete a pending request (admin only)

	// Filtered listing operations
	ListRequestsWithFilter(ctx context.Context, filter *DisclosureFilter) (*DisclosureListResult, error)
	ListGrantsWithFilter(ctx context.Context, filter *DisclosureFilter) (*GrantListResult, error)
	ListAllRequestsForUser(ctx context.Context, targetUserID string) ([]*RequestWithDetails, error) // All requests (not just pending)
	ListAllGrantsForTarget(ctx context.Context, targetUserID string) ([]*GrantWithRequest, error)   // All grants (not just active)

	// Grant operations
	CreateGrant(ctx context.Context, grant *Grant) error
	GetGrant(ctx context.Context, id string) (*Grant, error)
	GetGrantByToken(ctx context.Context, tokenHash string) (*Grant, error)
	GetGrantWithRequest(ctx context.Context, id string) (*GrantWithRequest, error)
	GetActiveGrantForRequest(ctx context.Context, requestID string) (*Grant, error)
	RevokeGrant(ctx context.Context, id string, reason string) error
	ListActiveGrantsForTarget(ctx context.Context, targetUserID string) ([]*GrantWithRequest, error)

	// Event operations
	CreateEvent(ctx context.Context, event *Event) error
	ListEventsByGrant(ctx context.Context, grantID string, limit, offset int) ([]*Event, error)
	GetEventStats(ctx context.Context, grantID string) (map[EventAction]int, error)

	// Report operations
	CreateReport(ctx context.Context, report *Report) error
	GetReport(ctx context.Context, id string) (*Report, error)
	GetReportByGrantAndType(ctx context.Context, grantID string, reportType ReportType) (*Report, error)
	DeleteExpiredReports(ctx context.Context) (int64, error)

	// Activity data access (for generating reports)
	GetActivityLogs(ctx context.Context, userExternalID string, scope *Scope, limit, offset int) ([]*ActivityLogEntry, error)
	GetActivitySummary(ctx context.Context, userExternalID string, scope *Scope) (*ActivitySummary, error)

	// User lookup (for converting internal IDs to external IDs)
	GetUserExternalID(ctx context.Context, userID string) (string, error)
}

// Service provides high-level disclosure operations.
type Service interface {
	// Request workflow
	CreateRequest(ctx context.Context, requesterUserID, requesterDID, targetUserID, orgID string, scope Scope, reason, legalBasis string, expiresIn *time.Duration) (*Request, error)
	ApproveRequest(ctx context.Context, requestID, decidedByUserID string, narrowedScope *Scope, grantDuration time.Duration, reason string) (*Grant, string, error) // returns grant and raw token
	RejectRequest(ctx context.Context, requestID, decidedByUserID, reason string) error
	RevokeRequest(ctx context.Context, requestID, revokedByUserID, reason string) error

	// Grant access
	ValidateGrantToken(ctx context.Context, token string) (*GrantWithRequest, error)
	RevokeGrant(ctx context.Context, grantID, reason string) error

	// Data access (requires valid grant)
	GetActivityLogs(ctx context.Context, grantID, viewerUserID, viewerIP string, limit, offset int) ([]*ActivityLogEntry, error)
	GetActivitySummary(ctx context.Context, grantID, viewerUserID, viewerIP string) (*ActivitySummary, error)
	GenerateComplianceReport(ctx context.Context, grantID, viewerUserID, viewerIP string, reportType ReportType) (*Report, error)

	// User-facing
	GetMyPendingRequests(ctx context.Context, userID string) ([]*RequestWithDetails, error)
	GetMyActiveGrants(ctx context.Context, userID string) ([]*GrantWithRequest, error)

	// Admin
	ListAllRequests(ctx context.Context, orgID string, status *RequestStatus) ([]*RequestWithDetails, error)

	// Maintenance
	ExpireOldRequests(ctx context.Context) (int64, error)
	CleanupExpiredReports(ctx context.Context) (int64, error)
}
