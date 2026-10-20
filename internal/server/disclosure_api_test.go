package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"privacy-proxy/internal/disclosure"
)

// mockDisclosureStore implements disclosure.Store for testing.
type mockDisclosureStore struct {
	requests          map[string]*disclosure.Request
	grants            map[string]*disclosure.Grant
	requestsWithDeets []*disclosure.RequestWithDetails
	grantsWithReqs    []*disclosure.GrantWithRequest
	deletedRequests   []string
	revokedGrants     []string
}

func newMockDisclosureStore() *mockDisclosureStore {
	return &mockDisclosureStore{
		requests:        make(map[string]*disclosure.Request),
		grants:          make(map[string]*disclosure.Grant),
		deletedRequests: []string{},
		revokedGrants:   []string{},
	}
}

func (m *mockDisclosureStore) CreateRequest(ctx context.Context, req *disclosure.Request) error {
	m.requests[req.ID] = req
	return nil
}

func (m *mockDisclosureStore) GetRequest(ctx context.Context, id string) (*disclosure.Request, error) {
	req, ok := m.requests[id]
	if !ok {
		return nil, nil
	}
	return req, nil
}

func (m *mockDisclosureStore) GetRequestWithDetails(ctx context.Context, id string) (*disclosure.RequestWithDetails, error) {
	req, ok := m.requests[id]
	if !ok {
		return nil, nil
	}
	return &disclosure.RequestWithDetails{Request: req, TargetDID: "did:test:target"}, nil
}

func (m *mockDisclosureStore) UpdateRequestStatus(ctx context.Context, id string, status disclosure.RequestStatus, decidedByUserID *string, reason string) error {
	req, ok := m.requests[id]
	if !ok {
		return disclosure.ErrRequestNotFound
	}
	req.Status = status
	req.DecisionReason = reason
	now := time.Now()
	req.DecidedAt = &now
	req.DecidedByUserID = decidedByUserID
	return nil
}

func (m *mockDisclosureStore) ListRequestsByTarget(ctx context.Context, targetUserID string, status *disclosure.RequestStatus) ([]*disclosure.Request, error) {
	var results []*disclosure.Request
	for _, req := range m.requests {
		if req.TargetUserID == targetUserID {
			if status == nil || req.Status == *status {
				results = append(results, req)
			}
		}
	}
	return results, nil
}

func (m *mockDisclosureStore) ListRequestsByRequester(ctx context.Context, requesterUserID string) ([]*disclosure.Request, error) {
	return nil, nil
}

func (m *mockDisclosureStore) ListRequestsByOrg(ctx context.Context, orgID string, status *disclosure.RequestStatus) ([]*disclosure.Request, error) {
	var results []*disclosure.Request
	for _, req := range m.requests {
		if req.OrgID == orgID {
			if status == nil || req.Status == *status {
				results = append(results, req)
			}
		}
	}
	return results, nil
}

func (m *mockDisclosureStore) ListPendingRequestsForUser(ctx context.Context, targetUserID string) ([]*disclosure.RequestWithDetails, error) {
	var results []*disclosure.RequestWithDetails
	for _, req := range m.requests {
		if req.TargetUserID == targetUserID && req.Status == disclosure.StatusPending {
			results = append(results, &disclosure.RequestWithDetails{Request: req, TargetDID: "did:test:target"})
		}
	}
	return results, nil
}

func (m *mockDisclosureStore) ExpirePendingRequests(ctx context.Context) (int64, error) {
	return 0, nil
}

func (m *mockDisclosureStore) DeleteRequest(ctx context.Context, id string) error {
	req, ok := m.requests[id]
	if !ok {
		return disclosure.ErrRequestNotFound
	}
	if req.Status != disclosure.StatusPending {
		return disclosure.ErrRequestNotPending
	}
	delete(m.requests, id)
	m.deletedRequests = append(m.deletedRequests, id)
	return nil
}

func (m *mockDisclosureStore) ListRequestsWithFilter(ctx context.Context, filter *disclosure.DisclosureFilter) (*disclosure.DisclosureListResult, error) {
	var results []*disclosure.RequestWithDetails
	for _, req := range m.requests {
		// Apply filters
		if filter.Status != nil && req.Status != *filter.Status {
			continue
		}
		if filter.TargetUserID != "" && req.TargetUserID != filter.TargetUserID {
			continue
		}
		if filter.RequesterDID != "" && req.RequesterDID != filter.RequesterDID {
			continue
		}
		if filter.OrgID != "" && req.OrgID != filter.OrgID {
			continue
		}
		if filter.DateFrom != nil && req.RequestedAt.Before(*filter.DateFrom) {
			continue
		}
		if filter.DateTo != nil && req.RequestedAt.After(*filter.DateTo) {
			continue
		}
		results = append(results, &disclosure.RequestWithDetails{Request: req, TargetDID: "did:test:target"})
	}

	// Apply pagination
	limit := filter.Limit
	if limit <= 0 {
		limit = 100
	}
	offset := filter.Offset
	if offset < 0 {
		offset = 0
	}

	total := int64(len(results))
	if offset >= len(results) {
		results = nil
	} else if offset+limit >= len(results) {
		results = results[offset:]
	} else {
		results = results[offset : offset+limit]
	}

	return &disclosure.DisclosureListResult{
		Requests: results,
		Total:    total,
		Limit:    limit,
		Offset:   offset,
	}, nil
}

func (m *mockDisclosureStore) ListGrantsWithFilter(ctx context.Context, filter *disclosure.DisclosureFilter) (*disclosure.GrantListResult, error) {
	var results []*disclosure.GrantWithRequest
	for _, grant := range m.grants {
		req := m.requests[grant.RequestID]
		if req == nil {
			continue
		}

		// Apply filters
		if filter.TargetUserID != "" && req.TargetUserID != filter.TargetUserID {
			continue
		}
		if filter.RequesterDID != "" && req.RequesterDID != filter.RequesterDID {
			continue
		}
		if filter.OrgID != "" && req.OrgID != filter.OrgID {
			continue
		}
		if filter.DateFrom != nil && grant.GrantedAt.Before(*filter.DateFrom) {
			continue
		}
		if filter.DateTo != nil && grant.GrantedAt.After(*filter.DateTo) {
			continue
		}

		// Status filter for grants
		if filter.Status != nil {
			now := time.Now()
			switch *filter.Status {
			case disclosure.StatusApproved:
				if grant.RevokedAt != nil || grant.ExpiresAt.Before(now) {
					continue
				}
			case disclosure.StatusRevoked:
				if grant.RevokedAt == nil {
					continue
				}
			case disclosure.StatusExpired:
				if grant.RevokedAt != nil || !grant.ExpiresAt.Before(now) {
					continue
				}
			}
		}

		results = append(results, &disclosure.GrantWithRequest{Grant: grant, Request: req})
	}

	// Apply pagination
	limit := filter.Limit
	if limit <= 0 {
		limit = 100
	}
	offset := filter.Offset
	if offset < 0 {
		offset = 0
	}

	total := int64(len(results))
	if offset >= len(results) {
		results = nil
	} else if offset+limit >= len(results) {
		results = results[offset:]
	} else {
		results = results[offset : offset+limit]
	}

	return &disclosure.GrantListResult{
		Grants: results,
		Total:  total,
		Limit:  limit,
		Offset: offset,
	}, nil
}

func (m *mockDisclosureStore) ListAllRequestsForUser(ctx context.Context, targetUserID string) ([]*disclosure.RequestWithDetails, error) {
	var results []*disclosure.RequestWithDetails
	for _, req := range m.requests {
		if req.TargetUserID == targetUserID {
			results = append(results, &disclosure.RequestWithDetails{Request: req, TargetDID: "did:test:target"})
		}
	}
	return results, nil
}

func (m *mockDisclosureStore) ListAllGrantsForTarget(ctx context.Context, targetUserID string) ([]*disclosure.GrantWithRequest, error) {
	var results []*disclosure.GrantWithRequest
	for _, grant := range m.grants {
		req := m.requests[grant.RequestID]
		if req != nil && req.TargetUserID == targetUserID {
			results = append(results, &disclosure.GrantWithRequest{Grant: grant, Request: req})
		}
	}
	return results, nil
}

func (m *mockDisclosureStore) CreateGrant(ctx context.Context, grant *disclosure.Grant) error {
	m.grants[grant.ID] = grant
	return nil
}

func (m *mockDisclosureStore) GetGrant(ctx context.Context, id string) (*disclosure.Grant, error) {
	grant, ok := m.grants[id]
	if !ok {
		return nil, nil
	}
	return grant, nil
}

func (m *mockDisclosureStore) GetGrantByToken(ctx context.Context, tokenHash string) (*disclosure.Grant, error) {
	for _, grant := range m.grants {
		if grant.GrantTokenHash == tokenHash {
			return grant, nil
		}
	}
	return nil, nil
}

func (m *mockDisclosureStore) GetGrantWithRequest(ctx context.Context, id string) (*disclosure.GrantWithRequest, error) {
	grant, ok := m.grants[id]
	if !ok {
		return nil, nil
	}
	req := m.requests[grant.RequestID]
	return &disclosure.GrantWithRequest{Grant: grant, Request: req}, nil
}

func (m *mockDisclosureStore) GetActiveGrantForRequest(ctx context.Context, requestID string) (*disclosure.Grant, error) {
	for _, grant := range m.grants {
		if grant.RequestID == requestID && grant.IsActive() {
			return grant, nil
		}
	}
	return nil, nil
}

func (m *mockDisclosureStore) RevokeGrant(ctx context.Context, id string, reason string) error {
	grant, ok := m.grants[id]
	if !ok {
		return disclosure.ErrGrantNotFound
	}
	now := time.Now()
	grant.RevokedAt = &now
	grant.RevokedReason = reason
	m.revokedGrants = append(m.revokedGrants, id)
	return nil
}

func (m *mockDisclosureStore) ListActiveGrantsForTarget(ctx context.Context, targetUserID string) ([]*disclosure.GrantWithRequest, error) {
	var results []*disclosure.GrantWithRequest
	for _, grant := range m.grants {
		if grant.IsActive() {
			req := m.requests[grant.RequestID]
			if req != nil && req.TargetUserID == targetUserID {
				results = append(results, &disclosure.GrantWithRequest{Grant: grant, Request: req})
			}
		}
	}
	return results, nil
}

// Implement remaining Store interface methods with stubs
func (m *mockDisclosureStore) CreateEvent(ctx context.Context, event *disclosure.Event) error {
	return nil
}

func (m *mockDisclosureStore) ListEventsByGrant(ctx context.Context, grantID string, limit, offset int) ([]*disclosure.Event, error) {
	return nil, nil
}

func (m *mockDisclosureStore) GetEventStats(ctx context.Context, grantID string) (map[disclosure.EventAction]int, error) {
	return nil, nil
}

func (m *mockDisclosureStore) CreateReport(ctx context.Context, report *disclosure.Report) error {
	return nil
}

func (m *mockDisclosureStore) GetReport(ctx context.Context, id string) (*disclosure.Report, error) {
	return nil, nil
}

func (m *mockDisclosureStore) GetReportByGrantAndType(ctx context.Context, grantID string, reportType disclosure.ReportType) (*disclosure.Report, error) {
	return nil, nil
}

func (m *mockDisclosureStore) DeleteExpiredReports(ctx context.Context) (int64, error) {
	return 0, nil
}

func (m *mockDisclosureStore) GetActivityLogs(ctx context.Context, userExternalID string, scope *disclosure.Scope, limit, offset int) ([]*disclosure.ActivityLogEntry, error) {
	return nil, nil
}

func (m *mockDisclosureStore) GetActivitySummary(ctx context.Context, userExternalID string, scope *disclosure.Scope) (*disclosure.ActivitySummary, error) {
	return nil, nil
}

func (m *mockDisclosureStore) GetUserExternalID(ctx context.Context, userID string) (string, error) {
	return "did:test:" + userID, nil
}

// Verify mockDisclosureStore implements Store interface
var _ disclosure.Store = (*mockDisclosureStore)(nil)

// TestListDisclosureRequestsWithFilter tests the filtered listing endpoint.
func TestListDisclosureRequestsWithFilter(t *testing.T) {
	gin.SetMode(gin.TestMode)

	store := newMockDisclosureStore()
	svc := disclosure.NewService(store)

	// Add test requests
	now := time.Now()
	requests := []*disclosure.Request{
		{
			ID:           "req-1",
			TargetUserID: "user-1",
			OrgID:        "org-1",
			RequesterDID: "did:auditor:1",
			Status:       disclosure.StatusPending,
			Reason:       "Test 1",
			RequestedAt:  now.Add(-24 * time.Hour),
		},
		{
			ID:           "req-2",
			TargetUserID: "user-1",
			OrgID:        "org-1",
			RequesterDID: "did:auditor:2",
			Status:       disclosure.StatusApproved,
			Reason:       "Test 2",
			RequestedAt:  now.Add(-12 * time.Hour),
		},
		{
			ID:           "req-3",
			TargetUserID: "user-2",
			OrgID:        "org-1",
			RequesterDID: "did:auditor:1",
			Status:       disclosure.StatusPending,
			Reason:       "Test 3",
			RequestedAt:  now,
		},
	}

	for _, req := range requests {
		store.requests[req.ID] = req
	}

	tests := []struct {
		name           string
		queryParams    string
		expectedCount  int
		expectedTotal  int64
		expectedStatus int
	}{
		{
			name:           "list all requests",
			queryParams:    "",
			expectedCount:  3,
			expectedTotal:  3,
			expectedStatus: http.StatusOK,
		},
		{
			name:           "filter by status pending",
			queryParams:    "status=pending",
			expectedCount:  2,
			expectedTotal:  2,
			expectedStatus: http.StatusOK,
		},
		{
			name:           "filter by target user",
			queryParams:    "target_user_id=user-1",
			expectedCount:  2,
			expectedTotal:  2,
			expectedStatus: http.StatusOK,
		},
		{
			name:           "filter by requester DID",
			queryParams:    "requester_did=did:auditor:1",
			expectedCount:  2,
			expectedTotal:  2,
			expectedStatus: http.StatusOK,
		},
		{
			name:           "filter with pagination",
			queryParams:    "limit=1&offset=0",
			expectedCount:  1,
			expectedTotal:  3,
			expectedStatus: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			router := gin.New()
			router.GET("/disclosure/requests", func(c *gin.Context) {
				// Parse filter from query params
				filter := &disclosure.DisclosureFilter{}
				if status := c.Query("status"); status != "" {
					st := disclosure.RequestStatus(status)
					filter.Status = &st
				}
				filter.TargetUserID = c.Query("target_user_id")
				filter.RequesterDID = c.Query("requester_did")
				filter.OrgID = c.DefaultQuery("org_id", "org-1")
				if limit := c.Query("limit"); limit != "" {
					var l int
					if _, err := json.Marshal(limit); err == nil {
						json.Unmarshal([]byte(limit), &l)
						filter.Limit = l
					}
				}
				if offset := c.Query("offset"); offset != "" {
					var o int
					if _, err := json.Marshal(offset); err == nil {
						json.Unmarshal([]byte(offset), &o)
						filter.Offset = o
					}
				}

				result, err := svc.ListRequestsWithFilter(c.Request.Context(), filter)
				if err != nil {
					c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
					return
				}
				c.JSON(http.StatusOK, result)
			})

			req, _ := http.NewRequest("GET", "/disclosure/requests?"+tt.queryParams, nil)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code)

			if tt.expectedStatus == http.StatusOK {
				var result disclosure.DisclosureListResult
				err := json.Unmarshal(w.Body.Bytes(), &result)
				require.NoError(t, err)
				assert.Equal(t, tt.expectedCount, len(result.Requests))
				assert.Equal(t, tt.expectedTotal, result.Total)
			}
		})
	}
}

// TestDeleteDisclosureRequest tests the delete endpoint.
func TestDeleteDisclosureRequest(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name           string
		setupRequest   *disclosure.Request
		requestID      string
		expectedStatus int
	}{
		{
			name: "delete pending request",
			setupRequest: &disclosure.Request{
				ID:     "req-delete-1",
				Status: disclosure.StatusPending,
			},
			requestID:      "req-delete-1",
			expectedStatus: http.StatusOK,
		},
		{
			name: "cannot delete approved request",
			setupRequest: &disclosure.Request{
				ID:     "req-delete-2",
				Status: disclosure.StatusApproved,
			},
			requestID:      "req-delete-2",
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "request not found",
			setupRequest:   nil,
			requestID:      "nonexistent",
			expectedStatus: http.StatusNotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := newMockDisclosureStore()
			if tt.setupRequest != nil {
				store.requests[tt.setupRequest.ID] = tt.setupRequest
			}
			svc := disclosure.NewService(store)

			router := gin.New()
			router.DELETE("/disclosure/requests/:request_id", func(c *gin.Context) {
				requestID := c.Param("request_id")
				err := svc.DeletePendingRequest(c.Request.Context(), requestID)
				if err != nil {
					if err == disclosure.ErrRequestNotFound {
						c.JSON(http.StatusNotFound, gin.H{"error": "request not found"})
						return
					}
					if err == disclosure.ErrRequestNotPending {
						c.JSON(http.StatusBadRequest, gin.H{"error": "can only delete pending requests"})
						return
					}
					c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
					return
				}
				c.JSON(http.StatusOK, gin.H{"status": "deleted"})
			})

			req, _ := http.NewRequest("DELETE", "/disclosure/requests/"+tt.requestID, nil)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code)

			if tt.expectedStatus == http.StatusOK {
				// Verify request was deleted
				assert.Contains(t, store.deletedRequests, tt.requestID)
			}
		})
	}
}

// TestAdminRevokeGrant tests the admin revoke endpoint.
func TestAdminRevokeGrant(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name           string
		setupGrant     *disclosure.Grant
		setupRequest   *disclosure.Request
		grantID        string
		revokeReason   string
		expectedStatus int
	}{
		{
			name: "revoke active grant",
			setupGrant: &disclosure.Grant{
				ID:        "grant-revoke-1",
				RequestID: "req-revoke-1",
				GrantedAt: time.Now(),
				ExpiresAt: time.Now().Add(24 * time.Hour),
			},
			setupRequest: &disclosure.Request{
				ID:     "req-revoke-1",
				Status: disclosure.StatusApproved,
			},
			grantID:        "grant-revoke-1",
			revokeReason:   "Admin revocation",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "grant not found",
			setupGrant:     nil,
			setupRequest:   nil,
			grantID:        "nonexistent",
			revokeReason:   "Test",
			expectedStatus: http.StatusNotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := newMockDisclosureStore()
			if tt.setupGrant != nil {
				store.grants[tt.setupGrant.ID] = tt.setupGrant
			}
			if tt.setupRequest != nil {
				store.requests[tt.setupRequest.ID] = tt.setupRequest
			}
			svc := disclosure.NewService(store)

			router := gin.New()
			router.POST("/disclosure/grants/:grant_id/revoke", func(c *gin.Context) {
				grantID := c.Param("grant_id")
				var input struct {
					Reason string `json:"reason"`
				}
				_ = c.ShouldBindJSON(&input)

				err := svc.RevokeGrant(c.Request.Context(), grantID, input.Reason)
				if err != nil {
					if err == disclosure.ErrGrantNotFound {
						c.JSON(http.StatusNotFound, gin.H{"error": "grant not found"})
						return
					}
					c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
					return
				}
				c.JSON(http.StatusOK, gin.H{"status": "revoked"})
			})

			body, _ := json.Marshal(map[string]string{"reason": tt.revokeReason})
			req, _ := http.NewRequest("POST", "/disclosure/grants/"+tt.grantID+"/revoke", bytes.NewBuffer(body))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code)

			if tt.expectedStatus == http.StatusOK {
				// Verify grant was revoked
				assert.Contains(t, store.revokedGrants, tt.grantID)
				assert.NotNil(t, store.grants[tt.grantID].RevokedAt)
				assert.Equal(t, tt.revokeReason, store.grants[tt.grantID].RevokedReason)
			}
		})
	}
}

// TestListGrantsWithFilter tests the grant listing endpoint with filters.
func TestListGrantsWithFilter(t *testing.T) {
	gin.SetMode(gin.TestMode)

	store := newMockDisclosureStore()
	svc := disclosure.NewService(store)

	now := time.Now()

	// Add test requests
	store.requests["req-1"] = &disclosure.Request{
		ID:           "req-1",
		TargetUserID: "user-1",
		OrgID:        "org-1",
		RequesterDID: "did:auditor:1",
		Status:       disclosure.StatusApproved,
	}
	store.requests["req-2"] = &disclosure.Request{
		ID:           "req-2",
		TargetUserID: "user-2",
		OrgID:        "org-1",
		RequesterDID: "did:auditor:2",
		Status:       disclosure.StatusApproved,
	}

	// Add test grants
	store.grants["grant-1"] = &disclosure.Grant{
		ID:        "grant-1",
		RequestID: "req-1",
		GrantedAt: now.Add(-24 * time.Hour),
		ExpiresAt: now.Add(24 * time.Hour), // Active
	}
	store.grants["grant-2"] = &disclosure.Grant{
		ID:        "grant-2",
		RequestID: "req-2",
		GrantedAt: now.Add(-48 * time.Hour),
		ExpiresAt: now.Add(-24 * time.Hour), // Expired
	}
	revokedAt := now.Add(-12 * time.Hour)
	store.grants["grant-3"] = &disclosure.Grant{
		ID:            "grant-3",
		RequestID:     "req-1",
		GrantedAt:     now.Add(-72 * time.Hour),
		ExpiresAt:     now.Add(24 * time.Hour),
		RevokedAt:     &revokedAt, // Revoked
		RevokedReason: "User requested",
	}

	tests := []struct {
		name           string
		queryParams    string
		expectedCount  int
		expectedStatus int
	}{
		{
			name:           "list all grants",
			queryParams:    "",
			expectedCount:  3,
			expectedStatus: http.StatusOK,
		},
		{
			name:           "filter active grants",
			queryParams:    "status=approved",
			expectedCount:  1,
			expectedStatus: http.StatusOK,
		},
		{
			name:           "filter revoked grants",
			queryParams:    "status=revoked",
			expectedCount:  1,
			expectedStatus: http.StatusOK,
		},
		{
			name:           "filter by target user",
			queryParams:    "target_user_id=user-1",
			expectedCount:  2,
			expectedStatus: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			router := gin.New()
			router.GET("/disclosure/grants", func(c *gin.Context) {
				filter := &disclosure.DisclosureFilter{}
				if status := c.Query("status"); status != "" {
					st := disclosure.RequestStatus(status)
					filter.Status = &st
				}
				filter.TargetUserID = c.Query("target_user_id")

				result, err := svc.ListGrantsWithFilter(c.Request.Context(), filter)
				if err != nil {
					c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
					return
				}
				c.JSON(http.StatusOK, result)
			})

			req, _ := http.NewRequest("GET", "/disclosure/grants?"+tt.queryParams, nil)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code)

			if tt.expectedStatus == http.StatusOK {
				var result disclosure.GrantListResult
				err := json.Unmarshal(w.Body.Bytes(), &result)
				require.NoError(t, err)
				assert.Equal(t, tt.expectedCount, len(result.Grants))
			}
		})
	}
}

// TestGetAllMyRequests tests the user endpoint for getting all requests.
func TestGetAllMyRequests(t *testing.T) {
	gin.SetMode(gin.TestMode)

	store := newMockDisclosureStore()
	svc := disclosure.NewService(store)

	// Add test requests for user-1
	store.requests["req-1"] = &disclosure.Request{
		ID:           "req-1",
		TargetUserID: "user-1",
		Status:       disclosure.StatusPending,
	}
	store.requests["req-2"] = &disclosure.Request{
		ID:           "req-2",
		TargetUserID: "user-1",
		Status:       disclosure.StatusApproved,
	}
	store.requests["req-3"] = &disclosure.Request{
		ID:           "req-3",
		TargetUserID: "user-1",
		Status:       disclosure.StatusRejected,
	}
	store.requests["req-4"] = &disclosure.Request{
		ID:           "req-4",
		TargetUserID: "user-2", // Different user
		Status:       disclosure.StatusPending,
	}

	router := gin.New()
	router.GET("/me/disclosure/requests/all", func(c *gin.Context) {
		// Simulate user-1 being authenticated
		userID := "user-1"
		requests, err := svc.GetAllMyRequests(c.Request.Context(), userID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, requests)
	})

	req, _ := http.NewRequest("GET", "/me/disclosure/requests/all", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var results []*disclosure.RequestWithDetails
	err := json.Unmarshal(w.Body.Bytes(), &results)
	require.NoError(t, err)
	assert.Len(t, results, 3) // Should get all 3 requests for user-1
}

// TestGetAllMyGrants tests the user endpoint for getting all grants.
func TestGetAllMyGrants(t *testing.T) {
	gin.SetMode(gin.TestMode)

	store := newMockDisclosureStore()
	svc := disclosure.NewService(store)

	now := time.Now()

	// Add requests
	store.requests["req-1"] = &disclosure.Request{
		ID:           "req-1",
		TargetUserID: "user-1",
		Status:       disclosure.StatusApproved,
	}
	store.requests["req-2"] = &disclosure.Request{
		ID:           "req-2",
		TargetUserID: "user-2",
		Status:       disclosure.StatusApproved,
	}

	// Add grants
	store.grants["grant-1"] = &disclosure.Grant{
		ID:        "grant-1",
		RequestID: "req-1",
		GrantedAt: now,
		ExpiresAt: now.Add(24 * time.Hour), // Active
	}
	store.grants["grant-2"] = &disclosure.Grant{
		ID:        "grant-2",
		RequestID: "req-1",
		GrantedAt: now.Add(-48 * time.Hour),
		ExpiresAt: now.Add(-24 * time.Hour), // Expired
	}
	store.grants["grant-3"] = &disclosure.Grant{
		ID:        "grant-3",
		RequestID: "req-2", // Different user
		GrantedAt: now,
		ExpiresAt: now.Add(24 * time.Hour),
	}

	router := gin.New()
	router.GET("/me/disclosure/grants/all", func(c *gin.Context) {
		userID := "user-1"
		grants, err := svc.GetAllMyGrants(c.Request.Context(), userID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, grants)
	})

	req, _ := http.NewRequest("GET", "/me/disclosure/grants/all", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var results []*disclosure.GrantWithRequest
	err := json.Unmarshal(w.Body.Bytes(), &results)
	require.NoError(t, err)
	assert.Len(t, results, 2) // Should get both grants for user-1 (active and expired)
}
