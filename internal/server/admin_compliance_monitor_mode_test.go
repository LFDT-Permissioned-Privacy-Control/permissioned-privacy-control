package server

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"privacy-proxy/internal/compliance"
)

// TestUpdateComplianceConfig_EnforcementMode covers RD-1044: the admin
// compliance-config endpoint persists enforce/monitor, defaults to enforce when
// the mode is omitted, and rejects invalid values. Mirrors the
// UnknownPricePolicy test and runs against a real Postgres (migration 061
// applied by setupTestServerForCompliance -> database.Migrate).
func TestUpdateComplianceConfig_EnforcementMode(t *testing.T) {
	ts := setupTestServerForCompliance(t)
	seed := seedComplianceTestData(t, ts.db)

	ctx := context.Background()
	orgID := seed.orgID

	tests := []struct {
		name       string
		body       string
		wantStatus int
		wantMode   compliance.EnforcementMode
	}{
		{
			// First PUT creates the config without a mode -> must default to
			// enforce (the safe default; AC: default = enforce).
			name:       "defaults to enforce when mode omitted",
			body:       `{"enabled": true, "threshold_fiat": 1000}`,
			wantStatus: http.StatusOK,
			wantMode:   compliance.EnforcementEnforce,
		},
		{
			name:       "valid monitor mode",
			body:       `{"enforcement_mode": "monitor"}`,
			wantStatus: http.StatusOK,
			wantMode:   compliance.EnforcementMonitor,
		},
		{
			name:       "valid enforce mode",
			body:       `{"enforcement_mode": "enforce"}`,
			wantStatus: http.StatusOK,
			wantMode:   compliance.EnforcementEnforce,
		},
		{
			name:       "invalid mode rejected",
			body:       `{"enforcement_mode": "audit"}`,
			wantStatus: http.StatusBadRequest,
			wantMode:   compliance.EnforcementEnforce, // unchanged from prior case
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			c.Request = httptest.NewRequest(http.MethodPut, "/", bytes.NewBuffer([]byte(tc.body)))
			c.Params = gin.Params{gin.Param{Key: "org_id", Value: orgID}}

			ts.updateComplianceConfig(c)

			assert.Equal(t, tc.wantStatus, w.Code)

			cfg, err := ts.db.GetComplianceConfig(ctx, orgID)
			require.NoError(t, err)
			require.NotNil(t, cfg)
			assert.Equal(t, tc.wantMode, cfg.EnforcementMode)
		})
	}
}
