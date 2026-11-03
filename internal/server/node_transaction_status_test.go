package server

import (
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"privacy-proxy/internal/config"
	"privacy-proxy/internal/db"
	"privacy-proxy/internal/nodepolicy"
	"privacy-proxy/internal/server/middleware"
)

func TestMyNodeTransactionStatusRequiresOriginalLivePrincipal(t *testing.T) {
	f := configurationAPI(t)
	s := f.server
	s.config.NodePolicy = config.NodePolicyConfig{Mode: "reth", ChainID: 31337, DeploymentID: "status-test"}
	s.rateLimiter = middleware.NewRateLimiter(middleware.RateLimiterCleanupInterval)
	t.Cleanup(s.rateLimiter.Stop)
	_, err := s.db.Conn().ExecContext(t.Context(), `UPDATE users SET kyc=true WHERE id=$1`, f.readonlyUserID)
	require.NoError(t, err)
	user, err := s.db.GetUser(t.Context(), f.readonlyUserID)
	require.NoError(t, err)
	network := nodepolicy.Network{ChainID: 31337, DeploymentID: "status-test"}
	tracking := newTestTracking(t, network)
	s.tracking = &executionTracking{runtime: tracking.runtime, admin: tracking.admin, meta: tracking.meta}
	transfer := newSignedTransfer(t, 0)
	hash := transfer.hash
	key := hashBytes(t, hash)
	results, err := tracking.runtime.AdmitBatch(t.Context(), tracking.meta.Incarnation, db.TrackLimits{}, []db.TrackAdmission{{Hash: key, PrincipalID: uuid.MustParse(user.ID), OrgID: uuid.MustParse(f.orgID), Signer: hashBytes(t, transfer.signer), ContextID: uuid.New(), EnvelopeHash: key, ExpiresAt: time.Now().Add(time.Minute), MinVersion: 7, Raw: []byte("private-raw-transaction"), VisibleTo: []string{"private-recipient"}, VisibleSender: user.ExternalID}})
	require.NoError(t, err)
	require.Equal(t, db.AdmitInserted, results[0].Outcome)
	router := gin.New()
	s.registerUserProfileRoutes(router)
	request := func(token, target string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/api/v1/me/transactions/"+target+"/execution", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		router.ServeHTTP(w, req)
		return w
	}
	response := request(f.readonly, hash)
	require.Equal(t, http.StatusOK, response.Code, response.Body.String())
	var got map[string]any
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &got))
	require.Equal(t, "pending", got["status"])
	require.Equal(t, false, got["reconciled"])
	for _, secret := range []string{hex.EncodeToString([]byte("private-raw-transaction")), "private-recipient", user.ExternalID} {
		require.NotContains(t, response.Body.String(), secret)
	}
	// Final status rows answer the owner until retention (G44).
	block := uint64(9)
	applied, err := tracking.runtime.FinalizeBatch(t.Context(), tracking.meta.Incarnation, []db.TrackFinal{{Hash: key, State: db.TrackIncluded, BlockNumber: &block, PrincipalID: uuid.MustParse(user.ID), OrgID: uuid.MustParse(f.orgID)}})
	require.NoError(t, err)
	require.True(t, applied[0])
	response = request(f.readonly, hash)
	require.Equal(t, http.StatusOK, response.Code, response.Body.String())
	got = map[string]any{}
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &got))
	require.Equal(t, "included", got["status"])
	require.Equal(t, true, got["reconciled"])
	require.EqualValues(t, 9, got["execution"].(map[string]any)["block_number"])
	require.Equal(t, http.StatusNotFound, request(f.admin, hash).Code, "other admin does not inherit submitter's status")
	require.Equal(t, http.StatusNotFound, request(f.readonly, "0x"+strings.Repeat("00", 32)).Code)
	_, err = s.db.Conn().ExecContext(t.Context(), `DELETE FROM user_memberships WHERE user_id=$1`, user.ID)
	require.NoError(t, err)
	require.Equal(t, http.StatusNotFound, request(f.readonly, hash).Code, "revoked organization membership retains no status visibility")
	// Authentication is still provided by the ordinary JWT middleware.
	require.Equal(t, http.StatusUnauthorized, request("", hash).Code)
}
