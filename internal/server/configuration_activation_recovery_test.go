package server

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"privacy-proxy/internal/configuration"
	"privacy-proxy/internal/db"
)

type lostActivationResponse struct {
	header http.Header
	status int
	failed bool
}

func (w *lostActivationResponse) Header() http.Header    { return w.header }
func (w *lostActivationResponse) WriteHeader(status int) { w.status = status }
func (w *lostActivationResponse) Write([]byte) (int, error) {
	w.failed = true
	return 0, io.ErrClosedPipe
}

// A failed response write is later than the transaction commit. It must not be
// interpreted as rollback or retried automatically. This bounded HTTP/database
// test proves readback with a fresh connection; it is not a full deployment or
// deployed-schema upgrade rehearsal.
func TestConfigurationActivationLostResponseReconcilesFromFreshReader(t *testing.T) {
	f := configurationAPI(t)
	doc := f.document(t)
	spec := doc.Spec.(configuration.GroupsSpec)
	groupID := uuid.NewString()
	spec.Groups = append(spec.Groups, configuration.Group{ID: groupID, Slug: "response-loss", Name: "Response loss", AllowedMethods: []string{"eth_call"}, Claims: []string{}})
	doc.Spec = spec
	response := f.request(t, f.readonly, http.MethodPost, f.base()+"/revisions", doc)
	require.Equal(t, http.StatusCreated, response.Code, response.Body.String())
	var draft struct {
		ID     string `json:"id"`
		Digest string `json:"digest"`
	}
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &draft))

	path := f.base() + "/revisions/" + draft.ID
	request := httptest.NewRequest(http.MethodPost, path+"/activate", nil)
	request.Header.Set("Authorization", "Bearer "+f.reviewer)
	lost := &lostActivationResponse{header: make(http.Header)}
	f.router.ServeHTTP(lost, request)
	require.True(t, lost.failed, "the activation response must actually be lost")
	require.Equal(t, http.StatusOK, lost.status)

	// Reconcile through the authenticated read path, without another mutation.
	response = f.request(t, f.reviewer, http.MethodGet, path, nil)
	require.Equal(t, http.StatusOK, response.Code, response.Body.String())
	var selected struct {
		ID     string `json:"id"`
		Digest string `json:"digest"`
		Status string `json:"status"`
	}
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &selected))
	require.Equal(t, draft.ID, selected.ID)
	require.Equal(t, draft.Digest, selected.Digest)
	require.Equal(t, "active", selected.Status)

	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		dsn = sharedTestDBURL(t)
	}
	fresh, err := db.New(dsn)
	require.NoError(t, err)
	t.Cleanup(func() { _ = fresh.Close() })
	context, err := fresh.GetConfigurationContext(t.Context(), configuration.Scope{Kind: "organization", ID: f.orgID}, configuration.Groups)
	require.NoError(t, err)
	require.NotNil(t, context.Active)
	require.Equal(t, draft.ID, context.Active.ID)
	require.Equal(t, draft.Digest, context.Active.Digest)
	group, err := fresh.GetGroup(t.Context(), groupID)
	require.NoError(t, err)
	require.NotNil(t, group)
	var activations int
	require.NoError(t, fresh.Conn().QueryRowContext(t.Context(), `SELECT COUNT(*) FROM rbac_audit_log WHERE org_id=$1 AND resource_type='configuration_revision' AND resource_id=$2 AND action='update'`, f.orgID, draft.ID).Scan(&activations))
	require.Equal(t, 1, activations, "one committed activation must have one attributed activation record")
}
