package server

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"privacy-proxy/internal/apimodels"
	"privacy-proxy/internal/config"
	"privacy-proxy/internal/configuration"
	"privacy-proxy/internal/policydsl"
)

func releaseCutExecutionDraft(t *testing.T, f configurationAPIFixture, actor string) apimodels.ConfigurationRevision {
	t.Helper()
	document := &configuration.Document{
		APIVersion: configuration.APIVersion, Kind: configuration.ExecutionRules,
		Scope:        configuration.Scope{Kind: "organization", ID: f.orgID},
		Dependencies: map[configuration.Kind]string{}, Deletions: []configuration.Deletion{},
		Spec: configuration.ExecutionSpec{Policy: mustJSON(t, &policydsl.Policy{
			APIVersion: policydsl.APIVersion, Kind: policydsl.Kind, Org: f.orgID,
			NestedCalls: policydsl.NestedCallsRequireOwnRule, Bindings: []policydsl.Binding{},
		})},
	}
	response := f.request(t, actor, http.MethodPost, "/api/v1/admin/orgs/"+f.orgID+"/configuration/execution-rules/revisions", document)
	require.Equal(t, http.StatusCreated, response.Code, response.Body.String())
	var draft apimodels.ConfigurationRevision
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &draft))
	return draft
}

func releaseCutConfigurationState(t *testing.T, f configurationAPIFixture) []int {
	t.Helper()
	values := make([]int, 3)
	for i, query := range []string{
		`SELECT COUNT(*) FROM configuration_revisions WHERE org_id=$1 AND status='active'`,
		`SELECT COUNT(*) FROM execution_policy_revisions WHERE org_id=$1 AND status='active'`,
		`SELECT COUNT(*) FROM rbac_audit_log WHERE org_id=$1 AND resource_type='configuration_revision'`,
	} {
		require.NoError(t, f.server.db.Conn().QueryRowContext(t.Context(), query, f.orgID).Scan(&values[i]))
	}
	return values
}

func TestExecutionPolicyActivationRequiresConsumerAndPreservesWithdrawal(t *testing.T) {
	f := configurationAPI(t)
	draft := releaseCutExecutionDraft(t, f, f.readonly)
	base := "/api/v1/admin/orgs/" + f.orgID + "/configuration/execution-rules/revisions/" + draft.ID

	// Review is useful without a live policy consumer; it makes no activation.
	response := f.request(t, f.readonly, http.MethodPost, base+"/simulate", nil)
	require.Equal(t, http.StatusOK, response.Code, response.Body.String())
	before := releaseCutConfigurationState(t, f)
	response = f.request(t, f.reviewer, http.MethodPost, base+"/activate", nil)
	require.Equal(t, http.StatusServiceUnavailable, response.Code, response.Body.String())
	require.Contains(t, response.Body.String(), executionConsumerUnavailable)
	require.Equal(t, before, releaseCutConfigurationState(t, f))

	// The activation-only wrapper must not poison withdrawal's shared authority
	// callback. An unsupported draft must not become impossible to retire.
	response = f.request(t, f.reviewer, http.MethodPost, base+"/withdraw", nil)
	require.Equal(t, http.StatusOK, response.Code, response.Body.String())
	var withdrawn apimodels.ConfigurationRevision
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &withdrawn))
	require.Equal(t, "withdrawn", withdrawn.Status)
}

func TestExecutionPolicyActivationChecksSiblingsBeforeAnyProjection(t *testing.T) {
	f := configurationAPI(t)
	execution := releaseCutExecutionDraft(t, f, f.readonly)
	doc := f.document(t)
	spec := doc.Spec.(configuration.GroupsSpec)
	groupID := uuid.NewString()
	spec.Groups = append(spec.Groups, configuration.Group{ID: groupID, Slug: "pending-group", Name: "Pending", AllowedMethods: []string{"eth_call"}, Claims: []string{}})
	doc.Spec = spec
	response := f.request(t, f.readonly, http.MethodPost, f.base()+"/revisions", doc)
	require.Equal(t, http.StatusCreated, response.Code, response.Body.String())
	var groups apimodels.ConfigurationRevision
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &groups))
	before := releaseCutConfigurationState(t, f)
	response = f.request(t, f.reviewer, http.MethodPost, f.base()+"/revisions/"+groups.ID+"/activate", map[string]any{"coactivate": []string{execution.ID}})
	require.Equal(t, http.StatusServiceUnavailable, response.Code, response.Body.String())
	require.Equal(t, before, releaseCutConfigurationState(t, f))
	stored, err := f.server.db.GetGroup(t.Context(), groupID)
	require.NoError(t, err)
	require.Nil(t, stored, "a non-execution URL must not partially activate a refused bundle")
}

func TestExecutionPolicyConfiguredConsumerCanActivateBeforeNodeApplication(t *testing.T) {
	f := configurationAPI(t)
	f.server.config.NodePolicy = releaseCutConsumerConfig(t)
	draft := releaseCutExecutionDraft(t, f, f.readonly)
	require.Nil(t, f.server.nodeExecution, "fixture deliberately has no reachable/applied bridge")
	response := f.request(t, f.reviewer, http.MethodPost, "/api/v1/admin/orgs/"+f.orgID+"/configuration/execution-rules/revisions/"+draft.ID+"/activate", nil)
	require.Equal(t, http.StatusOK, response.Code, response.Body.String())
	active, err := f.server.db.GetActiveExecutionPolicy(t.Context(), f.orgID)
	require.NoError(t, err)
	require.NotNil(t, active)
	require.Equal(t, draft.ID, active.ID)
}

func TestExecutionPolicyCapabilitiesAgreeAcrossBothContextAPIs(t *testing.T) {
	f := configurationAPI(t)
	for _, policy := range []config.NodePolicyConfig{{Mode: "legacy"}, releaseCutConsumerConfig(t)} {
		f.server.config.NodePolicy = policy
		expected := f.server.executionPolicyCapabilities()
		for _, path := range []string{f.base() + "/context", "/api/v1/admin/orgs/" + f.orgID + "/execution-policy/context"} {
			response := f.request(t, f.reviewer, http.MethodGet, path, nil)
			require.Equal(t, http.StatusOK, response.Code, response.Body.String())
			if strings.Contains(path, "/configuration/") {
				var value apimodels.ConfigurationContext
				require.NoError(t, json.Unmarshal(response.Body.Bytes(), &value))
				require.Equal(t, expected, value.Capabilities.ExecutionPolicy)
			} else {
				var value apimodels.ExecutionPolicyContext
				require.NoError(t, json.Unmarshal(response.Body.Bytes(), &value))
				require.Equal(t, expected, value.Capabilities)
			}
		}
		require.Equal(t, expected, f.server.executionStatus(t.Context()).PolicyCapabilities)
	}
}

func TestExecutionPolicyCIActivationCannotBypassConsumerFence(t *testing.T) {
	f := configurationAPI(t)
	reviewer, err := f.server.jwtService.ValidateAccessToken(f.reviewer)
	require.NoError(t, err)
	service, err := f.server.jwtService.ValidateAccessToken(f.service)
	require.NoError(t, err)
	var eligible string
	require.NoError(t, f.server.db.Conn().QueryRowContext(t.Context(), `SELECT g.id FROM groups g JOIN user_memberships m ON m.group_id=g.id JOIN users u ON u.id=m.user_id WHERE u.external_id=$1 AND g.org_id=$2`, reviewer.Subject, f.orgID).Scan(&eligible))
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	trust := configuration.TrustedCI{ID: uuid.NewString(), Issuer: "cut-review", Audience: "ops", Subject: service.Subject, Repository: "customer/ops", Ref: "refs/heads/main", PublicKey: base64.StdEncoding.EncodeToString(pub)}
	scope := configuration.Scope{Kind: "organization", ID: f.orgID}
	document := &configuration.Document{APIVersion: configuration.APIVersion, Kind: configuration.Approvers, Scope: scope, Dependencies: map[configuration.Kind]string{}, Deletions: []configuration.Deletion{}, Spec: configuration.ApproversSpec{GroupIDs: []string{eligible}, TrustedCI: []configuration.TrustedCI{trust}}}
	approversBase := "/api/v1/admin/orgs/" + f.orgID + "/configuration/approvers/revisions"
	response := f.request(t, f.admin, http.MethodPost, approversBase, document)
	require.Equal(t, http.StatusCreated, response.Code, response.Body.String())
	var approvers apimodels.ConfigurationRevision
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &approvers))
	response = f.request(t, f.reviewer, http.MethodPost, approversBase+"/"+approvers.ID+"/activate", nil)
	require.Equal(t, http.StatusOK, response.Code, response.Body.String())

	execution := releaseCutExecutionDraft(t, f, f.service)
	now := time.Now()
	proof := configuration.CIApproval{Version: "ops.configuration-approval/v1", TrustID: trust.ID, Issuer: trust.Issuer, Audience: trust.Audience, Subject: trust.Subject, Repository: trust.Repository, Ref: trust.Ref, Commit: strings.Repeat("a", 40), Scope: scope, CandidateDigests: map[configuration.Kind]string{configuration.ExecutionRules: execution.Digest}, ReviewerSubjects: []string{reviewer.Subject}, IssuedAt: now.Unix(), ExpiresAt: now.Add(time.Minute).Unix(), Nonce: uuid.NewString()}
	signing, err := proof.SigningBytes()
	require.NoError(t, err)
	proof.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(key, signing))
	before := releaseCutConfigurationState(t, f)
	path := "/api/v1/admin/orgs/" + f.orgID + "/configuration/execution-rules/revisions/" + execution.ID + "/activate-ci"
	response = f.request(t, f.service, http.MethodPost, path, map[string]any{"coactivate": []string{}, "approval": proof})
	require.Equal(t, http.StatusServiceUnavailable, response.Code, response.Body.String())
	require.Contains(t, response.Body.String(), executionConsumerUnavailable)
	require.Equal(t, before, releaseCutConfigurationState(t, f))
}

func TestExecutionPolicyLegacyActivationRequiresConsumer(t *testing.T) {
	s := setupTestServerForExecutionPolicy(t)
	s.config.NodePolicy = config.NodePolicyConfig{Mode: "legacy"}
	response := s.do(t, http.MethodPost, s.base()+"/revisions", map[string]any{"policy": s.epPolicy(t, "100"), "base_revision": 0})
	require.Equal(t, http.StatusCreated, response.Code, response.Body.String())
	var draft apimodels.ExecutionPolicyRevisionDetail
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &draft))
	response = s.do(t, http.MethodPost, s.base()+"/revisions/"+draft.ID+"/activate", nil)
	require.Equal(t, http.StatusServiceUnavailable, response.Code, response.Body.String())
	require.Contains(t, response.Body.String(), executionConsumerUnavailable)
	stored, err := s.db.GetExecutionPolicyRevision(t.Context(), s.orgID, draft.ID)
	require.NoError(t, err)
	require.Equal(t, "draft", stored.Status)
	active, err := s.db.GetActiveExecutionPolicy(t.Context(), s.orgID)
	require.NoError(t, err)
	require.Nil(t, active)
}

func TestExecutionPolicyReferenceCapabilityMatchesLiveRoute(t *testing.T) {
	s := setupTestServerForExecutionPolicy(t)
	response := s.do(t, http.MethodPost, s.base()+"/revisions", map[string]any{"policy": s.epPolicy(t, "100"), "base_revision": 0})
	require.Equal(t, http.StatusCreated, response.Code, response.Body.String())
	var draft apimodels.ExecutionPolicyRevisionDetail
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &draft))
	signer := common.HexToAddress("0x1111111111111111111111111111111111111111")
	input := map[string]any{"groups": []string{s.group}, "signer": signer.Hex(), "frames": []map[string]any{{
		"call_type": "call", "storage_address": s.vault, "calldata": epTransferCalldata(t, signer, 1),
	}}}
	for _, mode := range []string{"legacy", "reth"} {
		s.config.NodePolicy = config.NodePolicyConfig{Mode: "legacy"}
		if mode == "reth" {
			s.config.NodePolicy = releaseCutConsumerConfig(t)
		}
		response = s.do(t, http.MethodGet, s.base()+"/context", nil)
		require.Equal(t, http.StatusOK, response.Code, response.Body.String())
		var context apimodels.ExecutionPolicyContext
		require.NoError(t, json.Unmarshal(response.Body.Bytes(), &context))
		require.Equal(t, mode == "legacy", context.Capabilities.ReferenceSimulationSupported)
		require.Equal(t, mode == "reth", context.Capabilities.NodePreviewSupported)
		response = s.do(t, http.MethodPost, s.base()+"/revisions/"+draft.ID+"/simulate", input)
		if mode == "legacy" {
			require.Equal(t, http.StatusOK, response.Code, response.Body.String())
		} else {
			require.Equal(t, http.StatusConflict, response.Code, response.Body.String())
			require.Contains(t, response.Body.String(), "use_configuration_execution_rules")
		}
	}
}
