package server

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"privacy-proxy/internal/apimodels"
	"privacy-proxy/internal/auth"
	"privacy-proxy/internal/proxy"
	"privacy-proxy/internal/rbac"
	"privacy-proxy/internal/server/middleware"
)

// This opt-in cross-language integration uses real OPS handlers, JWT checks,
// EIP-191 signature verification, PostgreSQL projection/audit and SDK helpers.
// Only bootstrap identities and application-node responses are fixtures. It is
// neither a deployed-schema upgrade nor Guard v1 producer-execution evidence.
func TestConfigurationSDKRetainedWorkflow(t *testing.T) {
	if os.Getenv("OPS_TEST_SDK_WORKFLOW") != "1" {
		t.Skip("build sdk/dist and set OPS_TEST_SDK_WORKFLOW=1 with an owned TEST_DATABASE_URL")
	}
	require.NotEmpty(t, os.Getenv("TEST_DATABASE_URL"), "this test must use an explicitly owned disposable database")
	node := os.Getenv("OPS_TEST_NODE")
	if node == "" {
		var err error
		node, err = exec.LookPath("node")
		require.NoError(t, err)
	}
	sdk, err := filepath.Abs("../../sdk")
	require.NoError(t, err)
	_, err = os.Stat(filepath.Join(sdk, "dist", "index.js"))
	require.NoError(t, err, "build the SDK before running this opt-in integration")
	f := configurationAPI(t)
	memberDID := "did:test:sdk-member-" + uuid.NewString()
	member := &rbac.User{ID: uuid.NewString(), ExternalID: memberDID, KYC: true}
	require.NoError(t, f.server.db.CreateUser(t.Context(), member))
	memberToken, err := f.server.jwtService.IssueAccessTokenForPrincipal(memberDID, true, auth.PrincipalHuman, nil)
	require.NoError(t, err)
	walletKey, err := crypto.GenerateKey()
	require.NoError(t, err)
	wallet := strings.ToLower(crypto.PubkeyToAddress(walletKey.PublicKey).Hex())
	contract := "0x0000000000000000000000000000000000001500"
	abi := json.RawMessage(`[{"type":"event","name":"Visible","inputs":[],"anonymous":false},{"type":"event","name":"Secret","inputs":[],"anonymous":false}]`)
	topic := "0x" + hex.EncodeToString(crypto.Keccak256([]byte("Visible()")))
	secret := "0x" + hex.EncodeToString(crypto.Keccak256([]byte("Secret()")))
	var mu sync.Mutex
	upstreamCalls := []string{}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		type rpcRequest struct {
			ID     any    `json:"id"`
			Method string `json:"method"`
		}
		var raw json.RawMessage
		if json.NewDecoder(r.Body).Decode(&raw) != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		batch := len(raw) > 0 && raw[0] == '['
		var requests []rpcRequest
		if batch {
			_ = json.Unmarshal(raw, &requests)
		} else {
			var request rpcRequest
			_ = json.Unmarshal(raw, &request)
			requests = append(requests, request)
		}
		responses := []map[string]any{}
		for _, request := range requests {
			mu.Lock()
			upstreamCalls = append(upstreamCalls, request.Method)
			mu.Unlock()
			var result any
			if request.Method == "eth_getLogs" {
				logs := []map[string]any{}
				for _, event := range []string{topic, secret} {
					logs = append(logs, map[string]any{"address": contract, "topics": []string{event}, "data": "0x", "logIndex": "0x0", "transactionIndex": "0x0", "blockNumber": "0x1", "transactionHash": "0x" + strings.Repeat("a", 64), "blockHash": "0x" + strings.Repeat("b", 64), "removed": false})
				}
				result = logs
			}
			responses = append(responses, map[string]any{"jsonrpc": "2.0", "id": request.ID, "result": result})
		}
		w.Header().Set("Content-Type", "application/json")
		if batch {
			_ = json.NewEncoder(w).Encode(responses)
		} else {
			_ = json.NewEncoder(w).Encode(responses[0])
		}
	}))
	t.Cleanup(upstream.Close)
	f.server.proxy = proxy.New(upstream.URL)
	f.server.jsonrpcProcessor = NewJSONRPCProcessor(JSONRPCProcessorConfig{
		ReadProfile: rbac.ReadProfileStandard, RBACAccessCtrl: f.server.rbacAccessCtrl,
		RateLimiter: &noopRateLimiter{}, Proxy: f.server.proxy, AccessLogger: f.server.db,
		CircuitBreaker: middleware.NewCircuitBreaker(), ConcurrencyLimiter: middleware.NewConcurrencyLimiter(10, 0),
		TxVisibilityStore: f.server.db, AddressVisibilityResolver: f.server.db,
	})
	f.server.challengeStore = NewChallengeStore(time.Minute, time.Minute)
	t.Cleanup(f.server.challengeStore.Stop)
	f.router.POST("/api/v1/eth/link/challenge", auth.JWTAuthMiddleware(f.server.jwtService, f.server.db), f.server.handleEthLinkChallenge)
	f.router.POST("/api/v1/eth/link/verify", auth.JWTAuthMiddleware(f.server.jwtService, f.server.db), f.server.handleEthLinkVerify)
	f.router.GET("/api/v1/eth/addresses", auth.JWTAuthMiddleware(f.server.jwtService, f.server.db), f.server.handleGetEthAddresses)
	f.router.POST("/rpc/:org_id", auth.JWTAuthMiddleware(f.server.jwtService, f.server.db), f.server.handleJSONRPC)
	var observedRequests, observedMutations int
	application := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		observedRequests++
		if r.Method != http.MethodGet {
			observedMutations++
		}
		mu.Unlock()
		f.router.ServeHTTP(w, r)
	}))
	t.Cleanup(application.Close)

	// A fixture wallet signs a genuine challenge. The SDK driver performs the
	// verify-link HTTP request; no signing key is supplied to Node or OPS.
	request, err := http.NewRequestWithContext(t.Context(), http.MethodPost, application.URL+"/api/v1/eth/link/challenge", nil)
	require.NoError(t, err)
	request.Header.Set("Authorization", "Bearer "+memberToken)
	response, err := application.Client().Do(request)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, response.StatusCode)
	var challenge apimodels.ChallengeResponse
	require.NoError(t, json.NewDecoder(response.Body).Decode(&challenge))
	require.NoError(t, response.Body.Close())
	signature, err := crypto.Sign(auth.HashMessage(challenge.Message), walletKey)
	require.NoError(t, err)
	fixture := map[string]any{"baseUrl": application.URL, "orgId": f.orgID, "author": f.readonly, "reviewer": f.reviewer, "member": memberToken, "memberDID": memberDID,
		"wallet": wallet, "linkNonce": challenge.Nonce, "linkSignature": "0x" + hex.EncodeToString(signature), "contract": contract, "abi": abi, "allowedTopic": topic}
	encoded, err := json.Marshal(fixture)
	require.NoError(t, err)
	command := exec.CommandContext(t.Context(), node, filepath.Join(sdk, "test", "server-workflow.mjs"))
	command.Env = append(os.Environ(), "OPS_SDK_WORKFLOW_FIXTURE="+string(encoded))
	var stdout, stderr bytes.Buffer
	command.Stdout, command.Stderr = &stdout, &stderr
	err = command.Run()
	require.NoError(t, err, "SDK workflow failed: %s", stderr.String())
	var evidence struct {
		Requests, Mutations, StateMutationAttempts int
		GroupID, ContractID, GrantID, MembershipID string
		Selected                                   []struct{ Groups, Registry string }
		Checks                                     []string
		GuardV1ProducerChecked                     bool
	}
	require.NoError(t, json.Unmarshal(stdout.Bytes(), &evidence))
	require.Len(t, evidence.Selected, 2)
	require.Len(t, evidence.Checks, 7)
	require.False(t, evidence.GuardV1ProducerChecked)
	mu.Lock()
	require.Equal(t, evidence.Requests+1, observedRequests, "one fixture challenge is separate from SDK HTTP calls")
	require.Equal(t, evidence.Mutations+1, observedMutations)
	require.NotContains(t, upstreamCalls, "eth_getBalance", "a refused method must not reach even the canned upstream")
	require.Equal(t, 1, strings.Count(strings.Join(upstreamCalls, ","), "eth_getLogs"), "the banned replay must not reach upstream")
	mu.Unlock()
	stored, err := f.server.db.GetUser(t.Context(), member.ID)
	require.NoError(t, err)
	require.True(t, stored.Banned, "document replay must not undo the incident ban")
	memberships, err := f.server.db.ListUserMembershipsInOrg(t.Context(), member.ID, f.orgID)
	require.NoError(t, err)
	require.Len(t, memberships, 1)
	require.Equal(t, evidence.MembershipID, memberships[0].Membership.ID)
	links, err := f.server.db.GetLinkedEthAddresses(t.Context(), memberDID)
	require.NoError(t, err)
	require.Equal(t, []string{wallet}, links)
	grant, err := f.server.db.GetContractGrant(t.Context(), evidence.GrantID)
	require.NoError(t, err)
	require.NotNil(t, grant.Functions)
	require.Empty(t, grant.Functions, "registry review grants no execution by side effect")
	require.Len(t, grant.EventRules.Rules, 1)
	group, err := f.server.db.GetGroup(t.Context(), evidence.GroupID)
	require.NoError(t, err)
	require.Equal(t, "SDK readers replay", group.Name)
	registered, err := f.server.db.GetContract(t.Context(), evidence.ContractID)
	require.NoError(t, err)
	require.False(t, registered.AllowVisibleToUnlock)
	require.False(t, registered.EventsAllowDynamicPayload)
	var activations, executionActive int
	require.NoError(t, f.server.db.Conn().QueryRowContext(t.Context(), `SELECT COUNT(*) FROM rbac_audit_log WHERE org_id=$1 AND resource_type='configuration_revision' AND action='update'`, f.orgID).Scan(&activations))
	require.Equal(t, 2, activations, "one actor-attributed audit record commits each two-stream activation bundle")
	reviewer, err := f.server.jwtService.ValidateAccessToken(f.reviewer)
	require.NoError(t, err)
	rows, err := f.server.db.Conn().QueryContext(t.Context(), `SELECT actor_external_id,new_value FROM rbac_audit_log WHERE org_id=$1 AND resource_type='configuration_revision' AND action='update' ORDER BY created_at,id`, f.orgID)
	require.NoError(t, err)
	for index := 0; rows.Next(); index++ {
		var actor string
		var raw []byte
		require.NoError(t, rows.Scan(&actor, &raw))
		require.Equal(t, reviewer.Subject, actor)
		var audit struct{ Revisions []struct{ ID string } }
		require.NoError(t, json.Unmarshal(raw, &audit))
		ids := []string{}
		for _, revision := range audit.Revisions {
			ids = append(ids, revision.ID)
		}
		require.ElementsMatch(t, []string{evidence.Selected[index].Groups, evidence.Selected[index].Registry}, ids)
	}
	require.NoError(t, rows.Err())
	require.NoError(t, rows.Close())
	for index, selected := range evidence.Selected {
		for _, id := range []string{selected.Groups, selected.Registry} {
			var status string
			require.NoError(t, f.server.db.Conn().QueryRowContext(t.Context(), `SELECT status FROM configuration_revisions WHERE org_id=$1 AND id=$2`, f.orgID, id).Scan(&status))
			expected := "superseded"
			if index == len(evidence.Selected)-1 {
				expected = "active"
			}
			require.Equal(t, expected, status)
		}
	}
	require.NoError(t, f.server.db.Conn().QueryRowContext(t.Context(), `SELECT COUNT(*) FROM configuration_revisions WHERE org_id=$1 AND kind='execution-rules' AND status='active'`, f.orgID).Scan(&executionActive))
	require.Zero(t, executionActive)
	require.Equal(t, 9, evidence.StateMutationAttempts)
	t.Logf("SDK workflow: one Node driver invocation, %d HTTP calls (%d non-GET including review/RPC; %d state-changing requests), plus one fixture wallet challenge; real OPS/DB/signature checks, canned application RPC, no Guard v1 producer checked", evidence.Requests, evidence.Mutations, evidence.StateMutationAttempts)
}
