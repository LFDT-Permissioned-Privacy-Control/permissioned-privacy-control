package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func newTestServer(handler http.HandlerFunc) (*httpClient, func()) {
	ts := httptest.NewServer(handler)
	client, err := newHTTPClient(ts.URL, "test-admin-token")
	if err != nil {
		panic("test server URL invalid: " + err.Error())
	}
	return client, ts.Close
}

type testEnv struct {
	session *mcp.ClientSession
	cancel  context.CancelFunc
}

func setupMCP(t *testing.T, registerFn func(s *mcp.Server)) *testEnv {
	t.Helper()

	s := mcp.NewServer(&mcp.Implementation{Name: "test"}, nil)
	registerFn(s)

	clientTransport, serverTransport := mcp.NewInMemoryTransports()

	ctx, cancel := context.WithCancel(context.Background())

	go func() {
		_ = s.Run(ctx, serverTransport)
	}()

	client := mcp.NewClient(&mcp.Implementation{Name: "test-client"}, nil)
	session, err := client.Connect(ctx, clientTransport, nil)
	if err != nil {
		cancel()
		t.Fatalf("connect failed: %v", err)
	}

	t.Cleanup(func() {
		cancel()
	})

	return &testEnv{session: session, cancel: cancel}
}

func callTool(t *testing.T, env *testEnv, name string, args any) string {
	t.Helper()
	argsJSON, _ := json.Marshal(args)
	argsMap := map[string]any{}
	json.Unmarshal(argsJSON, &argsMap)

	result, err := env.session.CallTool(context.Background(), &mcp.CallToolParams{
		Name:      name,
		Arguments: argsMap,
	})
	if err != nil {
		t.Fatalf("tool %s returned error: %v", name, err)
	}
	if len(result.Content) == 0 {
		t.Fatalf("tool %s returned no content", name)
	}
	tc, ok := result.Content[0].(*mcp.TextContent)
	if !ok {
		t.Fatalf("tool %s returned non-text content", name)
	}
	return tc.Text
}

func TestHealth_OK(t *testing.T) {
	client, cleanup := newTestServer(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			fmt.Fprint(w, `{"status":"ok"}`)
			return
		}
		http.NotFound(w, r)
	})
	defer cleanup()

	env := setupMCP(t, func(s *mcp.Server) {
		registerSystemTools(s, client)
	})

	text := callTool(t, env, "health", struct{}{})
	if !strings.Contains(text, "OK") {
		t.Fatalf("expected OK in health output, got: %s", text)
	}
}

func TestNewHTTPClient_ValidURL(t *testing.T) {
	c, err := newHTTPClient("http://localhost:8080", "token")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c.baseURL.Host != "localhost:8080" {
		t.Fatalf("expected localhost:8080, got %s", c.baseURL.Host)
	}
}

func TestNewHTTPClient_InvalidScheme(t *testing.T) {
	_, err := newHTTPClient("ftp://localhost:8080", "")
	if err == nil {
		t.Fatal("expected error for ftp scheme")
	}
}

func TestNewHTTPClient_InvalidURL(t *testing.T) {
	_, err := newHTTPClient("://bad", "")
	if err == nil {
		t.Fatal("expected error for invalid URL")
	}
}

func TestHealth_Unreachable(t *testing.T) {
	client, _ := newHTTPClient("http://localhost:1", "")

	env := setupMCP(t, func(s *mcp.Server) {
		registerSystemTools(s, client)
	})

	text := callTool(t, env, "health", struct{}{})
	if !strings.Contains(text, "Error") {
		t.Fatalf("expected error in health output, got: %s", text)
	}
}

func TestListOrgs(t *testing.T) {
	client, cleanup := newTestServer(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/admin/orgs" {
			fmt.Fprint(w, `{"data":[{"id":"org-1","slug":"default","name":"Default Org"}],"total":1,"limit":50,"offset":0}`)
			return
		}
		http.NotFound(w, r)
	})
	defer cleanup()

	confirms := NewConfirmationEngine()
	env := setupMCP(t, func(s *mcp.Server) {
		registerOrgTools(s, client, confirms)
	})

	text := callTool(t, env, "list_orgs", listOrgsArgs{})
	if !strings.Contains(text, "Default Org") {
		t.Fatalf("expected Default Org, got: %s", text)
	}
}

func TestCreateOrg_Validation(t *testing.T) {
	client, cleanup := newTestServer(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	})
	defer cleanup()

	confirms := NewConfirmationEngine()
	env := setupMCP(t, func(s *mcp.Server) {
		registerOrgTools(s, client, confirms)
	})

	text := callTool(t, env, "create_org", createOrgArgs{})
	if !strings.Contains(text, "slug and name are required") {
		t.Fatalf("expected validation error, got: %s", text)
	}
}

func TestDeleteOrg_TwoStep(t *testing.T) {
	deleted := false
	client, cleanup := newTestServer(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/api/v1/admin/orgs/") {
			deleted = true
			fmt.Fprint(w, `{"message":"organization deleted"}`)
			return
		}
		http.NotFound(w, r)
	})
	defer cleanup()

	confirms := NewConfirmationEngine()
	env := setupMCP(t, func(s *mcp.Server) {
		registerOrgTools(s, client, confirms)
	})

	// Step 1: dry run
	text := callTool(t, env, "delete_org", deleteOrgArgs{OrgID: "org-1"})
	if !strings.Contains(text, "Confirmation Token") {
		t.Fatalf("expected confirmation token, got: %s", text)
	}
	if deleted {
		t.Fatal("should not have deleted on dry run")
	}

	// Extract token
	token := extractToken(t, text)

	// Step 2: confirm
	text = callTool(t, env, "delete_org", deleteOrgArgs{OrgID: "org-1", ConfirmToken: token})
	if !strings.Contains(text, "Deleted") {
		t.Fatalf("expected Deleted, got: %s", text)
	}
	if !deleted {
		t.Fatal("expected delete to have been called")
	}
}

func TestDeleteOrg_ReplayBlocked(t *testing.T) {
	client, cleanup := newTestServer(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"message":"deleted"}`)
	})
	defer cleanup()

	confirms := NewConfirmationEngine()
	env := setupMCP(t, func(s *mcp.Server) {
		registerOrgTools(s, client, confirms)
	})

	text := callTool(t, env, "delete_org", deleteOrgArgs{OrgID: "org-1"})
	token := extractToken(t, text)

	// Use token once
	callTool(t, env, "delete_org", deleteOrgArgs{OrgID: "org-1", ConfirmToken: token})

	// Replay should fail
	text = callTool(t, env, "delete_org", deleteOrgArgs{OrgID: "org-1", ConfirmToken: token})
	if !strings.Contains(text, "invalid or expired") {
		t.Fatalf("expected replay rejection, got: %s", text)
	}
}

func TestResolveUser(t *testing.T) {
	client, cleanup := newTestServer(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/v1/admin/users") {
			search := r.URL.Query().Get("search")
			if search == "0xABC" {
				fmt.Fprint(w, `{"data":[{"id":"user-1","external_id":"did:pkh:eip155:1:0xABC","banned":false}],"total":1}`)
			} else {
				fmt.Fprint(w, `{"data":[],"total":0}`)
			}
			return
		}
		http.NotFound(w, r)
	})
	defer cleanup()

	confirms := NewConfirmationEngine()
	env := setupMCP(t, func(s *mcp.Server) {
		registerUserTools(s, client, confirms)
	})

	text := callTool(t, env, "resolve_user", resolveUserArgs{Query: "0xABC"})
	if !strings.Contains(text, "user-1") {
		t.Fatalf("expected user-1, got: %s", text)
	}

	text = callTool(t, env, "resolve_user", resolveUserArgs{Query: "nobody"})
	if !strings.Contains(text, "No users found") {
		t.Fatalf("expected no users, got: %s", text)
	}
}

func TestEffectivePermissions(t *testing.T) {
	client, cleanup := newTestServer(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "effective-permissions") {
			fmt.Fprint(w, `{
				"user_id":"user-1",
				"org_id":"org-1",
				"claims":["read","write"],
				"allowed_methods":["eth_call","eth_getBalance"],
				"contract_access":{"0xDEAD":{"claims":["read"]}}
			}`)
			return
		}
		http.NotFound(w, r)
	})
	defer cleanup()

	confirms := NewConfirmationEngine()
	env := setupMCP(t, func(s *mcp.Server) {
		registerUserTools(s, client, confirms)
	})

	text := callTool(t, env, "effective_permissions", effectivePermsArgs{UserID: "user-1"})
	if !strings.Contains(text, "read") || !strings.Contains(text, "write") {
		t.Fatalf("expected claims, got: %s", text)
	}
	if !strings.Contains(text, "0xDEAD") {
		t.Fatalf("expected contract access, got: %s", text)
	}
}

func TestCheckAccess(t *testing.T) {
	client, cleanup := newTestServer(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/admin/access/check" {
			fmt.Fprint(w, `{"allowed":true,"reason":"user has read claim","claims":["read"]}`)
			return
		}
		http.NotFound(w, r)
	})
	defer cleanup()

	confirms := NewConfirmationEngine()
	env := setupMCP(t, func(s *mcp.Server) {
		registerUserTools(s, client, confirms)
	})

	text := callTool(t, env, "check_access", checkAccessArgs{
		UserExternalID: "did:pkh:eip155:1:0xABC",
		Method:         "eth_call",
	})
	if !strings.Contains(text, "ALLOWED") {
		t.Fatalf("expected ALLOWED, got: %s", text)
	}
}

func TestAdminTokenSent(t *testing.T) {
	var gotToken string
	client, cleanup := newTestServer(func(w http.ResponseWriter, r *http.Request) {
		gotToken = r.Header.Get("X-Admin-Token")
		fmt.Fprint(w, `{"status":"ok"}`)
	})
	defer cleanup()

	env := setupMCP(t, func(s *mcp.Server) {
		registerSystemTools(s, client)
	})

	callTool(t, env, "health", struct{}{})
	if gotToken != "test-admin-token" {
		t.Fatalf("expected admin token in header, got: %q", gotToken)
	}
}

func TestListContracts(t *testing.T) {
	client, cleanup := newTestServer(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/contracts") {
			fmt.Fprint(w, `{"data":[{"id":"c-1","address":"0xdead","name":"TestToken","abi":"[]"}],"total":1}`)
			return
		}
		http.NotFound(w, r)
	})
	defer cleanup()

	confirms := NewConfirmationEngine()
	env := setupMCP(t, func(s *mcp.Server) {
		registerContractTools(s, client, confirms)
	})

	text := callTool(t, env, "list_contracts", listContractsArgs{OrgID: "org-1"})
	if !strings.Contains(text, "TestToken") {
		t.Fatalf("expected TestToken, got: %s", text)
	}
}

func extractToken(t *testing.T, text string) string {
	t.Helper()
	for _, line := range strings.Split(text, "\n") {
		if strings.Contains(line, "Confirmation Token") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				token := strings.TrimSpace(parts[1])
				if token != "" {
					return token
				}
			}
		}
	}
	t.Fatal("could not extract confirmation token from output")
	return ""
}
